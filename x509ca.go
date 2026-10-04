// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The X.509 certificate authority, for NFS over TLS (RFC 9289): somebody who
// logged in through their institution has a client certificate issued for a
// few hours, naming them the way an NFS server can map to a user.
//
// ⛔ RFC 9289 says a server "cannot utilize the remote TLS peer identity to
// authenticate RPC users": the certificate authenticates the MACHINE, and on
// Linux the client certificate is set per mount (ktls-utils), so every user
// of that mount is the person it names. This is for a machine one person
// uses, and `bridge nfs-cert` says so.
//
// The name is where FreeBSD's rpc.tlsservd -u looks (rpc.tlsservd.c:99, and
// draft-cel-nfsv4-rpc-tls-othername, which has no IANA OID yet): a
// subjectAltName otherName 1.3.6.1.4.1.2238.1.1.1 holding a UTF8String
// "user@domain", exactly one. FreeBSD maps it only when domain is its own
// NFSv4 domain and user is in its passwd; go-fileshare maps the whole name.
//
// The groups go beside it as URI names, one per group:
// tag:go-authn.github.io,2026:group:<the group, percent-encoded> (RFC 4151,
// which needs no registration). Not a custom extension: an OID of the UUID
// arc (2.25.<128 bits>) does not fit Go's asn1.ObjectIdentifier, and
// x509.ParseCertificate refuses the WHOLE certificate over it ("malformed
// extension OID field") -- measured -- so every Go TLS server would. FreeBSD
// skips every name that is not an otherName (rpc.tlsservd.c:906-909).

var (
	oidNFSUser       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2238, 1, 1, 1}
	oidSubjectAltNam = asn1.ObjectIdentifier{2, 5, 29, 17}
	// groupURIPrefix names a group in a URI subjectAltName.
	groupURIPrefix = "tag:go-authn.github.io,2026:group:"
)

// x509Skew is how far back a certificate's validity starts.
const x509Skew = 5 * time.Minute

type x509CABlock struct {
	// KeyFile and CertFile are the CA's P-256 key and self-signed
	// certificate (`bridge keygen --x509-ca DIR` writes both). CertFile is
	// what go-fileshare trusts.
	KeyFile  string `hcl:"key_file"`
	CertFile string `hcl:"cert_file"`

	// Validity is how long a certificate lives: 12h by default, a week at
	// most, never longer than the IdP's session when it said when that
	// ends, nor than the CA's own certificate.
	Validity string `hcl:"validity,optional"`

	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	certPEM  []byte
	validity time.Duration
}

func (b *x509CABlock) load() error {
	k, err := loadSigningKey(b.KeyFile)
	if err != nil {
		return err
	}
	if k.ec == nil {
		return fmt.Errorf("%s: the CA key must be P-256 (`bridge keygen --x509-ca` writes one)", b.KeyFile)
	}
	b.key = k.ec
	if b.certPEM, err = os.ReadFile(b.CertFile); err != nil {
		return err
	}
	blk, _ := pem.Decode(b.certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("%s is not a PEM certificate", b.CertFile)
	}
	if b.cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
		return err
	}
	if !b.cert.IsCA || b.cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return fmt.Errorf("%s: not a CA certificate that signs certificates and CRLs", b.CertFile)
	}
	if pub, ok := b.cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&b.key.PublicKey) {
		return fmt.Errorf("%s is not the certificate of %s", b.CertFile, b.KeyFile)
	}
	b.validity = 12 * time.Hour
	if b.Validity != "" {
		d, err := time.ParseDuration(b.Validity)
		if err != nil || d <= 0 {
			return fmt.Errorf("validity = %q: a positive duration like \"12h\"", b.Validity)
		}
		if d > 7*24*time.Hour {
			return fmt.Errorf("validity = %s: more than a week", d)
		}
		b.validity = d
	}
	return nil
}

// generateX509CA writes ca.key and ca.crt in dir, refusing to overwrite
// either: a P-256 CA, valid ten years, that signs end-entity certificates
// and CRLs and nothing else (path length 0).
func generateX509CA(dir, name string) (string, error) {
	keyFile, certFile := filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(certFile); err == nil {
		return "", fmt.Errorf("%s: %w", certFile, os.ErrExist)
	}
	if err := generateECKey(keyFile); err != nil {
		return "", err
	}
	k, err := loadSigningKey(keyFile)
	if err != nil {
		return "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-x509Skew),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.ec.PublicKey, k.ec)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		f.Close()
		return "", err
	}
	return certFile, f.Close()
}

// nfsSAN is a subjectAltName holding one otherName, the NFS user, and a URI
// per group.
//
//	GeneralNames ::= SEQUENCE OF GeneralName
//	GeneralName  ::= otherName [0] IMPLICIT OtherName
//	               | uniformResourceIdentifier [6] IMPLICIT IA5String
//	OtherName    ::= SEQUENCE { type-id OID, value [0] EXPLICIT UTF8String }
func nfsSAN(user string, groups []string) ([]byte, error) {
	utf8, err := asn1.MarshalWithParams(user, "utf8")
	if err != nil {
		return nil, err
	}
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidNFSUser, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8}})
	if err != nil {
		return nil, err
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(other, &seq); err != nil {
		return nil, err
	}
	names := []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: seq.Bytes}}
	for _, g := range groups {
		// PathEscape keeps IA5String ASCII and the URI one: it escapes
		// '#', '?', '/', spaces and non-ASCII, and keeps ':' and '@'.
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(groupURIPrefix + url.PathEscape(g))})
	}
	return asn1.Marshal(names)
}

// x509Certificate issues a client certificate for the CSR in the request
// body, to the person the bearer token is about.
func (s *server) x509Certificate(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.X509CA
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	claims, err := s.bearerClaims(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	clientID, _ := claims["client_id"].(string)
	client, ok := s.cfg.client(clientID)
	scope, _ := claims["scope"].(string)
	if !ok || !client.X509Certificates || !slices.Contains(strings.Fields(scope), "nfs") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="nfs"`)
		http.Error(w, "this token may not have an NFS certificate issued", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	user, _ := claims["preferred_username"].(string)
	if len(user) < 3 || !strings.Contains(user, "@") {
		// FreeBSD refuses a name under 3 bytes, and a name with no domain
		// maps nowhere.
		http.Error(w, "the institution released no user@domain name to put in a certificate", http.StatusForbidden)
		return
	}
	if err := certifiableName(user); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		http.Error(w, "the request could not be read", http.StatusBadRequest)
		return
	}
	blk, _ := pem.Decode(body)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "the body is not a PEM certificate request", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		http.Error(w, "the certificate request does not parse", http.StatusBadRequest)
		return
	}
	// The request's own signature: whoever sent it holds the key.
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "the certificate request is not signed by its key", http.StatusBadRequest)
		return
	}
	if err := x509KeyStrongEnough(csr.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := s.now()
	until := now.Add(ca.validity)
	if end, ok := claims["session_end"].(float64); ok && end > 0 && time.Unix(int64(end), 0).Before(until) {
		until = time.Unix(int64(end), 0)
	}
	if ca.cert.NotAfter.Before(until) {
		until = ca.cert.NotAfter
	}
	serial, err := s.certs.newSerial("x509", 127)
	if err != nil {
		s.logf("x509: %v", err)
		http.Error(w, "the certificate could not be issued", http.StatusInternalServerError)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// The request's subject and extensions are ignored: what this
		// provider certifies is the token's person, not what they asked for.
		Subject:               pkix.Name{CommonName: user},
		NotBefore:             now.Add(-x509Skew),
		NotAfter:              until,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{s.cfg.Issuer + "/x509/crl"},
	}
	var groups []string
	if gs, ok := claims["groups"].([]any); ok {
		for _, g := range gs {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
	}
	san, err := nfsSAN(user, groups)
	if err != nil {
		http.Error(w, "the name cannot be put in a certificate", http.StatusBadRequest)
		return
	}
	// A CN is at most 64 characters (RFC 5280 ub-common-name). A longer name
	// leaves the subject empty, and the SAN is then critical (4.2.1.6).
	critical := false
	if len(user) > 64 {
		tmpl.Subject, critical = pkix.Name{}, true
	}
	tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltNam, Critical: critical, Value: san}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		s.logf("x509: %v", err)
		http.Error(w, "the certificate could not be issued", http.StatusInternalServerError)
		return
	}
	jti, _ := claims["jti"].(string)
	it, _ := s.issued.get(jti)
	if err := s.certs.add(issuedCert{Kind: "x509", Serial: serial.String(), KeyID: "jti=" + jti, Principal: user, IdP: it.idp, NotAfter: until}, now); err != nil {
		s.logf("x509: recording the certificate: %v", err)
		http.Error(w, "the certificate could not be recorded, so it is not issued", http.StatusInternalServerError)
		return
	}
	if s.withdrawn(w, jti, user, "x509", serial.String(), now) {
		return
	}
	s.counters.inc("bridge_x509_certificates_total", "")
	s.logf("x509: issued an NFS certificate for %s until %s", user, until.UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-store")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	w.Write(ca.certPEM)
}

func x509KeyStrongEnough(k crypto.PublicKey) error {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return nil
		}
		return errors.New("an ECDSA key must be P-256")
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
		return errors.New("an RSA key under 2048 bits")
	}
	return fmt.Errorf("a %T key is not certified", k)
}

// x509CRL is the CA's CRL: every unexpired revoked certificate, signed by
// the key that signs the certificates, its number the revocation counter
// shared with the SSH KRL. A verifier treats it as stale past NextUpdate.
func (s *server) x509CRL(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.X509CA
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	l, err := s.issueList("x509", func(revoked []issuedCert, _, number uint64, now time.Time) ([]byte, []byte, error) {
		entries := make([]x509.RevocationListEntry, 0, len(revoked))
		for _, c := range revoked {
			n, ok := new(big.Int).SetString(c.Serial, 10)
			if !ok {
				continue
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: c.Revoked})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    new(big.Int).SetUint64(number),
			ThisUpdate:                now,
			NextUpdate:                now.Add(listValidity),
			RevokedCertificateEntries: entries,
		}, ca.cert, ca.key)
		return der, nil, err
	})
	if err != nil {
		s.logf("x509: the CRL: %v", err)
		http.Error(w, "the CRL could not be made", http.StatusInternalServerError)
		return
	}
	serveList(w, r, l, "application/pkix-crl")
}
