// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

// The SSH certificate authority: somebody who logged in through their
// institution has an SSH public key certified for a few hours, and a server
// that trusts this CA -- go-fileshare's trusted_user_ca_file -- lets them in
// over SFTP with no account there and no key file to edit.

// sshSkew is how far back a certificate's validity starts, for clocks that
// disagree.
const sshSkew = 5 * time.Minute

// GroupsExtension is the certificate extension that carries the person's
// groups, one per line.
const GroupsExtension = "groups@go-authn.org"

func (b *sshCABlock) load() error {
	raw, err := os.ReadFile(b.KeyFile)
	if err != nil {
		return err
	}
	k, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		return err
	}
	// RSA CA keys sign with SHA-1 (ssh-rsa) unless told otherwise, which
	// OpenSSH has refused by default since 8.8. Ed25519 has one algorithm.
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("%s: the CA key must be Ed25519 (`bridge keygen --ssh-ca` writes one)", b.KeyFile)
	}
	b.signer = signer
	b.validity = 12 * time.Hour
	if b.Validity != "" {
		d, err := time.ParseDuration(b.Validity)
		if err != nil || d <= 0 {
			return fmt.Errorf("validity = %q: a positive duration like \"12h\"", b.Validity)
		}
		if d > 7*24*time.Hour {
			return fmt.Errorf("validity = %s: a certificate nobody can revoke, for more than a week", d)
		}
		b.validity = d
	}
	return nil
}

// generateSSHCA writes an Ed25519 CA key in OpenSSH format, refusing to
// overwrite one, and returns its public half as an authorized_keys line.
func generateSSHCA(file string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "go-authn/bridge SSH CA")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(f, blk); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " go-authn-bridge-ca", nil
}

// bearerClaims verifies an access token this provider issued and that has
// not been revoked, returning its claims.
// certifiableName refuses a username that would not stay ONE name in a
// certificate. sshd reads principals="a,b" in authorized_keys and
// AuthorizedPrincipalsFile entries as comma- and space-separated lists
// (sshd(8) AUTHORIZED_KEYS FILE FORMAT), so a principal holding a comma is
// two names to whatever splits it; a quote or a control character breaks
// those files' own quoting, and in an X.509 CN reaches DN parsers too. The
// IdP chose the name, and the federation vouched only for its scope.
func certifiableName(u string) error {
	for _, r := range u {
		if r == ',' || r == '"' || r == '\\' || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return fmt.Errorf("the username %q cannot be put in a certificate: it holds %q", u, r)
		}
	}
	return nil
}

// addressedHere says whether a token is addressed to this provider
// (accessAudience). Its own endpoints ask, after the scope: a token a
// resource server received must not be replayable here.
func (s *server) addressedHere(claims map[string]any) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == s.cfg.Issuer
	case []any:
		return slices.Contains(aud, any(s.cfg.Issuer))
	}
	return false
}

// notAddressedHere answers a token addressed to somebody else (RFC 6750 3.1).
func notAddressedHere(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="not addressed to this provider"`)
	http.Error(w, "the token is addressed to another audience", http.StatusUnauthorized)
}

func (s *server) bearerClaims(r *http.Request) (map[string]any, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errors.New("no bearer token")
	}
	claims, err := s.cfg.accessKey.verify("at+jwt", strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	jti, _ := claims["jti"].(string)
	if _, ok := s.issued.get(jti); !ok {
		return nil, errRevoked
	}
	return claims, nil
}

// sshCertificate certifies the public key in the request body for the
// person the bearer token is about.
//
// ⛔ The certificate always names its principal. PROTOCOL.certkeys: "a
// zero-length valid principals field means the certificate is valid for any
// principal" -- a certificate for somebody with no username would be a
// certificate for everybody, so there is none.
func (s *server) sshCertificate(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.SSHCA
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
	if !ok || !client.SSHCertificates || !slices.Contains(strings.Fields(scope), "ssh") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="ssh"`)
		http.Error(w, "this token may not have SSH keys certified", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	user, _ := claims["preferred_username"].(string)
	if user == "" {
		http.Error(w, "the institution released no username to put in a certificate", http.StatusForbidden)
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
	key, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		http.Error(w, "the body is not an SSH public key", http.StatusBadRequest)
		return
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		http.Error(w, "that is a certificate, not a key", http.StatusBadRequest)
		return
	}
	if err := strongEnough(key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := s.now()
	until := now.Add(ca.validity)
	// Not past the IdP's session, when it said when that ends -- carried in
	// the token as the time the provider must stop vouching.
	if end, ok := claims["session_end"].(float64); ok && end > 0 && time.Unix(int64(end), 0).Before(until) {
		until = time.Unix(int64(end), 0)
	}
	serial, err := s.certs.newSerial("ssh", 63)
	if err != nil {
		s.logf("ssh: %v", err)
		http.Error(w, "the certificate could not be signed", http.StatusInternalServerError)
		return
	}
	sub, _ := claims["sub"].(string)
	cert := &ssh.Certificate{
		Key:      key,
		Serial:   serial.Uint64(),
		CertType: ssh.UserCert,
		// The key ID is what sshd logs: who, and which login.
		KeyId:           fmt.Sprintf("%s sub=%s jti=%s", user, sub, claims["jti"]),
		ValidPrincipals: []string{user},
		ValidAfter:      uint64(now.Add(-sshSkew).Unix()),
		ValidBefore:     uint64(until.Unix()),
		// No permit-* extensions: SFTP needs none, and a certificate that
		// does not permit a pty, forwarding or an rc file is one that grants
		// file access and nothing else.
	}
	// The groups, for a server that authorizes by them (go-fileshare's
	// oidc:groups: rules): one per line, in an extension OpenSSH ignores,
	// as PROTOCOL.certkeys says an unrecognised extension must be. It grants
	// nothing by itself; it is signed, so a server trusting this CA can
	// believe it.
	if gs, ok := claims["groups"].([]any); ok && len(gs) > 0 {
		var lines []string
		for _, g := range gs {
			if s, ok := g.(string); ok && s != "" && !strings.ContainsRune(s, '\n') {
				lines = append(lines, s)
			}
		}
		if len(lines) > 0 {
			cert.Permissions.Extensions = map[string]string{GroupsExtension: strings.Join(lines, "\n")}
		}
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		s.logf("ssh: %v", err)
		http.Error(w, "the certificate could not be signed", http.StatusInternalServerError)
		return
	}
	// Recorded before it is handed out: one that is not can never be revoked.
	jti, _ := claims["jti"].(string)
	it, _ := s.issued.get(jti)
	if err := s.certs.add(issuedCert{Kind: "ssh", Serial: serial.String(), KeyID: cert.KeyId, Principal: user, IdP: it.idp, NotAfter: until}, now); err != nil {
		s.logf("ssh: recording the certificate: %v", err)
		http.Error(w, "the certificate could not be recorded, so it is not issued", http.StatusInternalServerError)
		return
	}
	s.counters.inc("bridge_ssh_certificates_total", "")
	s.logf("ssh: certified a %s key for %s until %s", key.Type(), user, until.UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}

// strongEnough refuses what is not worth certifying: RSA under 2048 bits
// (OpenSSH's own floor is 1024; NIST retired those), DSA, and anything
// this does not know.
func strongEnough(k ssh.PublicKey) error {
	switch k.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := k.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("an RSA key that cannot be read")
		}
		// The modulus's bits, as x509ca.go and keys.go count them: Size() is
		// the length in BYTES, rounded up, so a 2041-bit key read as 2048.
		if pk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && pk.N.BitLen() >= 2048 {
			return nil
		}
		return errors.New("an RSA key under 2048 bits")
	}
	return fmt.Errorf("a %s key is not certified", k.Type())
}

// sshKRL is the SSH CA's key revocation list (PROTOCOL.krl): every unexpired
// revoked certificate by serial, its krl_version the revocation counter
// shared with the X.509 CRL. Written by go-authn/krl, whose output ssh-keygen
// -Q reads and which never writes a bitmap ssh-keygen cannot read back.
//
// Not signed: OpenSSH no longer verifies KRL signatures (it reads a signed
// one and skips the signature), so its integrity is the HTTPS it is fetched
// over. Served with a short max-age: a server that caches it longer, or
// cannot fetch it, is to fail closed -- go-fileshare does.
func (s *server) sshKRL(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.SSHCA
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	l, err := s.issueKRL(ca)
	if err != nil {
		s.logf("ssh: the KRL: %v", err)
		http.Error(w, "the KRL could not be made", http.StatusInternalServerError)
		return
	}
	serveList(w, r, l, "application/octet-stream")
}

// sshKRLSig is the KRL's detached SSHSIG signature, by the CA key, in the
// namespace go-authn/revocation names. If-Match carries the ETag of the
// list the reader holds: a list issued again in between answers 412
// rather than a signature that does not match it.
func (s *server) sshKRLSig(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.SSHCA
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	l, err := s.issueKRL(ca)
	if err != nil {
		s.logf("ssh: the KRL: %v", err)
		http.Error(w, "the KRL could not be made", http.StatusInternalServerError)
		return
	}
	if m := r.Header.Get("If-Match"); m != "" && m != l.tag {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "max-age=60")
	w.Write(l.sig)
}

// issueKRL is the KRL currently issued: the CA's revoked serials, an
// expiry listValidity on, signed.
func (s *server) issueKRL(ca *sshCABlock) (*issuedList, error) {
	return s.issueList("ssh", func(revoked []issuedCert, version, _ uint64, now time.Time) ([]byte, []byte, error) {
		b := krl.NewBuilder(version, "go-authn/bridge "+s.cfg.Issuer)
		for _, c := range revoked {
			n, err := strconv.ParseUint(c.Serial, 10, 64)
			if err != nil {
				continue
			}
			b.RevokeSerial(ca.signer.PublicKey(), n)
		}
		b.SetExpires(now.Add(listValidity))
		raw, err := b.Marshal(now)
		if err != nil {
			return nil, nil, err
		}
		sig, err := revocation.SignKRL(raw, ca.signer)
		if err != nil {
			return nil, nil, err
		}
		return raw, sig, nil
	})
}
