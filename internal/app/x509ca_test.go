// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// x509Fixture is a provider with an X.509 CA, a certificates file and a
// device client that may ask for NFS certificates; and the CA's PEM file.
func x509Fixture(t *testing.T) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	caCert, err := generateX509CA(dir, "test NFS CA")
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, `
certificates_file = "`+filepath.ToSlash(filepath.Join(dir, "certs.json"))+`"
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
x509_ca {
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "ca.key"))+`"
  cert_file = "`+filepath.ToSlash(caCert)+`"
  validity  = "8h"
}
client "nfs" {
  device            = true
  x509_certificates = true
}
client "plain" {
  device = true
}
`)
	f.s.poll = time.Second
	return f, caCert
}

func csrFor(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "somebody else"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func postCSR(t *testing.T, f *fixture, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/x509/cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func getCRL(t *testing.T, f *fixture) (*x509.RevocationList, []byte, http.Header) {
	t.Helper()
	res, err := http.Get(f.s.cfg.Issuer + "/x509/crl")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	der, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/x509/crl: %s", res.Status)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl, der, res.Header
}

// otherNames reads the otherName entries of a certificate's SAN.
func otherNames(t *testing.T, c *x509.Certificate) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidSubjectAltNam) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(e.Value, &names); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if n.Class != asn1.ClassContextSpecific || n.Tag != 0 {
				continue
			}
			var on struct {
				ID    asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			if _, err := asn1.Unmarshal(append([]byte{0x30, byte(len(n.Bytes))}, n.Bytes...), &on); err != nil {
				t.Fatal(err)
			}
			var s string
			if _, err := asn1.UnmarshalWithParams(on.Value.Bytes, &s, "utf8"); err != nil {
				t.Fatalf("the otherName value is not a UTF8String: %v", err)
			}
			out[on.ID.String()] = append(out[on.ID.String()], s)
		}
	}
	return out
}

// openssl is the judge of what a certificate and a CRL say, when it is
// installed: it did not write them.
func openssl(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("openssl is required here and is not installed")
		}
		t.Skip("openssl is not installed")
	}
	return p
}

// An NFS client certificate: the FreeBSD otherName, the groups as URIs,
// client authentication only, verified by openssl against the CA; then
// revoked by disabling the person, as the CRL openssl checks says.
func TestNFSCertificate(t *testing.T) {
	f, caFile := x509Fixture(t)
	someone := assertionOpts{
		eppn:        "alice@" + idpScope,
		entitlement: []string{"urn:geant:univ-example.fr:group:physique#login.example.org", "urn:mace:univ-example.fr:fileshare:photos"},
	}
	tok := f.deviceTokenAs("nfs", someone, "openid", "nfs")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status, body := postCSR(t, f, tok.AccessToken, csrFor(t, key))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	blk, rest := pem.Decode(body)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("Go does not parse it: %v", err)
	}
	if caBlk, _ := pem.Decode(rest); caBlk == nil {
		t.Error("the CA certificate does not follow the leaf")
	}

	// What it says.
	if on := otherNames(t, leaf); len(on) != 1 || len(on["1.3.6.1.4.1.2238.1.1.1"]) != 1 || on["1.3.6.1.4.1.2238.1.1.1"][0] != "alice@"+idpScope {
		t.Errorf("otherNames %v: want exactly one, the FreeBSD user", on)
	}
	var groups []string
	for _, u := range leaf.URIs {
		g, ok := strings.CutPrefix(u.String(), groupURIPrefix)
		if !ok {
			t.Errorf("a URI that is not a group: %s", u)
			continue
		}
		dec, _ := url.PathUnescape(g)
		groups = append(groups, dec)
	}
	if strings.Join(groups, " ") != strings.Join(someone.entitlement, " ") {
		t.Errorf("groups %q, want %q", groups, someone.entitlement)
	}
	if leaf.Subject.CommonName == "somebody else" || leaf.Subject.CommonName != "alice@"+idpScope {
		t.Errorf("subject %q: the request\x27s, not the token\x27s", leaf.Subject)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA {
		t.Errorf("usage %v, CA %v", leaf.ExtKeyUsage, leaf.IsCA)
	}
	if d := time.Until(leaf.NotAfter); d > 8*time.Hour+time.Minute || d < 7*time.Hour {
		t.Errorf("valid for %s, want about the configured 8h", d)
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != f.s.cfg.Issuer+"/x509/crl" {
		t.Errorf("CRL DP %v", leaf.CRLDistributionPoints)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, f.s.cfg.X509CA.cert.SubjectKeyId) || len(leaf.AuthorityKeyId) == 0 {
		t.Error("no AKI naming the CA")
	}

	// The CRL, before: signed by the CA, nothing in it.
	crl, _, h := getCRL(t, f)
	if err := crl.CheckSignatureFrom(f.s.cfg.X509CA.cert); err != nil {
		t.Errorf("the CRL is not the CA\x27s: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 || h.Get("Content-Type") != "application/pkix-crl" || h.Get("Cache-Control") != "max-age=60" {
		t.Errorf("CRL before: %d entries, %v", len(crl.RevokedCertificateEntries), h)
	}
	before := crl.Number

	dir := t.TempDir()
	leafFile := filepath.Join(dir, "leaf.pem")
	os.WriteFile(leafFile, body[:len(body)-len(rest)], 0o600)
	judge := openssl(t)
	verify := func(crlDER []byte) (string, error) {
		crlFile := filepath.Join(dir, "crl.pem")
		os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o600)
		out, err := exec.Command(judge, "verify", "-CAfile", caFile, "-purpose", "sslclient", "-crl_check", "-CRLfile", crlFile, leafFile).CombinedOutput()
		return string(out), err
	}
	_, crlDER, _ := getCRL(t, f)
	if out, err := verify(crlDER); err != nil {
		t.Fatalf("openssl does not verify it: %v\n%s", err, out)
	}
	if out, _ := exec.Command(judge, "x509", "-in", leafFile, "-noout", "-ext", "subjectAltName").CombinedOutput(); !strings.Contains(string(out), "1.3.6.1.4.1.2238.1.1.1") || !strings.Contains(string(out), "alice@"+idpScope) || !strings.Contains(string(out), "URI:"+groupURIPrefix) {
		t.Errorf("openssl reads the SAN as:\n%s", out)
	}

	// Disabled: the CRL lists it, openssl says revoked, the number moved.
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	crl, crlDER, h = getCRL(t, f)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("CRL after: %v", crl.RevokedCertificateEntries)
	}
	// The ETag is the content's (revlists.go): the version alone stayed
	// put while thisUpdate and nextUpdate moved, and a reader polling with
	// If-None-Match kept a copy that then expired.
	sum := sha256.Sum256(crlDER)
	if crl.Number.Cmp(before) <= 0 || h.Get("ETag") != `"`+hex.EncodeToString(sum[:16])+`"` {
		t.Errorf("number %s after %s, ETag %s", crl.Number, before, h.Get("ETag"))
	}
	if out, err := verify(crlDER); err == nil || !strings.Contains(out, "revoked") {
		t.Errorf("openssl on a revoked certificate: %v\n%s", err, out)
	}
	// Enabling again brings nothing back.
	f.s.enablePerson("alice@"+idpScope, "test")
	if crl, _, _ := getCRL(t, f); len(crl.RevokedCertificateEntries) != 1 {
		t.Error("enabling the person took the certificate off the CRL")
	}
	// And the revocation is on disk.
	st, err := loadCertStore(f.s.cfg.CertificatesFile)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, _ := st.revoked("x509", time.Now()); len(revoked) != 1 {
		t.Errorf("certificates_file holds %d revoked", len(revoked))
	}
}

func TestNFSCertificateRefusals(t *testing.T) {
	f, _ := x509Fixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrFor(t, key)

	// A token without the nfs scope, and a client that may not ask for it.
	tok := f.deviceTokenAs("nfs", alice, "openid")
	if s, _ := postCSR(t, f, tok.AccessToken, good); s != http.StatusForbidden {
		t.Errorf("no nfs scope: %d", s)
	}
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	if _, err := (&oauth2.Config{ClientID: "plain", Endpoint: ep, Scopes: []string{"openid", "nfs"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("a client without x509_certificates got a device code for nfs")
	}

	tok = f.deviceTokenAs("nfs", alice, "openid", "nfs")
	// A request whose signature is not its key's: somebody else's key.
	blk, _ := pem.Decode(good)
	tampered := append([]byte{}, blk.Bytes...)
	tampered[len(tampered)-5] ^= 0xff
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, body := range map[string][]byte{
		"a tampered request": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}),
		"RSA 1024":           csrFor(t, small),
		"P-384":              csrFor(t, p384),
		"not PEM":            []byte("hello"),
		"a certificate":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.s.cfg.X509CA.cert.Raw}),
	} {
		if s, b := postCSR(t, f, tok.AccessToken, body); s != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, s, b)
		}
	}
	if s, _ := postCSR(t, f, "not-a-token", good); s != http.StatusUnauthorized {
		t.Errorf("no token: %d", s)
	}
	// And the control: that token, that key, is certified.
	if s, b := postCSR(t, f, tok.AccessToken, good); s != http.StatusOK {
		t.Errorf("the control: %d %s", s, b)
	}
}

// Without an x509_ca, neither endpoint exists: a server that requires the
// CRL fails closed rather than reading an empty one.
func TestNoX509CA(t *testing.T) {
	f := newFixture(t, "")
	for _, u := range []string{"/x509/crl", "/x509/cert", "/ssh/krl"} {
		res, err := http.Post(f.s.cfg.Issuer+u, "text/plain", nil)
		if u != "/x509/cert" {
			res, err = http.Get(f.s.cfg.Issuer + u)
		}
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", u, res.StatusCode)
		}
	}
}

func TestX509CAConfig(t *testing.T) {
	c := newConf(t)
	dir := filepath.ToSlash(c.dir)
	if _, err := generateX509CA(c.dir, "ca"); err != nil {
		t.Fatal(err)
	}
	if _, err := generateX509CA(c.dir, "ca"); err == nil {
		t.Error("an X.509 CA was overwritten")
	}
	store := "certificates_file = \"" + dir + "/certs.json\"\n"
	if err := generateECKey(filepath.Join(c.dir, "other.key")); err != nil {
		t.Fatal(err)
	}
	block := func(key, cert, extra string) string {
		return "x509_ca {\nkey_file = \"" + key + "\"\ncert_file = \"" + cert + "\"\n" + extra + "}\n"
	}
	for name, extra := range map[string]string{
		"no certificates_file": block(dir+"/ca.key", dir+"/ca.crt", ""),
		"an RSA key":           store + block(c.key, dir+"/ca.crt", ""),
		"not its certificate":  store + block(dir+"/other.key", dir+"/ca.crt", ""),
		"a leaf, not a CA":     store + block(dir+"/ca.key", c.spCert, ""),
		"more than a week":     store + block(dir+"/ca.key", dir+"/ca.crt", "validity = \"200h\"\n"),
		"certificates, no CA":  store + "client \"n\" {\ndevice = true\nx509_certificates = true\n}\n",
	} {
		if _, err := c.load(t, c.hcl(nil)+extra); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	if _, err := c.load(t, c.hcl(nil)+store+block(dir+"/ca.key", dir+"/ca.crt", "")); err != nil {
		t.Errorf("the control: %v", err)
	}
	if out, err := runCmd(t, "keygen", "--x509-ca", t.TempDir()); err != nil || !strings.Contains(out, "ca.crt") {
		t.Errorf("keygen --x509-ca: %v %s", err, out)
	}
}

// `authn-bridge nfs-cert`: a key made here, a certificate for it, both in PEM and
// DER, the key private, and the per-mount warning said.
func TestNFSCertCommand(t *testing.T) {
	f, caFile := x509Fixture(t)
	dir := t.TempDir()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var res nfsCertResult
	go func() {
		r, err := issueNFSCert(context.Background(), f.s.cfg.Issuer, "nfs", filepath.Join(dir, "out"), dir, pw)
		res = r
		pw.Close()
		done <- err
	}()
	sc := bufio.NewScanner(pr)
	var complete string
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "(or open ") {
			complete = strings.TrimSuffix(strings.TrimPrefix(sc.Text(), "(or open "), ")")
			break
		}
	}
	go io.Copy(io.Discard, pr)
	b := newBrowser(t)
	body, _ := io.ReadAll(b.get(complete).Body)
	m := csrfField.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no confirmation:\n%s", body)
	}
	u := complete[strings.Index(complete, "user_code=")+len("user_code="):]
	next := location(t, b.post(f.s.cfg.Issuer+"/device", map[string][]string{"user_code": {u}, "csrf": {string(m[1])}, "confirm": {"yes"}}))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
	}
	reqID, relay := authnRequest(t, next)
	b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("nfs-cert did not finish")
	}

	cert, err := tls.LoadX509KeyPair(res.Cert, res.Key)
	if err != nil {
		t.Fatalf("the PEM pair does not load: %v", err)
	}
	der, _ := os.ReadFile(res.CertDER)
	if !bytes.Equal(der, cert.Certificate[0]) {
		t.Error("the DER certificate is not the PEM one")
	}
	keyDER, _ := os.ReadFile(res.KeyDER)
	if k, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil || !k.(*ecdsa.PrivateKey).PublicKey.Equal(cert.Leaf.PublicKey) {
		t.Errorf("the DER key is not the certificate\x27s: %v", err)
	}
	for _, p := range []string{res.Key, res.KeyDER} {
		if fi, _ := os.Stat(p); os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v", p, fi.Mode())
		}
	}
	pool, _ := certPool(caFile)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the certificate does not verify for client auth: %v", err)
	}
	var out bytes.Buffer
	nfsCertTold.Execute(&out, res)
	for _, want := range []string{"every", "per NFS mount", "only you use", "xprtsec=mtls,cert_serial=", res.CertDER} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("nfs-cert does not say %q:\n%s", want, out.String())
		}
	}
}

// The store: a revocation that cannot be saved is not in force, a corrupt
// file stops the provider, and nothing is recorded without a file.
func TestCertStore(t *testing.T) {
	now := time.Now()
	s, err := loadCertStore("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.add(issuedCert{Kind: "ssh", Serial: "1", Principal: "a", NotAfter: now.Add(time.Hour)}, now); err == nil {
		t.Error("recorded with no certificates_file")
	}
	if n, err := s.revoke(func(string, string) bool { return true }, now); n != 0 || err != nil {
		t.Errorf("revoke with no file: %d %v", n, err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "certs.json")
	s, _ = loadCertStore(file)
	for i, p := range []string{"a", "b"} {
		if err := s.add(issuedCert{Kind: "x509", Serial: strconv.Itoa(i + 1), Principal: p, NotAfter: now.Add(time.Hour)}, now); err != nil {
			t.Fatal(err)
		}
	}
	// An expired one is dropped at the next write, and never listed.
	s.add(issuedCert{Kind: "x509", Serial: "9", Principal: "a", NotAfter: now.Add(time.Minute)}, now)
	s.path = filepath.Join(file, "under-a-file")
	if n, err := s.revoke(func(p, _ string) bool { return p == "a" }, now); err == nil || n != 0 {
		t.Errorf("a revocation that could not be saved: %d %v", n, err)
	}
	if r, v := s.revoked("x509", now); len(r) != 0 || v != 0 {
		t.Errorf("in force although not saved: %v at %d", r, v)
	}
	s.path = file
	if n, err := s.revoke(func(p, _ string) bool { return p == "a" }, now); err != nil || n != 2 {
		t.Errorf("revoke: %d %v", n, err)
	}
	if r, _ := s.revoked("x509", now.Add(2*time.Minute)); len(r) != 1 {
		t.Errorf("after the short one expired: %d revoked listed", len(r))
	}
	if n, _ := s.revoke(func(p, _ string) bool { return p == "a" }, now); n != 0 {
		t.Error("revoked twice")
	}
	if seen := map[string]bool{}; true {
		for range 50 {
			n, err := s.newSerial("x509", 127)
			if err != nil || n.Sign() <= 0 || seen[n.String()] {
				t.Fatalf("serial %v %v", n, err)
			}
			seen[n.String()] = true
		}
	}
	os.WriteFile(file, []byte("{broken"), 0o600)
	if _, err := loadCertStore(file); err == nil {
		t.Error("a corrupt certificates_file was read: the revoked would be forgotten")
	}
}

// A name past 64 characters: no CN, and the SAN is critical (RFC 5280
// 4.2.1.6). An RSA 2048 key is certified.
func TestNFSCertificateLongNameAndRSA(t *testing.T) {
	f, _ := x509Fixture(t)
	long := strings.Repeat("jean-baptiste.", 5) + "x@" + idpScope
	tok := f.deviceTokenAs("nfs", assertionOpts{eppn: long}, "openid", "nfs")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	status, body := postCSR(t, f, tok.AccessToken, csrFor(t, key))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	blk, _ := pem.Decode(body)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	critical := false
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSubjectAltNam) {
			critical = e.Critical
		}
	}
	if leaf.Subject.CommonName != "" || !critical {
		t.Errorf("CN %q, SAN critical %v", leaf.Subject.CommonName, critical)
	}
	if on := otherNames(t, leaf); on["1.3.6.1.4.1.2238.1.1.1"][0] != long {
		t.Errorf("otherName %v", on)
	}
}

func TestNFSCertCommandRefusals(t *testing.T) {
	if _, err := runCmd(t, "nfs-cert"); err == nil {
		t.Error("nfs-cert with no issuer")
	}
	if _, err := issueNFSCert(t.Context(), "http://127.0.0.1:1", "nfs", t.TempDir(), t.TempDir(), io.Discard); err == nil {
		t.Error("nfs-cert against nothing")
	}
}

// Disabling an institution revokes the certificates of its people: on the
// CRL, with the number moved.
func TestNFSCertificatesRevokedWithTheirIdP(t *testing.T) {
	f, _ := x509Fixture(t)
	tok := f.deviceTokenAs("nfs", alice, "openid", "nfs")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if s, b := postCSR(t, f, tok.AccessToken, csrFor(t, key)); s != http.StatusOK {
		t.Fatalf("%d %s", s, b)
	}
	before, _, _ := getCRL(t, f)
	_, r, err := f.s.disableIdP(idpEntity, "compromised", "test", time.Time{})
	if err != nil || r.certificates != 1 {
		t.Fatalf("disabling the IdP: %v, %d certificates", err, r.certificates)
	}
	// The number moved: higher than before the revocation (it rises at
	// every issue, revlists.go).
	if crl, _, _ := getCRL(t, f); len(crl.RevokedCertificateEntries) != 1 || crl.Number.Cmp(before.Number) <= 0 {
		t.Errorf("CRL %d entries, number %s after %s", len(crl.RevokedCertificateEntries), crl.Number, before.Number)
	}
	// Through the command line: a client that may not ask for the nfs scope
	// is refused before any login.
	if _, err := runCmd(t, "nfs-cert", "--issuer", f.s.cfg.Issuer, "--client", "plain", "--dir", t.TempDir(), "--cache", t.TempDir()); err == nil {
		t.Error("nfs-cert with a client that may not have NFS certificates")
	}
}

// What the CA and the state files refuse to start with.
func TestX509CAAndStateFilesRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := generateX509CA(dir, "ca"); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	os.WriteFile(notPEM, []byte("hello"), 0o600)
	badDER := filepath.Join(dir, "bad.pem")
	os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), 0o600)
	for name, b := range map[string]*x509CABlock{
		"a certificate that is not PEM": {KeyFile: filepath.Join(dir, "ca.key"), CertFile: notPEM},
		"a certificate that is not DER": {KeyFile: filepath.Join(dir, "ca.key"), CertFile: badDER},
		"no certificate":                {KeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "none")},
		"no key":                        {KeyFile: filepath.Join(dir, "none"), CertFile: filepath.Join(dir, "ca.crt")},
		"a validity that is not one":    {KeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "ca.crt"), Validity: "soon"},
	} {
		if err := b.load(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	// A directory where a state file should be: an error, not an empty list.
	if _, err := loadCertStore(dir); err == nil {
		t.Error("certificates_file: a directory read as empty")
	}
	if _, err := loadDisabled(dir); err == nil {
		t.Error("disabled_file: a directory read as empty")
	}
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte("{}"), 0o600)
	d, err := loadDisabled(empty)
	if err != nil || d.People == nil || d.IdPs == nil {
		t.Errorf("an empty disabled_file: %v %+v", err, d)
	}
}

// Never past the CA's own certificate; never issued when it cannot be
// recorded.
func TestNFSCertificateBounds(t *testing.T) {
	f, _ := x509Fixture(t)
	tok := f.deviceTokenAs("nfs", alice, "openid", "nfs")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caEnd := time.Now().Add(time.Hour).Truncate(time.Second)
	f.s.cfg.X509CA.cert.NotAfter = caEnd
	s, b := postCSR(t, f, tok.AccessToken, csrFor(t, key))
	if s != http.StatusOK {
		t.Fatalf("%d %s", s, b)
	}
	blk, _ := pem.Decode(b)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if leaf.NotAfter.After(caEnd) {
		t.Errorf("valid until %s, past the CA\x27s %s", leaf.NotAfter, caEnd)
	}
	f.s.certs.mu.Lock()
	f.s.certs.path = filepath.Join(f.s.cfg.CertificatesFile, "under-a-file.json")
	f.s.certs.mu.Unlock()
	if s, b := postCSR(t, f, tok.AccessToken, csrFor(t, key)); s != http.StatusInternalServerError || bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("issued without being recorded: %d %s", s, b)
	}
}

// nfs-cert against a provider that answers badly: it says so and writes
// nothing it could not check.
func TestNFSCertCommandBadAnswers(t *testing.T) {
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			i := "http://" + r.Host
			writeJSON(w, http.StatusOK, map[string]any{"issuer": i, "token_endpoint": i + "/token", "device_authorization_endpoint": i + "/device_authorization"})
		case "/x509/cert":
			answer(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache := t.TempDir()
	p, err := cachePath(cache, srv.URL, "nfs", []string{"openid", "nfs"})
	if err != nil {
		t.Fatal(err)
	}
	writeCache(p, &oauth2.Token{AccessToken: "cached", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	for name, a := range map[string]func(http.ResponseWriter){
		"refused":    func(w http.ResponseWriter) { http.Error(w, "no", http.StatusForbidden) },
		"not PEM":    func(w http.ResponseWriter) { io.WriteString(w, "hello") },
		"not a cert": func(w http.ResponseWriter) { pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}) },
	} {
		answer = a
		dir := t.TempDir()
		if _, err := issueNFSCert(t.Context(), srv.URL, "nfs", dir, cache, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: wrote %d files", name, len(entries))
		}
	}
}
