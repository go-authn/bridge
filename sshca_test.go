// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

// The certificate is read back by OpenSSH's own ssh-keygen -L, and checked
// by x/crypto/ssh's CertChecker exactly as go-fileshare checks the
// certificates SFTP clients present.

func sshFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.ToSlash(filepath.Join(dir, "ca"))
	pub, err := generateSSHCA(ca)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, `
certificates_file = "`+filepath.ToSlash(filepath.Join(dir, "certs.json"))+`"
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
ssh_ca {
  key_file = "`+ca+`"
  validity = "8h"
}
client "sftp" {
  device           = true
  ssh_certificates = true
}
client "rclone" {
  device = true
}
`)
	f.s.poll = time.Second
	return f, pub
}

// deviceToken logs in through the device grant for client, with scopes.
func (f *fixture) deviceToken(client string, scopes ...string) *oauth2.Token {
	f.t.Helper()
	return f.deviceTokenAs(client, alice, scopes...)
}

// deviceTokenAs is deviceToken for whoever o says.
func (f *fixture) deviceTokenAs(client string, o assertionOpts, scopes ...string) *oauth2.Token {
	f.t.Helper()
	ep, err := endpoints(f.t.Context(), f.s.cfg.Issuer)
	if err != nil {
		f.t.Fatal(err)
	}
	cfg := &oauth2.Config{ClientID: client, Endpoint: ep, Scopes: scopes}
	da, err := cfg.DeviceAuth(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	b := newBrowser(f.t)
	page := b.get(da.VerificationURIComplete)
	body, _ := io.ReadAll(page.Body)
	m := csrfField.FindSubmatch(body)
	if m == nil {
		f.t.Fatalf("no confirmation page:\n%s", body)
	}
	next := location(f.t, b.post(f.s.cfg.Issuer+"/device", map[string][]string{"user_code": {da.UserCode}, "csrf": {string(m[1])}, "confirm": {"yes"}}))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
	}
	reqID, relay := authnRequest(f.t, next)
	b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, o)}, "RelayState": {relay}})
	tok, err := cfg.DeviceAccessToken(f.t.Context(), da)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func certify(t *testing.T, f *fixture, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/ssh/certificate", strings.NewReader(string(body)))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, b
}

func authorizedKey(t *testing.T, k any) []byte {
	t.Helper()
	p, err := ssh.NewPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(p)
}

func TestSSHCertificate(t *testing.T) {
	f, caLine := sshFixture(t)
	tok := f.deviceToken("sftp", "openid", "ssh")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}

	// OpenSSH reads it.
	if kg, err := exec.LookPath("ssh-keygen"); err == nil {
		p := filepath.Join(t.TempDir(), "id-cert.pub")
		os.WriteFile(p, body, 0o644)
		out, err := exec.Command(kg, "-L", "-f", p).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen -L: %v\n%s", err, out)
		}
		s := string(out)
		for _, want := range []string{"Type: ssh-ed25519-cert-v01@openssh.com user certificate", "alice@" + idpScope, "Critical Options: (none)", "groups@go-authn.org"} {
			if !strings.Contains(s, want) {
				t.Errorf("ssh-keygen -L does not show %q:\n%s", want, s)
			}
		}
	} else if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
		t.Fatal("ssh-keygen is required here")
	}

	// The CertChecker go-fileshare uses accepts it for alice, and for
	// nobody else.
	certKey, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		t.Fatal(err)
	}
	cert := certKey.(*ssh.Certificate)
	caKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(caLine))
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(caKey.Marshal())
	}}
	if _, err := checker.Authenticate(connMeta("alice@"+idpScope), cert); err != nil {
		t.Fatalf("CertChecker refused alice's certificate: %v", err)
	}
	if _, err := checker.Authenticate(connMeta("root"), cert); err == nil {
		t.Fatal("the certificate let in another user")
	}
	if cert.Extensions[GroupsExtension] != strings.Join(alice.entitlement, "\n") {
		t.Errorf("groups extension %q", cert.Extensions[GroupsExtension])
	}
	for k := range cert.Extensions {
		if strings.HasPrefix(k, "permit-") {
			t.Errorf("the certificate permits %s", k)
		}
	}
	if len(cert.ValidPrincipals) != 1 {
		t.Errorf("principals %q", cert.ValidPrincipals)
	}
	if life := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Now()); life > 8*time.Hour+time.Minute || life < 7*time.Hour {
		t.Errorf("validity %s, configured 8h", life)
	}
	_ = priv

	// The certificate is not a key to certify again.
	if s, _ := certify(t, f, tok.AccessToken, body); s != http.StatusBadRequest {
		t.Errorf("a certificate was certified: %d", s)
	}
}

type meta string

func (m meta) User() string          { return string(m) }
func (m meta) SessionID() []byte     { return []byte("x") }
func (m meta) ClientVersion() []byte { return []byte("SSH-2.0-x") }
func (m meta) ServerVersion() []byte { return []byte("SSH-2.0-y") }
func (m meta) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (m meta) LocalAddr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func connMeta(user string) ssh.ConnMetadata { return meta(user) }

func TestSSHCertificateRefusals(t *testing.T) {
	f, _ := sshFixture(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := authorizedKey(t, pub)

	if s, _ := certify(t, f, "", key); s != http.StatusUnauthorized {
		t.Errorf("no token: %d", s)
	}
	if s, _ := certify(t, f, "not.a.token", key); s != http.StatusUnauthorized {
		t.Errorf("garbage token: %d", s)
	}
	// A token without the ssh scope, from a client that may have it.
	plain := f.deviceToken("sftp", "openid")
	if s, _ := certify(t, f, plain.AccessToken, key); s != http.StatusForbidden {
		t.Errorf("a token without the ssh scope: %d", s)
	}
	// A client that may not ask for it at all.
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	if _, err := (&oauth2.Config{ClientID: "rclone", Endpoint: ep, Scopes: []string{"openid", "ssh"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("a client without ssh_certificates was given the ssh scope")
	}
	tok := f.deviceToken("sftp", "openid", "ssh")
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, c := range map[string]struct {
		body   []byte
		status int
	}{
		"not a key":   {[]byte("hello"), http.StatusBadRequest},
		"RSA-1024":    {authorizedKey(t, &rk.PublicKey), http.StatusBadRequest},
		"ECDSA P-256": {authorizedKey(t, &ek.PublicKey), http.StatusOK},
	} {
		if s, b := certify(t, f, tok.AccessToken, c.body); s != c.status {
			t.Errorf("%s: %d %s", name, s, b)
		}
	}
	// A revoked token certifies nothing.
	f.s.issued.sweep()
	for k := range f.s.issued.m {
		f.s.issued.take(k)
	}
	if s, _ := certify(t, f, tok.AccessToken, key); s != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", s)
	}
}

// No ssh_ca block: no endpoint.
func TestSSHCertificateNotConfigured(t *testing.T) {
	f := newFixture(t, "")
	if s, _ := certify(t, f, "x", nil); s != http.StatusNotFound {
		t.Errorf("%d", s)
	}
}

func TestSSHCertCommand(t *testing.T) {
	f, _ := sshFixture(t)
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyFile := filepath.Join(dir, "id_ed25519.pub")
	os.WriteFile(keyFile, authorizedKey(t, pub), 0o644)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var wrote string
	go func() {
		p, err := certifyKey(context.Background(), f.s.cfg.Issuer, "sftp", keyFile, dir, pw)
		wrote = p
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
	page := b.get(complete)
	body, _ := io.ReadAll(page.Body)
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
		t.Fatal("ssh-cert never finished")
	}
	if wrote != filepath.Join(dir, "id_ed25519-cert.pub") {
		t.Errorf("wrote %q", wrote)
	}
	if b, _ := os.ReadFile(wrote); !strings.HasPrefix(string(b), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Errorf("%s", b)
	}
	// A private key is not sent anywhere.
	if _, err := certifyKey(t.Context(), f.s.cfg.Issuer, "sftp", filepath.Join(dir, "id_ed25519"), dir, io.Discard); err == nil {
		t.Error("a private key file was accepted")
	}
	if _, err := runCmd(t, "ssh-cert"); err == nil {
		t.Error("ssh-cert with no issuer")
	}
}

func TestSSHCAConfig(t *testing.T) {
	c := newConf(t)
	rsaCA := filepath.ToSlash(filepath.Join(c.dir, "rsa-ca"))
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	blk, _ := ssh.MarshalPrivateKey(k, "")
	f, _ := os.Create(rsaCA)
	f.Write(pemBytes(blk.Type, blk.Bytes))
	f.Close()
	good := filepath.ToSlash(filepath.Join(c.dir, "ca"))
	if _, err := generateSSHCA(good); err != nil {
		t.Fatal(err)
	}
	if _, err := generateSSHCA(good); err == nil {
		t.Error("an SSH CA key was overwritten")
	}
	for name, extra := range map[string]string{
		"an RSA CA":               `ssh_ca { key_file = "` + rsaCA + `" }`,
		"a week and a day":        `ssh_ca {` + "\n" + `key_file = "` + good + `"` + "\n" + `validity = "192h"` + "\n}",
		"a validity":              `ssh_ca {` + "\n" + `key_file = "` + good + `"` + "\n" + `validity = "soon"` + "\n}",
		"no CA file":              `ssh_ca { key_file = "` + c.dir + `/none" }`,
		"not a key":               `ssh_ca { key_file = "` + c.salt + `" }`,
		"certificates with no CA": `client "s" {` + "\n" + `device = true` + "\n" + `ssh_certificates = true` + "\n}",
	} {
		// With a certificates_file, so that each is refused for its own reason.
		store := "certificates_file = \"" + c.dir + "/certs.json\"\n"
		if _, err := c.load(t, c.hcl(nil)+store+extra); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	// And the CA alone, with nowhere to record what it issues.
	if _, err := c.load(t, c.hcl(nil)+`ssh_ca { key_file = "`+good+`" }`); err == nil || !strings.Contains(err.Error(), "certificates_file") {
		t.Errorf("an ssh_ca with no certificates_file: %v", err)
	}
	if _, err := runCmd(t, "keygen", "--ssh-ca", filepath.Join(c.dir, "ca2")); err != nil {
		t.Errorf("keygen --ssh-ca: %v", err)
	}
}

func pemBytes(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

// A client whose ssh_certificates was withdrawn: the tokens it already holds
// carry the ssh scope, and they certify nothing any more.
func TestSSHCertificatesWithdrawn(t *testing.T) {
	f, _ := sshFixture(t)
	tok := f.deviceToken("sftp", "openid", "ssh")
	c, _ := f.s.cfg.client("sftp")
	c.SSHCertificates = false
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if s, _ := certify(t, f, tok.AccessToken, authorizedKey(t, pub)); s != http.StatusForbidden {
		t.Fatalf("a withdrawn client's token was certified: %d", s)
	}
}

// Every SSH certificate is recorded before it is handed out, and revoked
// with its person; one that cannot be recorded is not issued.
func TestSSHCertificatesRecordedAndRevoked(t *testing.T) {
	f, _ := sshFixture(t)
	tok := f.deviceToken("sftp", "openid", "ssh")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	k, _, _, _, _ := ssh.ParseAuthorizedKey(body)
	cert := k.(*ssh.Certificate)
	st, err := loadCertStore(f.s.cfg.CertificatesFile)
	if err != nil || len(st.Certs) != 1 || st.Certs[0].Serial != strconv.FormatUint(cert.Serial, 10) ||
		st.Certs[0].Principal != "alice@"+idpScope || st.Certs[0].IdP != idpEntity || st.Certs[0].Kind != "ssh" {
		t.Fatalf("recorded %v %+v", err, st.Certs)
	}

	certFile := filepath.Join(t.TempDir(), "id-cert.pub")
	os.WriteFile(certFile, body, 0o644)
	keygen, kgErr := exec.LookPath("ssh-keygen")
	query := func() string {
		res, err := http.Get(f.s.cfg.Issuer + "/ssh/krl")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "max-age=60" {
			t.Fatalf("/ssh/krl: %s %v", res.Status, res.Header)
		}
		k, err := krl.Parse(data)
		if err != nil {
			t.Fatalf("the KRL does not parse: %v", err)
		}
		verdict := "ok"
		if k.IsRevoked(cert) {
			verdict = "REVOKED"
		}
		// And OpenSSH's own reading of it, when it is here.
		if kgErr == nil {
			kf := filepath.Join(t.TempDir(), "krl")
			os.WriteFile(kf, data, 0o644)
			out, _ := exec.Command(keygen, "-Q", "-f", kf, certFile).CombinedOutput()
			if got := strings.Contains(string(out), "REVOKED"); got != (verdict == "REVOKED") {
				t.Errorf("ssh-keygen -Q says %q, go-authn/krl %s", out, verdict)
			}
		} else if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("ssh-keygen is required here")
		}
		return verdict
	}
	if v := query(); v != "ok" {
		t.Fatalf("revoked before anybody revoked it: %s", v)
	}
	_, r, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{})
	if r.certificates != 1 {
		t.Errorf("revoked %d certificates", r.certificates)
	}
	if err != nil {
		t.Fatal(err)
	}
	st, _ = loadCertStore(f.s.cfg.CertificatesFile)
	revoked, version := st.revoked("ssh", time.Now())
	if len(revoked) != 1 || revoked[0].Serial != strconv.FormatUint(cert.Serial, 10) || version != 1 {
		t.Errorf("revoked %+v at version %d", revoked, version)
	}
	if v := query(); v != "REVOKED" {
		t.Errorf("the KRL does not revoke the certificate of a disabled person: %s", v)
	}

	// Somewhere it cannot be written: no certificate.
	f.s.enablePerson("alice@"+idpScope, "test")
	tok = f.deviceToken("sftp", "openid", "ssh")
	f.s.certs.mu.Lock()
	f.s.certs.path = filepath.Join(f.s.cfg.CertificatesFile, "under-a-file.json")
	f.s.certs.mu.Unlock()
	if status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub)); status != http.StatusInternalServerError || strings.Contains(string(body), "cert-v01") {
		t.Errorf("issued without being recorded: %d %s", status, body)
	}
}
