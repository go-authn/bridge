// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	opkclient "github.com/openpubkey/openpubkey/client"
	opkjose "github.com/openpubkey/openpubkey/jose"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The two halves together: what this provider issues, go-fileshare
// (the real binary, a release) accepts -- and refuses once the person is
// disabled here, through the KRL and the CRL it fetches from this provider.
// Neither repository can see this alone.

// fileshareBin is the go-fileshare binary, when it is installed.
func fileshareBin(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("fileshare"); err == nil {
		return p
	}
	if gp, _ := exec.Command("go", "env", "GOPATH").Output(); len(gp) > 0 {
		for _, name := range []string{"fileshare", "fileshare.exe"} {
			if p := filepath.Join(strings.TrimSpace(string(gp)), "bin", name); fileExists(p) {
				return p
			}
		}
	}
	if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
		t.Fatal("fileshare is required here (go install github.com/go-fileshare/fileshare@v0.22.1)")
	}
	t.Skip("fileshare is not installed")
	return ""
}

type interop struct {
	f          *fixture
	front      *httptest.Server // this provider over https, for the lists
	frontCA    string
	sshCAPub   string
	x509CA     string
	serverCert string
	serverKey  string
	serverPool *x509.CertPool
	dir        string
}

func newInterop(t *testing.T) *interop {
	t.Helper()
	dir := t.TempDir()
	sshCA := filepath.ToSlash(filepath.Join(dir, "ssh-ca"))
	pub, err := generateSSHCA(sshCA)
	if err != nil {
		t.Fatal(err)
	}
	x509CA, err := generateX509CA(dir, "interop NFS CA")
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, `
certificates_file = "`+filepath.ToSlash(filepath.Join(dir, "certs.json"))+`"
disabled_file     = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
ssh_ca { key_file = "`+sshCA+`" }
x509_ca {
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "ca.key"))+`"
  cert_file = "`+filepath.ToSlash(x509CA)+`"
}
client "sftp" {
  device           = true
  ssh_certificates = true
}
client "nfs" {
  device            = true
  x509_certificates = true
}
`)
	f.s.poll = time.Second
	// The lists are fetched over https only: the same provider, behind TLS.
	front := httptest.NewTLSServer(f.s.handler())
	t.Cleanup(front.Close)
	frontCA := filepath.Join(dir, "front.pem")
	os.WriteFile(frontCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0o644)
	pubFile := filepath.Join(dir, "ssh-ca.pub")
	os.WriteFile(pubFile, []byte(pub+"\n"), 0o644)
	certFile, keyFile, cert := selfSigned(t, dir, "fileshare", "localhost", "127.0.0.1")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &interop{f: f, front: front, frontCA: frontCA, sshCAPub: pubFile, x509CA: x509CA,
		serverCert: certFile, serverKey: keyFile, serverPool: pool, dir: dir}
}

func hclP(p string) string { return filepath.ToSlash(p) }

// config is a fileshare configuration with one share alice may use, served
// over NFS (identities from certificates) and SFTP (certificates from this
// provider), both checking this provider's lists every second.
func (i *interop) config(t *testing.T, nfsAddr, sftpAddr string) string {
	t.Helper()
	share := filepath.Join(i.dir, "share")
	os.MkdirAll(share, 0o755)
	os.WriteFile(filepath.Join(share, "x.txt"), []byte("hello from fileshare\n"), 0o644)
	lists := i.front.URL
	body := fmt.Sprintf(`
share "t" {
  directory = %q
  allow     = ["oidc:user:alice@%s"]
}
tls {
  cert_file = %q
  key_file  = %q
}
oidc {
  issuer          = %q
  audience        = "fileshare"
  ssh_ca_file     = %q
  ssh_krl_url     = %q
  ssh_krl_ca_file = %q
  ssh_krl_refresh = "1s"
}
serve "nfs" {
  addr           = %q
  tls            = true
  client_ca_file = %q
  identity       = "certificate"
  crl_url        = %q
  crl_ca_file    = %q
  crl_refresh    = "1s"
}
serve "sftp" { addr = %q }
`, hclP(share), idpScope, hclP(i.serverCert), hclP(i.serverKey),
		i.f.s.cfg.Issuer, hclP(i.sshCAPub), lists+"/ssh/krl", hclP(i.frontCA),
		nfsAddr, hclP(i.x509CA), lists+"/x509/crl", hclP(i.frontCA), sftpAddr)
	d := filepath.Join(i.dir, "fileshare.d")
	os.MkdirAll(d, 0o700)
	p := filepath.Join(d, "fileshare.hcl")
	os.WriteFile(p, []byte(body), 0o600)
	return d
}

func TestInteropFileshareCheck(t *testing.T) {
	bin := fileshareBin(t)
	i := newInterop(t)
	d := i.config(t, "127.0.0.1:"+freePort(t), "127.0.0.1:"+freePort(t))
	out, err := exec.Command(bin, "check", d).CombinedOutput()
	if err != nil {
		t.Fatalf("fileshare check: %v\n%s", err, out)
	}
	for _, want := range []string{"/ssh/krl", "/x509/crl", "this configuration can be served"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("fileshare check does not say %q:\n%s", want, out)
		}
	}
}

// A person accepted by go-fileshare with what this provider issued -- an
// X.509 certificate over NFS, an SSH certificate over SFTP -- and refused
// once disabled here: NFS calls, the SFTP session already open, and a new
// SFTP login, each within a few seconds (fileshare refetches both lists
// every second).
func TestInteropRevocation(t *testing.T) {
	bin := fileshareBin(t)
	i := newInterop(t)
	nfsAddr, sftpAddr := "127.0.0.1:"+freePort(t), "127.0.0.1:"+freePort(t)
	d := i.config(t, nfsAddr, sftpAddr)
	var log syncWriter
	cmd := exec.Command(bin, "--config", d)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("fileshare:\n%s", log.String())
		}
	})
	for _, a := range []string{nfsAddr, sftpAddr} {
		for n := 0; ; n++ {
			if c, err := net.DialTimeout("tcp", a, time.Second); err == nil {
				c.Close()
				break
			}
			if n == 100 {
				t.Fatalf("fileshare does not listen on %s:\n%s", a, log.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// NFS: an X.509 certificate for alice, from this provider.
	tok := i.f.deviceTokenAs("nfs", alice, "openid", "nfs")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status, body := postCSR(t, i.f, tok.AccessToken, csrFor(t, key))
	if status != http.StatusOK {
		t.Fatalf("x509: %d %s", status, body)
	}
	blk, _ := pem.Decode(body)
	nfsCert := &tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}
	if st, err := nfsMount(nfsAddr, i.serverPool, nfsCert, "/t"); err != nil || st != 0 {
		t.Fatalf("NFS with alice's certificate: status %d, %v", st, err)
	}

	// SFTP: an SSH certificate for alice, from this provider.
	sshTok := i.f.deviceTokenAs("sftp", alice, "openid", "ssh")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	status, body = certify(t, i.f, sshTok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("ssh: %d %s", status, body)
	}
	sftpc, err := sftpDial(sftpAddr, "alice@"+idpScope, body, priv)
	if err != nil {
		t.Fatalf("SFTP with alice's certificate: %v", err)
	}
	defer sftpc.Close()
	// The shares are directories at the root.
	open, err := sftpc.Open("/t/x.txt")
	if err != nil {
		t.Fatalf("SFTP open: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := open.ReadAt(buf, 0); err != nil || string(buf) != "hello" {
		t.Fatalf("SFTP read: %q %v", buf, err)
	}

	// Disabled here.
	if _, r, err := i.f.s.disablePerson("alice@"+idpScope, "interop", "test", time.Time{}); err != nil || r.certificates != 2 {
		t.Fatalf("disabling: %v, %d certificates revoked", err, r.certificates)
	}
	deadline := time.Now().Add(15 * time.Second)
	refusedNFS, refusedOpen, refusedLogin := false, false, false
	for time.Now().Before(deadline) && !(refusedNFS && refusedOpen && refusedLogin) {
		if !refusedNFS {
			st, err := nfsMount(nfsAddr, i.serverPool, nfsCert, "/t")
			refusedNFS = err != nil || st == 13
		}
		if !refusedOpen {
			_, err := open.ReadAt(buf, 0)
			refusedOpen = err != nil
		}
		if !refusedLogin {
			c, err := sftpDial(sftpAddr, "alice@"+idpScope, body, priv)
			if err != nil {
				refusedLogin = true
			} else {
				c.Close()
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !refusedNFS {
		t.Error("NFS still serves alice after she was disabled")
	}
	if !refusedOpen {
		t.Error("the SFTP session alice already had still reads")
	}
	if !refusedLogin {
		t.Error("alice still logs in over SFTP after she was disabled")
	}
}

type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func sftpDial(addr, user string, certLine []byte, priv ed25519.PrivateKey) (*sftp.Client, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	cs, err := ssh.NewCertSigner(k.(*ssh.Certificate), signer)
	if err != nil {
		return nil, err
	}
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)},
		// The host key is fileshare's, made for this test: not what is judged.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Shared Signals between the two: go-fileshare (the release) is an SSF
// receiver of this provider, and verifies on its own what this provider
// issued -- access tokens over WebDAV, opkssh certificates over SFTP -- until
// the person, or their institution, is disabled here.
//
// Linux only: the provider is https with a certificate made for the test,
// which go-fileshare's token verifier trusts through SSL_CERT_FILE, and Go
// honours that variable everywhere but macOS and Windows.

type ssfInterop struct {
	f         *fixture
	dav, sftp string
	log       *syncWriter
}

func startSSFInterop(t *testing.T) *ssfInterop {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("go-fileshare trusts the test's certificate through SSL_CERT_FILE, which Go reads on Linux only")
	}
	bin := fileshareBin(t)
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "state.db"))), 0o600)
	secret := filepath.Join(dir, "ssf.secret")
	os.WriteFile(secret, []byte("an-ssf-receiver-secret-long-enough"), 0o600)
	f := newFixtureTLS(t, deviceClients+opkClients+`
disabled_file = "`+hclP(filepath.Join(dir, "disabled.json"))+`"
state {
  driver   = "sqlite"
  dsn_file = "`+hclP(dsn)+`"
}
ssf {}
client "fileshare-ssf" {
  secret_file  = "`+hclP(secret)+`"
  ssf_receiver = true
  audience     = ["fileshare"]
}
`)
	f.s.poll = 1e9
	caFile := filepath.Join(dir, "issuer.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o644)

	share := filepath.Join(dir, "share")
	os.MkdirAll(share, 0o755)
	os.WriteFile(filepath.Join(share, "x.txt"), []byte("hello"), 0o644)
	in := &ssfInterop{f: f, dav: "127.0.0.1:" + freePort(t), sftp: "127.0.0.1:" + freePort(t), log: &syncWriter{}}
	d := filepath.Join(dir, "fileshare.d")
	os.MkdirAll(d, 0o700)
	os.WriteFile(filepath.Join(d, "fileshare.hcl"), []byte(fmt.Sprintf(`
share "t" {
  directory = %q
  allow     = ["oidc:user:alice@%[2]s", "oidc:user:bob@%[2]s"]
}
oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opk"
}
ssf {
  transmitter        = %[3]q
  audience           = "fileshare"
  client_id          = "fileshare-ssf"
  client_secret_file = %q
  state_file         = %q
  ca_file            = %q
  max_age            = "5m"
}
serve "webdav" { addr = %q }
serve "sftp"   { addr = %q }
`, hclP(share), idpScope, f.s.cfg.Issuer, hclP(secret), hclP(filepath.Join(dir, "revocations.json")), hclP(caFile), in.dav, in.sftp)), 0o600)

	cmd := exec.Command(bin, "--config", d)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caFile)
	cmd.Stdout, cmd.Stderr = in.log, in.log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("fileshare:\n%s", in.log.String())
		}
	})
	// Up, and its stream made here: events before it would reach nobody.
	deadline := time.Now().Add(20 * time.Second)
	for f.s.ssfStreams.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("fileshare made no stream:\n%s", in.log.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return in
}

func (in *ssfInterop) get(tok string) int {
	req, _ := http.NewRequest("GET", "http://"+in.dav+"/t/x.txt", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	res.Body.Close()
	return res.StatusCode
}

// until reports whether cond holds within d.
func until(d time.Duration, cond func() bool) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func refused(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

// Access tokens over WebDAV: alice disabled; then bob, forgotten here, by
// his institution.
func TestInteropSSF(t *testing.T) {
	in := startSSFInterop(t)
	f := in.f
	alice := f.deviceTokenAs("rclone", assertionOpts{eppn: "alice@" + idpScope}, "openid")
	bob := f.deviceTokenAs("rclone", assertionOpts{eppn: "bob@" + idpScope}, "openid")
	for name, tok := range map[string]string{"alice": alice.AccessToken, "bob": bob.AccessToken} {
		if s := in.get(tok); s != http.StatusOK {
			t.Fatalf("%s over WebDAV before anything: %d", name, s)
		}
	}
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "interop", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !until(45*time.Second, func() bool { return refused(in.get(alice.AccessToken)) }) {
		t.Error("fileshare still accepts alice's token after she was disabled here")
	}
	if s := in.get(bob.AccessToken); s != http.StatusOK {
		t.Errorf("bob refused with alice: %d", s)
	}

	// Bob forgotten here -- his tokens gone from this provider's memory --
	// then his institution disabled: only the tenant event, by domain,
	// reaches him.
	var jtis, rts []string
	f.s.issued.each(func(jti string, it issuedToken) {
		if it.username == "bob@"+idpScope {
			jtis = append(jtis, jti)
		}
	})
	f.s.refresh.each(func(k string, g *refreshGrant) {
		if g.who.username == "bob@"+idpScope {
			rts = append(rts, k)
		}
	})
	for _, j := range jtis {
		f.s.issued.take(j)
	}
	for _, k := range rts {
		f.s.refresh.take(k)
	}
	if people := f.s.peopleOf(idpEntity); slices.Contains(people, "bob@"+idpScope) {
		t.Fatalf("the provider still knows bob: %v", people)
	}
	if _, _, err := f.s.disableIdP(idpEntity, "compromised", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !until(45*time.Second, func() bool { return refused(in.get(bob.AccessToken)) }) {
		t.Error("fileshare still accepts bob's token after his institution was disabled here")
	}
}

// opkssh: a certificate the person's own key signs, around a PK Token from
// this provider, that no revocation list can reach. Alice's session already
// open, her open file, and a new login with that certificate all stop once
// she is disabled here; a certificate from after she is enabled again logs
// in -- the control.
func TestInteropSSFOpkssh(t *testing.T) {
	in := startSSFInterop(t)
	f := in.f
	user := "alice@" + idpScope
	opkCert := func() (ssh.Signer, *ssh.Certificate) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		pkt := f.deviceAuth(opkOp(f, "opk", true, false, ""), opkclient.WithSigner(crypto.Signer(priv), opkjose.EdDSA))
		compact, err := pkt.Compact()
		if err != nil {
			t.Fatal(err)
		}
		signer, _ := ssh.NewSignerFromKey(priv)
		now := time.Now()
		// What `opkssh login` writes: signed by the user's own key, the PK
		// Token in the openpubkey-pkt extension.
		cert := &ssh.Certificate{
			Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: user,
			ValidAfter: uint64(now.Add(-5 * time.Minute).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
			Permissions: ssh.Permissions{Extensions: map[string]string{"openpubkey-pkt": string(compact)}},
		}
		if err := cert.SignCert(rand.Reader, signer); err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			t.Fatal(err)
		}
		return cs, cert
	}
	login := func(cs ssh.Signer) (*sftp.Client, error) {
		conn, err := ssh.Dial("tcp", in.sftp, &ssh.ClientConfig{
			User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		c, err := sftp.NewClient(conn)
		if err != nil {
			conn.Close()
		}
		return c, err
	}

	cs, _ := opkCert()
	session, err := login(cs)
	if err != nil {
		t.Fatalf("alice's opkssh certificate over SFTP: %v", err)
	}
	defer session.Close()
	file, err := session.Open("/t/x.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := file.ReadAt(buf, 0); err != nil {
		t.Fatalf("read: %v", err)
	}

	if _, _, err := f.s.disablePerson(user, "interop", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !until(45*time.Second, func() bool { _, err := session.ReadDir("/t"); return err != nil }) {
		t.Error("the SFTP session alice opened still lists after she was disabled here")
	}
	if _, err := file.ReadAt(buf, 0); err == nil {
		t.Error("alice's open file still reads after she was disabled here")
	}
	if c, err := login(cs); err == nil {
		c.Close()
		t.Error("alice's opkssh certificate still logs in after she was disabled here")
	}

	// Enabled again: a PK Token from now on is not before the revocation.
	f.s.enablePerson(user, "test")
	time.Sleep(1100 * time.Millisecond) // a second: event_timestamp is in seconds
	fresh, _ := opkCert()
	c, err := login(fresh)
	if err != nil {
		t.Fatalf("a certificate from after alice was enabled again: %v", err)
	}
	c.Close()
}
