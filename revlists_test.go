// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

func get(t *testing.T, url string, hdr ...string) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, res.Header
}

// The KRL is issued as go-authn/revocation reads it: an expiry, a detached
// signature by the CA that go-authn/revocation and ssh-keygen -Y verify
// both accept, kept unchanged between issues, its ETag its content's.
func TestKRLIsSignedAndExpires(t *testing.T) {
	f, _ := sshFixture(t)
	ca := f.s.cfg.SSHCA.signer.PublicKey()
	base := f.s.cfg.Issuer + "/ssh/krl"
	c1, raw, h := get(t, base)
	c2, sig, _ := get(t, base+".sig", "If-Match", h.Get("ETag"))
	if c1 != 200 || c2 != 200 {
		t.Fatalf("GET: %d %d", c1, c2)
	}
	l, err := revocation.VerifyKRL(raw, sig, ca)
	if err != nil {
		t.Fatalf("go-authn/revocation refuses bridge's KRL: %v", err)
	}
	if d := time.Until(l.Expires); d < 55*time.Minute || d > listValidity {
		t.Errorf("expires in %v, want about %v", d, listValidity)
	}
	if err := l.Current(time.Now(), 0); err != nil {
		t.Error(err)
	}
	// OpenSSH's own check of the signature.
	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "krl"), raw, 0o644)
		os.WriteFile(filepath.Join(dir, "krl.sig"), sig, 0o644)
		os.WriteFile(filepath.Join(dir, "allowed"), []byte(`ca namespaces="`+revocation.Namespace+`" `+string(ssh.MarshalAuthorizedKey(ca))), 0o644)
		cmd := exec.Command(keygen, "-Y", "verify", "-f", "allowed", "-I", "ca", "-n", revocation.Namespace, "-s", "krl.sig")
		cmd.Dir = dir
		in, _ := os.Open(filepath.Join(dir, "krl"))
		defer in.Close()
		cmd.Stdin = in
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("ssh-keygen -Y verify refuses bridge's signature: %v %s", err, out)
		}
	} else if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
		t.Fatal("ssh-keygen is required here")
	}

	// The same issue, byte for byte, until something changes; 304 for it.
	_, again, h2 := get(t, base)
	if string(again) != string(raw) || h2.Get("ETag") != h.Get("ETag") {
		t.Error("two GETs a moment apart are two issues")
	}
	if c, _, _ := get(t, base, "If-None-Match", h.Get("ETag")); c != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", c)
	}
	if c, _, _ := get(t, base+".sig", "If-Match", `"another"`); c != http.StatusPreconditionFailed {
		t.Errorf("If-Match another list: %d", c)
	}
}

// ⛔ The defect this fixes: an ETag that was the version while the content
// changed. With nothing revoked for an hour, a reader that polls with
// If-None-Match was answered 304 and kept a copy whose expiry passed --
// failing closed for good against a healthy provider. A fetcher polling
// through two hours of clock stays current.
func TestAPollingReaderStaysCurrent(t *testing.T) {
	f, _ := x509Fixture(t)
	sf, _ := sshFixture(t)
	start := time.Now()
	for _, c := range []struct {
		name string
		s    *server
		src  revocation.Source
	}{
		{"KRL", sf.s, revocation.Source{URL: sf.s.cfg.Issuer + "/ssh/krl", Kind: revocation.KRL, SSHCA: sf.s.cfg.SSHCA.signer.PublicKey()}},
		{"CRL", f.s, revocation.Source{URL: f.s.cfg.Issuer + "/x509/crl", Kind: revocation.CRL, X509CA: f.s.cfg.X509CA.cert}},
	} {
		t.Run(c.name, func(t *testing.T) {
			at := start
			c.s.now = func() time.Time { return at }
			defer func() { c.s.now = time.Now }()
			c.src.Clock = func() time.Time { return at }
			fe, err := revocation.NewFetcher(c.src, nil)
			if err != nil {
				t.Fatal(err)
			}
			issues := 0
			for step := 0; step <= 24; step++ { // two hours, every five minutes
				at = start.Add(time.Duration(step) * 5 * time.Minute)
				l, changed, err := fe.Fetch(context.Background())
				if err != nil {
					t.Fatalf("at +%v: %v", at.Sub(start), err)
				}
				if changed {
					issues++
				}
				if err := l.Current(at, 0); err != nil {
					t.Fatalf("at +%v the list held is not current: %v", at.Sub(start), err)
				}
			}
			// Issued at 0, then every half validity: 0, 30, 60, 90, 120.
			if issues != 5 {
				t.Errorf("%d issues in two hours, want 5", issues)
			}
		})
	}
}

// Revoking issues a new list at once, whatever the half-validity schedule.
func TestARevocationIssuesAtOnce(t *testing.T) {
	f, _ := sshFixture(t)
	base := f.s.cfg.Issuer + "/ssh/krl"
	_, _, h := get(t, base)
	tok := f.deviceToken("sftp", "openid", "ssh")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub)); status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	c, raw, h2 := get(t, base, "If-None-Match", h.Get("ETag"))
	if c != 200 || h2.Get("ETag") == h.Get("ETag") {
		t.Fatalf("after a revocation: %d, ETag %s", c, h2.Get("ETag"))
	}
	_, sig, _ := get(t, base+".sig", "If-Match", h2.Get("ETag"))
	l, err := revocation.VerifyKRL(raw, sig, f.s.cfg.SSHCA.signer.PublicKey())
	if err != nil || len(l.KRL.Comment) == 0 {
		t.Fatalf("the new issue: %v", err)
	}
}

// Without an SSH CA there is no KRL, nor its signature.
func TestNoKRLWithoutAnSSHCA(t *testing.T) {
	f, _ := x509Fixture(t)
	for _, p := range []string{"/ssh/krl", "/ssh/krl.sig"} {
		if c, _, _ := get(t, f.s.cfg.Issuer+p); c != http.StatusNotFound {
			t.Errorf("GET %s without an ssh_ca: %d", p, c)
		}
	}
}
