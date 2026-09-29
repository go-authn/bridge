// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// drive runs a command that logs in with a code, plays the person on the
// other device, and returns what the command printed.
func (f *fixture) drive(args ...string) (string, error) {
	f.t.Helper()
	pr, pw := io.Pipe()
	var out bytes.Buffer
	cmd := newRootCmd(&out)
	cmd.SetArgs(args)
	cmd.SetErr(pw)
	done := make(chan error, 1)
	go func() { err := cmd.Execute(); pw.Close(); done <- err }()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "(or open "); ok {
			f.deviceApprove(strings.TrimSuffix(rest, ")"))
			break
		}
	}
	go io.Copy(io.Discard, pr)
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(60 * time.Second):
		f.t.Fatal("the command never finished")
	}
	return "", nil
}

func TestAppPasswordCommand(t *testing.T) {
	f, dsn := appFixture(t, `["nt_hash"]`)
	cache := t.TempDir()
	out, err := f.drive("app-password", "--issuer", f.s.cfg.Issuer, "--client", "files", "--cache", cache)
	if err != nil || !strings.Contains(out, "username  alice@"+idpScope) || !strings.Contains(out, "shown once") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, ok := people(t, dsn)["alice@"+idpScope]; !ok {
		t.Fatal("the command did not set a password")
	}
	// Removed, from the cached login: no second code.
	var buf bytes.Buffer
	cmd := newRootCmd(&buf)
	cmd.SetArgs([]string{"app-password", "--issuer", f.s.cfg.Issuer, "--client", "files", "--cache", cache, "--remove"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "removed") {
		t.Fatalf("--remove: %v %s", err, buf.String())
	}
	if _, ok := people(t, dsn)["alice@"+idpScope]; ok {
		t.Error("--remove left the password")
	}
	if _, err := runCmd(t, "app-password"); err == nil {
		t.Error("app-password with no issuer")
	}
	// A client that may not set one: refused by the provider.
	if _, err := f.drive("app-password", "--issuer", f.s.cfg.Issuer, "--client", "rclone", "--cache", t.TempDir()); err == nil {
		t.Error("a client without app_passwords set one")
	}
}

func TestTokenAndSSHCertCommands(t *testing.T) {
	f, _ := sshFixture(t)
	cache := t.TempDir()
	out, err := f.drive("token", "--issuer", f.s.cfg.Issuer, "--client", "sftp", "--cache", cache)
	if err != nil || strings.Count(strings.TrimSpace(out), ".") != 2 {
		t.Fatalf("token: %v %q", err, out)
	}
	// ssh-cert with the default key location.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), authorizedKey(t, pub), 0o644)
	// ⛔ The SAME cache as `bridge token` above: a login for openid alone must
	// not be taken for one with ssh (the cache is keyed by scopes).
	sshCache := cache
	out, err = f.drive("ssh-cert", "--issuer", f.s.cfg.Issuer, "--client", "sftp", "--cache", sshCache)
	if err != nil || !strings.Contains(out, "id_ed25519-cert.pub") {
		t.Fatalf("ssh-cert: %v %s", err, out)
	}
	// A key the provider refuses: the refusal reaches the person.
	weak := filepath.Join(home, "weak.pub")
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	os.WriteFile(weak, authorizedKey(t, &rk.PublicKey), 0o644)
	if _, err := certifyKey(t.Context(), f.s.cfg.Issuer, "sftp", weak, sshCache, io.Discard); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("a weak key: %v", err)
	}
	if _, err := certifyKey(t.Context(), f.s.cfg.Issuer, "sftp", filepath.Join(home, "missing.pub"), sshCache, io.Discard); err == nil {
		t.Error("a missing key file")
	}
	if _, err := runCmd(t, "token", "--issuer", "http://127.0.0.1:1", "--client", "x", "--cache", cache); err == nil {
		t.Error("token from a provider that is not there")
	}
	// A cache that is not JSON is a login to redo, not an error.
	files, _ := filepath.Glob(filepath.Join(cache, "*.json"))
	for _, p := range files {
		os.WriteFile(p, []byte("not json"), 0o600)
	}
	if readCache(files[0]) != nil {
		t.Error("a garbled cache was read")
	}
}

// A refresh token shown to the wrong client has leaked: refused, and its
// family ended.
func TestRefreshTokenOfAnotherClient(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, _ := cfg.DeviceAuth(t.Context())
	f.approve(newBrowser(t), da.VerificationURIComplete, true, alice)
	tok, err := cfg.DeviceAccessToken(t.Context(), da)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.PostForm(f.s.cfg.Issuer+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"cli"}})
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("another client's refresh: %d", r.StatusCode)
	}
	r, _ = http.PostForm(f.s.cfg.Issuer+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"rclone"}})
	if r.StatusCode != http.StatusBadRequest {
		t.Error("a refresh token that leaked to another client still works for its own")
	}
}

func TestStrongEnough(t *testing.T) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, k := range []any{ed, &rk.PublicKey} {
		p, _, _, _, _ := sshParse(t, authorizedKey(t, k))
		if err := strongEnough(p); err != nil {
			t.Errorf("%s: %v", p.Type(), err)
		}
	}
}

func sshParse(t *testing.T, b []byte) (sshPublicKey, string, []string, []byte, error) {
	t.Helper()
	return parseAuthorizedKey(b)
}
