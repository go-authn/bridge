// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd(&out)
	cmd.SetArgs(args)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	return out.String(), err
}

func TestCommands(t *testing.T) {
	f := newFixture(t, "")
	out, err := runCmd(t, "check", "--config", f.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 IdPs, 2 usable", "client        web (confidential, public subject, audience [fileshare])", "cli (public, pairwise"} {
		if !strings.Contains(out, want) {
			t.Errorf("check does not say %q:\n%s", want, out)
		}
	}
	out, err = runCmd(t, "metadata", "--config", f.cfgFile)
	if err != nil || !strings.Contains(out, "SPSSODescriptor") {
		t.Fatalf("metadata: %v\n%s", err, out)
	}
	if _, err := runCmd(t, "check", "--config", filepath.Join(f.dir, "missing.hcl")); err == nil {
		t.Error("check with no configuration")
	}
	if _, err := runCmd(t, "metadata", "--config", filepath.Join(f.dir, "missing.hcl")); err == nil {
		t.Error("metadata with no configuration")
	}
	if _, err := runCmd(t, "--config", filepath.Join(f.dir, "missing.hcl")); err == nil {
		t.Error("serve with no configuration")
	}

	// An allowlist naming an IdP the federation does not have.
	bad := filepath.Join(f.dir, "bad.hcl")
	b, _ := os.ReadFile(f.cfgFile)
	os.WriteFile(bad, bytes.Replace(b, []byte("names = {"), []byte(`idps = ["https://gone.example/idp"]
  names = {`), 1), 0o644)
	if _, err := runCmd(t, "check", "--config", bad); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Errorf("an allowlist of an IdP the federation lacks: %v", err)
	}

	dir := t.TempDir()
	if _, err := runCmd(t, "keygen"); err == nil {
		t.Error("keygen with nothing to write")
	}
	out, err = runCmd(t, "keygen", "--key", filepath.Join(dir, "k"), "--salt", filepath.Join(dir, "s"))
	if err != nil || !strings.Contains(out, "keep it") {
		t.Fatalf("keygen: %v %s", err, out)
	}
	if _, err := runCmd(t, "keygen", "--key", filepath.Join(dir, "k")); err == nil {
		t.Error("keygen overwrote a key")
	}
	if _, err := runCmd(t, "keygen", "--salt", filepath.Join(dir, "s")); err == nil {
		t.Error("keygen overwrote a salt")
	}
	if version() == "" {
		t.Error("no version")
	}
}

// serve starts, answers, and stops with its context.
func TestServe(t *testing.T) {
	f := newFixture(t, "")
	cfg := f.s.cfg
	cfg.Listen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var log bytes.Buffer
	go func() { done <- serve(ctx, cfg, &syncBuf{b: &log}) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}

	// A federation that cannot be read: refused before listening.
	cfg.SAML.MetadataURL = "https://127.0.0.1:1/none.xml"
	if err := serve(t.Context(), cfg, io.Discard); err == nil {
		t.Error("served without the federation's metadata")
	}
}

type syncBuf struct{ b *bytes.Buffer }

func (s *syncBuf) Write(p []byte) (int, error) { return len(p), nil }

// One IdP allowed: straight to it, no list.
func TestSingleIdP(t *testing.T) {
	f := newFixture(t, "")
	f.s.cfg.SAML.IdPs = []string{idpEntity}
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	next := location(t, newBrowser(t).get(r.authURL()))
	if next.Host != idpScope {
		t.Fatalf("sent to %s rather than straight to the only IdP", next)
	}
	// And one that is not on the list is refused at the disco step.
	b := newBrowser(t)
	f.s.cfg.SAML.IdPs = []string{idpEntity, "https://idp.univ-example.fr/other"}
	location(t, b.get(r.authURL()))
	if got := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape("https://idp.other-univ.fr/idp")); got.StatusCode != http.StatusBadRequest {
		t.Errorf("an IdP outside the allowlist: %d", got.StatusCode)
	}
}

// An external discovery service: sent there with this SP's entity ID and
// the way back.
func TestDiscoveryService(t *testing.T) {
	f := newFixture(t, "")
	f.s.cfg.SAML.Discovery = "https://discovery.renater.fr/renater"
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	next := location(t, b.get(r.authURL()))
	q := next.Query()
	if next.Host != "discovery.renater.fr" || q.Get("entityID") != f.s.sp.EntityID || q.Get("return") != f.s.cfg.Issuer+"/saml/disco" {
		t.Fatalf("%s", next)
	}
	// The discovery service answers; the login continues.
	idp := location(t, b.get(q.Get("return")+"?entityID="+url.QueryEscape(idpEntity)))
	if idp.Host != idpScope {
		t.Fatalf("%s", idp)
	}
	// Twice is refused: one login, one request.
	if got := b.get(q.Get("return") + "?entityID=" + url.QueryEscape(idpEntity)); got.StatusCode != http.StatusBadRequest {
		t.Errorf("a second AuthnRequest for one login: %d", got.StatusCode)
	}
	// The SP metadata says where the discovery service may send people back.
	body, _ := io.ReadAll(newBrowser(t).get(f.s.cfg.Issuer + "/saml/metadata").Body)
	if !strings.Contains(string(body), "DiscoveryResponse") {
		t.Error("the SP metadata does not declare its discovery response location")
	}
}

func TestLoginPagesWithoutALogin(t *testing.T) {
	f := newFixture(t, "")
	b := newBrowser(t)
	for _, p := range []string{"/saml/choose", "/saml/disco?entityID=x"} {
		if got := b.get(f.s.cfg.Issuer + p); got.StatusCode != http.StatusBadRequest {
			t.Errorf("%s without a login: %d", p, got.StatusCode)
		}
	}
	if got := b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {"x"}}); got.StatusCode != http.StatusBadRequest {
		t.Errorf("acs without a login: %d", got.StatusCode)
	}
	// With a login, but nothing chosen / a login never sent anywhere.
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	location(t, b.get(r.authURL()))
	if got := b.get(f.s.cfg.Issuer + "/saml/disco"); got.StatusCode != http.StatusBadRequest {
		t.Errorf("disco with no choice: %d", got.StatusCode)
	}
	c, _ := url.Parse(f.s.cfg.Issuer)
	var relay string
	for _, k := range b.c.Jar.Cookies(c) {
		if k.Name == loginCookie {
			relay = k.Value
		}
	}
	if got := b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {"x"}, "RelayState": {relay}}); got.StatusCode != http.StatusBadRequest {
		t.Errorf("acs for a login that never went to an IdP: %d", got.StatusCode)
	}
	// A garbage response for a real login.
	location(t, b.get(r.authURL()))
	next := location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	_, relay = authnRequest(t, next)
	if got := b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {"bm90IFNBTUw="}, "RelayState": {relay}}); got.StatusCode != http.StatusBadRequest {
		t.Errorf("a response that is not SAML: %d", got.StatusCode)
	}
	if got := b.get(f.s.cfg.Issuer + "/authorize?client_id=web&client_id=web"); got.StatusCode != http.StatusBadRequest {
		t.Errorf("a parameter twice: %d", got.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, f.s.cfg.Issuer+"/authorize", nil)
	if got, _ := b.c.Do(req); got.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /authorize: %d", got.StatusCode)
	}
}

func TestChooseFilter(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	location(t, b.get(r.authURL()))
	body := func(q string) string {
		raw, _ := io.ReadAll(b.get(f.s.cfg.Issuer + "/saml/choose?q=" + url.QueryEscape(q)).Body)
		return string(raw)
	}
	if s := body("OTHER"); !strings.Contains(s, "other-univ.fr") || strings.Contains(s, ">"+idpScope+"<") {
		t.Errorf("filtering by name:\n%s", s)
	}
	if s := body("shibboleth"); !strings.Contains(s, ">"+idpScope+"<") {
		t.Errorf("filtering by entity ID:\n%s", s)
	}
	if s := body("nothing-matches"); !strings.Contains(s, "Aucun") {
		t.Errorf("an empty result:\n%s", s)
	}
}

func TestUserinfoRefusals(t *testing.T) {
	f := newFixture(t, "")
	b := newBrowser(t)
	if got := b.get(f.s.cfg.Issuer + "/userinfo"); got.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo without a token: %d", got.StatusCode)
	}
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	if got, _ := b.c.Do(req); got.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo with garbage: %d", got.StatusCode)
	}
	if got := b.get(f.s.cfg.Issuer + "/jwks"); got.Header.Get("Content-Type") != "application/jwk-set+json" {
		t.Errorf("jwks content type %q", got.Header.Get("Content-Type"))
	}
}
