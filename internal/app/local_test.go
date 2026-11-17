// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	localScope = "mesocentre.example"
	localPW    = "correct horse battery staple"
	localGroup = "urn:geant:mesocentre.example:hpc:users"
)

// The hash of localPW, made once: an argon2id costs a tenth of a second and
// 64 MiB, and every fixture needs one.
var localPWHash = sync.OnceValue(func() string {
	h, err := hashPassword(localPW)
	if err != nil {
		panic(err)
	}
	return h
})

func localAccountsText() string {
	return fmt.Sprintf(`# the mésocentre's people
account "alice" {
  password_hash = %q
  name          = "Alice Martin"
  mail          = "alice@mesocentre.example"
  groups        = [%q]
}

account "bob" {
  password_hash = %[1]q
  name          = "Bob Durand"
}
`, localPWHash(), localGroup)
}

// writeAccountsFile writes an accounts file, 0640.
func writeAccountsFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "accounts.hcl")
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// localExtra is the local block for a fixture's configuration.
func localExtra(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("local {\n  accounts_file = %q\n  scope = %q\n}\n", filepath.ToSlash(writeAccountsFile(t, localAccountsText())), localScope)
}

func localFixture(t *testing.T, extra string) *fixture {
	t.Helper()
	return newFixture(t, localExtra(t)+extra)
}

func readBody(r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// openLocal walks a browser from the authorization URL to the local login
// form, and returns the form's CSRF token.
func (f *fixture) openLocal(b *browser, authURL string) string {
	f.t.Helper()
	next := location(f.t, b.get(authURL))
	if next.Path != "/login" {
		f.t.Fatalf("sent to %s, where the choice between the federation and a local account was expected", next)
	}
	page := readBody(b.get(next.String()))
	if !strings.Contains(page, `href="local/login"`) || !strings.Contains(page, "saml/") {
		f.t.Fatalf("the choice does not offer both ways in:\n%s", page)
	}
	return f.localForm(b)
}

func (f *fixture) localForm(b *browser) string {
	f.t.Helper()
	res := b.get(f.s.cfg.Issuer + "/local/login")
	body := readBody(res)
	m := csrfField.FindStringSubmatch(body)
	if res.StatusCode != http.StatusOK || m == nil {
		f.t.Fatalf("the local login form: status %d:\n%s", res.StatusCode, body)
	}
	return m[1]
}

// postLocal submits the form, with extra request headers as name, value pairs.
func (f *fixture) postLocal(b *browser, csrf, login, pw string, hdr ...string) *http.Response {
	f.t.Helper()
	v := url.Values{"csrf": {csrf}, "login": {login}, "password": {pw}}
	req, err := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/local/login", strings.NewReader(v.Encode()))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := b.c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *fixture) userinfo(t *testing.T, at string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(readBody(res)), &m); err != nil || res.StatusCode != 200 {
		t.Fatalf("userinfo: status %d, %v", res.StatusCode, err)
	}
	return m
}

func TestLocalLoginEndToEnd(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	res := f.postLocal(b, csrf, "alice", localPW)
	back := location(t, res)
	if got := back.String(); !strings.HasPrefix(got, f.redirect+"?") {
		t.Fatalf("sent to %s, not to the registered redirect URI", got)
	}
	q := back.Query()
	if q.Get("state") != r.state || q.Get("iss") != f.s.cfg.Issuer {
		t.Errorf("state/iss = %q/%q", q.Get("state"), q.Get("iss"))
	}
	tok, err := r.cfg.Exchange(t.Context(), q.Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatalf("the code exchange: %v", err)
	}

	id := jwtClaims(t, tok.Extra("id_token").(string))
	if id["acr"] != localACR {
		t.Errorf("acr = %v, want the password-only class %s", id["acr"], localACR)
	}
	if id["nonce"] != r.nonce {
		t.Errorf("nonce %v", id["nonce"])
	}
	client, _ := f.s.cfg.client("web")
	want := (&person{subject: "local:alice"}).sub(f.s.cfg.salt, client)
	if id["sub"] != want {
		t.Errorf("sub = %v, want the HMAC of \"local:alice\" under the salt: %s", id["sub"], want)
	}
	if strings.Contains(fmt.Sprint(id["sub"]), "alice") {
		t.Errorf("sub %v exposes the login", id["sub"])
	}

	at := jwtClaims(t, tok.AccessToken)
	if at["idp"] != f.s.cfg.Issuer+"/local" || at["preferred_username"] != "alice" {
		t.Errorf("access token idp/preferred_username = %v/%v", at["idp"], at["preferred_username"])
	}
	if g, _ := at["groups"].([]any); len(g) != 1 || g[0] != localGroup {
		t.Errorf("access token groups = %v", at["groups"])
	}
	ui := f.userinfo(t, tok.AccessToken)
	for k, v := range map[string]string{
		"preferred_username":       "alice",
		"name":                     "Alice Martin",
		"email":                    "alice@mesocentre.example",
		"eduperson_principal_name": "alice@" + localScope,
	} {
		if ui[k] != v {
			t.Errorf("userinfo %s = %v, want %s", k, ui[k], v)
		}
	}
	if _, ok := ui["email_verified"]; ok {
		t.Error("userinfo says email_verified: nobody verified it")
	}

	// A login is single-use: the same form, posted again, finds it spent.
	if res := f.postLocal(b, csrf, "alice", localPW); res.StatusCode == http.StatusFound {
		t.Error("a second post of an answered login was accepted")
	}
}

// Two people with different logins are different subjects, and the same login
// is the same subject across logins.
func TestLocalSubjectsAreStablePerLogin(t *testing.T) {
	f := localFixture(t, "")
	sub := func(login string) string {
		r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		back := location(t, f.postLocal(b, csrf, login, localPW))
		tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatal(err)
		}
		return jwtClaims(t, tok.Extra("id_token").(string))["sub"].(string)
	}
	a1, a2, b1 := sub("alice"), sub("alice"), sub("bob")
	if a1 != a2 || a1 == b1 {
		t.Errorf("subjects: alice %s, alice again %s, bob %s", a1, a2, b1)
	}
}

func TestLocalWrongAndUnknownAreIndistinguishable(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	timed := func(login, pw string) (int, string, time.Duration) {
		start := time.Now()
		res := f.postLocal(b, csrf, login, pw)
		return res.StatusCode, readBody(res), time.Since(start)
	}
	s1, b1, d1 := timed("alice", "not the password at all")
	s2, b2, d2 := timed("nobody", "not the password at all")
	s3, b3, d3 := timed("Not A Login!", "x")
	if s1 != http.StatusUnauthorized || s2 != s1 || s3 != s1 {
		t.Fatalf("statuses %d, %d, %d: a refusal each, the same", s1, s2, s3)
	}
	if b1 != b2 || b1 != b3 {
		t.Errorf("the pages differ between a wrong password and an unknown login:\n%s\n---\n%s", b1, b2)
	}
	// An unknown login must cost an argon2id as a known one does: with no
	// hashing it answers in well under a millisecond. 10 ms is far below one
	// hash and far above a map lookup, so a loaded machine makes this pass, not
	// fail.
	if d2 < 10*time.Millisecond || d3 < 10*time.Millisecond {
		t.Errorf("an unknown login answered in %v and %v (a known one's wrong password in %v): the dummy hash was not run", d2, d3, d1)
	}
	// And no code was issued for any of them.
	for _, body := range []string{b1, b2, b3} {
		if strings.Contains(body, "code=") {
			t.Error("a refusal carried a code")
		}
	}
}

func TestLocalLoginRefusesWhatDidNotComeFromTheForm(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	for name, c := range map[string]struct {
		csrf string
		hdr  []string
	}{
		"no token":         {"", nil},
		"a forged token":   {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil},
		"cross-site":       {csrf, []string{"Sec-Fetch-Site", "cross-site"}},
		"same-site":        {csrf, []string{"Sec-Fetch-Site", "same-site"}},
		"another origin":   {csrf, []string{"Origin", "https://evil.example"}},
		"a null origin":    {csrf, []string{"Origin", "null"}},
		"an origin prefix": {csrf, []string{"Origin", f.s.cfg.Issuer + ".evil.example"}},
	} {
		res := f.postLocal(b, c.csrf, "alice", localPW, c.hdr...)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (correct password and all)", name, res.StatusCode)
		}
		if res.Header.Get("Location") != "" {
			t.Errorf("%s: redirected to %s", name, res.Header.Get("Location"))
		}
	}

	// A token is bound to ITS login: another browser's login cannot use it.
	other := newBrowser(t)
	f.openLocal(other, r.authURL())
	if res := f.postLocal(other, csrf, "alice", localPW); res.StatusCode != http.StatusForbidden {
		t.Errorf("another login's token: status %d, want 403", res.StatusCode)
	}

	// The form's own headers are the ones a browser sends from the page.
	res := f.postLocal(b, csrf, "alice", localPW, "Sec-Fetch-Site", "same-origin", "Origin", f.s.cfg.Issuer)
	if res.StatusCode != http.StatusFound {
		t.Errorf("a post from the page itself: status %d", res.StatusCode)
	}
}

// No open redirect: where a login ends is in the sealed login, which authorize
// matched against the registered URIs; nothing the form's request says moves it.
func TestLocalLoginTakesNoDestinationFromTheRequest(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	v := url.Values{"csrf": {csrf}, "login": {"alice"}, "password": {localPW},
		"redirect_uri": {"https://evil.example/cb"}, "next": {"https://evil.example"}, "return_to": {"https://evil.example"}}
	res, err := b.c.PostForm(f.s.cfg.Issuer+"/local/login?redirect_uri=https://evil.example/cb&next=//evil.example", v)
	if err != nil {
		t.Fatal(err)
	}
	if loc := location(t, res).String(); !strings.HasPrefix(loc, f.redirect+"?") || strings.Contains(loc, "evil") {
		t.Errorf("sent to %s", loc)
	}
}

func TestLocalLoginPageIsStrict(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	f.openLocal(b, r.authURL())
	res := b.get(f.s.cfg.Issuer + "/local/login")
	csp := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self' http://127.0.0.1:9"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	for _, bad := range []string{"script-src", "unsafe-eval", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP %q has %q", csp, bad)
		}
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers: %v", res.Header)
	}
	body := readBody(res)
	if strings.Contains(body, "<script") || !strings.Contains(body, `type="password"`) {
		t.Errorf("the form:\n%s", body)
	}
	// Without a login in progress there is no form.
	if res := newBrowser(t).get(f.s.cfg.Issuer + "/local/login"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("no login in progress: status %d", res.StatusCode)
	}
}

// Wrong passwords for one login are refused, before any hashing, from the
// sixth -- the correct password included -- and the same for a login that does
// not exist.
func TestLocalLoginThrottlePerLogin(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	for _, login := range []string{"alice", "ghost"} {
		for i := range localLoginMax {
			if res := f.postLocal(b, csrf, login, "wrong wrong wrong"); res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: failure %d: status %d", login, i+1, res.StatusCode)
			}
		}
	}
	for _, login := range []string{"alice", "ghost"} {
		start := time.Now()
		res := f.postLocal(b, csrf, login, localPW)
		if res.StatusCode != http.StatusTooManyRequests {
			t.Errorf("%s: the sixth try, with the right password: status %d, want 429", login, res.StatusCode)
		}
		if res.Header.Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", login)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s: refused after %v", login, time.Since(start))
		}
	}
	// Another login is not held by it (the host has had 10, which is its own
	// limit: see the next test).
	if f.s.localLimit.blocked("203.0.113.9", "bob") {
		t.Error("bob is blocked from another host by alice's failures")
	}
}

func TestLocalLoginThrottlePerHost(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	// Different logins every time: no login limit is reached, the host's is.
	for i := range localHostMax {
		if res := f.postLocal(b, csrf, fmt.Sprintf("user%d", i), "wrong wrong wrong"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d", i+1, res.StatusCode)
		}
	}
	res := f.postLocal(b, csrf, "alice", localPW)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the eleventh try from one host, with a right password: status %d, want 429", res.StatusCode)
	}
	if res.Header.Get("Location") != "" {
		t.Error("a throttled try was redirected")
	}
}

func TestLocalThrottleWindowAndBounds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newLocalThrottle(func() time.Time { return now })
	for range localLoginMax {
		th.failed("192.0.2.1", "alice")
	}
	if !th.blocked("198.51.100.7", "alice") {
		t.Error("five failures for a login did not block it from another host")
	}
	if !th.blocked("198.51.100.7", "ALICE") {
		t.Error("the login limit is case-sensitive")
	}
	if th.blocked("198.51.100.7", "carol") {
		t.Error("carol is blocked")
	}
	th.succeeded("alice")
	if th.blocked("198.51.100.7", "alice") {
		t.Error("a success did not forget the failures")
	}
	for range localLoginMax {
		th.failed("192.0.2.1", "alice")
	}
	now = now.Add(localWindow + time.Second)
	if th.blocked("192.0.2.1", "alice") {
		t.Error("still blocked after the window")
	}
	// A clock that goes back is no time elapsed: nothing is blocked for ever by it.
	now = now.Add(-24 * time.Hour)
	if th.blocked("192.0.2.1", "alice") {
		t.Error("blocked by failures from the future")
	}

	// The table is capped, and past it a login nobody failed is refused rather
	// than evicting one somebody did.
	th = newLocalThrottle(func() time.Time { return now })
	th.perHost = 1 << 30
	for i := range localTracked {
		th.failed("192.0.2.1", fmt.Sprintf("u%d", i))
	}
	if len(th.logins) != localTracked {
		t.Fatalf("%d logins tracked", len(th.logins))
	}
	th.failed("192.0.2.2", "one-more")
	if len(th.logins) != localTracked {
		t.Errorf("the table grew to %d", len(th.logins))
	}
	if !th.blocked("192.0.2.3", "never-seen") {
		t.Error("a new login was let through a full table")
	}
}

func TestLocalLoginBoundsTheRequest(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	if res := f.postLocal(b, csrf, "alice", strings.Repeat("x", maxPasswordLen+1)); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a password past the bound: status %d", res.StatusCode)
	}
	if res := f.postLocal(b, csrf, strings.Repeat("a", 100000), "x"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a login of 100 kB: status %d, want 400", res.StatusCode)
	}
	if res := f.postLocal(b, csrf, "alice", ""); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an empty password: status %d", res.StatusCode)
	}
}

// At most localHashers checks run at once; the rest wait, then are told so,
// and nothing is checked for them.
func TestLocalLoginBoundsConcurrentHashing(t *testing.T) {
	f := localFixture(t, "")
	for range localHashers {
		f.s.localHash <- struct{}{}
	}
	start := time.Now()
	_, ok, busy := f.s.checkLocal("alice", localPW)
	if !busy || ok {
		t.Errorf("with every hasher taken: ok=%v busy=%v", ok, busy)
	}
	if d := time.Since(start); d < localHashWait/2 || d > 3*localHashWait {
		t.Errorf("waited %v for a hasher", d)
	}
	for range localHashers {
		<-f.s.localHash
	}
	if _, ok, busy := f.s.checkLocal("alice", localPW); !ok || busy {
		t.Errorf("with the hashers free: ok=%v busy=%v", ok, busy)
	}
}

// prompt=none cannot be answered by a form: it goes the federation's way, as
// it did before local accounts, and the choice page is not in its way.
func TestLocalLoginDoesNotInterceptPromptNone(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	next := location(t, newBrowser(t).get(r.authURL(oauth2.SetAuthURLParam("prompt", "none"))))
	if next.Path == "/login" {
		t.Errorf("prompt=none was sent to the choice page: %s", next)
	}
}

func TestLocalDisabledPersonIsRefused(t *testing.T) {
	f := localFixture(t, "disabled_file = "+fmt.Sprintf("%q", filepath.ToSlash(filepath.Join(t.TempDir(), "disabled.json")))+"\n")
	if _, _, err := f.s.disablePerson("alice", "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.postLocal(b, csrf, "alice", localPW))
	if back.Query().Get("error") != "access_denied" || back.Query().Get("code") != "" {
		t.Errorf("a disabled local account got %s", back)
	}
}

// The federation does not reach the local entity ID, and a local grant does
// not reach the federation's rule.
func TestLocalEntityIDIsNotAFederationIdP(t *testing.T) {
	f := localFixture(t, "")
	local := f.s.cfg.Issuer + "/local"
	if f.s.allowedIdP(local) {
		t.Error("the local entity ID is an allowed SAML IdP")
	}
	if !configuredIdP(f.s.cfg, local) {
		t.Error("the local entity ID is not configured, with a local block")
	}
	if f.s.refused(&person{username: "alice", idp: local}) != "" {
		t.Errorf("alice is refused: %s", f.s.refused(&person{username: "alice", idp: local}))
	}
	if why := f.s.refused(&person{username: "ghost", idp: local}); why != "account removed" {
		t.Errorf("a login the file does not have: %q", why)
	}
}

func TestLocalAccountsReloadWithoutARestart(t *testing.T) {
	f := localFixture(t, "")
	path := f.s.cfg.Local.AccountsFile
	// bob is removed and carol added, from outside.
	text := strings.Replace(localAccountsText(), `account "bob"`, `account "carol"`, 1)
	if err := os.WriteFile(path, []byte(text+"\n# changed\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	if _, ok := f.s.cfg.Local.store.get("carol"); !ok {
		t.Error("carol, added to the file, is not known")
	}
	if _, ok := f.s.cfg.Local.store.get("bob"); ok {
		t.Error("bob, removed from the file, is still known")
	}

	// A file that no longer parses leaves the accounts that were.
	if err := os.WriteFile(path, []byte("account \"x\" {\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	if _, ok := f.s.cfg.Local.store.get("alice"); !ok {
		t.Error("a broken file logged alice out")
	}
	// A file somebody made world-readable is not read either.
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.WriteFile(path, []byte(strings.Replace(localAccountsText(), `account "bob"`, `account "dave"`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	if _, ok := f.s.cfg.Local.store.get("dave"); ok {
		t.Error("a world-readable accounts file was read")
	}
}
