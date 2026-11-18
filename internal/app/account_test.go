// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// The account page's tests drive the HTTP surface with go-authn/webauthn's
// test authenticator. What a browser does with these pages -- the script, the
// cookie, the CSP -- is proved by browser_test.go, which drives a real Chrome.

var accountCSRFField = regexp.MustCompile(`data-csrf="([^"]+)"`)

// accountSess is a step-up as a client holds it: the cookie, and the page's
// CSRF token.
type accountSess struct {
	cookie, csrf string
}

func (f *fixture) accountReq(method, path, cookie string, body any, hdr ...string) *http.Response {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.s.cfg.Issuer+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := newBrowser(f.t).c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

// stepUpBegin returns the handle and the challenge.
func (f *fixture) stepUpBegin() (string, []byte) {
	f.t.Helper()
	res := f.accountReq("POST", "/account/stepup/begin", "", struct{}{})
	body := readBody(res)
	if res.StatusCode != http.StatusOK {
		f.t.Fatalf("stepup/begin: status %d: %s", res.StatusCode, body)
	}
	var o struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &o); err != nil {
		f.t.Fatalf("%v: %s", err, body)
	}
	if o.PublicKey["userVerification"] != "required" {
		f.t.Errorf("the step-up does not require user verification: %v", o.PublicKey)
	}
	return o.Handle, decB64(f.t, o.PublicKey["challenge"].(string))
}

func (f *fixture) assertionBody(a *webauthntest.Authenticator, login, handle string, challenge []byte, o webauthntest.Options) map[string]string {
	cd, ad, sig := a.Assert(f.s.cfg.rpID(), f.s.cfg.origin(), challenge, o)
	return map[string]string{
		"handle": handle, "id": b64(a.ID), "clientDataJSON": b64(cd),
		"authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64(f.s.userHandle(login)),
	}
}

// stepUpRaw is a whole step-up, the finish's response unread.
func (f *fixture) stepUpRaw(a *webauthntest.Authenticator, login string, o webauthntest.Options) *http.Response {
	f.t.Helper()
	h, ch := f.stepUpBegin()
	return f.accountReq("POST", "/account/stepup/finish", "", f.assertionBody(a, login, h, ch, o))
}

func accountCookieOf(res *http.Response) string {
	for _, c := range res.Cookies() {
		if c.Name == accountCookieName && c.MaxAge >= 0 && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

// signedIn is a step-up that must succeed, and the page's token with it.
func (f *fixture) signedIn(a *webauthntest.Authenticator, login string) *accountSess {
	f.t.Helper()
	res := f.stepUpRaw(a, login, webauthntest.Options{})
	body := readBody(res)
	if res.StatusCode != http.StatusOK {
		f.t.Fatalf("step-up of %s: status %d: %s", login, res.StatusCode, body)
	}
	c := accountCookieOf(res)
	if c == "" {
		f.t.Fatal("the step-up set no session cookie")
	}
	s := &accountSess{cookie: c}
	s.csrf = f.accountPageCSRF(c)
	return s
}

func (f *fixture) accountPage(cookie string) (int, string) {
	f.t.Helper()
	res := f.accountReq("GET", "/account", cookie, nil)
	return res.StatusCode, readBody(res)
}

func (f *fixture) accountPageCSRF(cookie string) string {
	f.t.Helper()
	status, body := f.accountPage(cookie)
	m := accountCSRFField.FindStringSubmatch(body)
	if status != http.StatusOK || m == nil {
		f.t.Fatalf("the account page with a session: status %d:\n%s", status, body)
	}
	return m[1]
}

// addKey is begin and finish with authenticator a; it returns the finish's
// status.
func (f *fixture) addKey(s *accountSess, a *webauthntest.Authenticator, o webauthntest.Options) int {
	f.t.Helper()
	res := f.accountReq("POST", "/account/add/begin", s.cookie, map[string]string{"csrf": s.csrf})
	body := readBody(res)
	if res.StatusCode != http.StatusOK {
		return res.StatusCode
	}
	var b struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		f.t.Fatalf("%v: %s", err, body)
	}
	cd, ao := a.Register(f.s.cfg.rpID(), f.s.cfg.origin(), decB64(f.t, b.PublicKey["challenge"].(string)), o)
	res = f.accountReq("POST", "/account/add/finish", s.cookie, map[string]any{
		"csrf": s.csrf, "handle": b.Handle, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(ao), "transports": []string{"internal"},
	})
	readBody(res)
	return res.StatusCode
}

func (f *fixture) removeKey(s *accountSess, a *webauthntest.Authenticator, hdr ...string) (int, string) {
	f.t.Helper()
	res := f.accountReq("POST", "/account/remove", s.cookie, map[string]string{"csrf": s.csrf, "key": passkeyKey(a.ID)}, hdr...)
	return res.StatusCode, readBody(res)
}

// loginWith is a whole OIDC login with a's passkey; it returns the login
// form's status (302 and a code, or 401).
func (f *fixture) loginWith(a *webauthntest.Authenticator, login string) int {
	f.t.Helper()
	r := newRP(f.t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(f.t)
	csrf := f.openLocal(b, r.authURL())
	res := f.passkeyLogin(b, a, login, csrf, webauthntest.Options{})
	readBody(res)
	return res.StatusCode
}

func (f *fixture) logs(into *bytes.Buffer) string {
	f.s.logMu.Lock()
	defer f.s.logMu.Unlock()
	return into.String()
}

func TestAccountPageAsksForAStepUpFirst(t *testing.T) {
	f := localFixture(t, "")
	f.enrolled("alice", webauthn.AlgES256)
	res := f.accountReq("GET", "/account", "", nil)
	body := readBody(res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `data-mode="stepup"`) {
		t.Fatalf("no session: status %d:\n%s", res.StatusCode, body)
	}
	if strings.Contains(body, "data-remove") || strings.Contains(body, "data-csrf") || strings.Contains(body, "alice") {
		t.Errorf("the page without a step-up shows what is behind it:\n%s", body)
	}
	if strings.Contains(strings.ToLower(body), "password") || strings.Contains(strings.ToLower(body), "mot de passe") || strings.Contains(body, `type="password"`) {
		t.Error("the account page mentions a password")
	}
	h := res.Header
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers: %v", h)
	}
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP: %q", csp)
	}
	if strings.Count(body, "<script") != 1 {
		t.Error("the page runs more than the one script of this provider")
	}
	// Methods other than GET are not the page.
	if r := f.accountReq("POST", "/account", "", struct{}{}); r.StatusCode != http.StatusNotFound {
		t.Errorf("POST /account: %d", r.StatusCode)
	}
	// /local/account is where it was, and redirects.
	if r := f.accountReq("GET", "/local/account", "", nil); r.StatusCode != http.StatusFound || r.Header.Get("Location") != f.s.cfg.Issuer+"/account" {
		t.Errorf("GET /local/account: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	// And the login page links to it.
	b := newBrowser(t)
	rp := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	f.openLocal(b, rp.authURL())
	if page := readBody(b.get(f.s.cfg.Issuer + "/local/login")); !strings.Contains(page, `href="/account"`) {
		t.Error("the local login page does not link to /account")
	}
}

func TestAccountSelfServiceEndToEnd(t *testing.T) {
	f := localFixture(t, "")
	var logs bytes.Buffer
	f.s.log = &logs
	laptop := f.enrolled("alice", webauthn.AlgES256)

	res := f.stepUpRaw(laptop, "alice", webauthntest.Options{})
	readBody(res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("step-up: %d", res.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == accountCookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("no session cookie")
	}
	if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" || ck.MaxAge != int(accountTTL.Seconds()) || !strings.HasPrefix(ck.Name, "__Host-") {
		t.Errorf("the session cookie is not a short-lived __Host- Secure HttpOnly SameSite=Strict one: %+v", ck)
	}
	s := &accountSess{cookie: ck.Name + "=" + ck.Value}
	s.csrf = f.accountPageCSRF(s.cookie)

	_, page := f.accountPage(s.cookie)
	for _, want := range []string{"alice", passkeyKey(laptop.ID)[:16], "data-remove", "backup-eligible", "this confirmation"} {
		if !strings.Contains(page, want) {
			t.Errorf("the key list lacks %q:\n%s", want, page)
		}
	}

	phone, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if st := f.addKey(s, phone, webauthntest.Options{}); st != http.StatusOK {
		t.Fatalf("adding a passkey: %d", st)
	}
	keys, _ := f.s.passkeys.passkeys("alice")
	if len(keys) != 2 {
		t.Fatalf("alice has %d passkeys after an add, want 2", len(keys))
	}
	_, page = f.accountPage(s.cookie)
	if strings.Count(page, "data-remove") != 2 || !strings.Contains(page, passkeyKey(phone.ID)[:16]) || strings.Count(page, "this confirmation") != 1 {
		t.Errorf("the list after an add:\n%s", page)
	}
	// The new key signs in; the one before still does.
	if st := f.loginWith(phone, "alice"); st != http.StatusFound {
		t.Errorf("login with the added passkey: %d", st)
	}
	if st := f.loginWith(laptop, "alice"); st != http.StatusFound {
		t.Errorf("login with the first passkey: %d", st)
	}

	// Remove the first, with the step-up made with it: allowed (another key
	// stands), and it ends the session, whose credential is gone.
	st, body := f.removeKey(s, laptop)
	if st != http.StatusOK || !strings.Contains(body, `"signedOut":true`) {
		t.Fatalf("removing the first passkey: %d %s", st, body)
	}
	if status, page := f.accountPage(s.cookie); status != http.StatusOK || !strings.Contains(page, `data-mode="stepup"`) {
		t.Errorf("the session of a removed key still opens the page:\n%s", page)
	}
	if st := f.loginWith(laptop, "alice"); st != http.StatusUnauthorized {
		t.Errorf("login with the removed passkey: %d, want 401", st)
	}
	if st := f.loginWith(phone, "alice"); st != http.StatusFound {
		t.Errorf("control: the remaining passkey no longer signs in: %d", st)
	}
	if res := f.stepUpRaw(laptop, "alice", webauthntest.Options{}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a removed passkey makes a step-up: %d", res.StatusCode)
	}

	out := f.logs(&logs)
	for _, want := range []string{
		"account: audit: alice stepup " + passkeyKey(laptop.ID)[:16] + " from 127.0.0.1",
		"account: audit: alice add " + passkeyKey(phone.ID)[:16] + " from 127.0.0.1",
		"account: audit: alice remove " + passkeyKey(laptop.ID)[:16] + " from 127.0.0.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the audit log lacks %q:\n%s", want, out)
		}
	}
}

// A step-up is for this page. Its challenge is a ceremony of its own kind, so
// it is not an OIDC login's, and a login's is not a step-up's.
func TestStepUpAndLoginCeremoniesAreNotInterchangeable(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)

	// A login's challenge, answered at the step-up.
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	status, h, ch := f.loginBegin(b, csrf)
	if status != http.StatusOK {
		t.Fatal(status)
	}
	res := f.accountReq("POST", "/account/stepup/finish", "", f.assertionBody(alice, "alice", h, ch, webauthntest.Options{}))
	readBody(res)
	if res.StatusCode != http.StatusUnauthorized || accountCookieOf(res) != "" {
		t.Errorf("a login's assertion opened the account page: %d", res.StatusCode)
	}

	// A step-up's challenge, answered at the login. The control is the same
	// request with a login's own challenge.
	f.resetThrottle()
	sh, sch := f.stepUpBegin()
	b2 := newBrowser(t)
	csrf2 := f.openLocal(b2, r.authURL())
	fields := f.loginFields(alice, "alice", csrf2, sh, sch, webauthntest.Options{})
	if res := f.postFinish(b2, fields); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a step-up's assertion ended an OIDC login: %d", res.StatusCode)
	}
	b3 := newBrowser(t)
	csrf3 := f.openLocal(b3, r.authURL())
	if res := f.passkeyLogin(b3, alice, "alice", csrf3, webauthntest.Options{}); res.StatusCode != http.StatusFound {
		t.Errorf("control: the login's own assertion: %d", res.StatusCode)
	}

	// An add's challenge answered at the step-up.
	f.resetThrottle()
	s := f.signedIn(alice, "alice")
	res = f.accountReq("POST", "/account/add/begin", s.cookie, map[string]string{"csrf": s.csrf})
	var o struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	json.Unmarshal([]byte(readBody(res)), &o)
	res = f.accountReq("POST", "/account/stepup/finish", "", f.assertionBody(alice, "alice", o.Handle, decB64(t, o.PublicKey["challenge"].(string)), webauthntest.Options{}))
	readBody(res)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an add's challenge made a step-up: %d", res.StatusCode)
	}
}

func TestStepUpRefusals(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	bob := f.enrolled("bob", webauthn.AlgES256)
	stranger := mustAuth(t, webauthn.AlgES256)

	// The control: the same call, nothing bent.
	if res := f.stepUpRaw(alice, "alice", webauthntest.Options{}); res.StatusCode != http.StatusOK {
		t.Fatalf("control: %d", res.StatusCode)
	}
	cases := []struct {
		name string
		do   func() *http.Response
	}{
		{"user verification not performed", func() *http.Response {
			return f.stepUpRaw(alice, "alice", webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUP})
		}},
		{"another origin", func() *http.Response {
			return f.stepUpRaw(alice, "alice", webauthntest.Options{Origin: "https://evil.example"})
		}},
		{"another RP ID", func() *http.Response {
			return f.stepUpRaw(alice, "alice", webauthntest.Options{RPID: "evil.example"})
		}},
		{"a registration's type", func() *http.Response {
			return f.stepUpRaw(alice, "alice", webauthntest.Options{Type: "webauthn.create"})
		}},
		{"a credential nobody enrolled", func() *http.Response { return f.stepUpRaw(stranger, "alice", webauthntest.Options{}) }},
		{"another account's user handle", func() *http.Response { return f.stepUpRaw(alice, "bob", webauthntest.Options{}) }},
		{"a handle that was never issued", func() *http.Response {
			_, ch := f.stepUpBegin()
			return f.accountReq("POST", "/account/stepup/finish", "", f.assertionBody(alice, "alice", "nope", ch, webauthntest.Options{}))
		}},
		{"a signature of another challenge", func() *http.Response {
			h, _ := f.stepUpBegin()
			return f.accountReq("POST", "/account/stepup/finish", "", f.assertionBody(alice, "alice", h, []byte("another challenge of 32 bytes...."), webauthntest.Options{}))
		}},
		{"an assertion made by another account's key for this account's handle", func() *http.Response {
			return f.stepUpRaw(bob, "alice", webauthntest.Options{})
		}},
	}
	for _, c := range cases {
		f.resetThrottle()
		res := c.do()
		readBody(res)
		if res.StatusCode != http.StatusUnauthorized || accountCookieOf(res) != "" {
			t.Errorf("%s: status %d, cookie %q; want 401 and none", c.name, res.StatusCode, accountCookieOf(res))
		}
	}

	// A handle answers once.
	f.resetThrottle()
	h, ch := f.stepUpBegin()
	body := f.assertionBody(alice, "alice", h, ch, webauthntest.Options{})
	if res := f.accountReq("POST", "/account/stepup/finish", "", body); res.StatusCode != http.StatusOK {
		t.Fatalf("control: %d", res.StatusCode)
	}
	if res := f.accountReq("POST", "/account/stepup/finish", "", body); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a replayed step-up: %d", res.StatusCode)
	}

	// And it expires with the ceremony: a challenge older than five minutes.
	f.resetThrottle()
	h, ch = f.stepUpBegin()
	body = f.assertionBody(alice, "alice", h, ch, webauthntest.Options{})
	real := time.Now()
	f.s.now = func() time.Time { return real.Add(ceremonyTTL + time.Second) }
	res := f.accountReq("POST", "/account/stepup/finish", "", body)
	f.s.now = time.Now
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an assertion over a challenge older than five minutes: %d", res.StatusCode)
	}

	// Not JSON, not this origin, no body.
	for name, hdr := range map[string][]string{
		"a cross-site request":     {"Sec-Fetch-Site", "cross-site"},
		"another origin":           {"Origin", "https://evil.example"},
		"a null origin on its own": {"Origin", "null"},
		"a form content type":      {"Content-Type", "application/x-www-form-urlencoded"},
	} {
		f.resetThrottle()
		res := f.accountReq("POST", "/account/stepup/begin", "", struct{}{}, hdr...)
		readBody(res)
		if res.StatusCode < 400 {
			t.Errorf("%s: status %d", name, res.StatusCode)
		}
	}
}

func TestAccountSessionExpiresAfterFiveMinutes(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")
	real := time.Now()
	f.s.now = func() time.Time { return real.Add(accountTTL - time.Second) }
	if st := f.addKey(s, mustAuth(t, webauthn.AlgES256), webauthntest.Options{}); st != http.StatusOK {
		t.Errorf("control: just inside the five minutes: %d", st)
	}
	f.s.now = func() time.Time { return real.Add(accountTTL + time.Second) }
	defer func() { f.s.now = time.Now }()
	if status, page := f.accountPage(s.cookie); status != http.StatusOK || !strings.Contains(page, `data-mode="stepup"`) || strings.Contains(page, "data-remove") {
		t.Errorf("the page after five minutes:\n%s", page)
	}
	res := f.accountReq("POST", "/account/add/begin", s.cookie, map[string]string{"csrf": s.csrf})
	readBody(res)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a change after five minutes: %d", res.StatusCode)
	}
}

func TestAccountChangesRefuseWhatDidNotComeFromThePage(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	bob := f.enrolled("bob", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")
	sb := f.signedIn(bob, "bob")
	origin := f.s.cfg.origin()

	type call struct {
		path string
		body map[string]string
	}
	calls := []call{
		{"/account/add/begin", map[string]string{"csrf": s.csrf}},
		{"/account/remove", map[string]string{"csrf": s.csrf, "key": passkeyKey(alice.ID)}},
		{"/account/signout", map[string]string{"csrf": s.csrf}},
	}
	// The controls first, on a call that changes nothing: add/begin from the
	// page's origin, and from a form's "null" that the browser says is same-origin.
	for _, hdr := range [][]string{nil, {"Origin", origin}, {"Origin", "null", "Sec-Fetch-Site", "same-origin"}} {
		f.resetThrottle()
		res := f.accountReq("POST", calls[0].path, s.cookie, calls[0].body, hdr...)
		readBody(res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("control %v: %d", hdr, res.StatusCode)
		}
	}
	for _, c := range calls {
		for name, v := range map[string]struct {
			cookie string
			body   map[string]string
			hdr    []string
			want   int
		}{
			"no session":                {"", c.body, nil, 401},
			"a forged cookie":           {accountCookieName + "=forged", c.body, nil, 401},
			"no token":                  {s.cookie, withCSRF(c.body, ""), nil, 403},
			"another account's token":   {s.cookie, withCSRF(c.body, sb.csrf), nil, 403},
			"a token of the login page": {s.cookie, withCSRF(c.body, mustLocalCSRF(t, f, "x")), nil, 403},
			"a cross-site request":      {s.cookie, c.body, []string{"Sec-Fetch-Site", "cross-site"}, 403},
			"a same-site request":       {s.cookie, c.body, []string{"Sec-Fetch-Site", "same-site"}, 403},
			"another origin":            {s.cookie, c.body, []string{"Origin", "https://evil.example"}, 403},
			"a null origin alone":       {s.cookie, c.body, []string{"Origin", "null"}, 403},
			"a form content type":       {s.cookie, c.body, []string{"Content-Type", "text/plain"}, 415},
		} {
			f.resetThrottle()
			res := f.accountReq("POST", c.path, v.cookie, v.body, v.hdr...)
			readBody(res)
			if res.StatusCode != v.want {
				t.Errorf("%s with %s: status %d, want %d", c.path, name, res.StatusCode, v.want)
			}
		}
		if res := f.accountReq("GET", c.path, s.cookie, nil); res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", c.path, res.StatusCode)
		}
	}
	// Nothing above changed anything: the key is there, the session works.
	if keys, _ := f.s.passkeys.passkeys("alice"); len(keys) != 1 {
		t.Errorf("a refused request changed alice's keys: %d", len(keys))
	}
	f.resetThrottle()
	if st := f.addKey(s, mustAuth(t, webauthn.AlgES256), webauthntest.Options{}); st != http.StatusOK {
		t.Errorf("control: the session no longer works: %d", st)
	}
}

// withCSRF is body with another token (none when csrf is empty).
func withCSRF(body map[string]string, csrf string) map[string]string {
	out := map[string]string{}
	for k, v := range body {
		out[k] = v
	}
	delete(out, "csrf")
	if csrf != "" {
		out["csrf"] = csrf
	}
	return out
}

func mustLocalCSRF(t *testing.T, f *fixture, id string) string {
	t.Helper()
	c, err := f.s.localCSRF(id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAccountAddRefusals(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	bob := f.enrolled("bob", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")
	sb := f.signedIn(bob, "bob")

	// The same authenticator again: excluded, and refused if it tries.
	if st := f.addKey(s, alice, webauthntest.Options{}); st != http.StatusConflict {
		t.Errorf("registering the account's own key again: %d, want 409", st)
	}
	// User verification is required to register.
	f.resetThrottle()
	if st := f.addKey(s, mustAuth(t, webauthn.AlgES256), webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUP}); st != http.StatusForbidden {
		t.Errorf("a registration without user verification: %d, want 403", st)
	}
	// Another session's ceremony.
	f.resetThrottle()
	res := f.accountReq("POST", "/account/add/begin", sb.cookie, map[string]string{"csrf": sb.csrf})
	var o struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	json.Unmarshal([]byte(readBody(res)), &o)
	a := mustAuth(t, webauthn.AlgES256)
	cd, ao := a.Register(f.s.cfg.rpID(), f.s.cfg.origin(), decB64(t, o.PublicKey["challenge"].(string)), webauthntest.Options{})
	res = f.accountReq("POST", "/account/add/finish", s.cookie, map[string]any{
		"csrf": s.csrf, "handle": o.Handle, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(ao),
	})
	readBody(res)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("finishing another session's ceremony: %d, want 403", res.StatusCode)
	}
	if keys, _ := f.s.passkeys.passkeys("alice"); len(keys) != 1 {
		t.Errorf("alice has %d keys after the refusals", len(keys))
	}
	// A step-up's challenge cannot finish an add.
	f.resetThrottle()
	sh, sch := f.stepUpBegin()
	cd, ao = a.Register(f.s.cfg.rpID(), f.s.cfg.origin(), sch, webauthntest.Options{})
	res = f.accountReq("POST", "/account/add/finish", s.cookie, map[string]any{
		"csrf": s.csrf, "handle": sh, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(ao),
	})
	readBody(res)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a step-up's challenge finished an add: %d, want 403", res.StatusCode)
	}
	// The control: nothing bent.
	f.resetThrottle()
	if st := f.addKey(s, mustAuth(t, webauthn.AlgEdDSA), webauthntest.Options{}); st != http.StatusOK {
		t.Errorf("control: %d", st)
	}
}

func TestAccountKeysAreBoundedPerAccount(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")
	for i := 1; i < maxPasskeys-1; i++ {
		a := mustAuth(t, webauthn.AlgES256)
		if err := f.s.passkeys.savePasskey(&passkeyRecord{Login: "alice", ID: a.ID, PublicKey: a.COSE, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	// Nine: one more is allowed (the control), and then the tenth is refused.
	if st := f.addKey(s, mustAuth(t, webauthn.AlgES256), webauthntest.Options{}); st != http.StatusOK {
		t.Fatalf("the tenth key: %d", st)
	}
	f.resetThrottle()
	if st := f.addKey(s, mustAuth(t, webauthn.AlgES256), webauthntest.Options{}); st != http.StatusConflict {
		t.Errorf("an eleventh key: %d, want 409", st)
	}
	if keys, _ := f.s.passkeys.passkeys("alice"); len(keys) != maxPasskeys {
		t.Errorf("alice has %d keys, want %d", len(keys), maxPasskeys)
	}
	if _, page := f.accountPage(s.cookie); strings.Contains(page, `data-mode="add"`) {
		t.Error("a full account is still offered an add button")
	}
}

func TestAccountRemoveRules(t *testing.T) {
	f := localFixture(t, "")
	laptop := f.enrolled("alice", webauthn.AlgES256)
	bob := f.enrolled("bob", webauthn.AlgES256)
	s := f.signedIn(laptop, "alice")

	// The last key is never removed, even by the session made with it.
	if st, _ := f.removeKey(s, laptop); st != http.StatusConflict {
		t.Errorf("removing the last passkey: %d, want 409", st)
	}
	if keys, _ := f.s.passkeys.passkeys("alice"); len(keys) != 1 {
		t.Fatalf("the last passkey was removed")
	}
	phone := mustAuth(t, webauthn.AlgEdDSA)
	if st := f.addKey(s, phone, webauthntest.Options{}); st != http.StatusOK {
		t.Fatal(st)
	}
	// Another account's key is not alice's to remove, whatever she names.
	if st, _ := f.removeKey(s, bob); st != http.StatusNotFound {
		t.Errorf("removing bob's passkey: %d, want 404", st)
	}
	if _, ok, _ := f.s.passkeys.passkey(passkeyKey(bob.ID)); !ok {
		t.Error("bob's passkey was removed through alice's session")
	}
	// A prefix too short to be unique is refused, and removes nothing.
	f.resetThrottle()
	res := f.accountReq("POST", "/account/remove", s.cookie, map[string]string{"csrf": s.csrf, "key": passkeyKey(phone.ID)[:4]})
	readBody(res)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("a four-character prefix: %d", res.StatusCode)
	}
	// The key the session was NOT made with: removed, and the session stays.
	f.resetThrottle()
	st, body := f.removeKey(s, phone)
	if st != http.StatusOK || !strings.Contains(body, `"signedOut":false`) {
		t.Fatalf("removing the other key: %d %s", st, body)
	}
	if status, page := f.accountPage(s.cookie); status != http.StatusOK || !strings.Contains(page, "data-remove") {
		t.Errorf("the session ended with a key it was not made with:\n%s", page)
	}
	if _, ok, _ := f.s.passkeys.passkey(passkeyKey(phone.ID)); ok {
		t.Error("the removed key is still stored")
	}
	// Back to one key: the session's own is the last, and stays.
	if st, _ := f.removeKey(s, laptop); st != http.StatusConflict {
		t.Errorf("removing the last key after removing the other: %d", st)
	}
}

// The #87 invariant from the self-service path: removing a key refuses the
// grants it bought, and only those.
func TestSelfServiceRemovalRefusesWhatTheKeyBought(t *testing.T) {
	f, _, _, _ := adminFixture(t, localExtra(t)+localClients)
	laptop := f.enrolled("alice", webauthn.AlgES256)
	phone := f.enrolled("alice", webauthn.AlgEdDSA)

	laptopTok, err := f.refreshed(f.deviceLocal("files", "alice", laptop, "openid"))
	if err != nil {
		t.Fatalf("setup: the laptop's grant does not refresh: %v", err)
	}
	phoneTok, err := f.refreshed(f.deviceLocal("files", "alice", phone, "openid"))
	if err != nil {
		t.Fatalf("setup: the phone's grant does not refresh: %v", err)
	}
	// A code bought with the laptop, not yet exchanged.
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	code := location(t, f.passkeyLogin(b, laptop, "alice", csrf, webauthntest.Options{})).Query().Get("code")
	if code == "" {
		t.Fatal("setup: no code")
	}

	// Step up with the PHONE, and remove the laptop from the page.
	f.resetThrottle()
	s := f.signedIn(phone, "alice")
	if st, body := f.removeKey(s, laptop); st != http.StatusOK {
		t.Fatalf("removing the laptop: %d %s", st, body)
	}
	if _, err := f.refreshed(laptopTok); err == nil {
		t.Error("a refresh token bought with a passkey removed from the account page still refreshes")
	}
	if _, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier)); err == nil {
		t.Error("an authorization code bought with a passkey removed from the account page still exchanges")
	}
	if _, err := f.refreshed(phoneTok); err != nil {
		t.Errorf("control: removing the laptop ended the phone's grant: %v", err)
	}
	if status, page := f.accountPage(s.cookie); status != http.StatusOK || !strings.Contains(page, "data-remove") {
		t.Errorf("control: the phone's session ended with the laptop's key:\n%s", page)
	}
	// And the last key cannot be removed from here, so what the account bought
	// without a passkey is not ended by a page.
	if st, _ := f.removeKey(s, phone); st != http.StatusConflict {
		t.Errorf("removing the last key: %d", st)
	}
}

func TestAccountEndpointsAreThrottledPerHost(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	stranger := mustAuth(t, webauthn.AlgES256)
	f.resetThrottle()
	for i := 0; i < localHostMax; i++ {
		if res := f.stepUpRaw(stranger, "alice", webauthntest.Options{}); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("refusal %d: %d", i, res.StatusCode)
		}
	}
	// The eleventh is refused before anything is checked.
	res := f.accountReq("POST", "/account/stepup/begin", "", struct{}{})
	readBody(res)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after %d failures from one host: %d, want 429", localHostMax, res.StatusCode)
	}
	f.resetThrottle()
	if res := f.stepUpRaw(alice, "alice", webauthntest.Options{}); res.StatusCode != http.StatusOK {
		t.Errorf("control: after the window, the right key: %d", res.StatusCode)
	}
	// Failures on a signed-in page count too: a forged CSRF token, ten times.
	s := f.signedIn(alice, "alice")
	f.resetThrottle()
	for i := 0; i < localHostMax; i++ {
		f.accountReq("POST", "/account/add/begin", s.cookie, map[string]string{"csrf": fmt.Sprint("wrong", i)})
	}
	if res := f.accountReq("POST", "/account/add/begin", s.cookie, map[string]string{"csrf": s.csrf}); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a host that forged ten tokens: %d, want 429", res.StatusCode)
	}
}

func TestAccountRoutesAreGoneWithoutALocalBlock(t *testing.T) {
	f := newFixture(t, "")
	// The passkey routes belong to the local block.
	for _, p := range []string{"/account/stepup/begin", "/account/stepup/finish", "/account/add/begin", "/account/add/finish", "/account/remove"} {
		res := f.accountReq("POST", p, "", struct{}{})
		readBody(res)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s without a local block: %d", p, res.StatusCode)
		}
	}
	// The account page is every person's: it offers the institution, no passkey.
	res := f.accountReq("GET", "/account", "", nil)
	body := readBody(res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `id="federation-link"`) || strings.Contains(body, "passkey-button") {
		t.Errorf("/account without a local block: %d\n%s", res.StatusCode, body)
	}
	// And what changes something needs a confirmation.
	for _, p := range []string{"/account/profile", "/account/apps/revoke", "/account/access/revoke", "/account/signout"} {
		res := f.accountReq("POST", p, "", struct{}{})
		readBody(res)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s with no confirmation: %d, want 401", p, res.StatusCode)
		}
	}
}
