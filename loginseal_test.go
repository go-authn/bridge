// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// cookieOf and setCookie read and replace a browser's login cookie.
func (b *browser) cookieOf(issuer string) string {
	u, _ := url.Parse(issuer)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == loginCookie {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setCookie(issuer, v string) {
	u, _ := url.Parse(issuer)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: loginCookie, Value: v, Path: "/"}})
}

// startTo starts a login in b and takes it as far as the IdP: the
// AuthnRequest's ID, and the RelayState.
func (f *fixture) startTo(t *testing.T, b *browser, authURL string) (reqID, relay string) {
	t.Helper()
	location(t, b.get(authURL))
	return authnRequest(t, location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity))))
}

// The browser carries its login, and can neither read nor change it: a
// byte flipped, or a login sealed by another deployment, opens as nothing.
func TestASealedLoginCannotBeChanged(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	location(t, b.get(r.authURL()))
	v := b.cookieOf(f.s.cfg.Issuer)
	if v == "" || strings.Contains(v, f.redirect) || strings.Contains(v, "web") {
		t.Fatalf("the cookie is empty, or carries the login in the clear: %q", v)
	}
	flipped := []byte(v)
	flipped[len(flipped)/2] ^= 0x01
	if flipped[len(flipped)/2] == '-' || flipped[len(flipped)/2] == '_' { // stay in base64url
		flipped[len(flipped)/2] = 'A'
	}
	b.setCookie(f.s.cfg.Issuer, string(flipped))
	if res := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape(idpEntity)); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a changed login was followed: %d", res.StatusCode)
	}

	other := newFixture(t, "")
	ob := newBrowser(t)
	location(t, ob.get(newRP(t, other, "web", "a-secret-long-enough-to-pass", other.redirect).authURL()))
	b.setCookie(f.s.cfg.Issuer, ob.cookieOf(other.s.cfg.Issuer))
	if res := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape(idpEntity)); res.StatusCode != http.StatusBadRequest {
		t.Errorf("another deployment's login opened here: %d", res.StatusCode)
	}
}

// A login is held by nobody but its browser, so a restart between the
// application and the IdP's answer costs nothing.
func TestALoginSurvivesARestart(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	reqID, relay := f.startTo(t, b, r.authURL())
	f.restart(t)
	back := location(t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}}))
	if back.Query().Get("code") == "" {
		t.Fatalf("the login did not survive the restart: %s", back)
	}
}

// One login, one answer: the cookie kept and replayed with a second valid
// response for the same request is refused.
func TestALoginIsAnsweredOnce(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	reqID, relay := f.startTo(t, b, r.authURL())
	kept := b.cookieOf(f.s.cfg.Issuer)
	first, second := f.respond(reqID, alice), f.respond(reqID, alice)
	if back := location(t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {first}, "RelayState": {relay}})); back.Query().Get("code") == "" {
		t.Fatalf("the first answer was refused: %s", back)
	}
	b.setCookie(f.s.cfg.Issuer, kept)
	res := b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {second}, "RelayState": {relay}})
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "already been answered") {
		t.Errorf("a second answer to the same login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

// A login sealed a quarter of an hour ago does not open. Asked at the
// discovery return, where no assertion's own times can refuse it instead.
func TestASealedLoginExpires(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	location(t, b.get(r.authURL()))
	later := time.Now().Add(loginLifetime + time.Second)
	f.s.now = func() time.Time { return later }
	res := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape(idpEntity))
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "expired") {
		t.Errorf("an expired login: %d", res.StatusCode)
	}
	// A minute before, it still opens.
	f.s.now = func() time.Time { return later.Add(-time.Minute) }
	b2 := newBrowser(t)
	location(t, b2.get(r.authURL()))
	f.s.now = time.Now
	if res := b2.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape(idpEntity)); res.StatusCode != http.StatusFound {
		t.Errorf("a live login: %d", res.StatusCode)
	}
}

// What a cookie cannot carry is refused at the start, on a page of this
// provider's, not lost on the way back from the IdP.
func TestAnAuthorizationTooLargeToCarryIsRefused(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	r.state = strings.Repeat("s", 4000)
	b := newBrowser(t)
	res := b.get(r.authURL())
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("a 4000-byte state: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if b.cookieOf(f.s.cfg.Issuer) != "" {
		t.Error("a login cookie was set anyway")
	}
	// An ordinary one still starts.
	r.state = token()
	if res := newBrowser(t).get(r.authURL()); res.StatusCode != http.StatusFound {
		t.Errorf("an ordinary login: %d", res.StatusCode)
	}
}

// Two answers to one login, posted at once, both get past the cookie
// check -- neither has been accepted yet -- and only one gets a code.
func TestTwoAnswersAtOnceGetOneCode(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	for round := range 5 {
		b := newBrowser(t)
		reqID, relay := f.startTo(t, b, r.authURL())
		kept := b.cookieOf(f.s.cfg.Issuer)
		answers := []string{f.respond(reqID, alice), f.respond(reqID, alice)}
		codes := make(chan bool, 2)
		var wg sync.WaitGroup
		for _, a := range answers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := newBrowser(t)
				c.setCookie(f.s.cfg.Issuer, kept)
				res := c.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {a}, "RelayState": {relay}})
				loc, _ := res.Location()
				codes <- loc != nil && loc.Query().Get("code") != ""
			}()
		}
		wg.Wait()
		close(codes)
		n := 0
		for got := range codes {
			if got {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("round %d: %d codes for one login", round, n)
		}
	}
}
