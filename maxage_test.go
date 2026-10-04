// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// forceAuthn says whether the AuthnRequest a URL carries asks the IdP to
// authenticate the person again.
func forceAuthn(t *testing.T, u *url.URL) bool {
	t.Helper()
	z, _ := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	raw, _ := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	return strings.Contains(string(raw), `ForceAuthn="true"`)
}

// max_age asks for a new authentication only "if the elapsed time is
// greater than this value" (OIDC Core 3.1.2.1). Before, any max_age sent
// ForceAuthn, so an IdP authenticated the person again every time, and the
// OpenID Foundation's oidcc-max-age-10000 saw two different auth_time --
// passing only when both logins fell in the same second.
func TestMaxAgeAsksAgainOnlyWhenTooOld(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	start := func(maxAge string) (*browser, *url.URL) {
		b := newBrowser(t)
		next := location(t, b.get(r.authURL(oauth2.SetAuthURLParam("max_age", maxAge))))
		if strings.HasSuffix(next.Path, "/saml/choose") {
			next = location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
		}
		return b, next
	}
	answer := func(b *browser, req *url.URL, o assertionOpts) *url.URL {
		id, relay := authnRequest(t, req)
		return location(t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(id, o)}, "RelayState": {relay}}))
	}

	// A session younger than max_age: no ForceAuthn, and a code.
	b, req := start("10000")
	if forceAuthn(t, req) {
		t.Error("max_age=10000 sent ForceAuthn")
	}
	if back := answer(b, req, alice); back.Query().Get("code") == "" {
		t.Errorf("max_age=10000, a fresh session: %s", back)
	}

	// Older than max_age: back to the IdP, with ForceAuthn, and then a code.
	b, req = start("60")
	old := alice
	old.authnAt = time.Now().Add(-time.Hour)
	again := answer(b, req, old)
	if again.Host != idpScope || !forceAuthn(t, again) {
		t.Fatalf("an authentication an hour old for max_age=60 went to %s (ForceAuthn %v)", again, forceAuthn(t, again))
	}
	if back := answer(b, again, alice); back.Query().Get("code") == "" {
		t.Errorf("after authenticating again: %s", back)
	}

	// 0 is prompt=login: ForceAuthn at once.
	if _, req := start("0"); !forceAuthn(t, req) {
		t.Error("max_age=0 did not send ForceAuthn")
	}
	// Not a number of seconds.
	if loc, _ := authorizeRefused(t, f, r.authURL(oauth2.SetAuthURLParam("max_age", "soon"))); loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("max_age=soon: %v", loc)
	}
}
