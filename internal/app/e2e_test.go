// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	authnoidc "github.com/go-authn/oidc"
	"golang.org/x/oauth2"
)

// The relying party in these tests is golang.org/x/oauth2 and
// coreos/go-oidc, which build the authorization request, exchange the code
// with PKCE and verify the ID token: a client this repository did not write.
// The access token is then checked by go-authn/oidc exactly as go-fileshare
// checks the tokens WebDAV clients bring it.

type rp struct {
	cfg      oauth2.Config
	provider *gooidc.Provider
	verifier string
	state    string
	nonce    string
}

func newRP(t *testing.T, f *fixture, clientID, secret, redirect string, scopes ...string) *rp {
	t.Helper()
	p, err := gooidc.NewProvider(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatalf("discovery, as go-oidc reads it: %v", err)
	}
	return &rp{
		cfg: oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: p.Endpoint(),
			RedirectURL: redirect, Scopes: append([]string{gooidc.ScopeOpenID}, scopes...)},
		provider: p, verifier: oauth2.GenerateVerifier(), state: token(), nonce: token(),
	}
}

func (r *rp) authURL(extra ...oauth2.AuthCodeOption) string {
	return r.cfg.AuthCodeURL(r.state, append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(r.verifier), gooidc.Nonce(r.nonce)}, extra...)...)
}

// login walks a browser from the client's authorization URL, through the
// institution list and the IdP, back to the client's redirect URI.
func (f *fixture) login(b *browser, authURL string, o assertionOpts) *url.URL {
	f.t.Helper()
	next := location(f.t, b.get(authURL))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		page := b.get(next.String())
		body, _ := io.ReadAll(page.Body)
		if !strings.Contains(string(body), ">"+idpScope+"<") {
			f.t.Fatalf("the institution list does not offer the university:\n%s", body)
		}
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	}
	if next.Host != idpScope {
		f.t.Fatalf("sent to %s, not to the IdP", next)
	}
	reqID, relay := authnRequest(f.t, next)
	return location(f.t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{
		"SAMLResponse": {f.respond(reqID, o)},
		"RelayState":   {relay},
	}))
}

var alice = assertionOpts{
	eppn:        "alice@" + idpScope,
	subjectID:   "A1B2C3@" + idpScope,
	entitlement: []string{"urn:mace:univ-example.fr:fileshare:photos"},
}

func TestLoginEndToEnd(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
	back := f.login(newBrowser(t), r.authURL(), alice)

	q := back.Query()
	if q.Get("state") != r.state {
		t.Fatalf("state %q came back as %q", r.state, q.Get("state"))
	}
	if q.Get("iss") != f.s.cfg.Issuer {
		t.Errorf("iss = %q: RFC 9207 says the authorization response names the issuer", q.Get("iss"))
	}
	tok, err := r.cfg.Exchange(t.Context(), q.Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatalf("the code exchange, as x/oauth2 does it: %v", err)
	}

	// The ID token, as go-oidc verifies it.
	raw, _ := tok.Extra("id_token").(string)
	idt, err := r.provider.Verifier(&gooidc.Config{ClientID: "web"}).Verify(t.Context(), raw)
	if err != nil {
		t.Fatalf("go-oidc refused the ID token: %v", err)
	}
	if idt.Nonce != r.nonce {
		t.Errorf("nonce %q came back as %q", r.nonce, idt.Nonce)
	}
	if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
		t.Errorf("at_hash: %v", err)
	}
	// ⛔ What the scopes release is at /userinfo, NOT in the ID token (OIDC
	// Core 5.4: an access token was issued). The ID token says who, and
	// nothing about them.
	var claims map[string]any
	idt.Claims(&claims)
	released := map[string]any{
		"preferred_username":       "alice@" + idpScope,
		"name":                     "Alice Martin",
		"email":                    "alice@" + idpScope,
		"eduperson_principal_name": "alice@" + idpScope,
		"voperson_id":              "a1b2c3@" + idpScope,
	}
	for k := range released {
		if v, ok := claims[k]; ok {
			t.Errorf("the ID token carries %s = %v", k, v)
		}
	}
	if strings.Contains(idt.Subject, "alice") || strings.Contains(idt.Subject, "A1B2C3") {
		t.Errorf("sub %q exposes the institution's identifier", idt.Subject)
	}

	// The access token, as go-fileshare checks it.
	v, err := authnoidc.New(t.Context(), authnoidc.Config{Issuer: f.s.cfg.Issuer, Audience: "fileshare"})
	if err != nil {
		t.Fatal(err)
	}
	at, err := v.Verify(t.Context(), tok.AccessToken)
	if err != nil {
		t.Fatalf("go-authn/oidc refused the access token: %v", err)
	}
	if at.Username() != "alice@"+idpScope || !slices.Equal(at.Groups(), alice.entitlement) {
		t.Errorf("fileshare would see %q in %v", at.Username(), at.Groups())
	}
	if at.Subject() != idt.Subject {
		t.Error("the access token and the ID token name different subjects")
	}
	// ... and an ID token is not an access token.
	if _, err := v.Verify(t.Context(), raw); err == nil {
		t.Error("the ID token was accepted where an access token is expected")
	}

	// /userinfo, as go-oidc asks it.
	ui, err := r.provider.UserInfo(t.Context(), oauth2.StaticTokenSource(tok))
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if ui.Subject != idt.Subject || ui.Email != "alice@"+idpScope {
		t.Errorf("userinfo = %+v", ui)
	}
	var uc map[string]any
	ui.Claims(&uc)
	for k, want := range released {
		if uc[k] != want {
			t.Errorf("userinfo %s = %v, want %v", k, uc[k], want)
		}
	}
	if _, ok := uc["email_verified"]; ok {
		t.Error("email_verified was claimed: nobody verified the address")
	}
}

// Scopes decide what is released: without profile or email, nothing but
// who.
func TestScopesRelease(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	back := f.login(newBrowser(t), r.authURL(), alice)
	tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	idt, err := r.provider.Verifier(&gooidc.Config{ClientID: "web"}).Verify(t.Context(), tok.Extra("id_token").(string))
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	idt.Claims(&claims)
	for _, k := range []string{"email", "name", "preferred_username", "eduperson_principal_name", "groups"} {
		if _, ok := claims[k]; ok {
			t.Errorf("%s released under scope openid alone", k)
		}
	}
}

// Pairwise subjects: the same person, two clients, two subjects -- and the
// same one again for the same client.
func TestPairwise(t *testing.T) {
	f := newFixture(t, "")
	subject := func(clientID, secret, redirect string) string {
		r := newRP(t, f, clientID, secret, redirect)
		back := f.login(newBrowser(t), r.authURL(), alice)
		tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatal(err)
		}
		idt, err := r.provider.Verifier(&gooidc.Config{ClientID: clientID}).Verify(t.Context(), tok.Extra("id_token").(string))
		if err != nil {
			t.Fatal(err)
		}
		return idt.Subject
	}
	web := subject("web", "a-secret-long-enough-to-pass", f.redirect)
	// A native client on a loopback port it chose (RFC 8252 7.3).
	cli := subject("cli", "", "http://127.0.0.1:53127/callback")
	if web == cli {
		t.Error("a pairwise client sees the public subject")
	}
	if again := subject("cli", "", "http://127.0.0.1:40001/callback"); again != cli {
		t.Error("the pairwise subject is not stable")
	}
}

// authorizeRefused sends a browser to an authorization URL and returns
// where the error went: to the client's redirect URI, or shown here.
func authorizeRefused(t *testing.T, f *fixture, u string) (redirected *url.URL, status int) {
	t.Helper()
	r := newBrowser(t).get(u)
	if r.StatusCode == http.StatusFound {
		loc, _ := url.Parse(r.Header.Get("Location"))
		if loc.Query().Get("error") == "" {
			t.Fatalf("not refused: sent on to %s", loc)
		}
		return loc, 0
	}
	return nil, r.StatusCode
}

func TestAuthorizeRefusals(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	good := r.authURL()
	edit := func(set map[string]string, del ...string) string {
		u, _ := url.Parse(good)
		q := u.Query()
		for k, v := range set {
			q.Set(k, v)
		}
		for _, k := range del {
			q.Del(k)
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	// ⛔ Shown HERE, never sent to the URI: an unknown client, an
	// unregistered redirect, a parameter twice.
	for name, u := range map[string]string{
		"unknown client":         edit(map[string]string{"client_id": "nobody"}),
		"unregistered redirect":  edit(map[string]string{"redirect_uri": "https://evil.example/cb"}),
		"redirect with a suffix": edit(map[string]string{"redirect_uri": f.redirect + "/../evil"}),
		"no redirect":            edit(nil, "redirect_uri"),
		"a parameter twice":      good + "&scope=openid",
	} {
		if loc, status := authorizeRefused(t, f, u); loc != nil || status != http.StatusBadRequest {
			t.Errorf("%s: sent to %v (status %d); an unchecked redirect URI must not be used", name, loc, status)
		}
	}

	// Sent to the client, with state and iss.
	for name, c := range map[string]struct {
		u    string
		code string
	}{
		"no PKCE":             {edit(nil, "code_challenge", "code_challenge_method"), "invalid_request"},
		"PKCE with no method": {edit(nil, "code_challenge_method"), "invalid_request"},
		"PKCE plain":          {edit(map[string]string{"code_challenge_method": "plain"}), "invalid_request"},
		"a short challenge":   {edit(map[string]string{"code_challenge": "abc"}), "invalid_request"},
		"implicit":            {edit(map[string]string{"response_type": "id_token token"}), "unsupported_response_type"},
		"no openid":           {edit(map[string]string{"scope": "profile"}), "invalid_scope"},
		"ssh, not allowed":    {edit(map[string]string{"scope": "openid ssh"}), "invalid_scope"},
		"nfs, not allowed":    {edit(map[string]string{"scope": "openid nfs"}), "invalid_scope"},
		"prompt none + login": {edit(map[string]string{"prompt": "none login"}), "invalid_request"},
		"a request object":    {edit(map[string]string{"request": "eyJ..."}), "request_not_supported"},
	} {
		loc, _ := authorizeRefused(t, f, c.u)
		if loc == nil {
			t.Errorf("%s: shown here rather than sent to the client", name)
			continue
		}
		q := loc.Query()
		if q.Get("error") != c.code || q.Get("state") != r.state || q.Get("iss") != f.s.cfg.Issuer {
			t.Errorf("%s: %v", name, q)
		}
	}
}

func TestTokenRefusals(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	code := f.login(newBrowser(t), r.authURL(), alice).Query().Get("code")

	post := func(v url.Values, user, pass string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/token", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Error("a token response without Cache-Control: no-store")
		}
		return resp.StatusCode, out
	}
	form := func(verifier string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect}, "code_verifier": {verifier}}
	}
	for name, c := range map[string]struct {
		v          url.Values
		user, pass string
		status     int
		err        string
	}{
		"a wrong secret":         {form(r.verifier), "web", "not-the-secret-at-all", 401, "invalid_client"},
		"no secret":              {form(r.verifier), "", "", 401, "invalid_client"},
		"a public client's code": {url.Values{"client_id": {"cli"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect}, "code_verifier": {r.verifier}}, "", "", 400, "invalid_grant"},
	} {
		if status, out := post(c.v, c.user, c.pass); status != c.status || out["error"] != c.err {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	// ⛔ The code went to "cli" above and was spent by that attempt: a code
	// is taken once, whoever takes it. Log in again for the rest.
	code = f.login(newBrowser(t), r.authURL(), alice).Query().Get("code")
	if status, out := post(form(strings.Repeat("x", 43)), "web", "a-secret-long-enough-to-pass"); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("a wrong verifier: %d %v", status, out)
	}
	code = f.login(newBrowser(t), r.authURL(), alice).Query().Get("code")
	v := form(r.verifier)
	v.Set("redirect_uri", "http://127.0.0.1:9/other")
	if status, out := post(v, "web", "a-secret-long-enough-to-pass"); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("another redirect_uri: %d %v", status, out)
	}

	// ⛔ A code used twice: the second use is refused, and the token the
	// first use bought stops working at /userinfo.
	code = f.login(newBrowser(t), r.authURL(), alice).Query().Get("code")
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.provider.UserInfo(t.Context(), oauth2.StaticTokenSource(tok)); err != nil {
		t.Fatalf("userinfo before the replay: %v", err)
	}
	if _, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier)); err == nil {
		t.Fatal("a code was exchanged twice")
	}
	if _, err := r.provider.UserInfo(t.Context(), oauth2.StaticTokenSource(tok)); err == nil {
		t.Error("the token bought with a replayed code still works")
	}
	if status, out := post(url.Values{"grant_type": {"password"}}, "web", "a-secret-long-enough-to-pass"); status != 400 || out["error"] != "unsupported_grant_type" {
		t.Errorf("the password grant: %d %v", status, out)
	}
}

// ⛔ Login CSRF: a response delivered into a browser that did not start
// that login is refused, even though the response itself is perfectly
// valid.
func TestResponseInAnotherBrowser(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	attacker, victim := newBrowser(t), newBrowser(t)

	next := location(t, attacker.get(r.authURL()))
	next = location(t, attacker.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	reqID, relay := authnRequest(t, next)
	resp := f.respond(reqID, assertionOpts{eppn: "mallory@" + idpScope, subjectID: "M@" + idpScope})

	// The victim has a login of their own in progress.
	location(t, victim.get(r.authURL()))
	got := victim.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {resp}, "RelayState": {relay}})
	if got.StatusCode == http.StatusFound {
		t.Fatalf("the attacker's login was completed in the victim's browser: %s", got.Header.Get("Location"))
	}
	// And the attacker's own browser can still use it.
	back := location(t, attacker.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {resp}, "RelayState": {relay}}))
	if back.Query().Get("code") == "" {
		t.Fatalf("the rightful browser was refused: %s", back)
	}
}

// prompt=none, and the IdP had no session: OIDC's login_required.
func TestPromptNone(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	location(t, b.get(r.authURL(oauth2.SetAuthURLParam("prompt", "none"))))
	next := location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	reqID, relay := authnRequest(t, next)
	back := location(t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{
		"SAMLResponse": {f.respond(reqID, assertionOpts{status: `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/></samlp:StatusCode>`})},
		"RelayState":   {relay},
	}))
	if back.Query().Get("error") != "login_required" || back.Query().Get("state") != r.state {
		t.Fatalf("%s", back)
	}
}

// An IdP that releases nothing persistent: nobody to call sub.
func TestNoIdentifier(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	back := f.login(newBrowser(t), r.authURL(), assertionOpts{})
	if back.Query().Get("error") != "access_denied" {
		t.Fatalf("%s", back)
	}
}

// A scoped identifier from outside the IdP's scope is dropped by the SAML
// side, so a person claiming to be at another university has no eppn here.
func TestForeignScope(t *testing.T) {
	f := newFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile")
	back := f.login(newBrowser(t), r.authURL(), assertionOpts{eppn: "president@other-univ.fr", subjectID: "P@other-univ.fr"})
	// Neither identifier survives, so there is nobody to log in.
	if back.Query().Get("error") != "access_denied" {
		t.Fatalf("an identifier from another university's scope was accepted: %s", back)
	}
}

func TestDiscoveryDocument(t *testing.T) {
	f := newFixture(t, "")
	resp := newBrowser(t).get(f.s.cfg.Issuer + "/.well-known/openid-configuration")
	var d map[string]any
	json.NewDecoder(resp.Body).Decode(&d)
	if d["issuer"] != f.s.cfg.Issuer || d["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("%v", d)
	}
	if m, _ := d["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v", m)
	}
	// SP metadata, for the federation's registry.
	md := newBrowser(t).get(f.s.cfg.Issuer + "/saml/metadata")
	body, _ := io.ReadAll(md.Body)
	for _, want := range []string{f.s.cfg.Issuer + "/saml/acs", "Passerelle", "mailto:noc@example.org"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("SP metadata lacks %q", want)
		}
	}
}

// A public client that sends a secret is configured as something it is
// not, and is refused rather than let through with the secret ignored.
func TestPublicClientWithSecret(t *testing.T) {
	f := newFixture(t, "")
	req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/token", strings.NewReader(url.Values{
		"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"cli"}, "client_secret": {"anything-at-all-here"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d: a public client authenticated with a secret it does not have", resp.StatusCode)
	}
}
