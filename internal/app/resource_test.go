// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authnoidc "github.com/go-authn/oidc"
	"golang.org/x/oauth2"
)

// RFC 8707 resource indicators: a client whose audience names several
// resource servers -- go-fileshare/portal in front of several fileshare
// servers -- gets a token for ONE of them at a time, so that none can replay
// what it receives to the others (RFC 8707 3).

const (
	fsA = "https://fs-a.example.org/"
	fsB = "https://fs-b.example.org/"
	// fsFrag is in the audience, so that a refusal of it is the fragment
	// check's alone (RFC 8707 2: "MUST NOT include a fragment component").
	fsFrag = "https://fs-c.example.org/#x"
)

// portalFixture is a provider with a confidential client "portal" whose
// audience names two servers and a logical name, with refresh tokens; with
// state, a database the grant survives a restart in.
func portalFixture(t *testing.T, state bool) *fixture {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "portal.secret")
	os.WriteFile(secret, []byte("a-secret-long-enough-to-pass"), 0o600)
	extra := fmt.Sprintf(`
client "portal" {
  secret_file      = %q
  redirect_uris    = ["http://127.0.0.1:9/portal"]
  audience         = [%q, %q, "fileshare", %q]
  refresh_lifetime = "1h"
}
`, filepath.ToSlash(secret), fsA, fsB, fsFrag)
	if state {
		dsn := filepath.Join(dir, "dsn")
		os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "state.db"))), 0o600)
		extra += fmt.Sprintf("state {\n  driver = \"sqlite\"\n  dsn_file = %q\n}\n", filepath.ToSlash(dsn))
	}
	return newFixture(t, extra)
}

// portalLogin logs alice in through the portal client, with the extra
// authorization parameters given, and returns the code.
func portalLogin(t *testing.T, f *fixture, extra ...oauth2.AuthCodeOption) (*rp, string) {
	t.Helper()
	r := newRP(t, f, "portal", "a-secret-long-enough-to-pass", "http://127.0.0.1:9/portal")
	back := f.login(newBrowser(t), r.authURL(extra...), alice)
	if e := back.Query().Get("error"); e != "" {
		t.Fatalf("authorization: %s: %s", e, back.Query().Get("error_description"))
	}
	return r, back.Query().Get("code")
}

// tokenPost is a raw token request with the portal's credentials: what
// the provider answers, refusals included.
func tokenPost(t *testing.T, f *fixture, form url.Values) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("portal", "a-secret-long-enough-to-pass")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}

func refreshFor(t *testing.T, f *fixture, rt, resource string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if resource != "" {
		form.Set("resource", resource)
	}
	return tokenPost(t, f, form)
}

// audOf is the access token's aud, unverified: what the provider wrote.
func audOf(t *testing.T, at string) any {
	t.Helper()
	parts := strings.Split(at, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	json.Unmarshal(b, &c)
	return c["aud"]
}

func TestResourceAtTheTokenEndpoint(t *testing.T) {
	f := portalFixture(t, false)
	r, code := portalLogin(t, f)
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier), oauth2.SetAuthURLParam("resource", fsA))
	if err != nil {
		t.Fatal(err)
	}
	if got := audOf(t, tok.AccessToken); got != fsA {
		t.Fatalf("aud = %v, want %s alone", got, fsA)
	}
	// As fileshare checks it: A accepts it, B does not.
	for res, ok := range map[string]bool{fsA: true, fsB: false} {
		v, err := authnoidc.New(t.Context(), authnoidc.Config{Issuer: f.s.cfg.Issuer, Audience: res})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(t.Context(), tok.AccessToken); (err == nil) != ok {
			t.Errorf("%s: verify %v, want accepted=%v", res, err, ok)
		}
	}

	// A refresh for B: a token for B alone, and a new refresh token.
	rt := tok.RefreshToken
	st, m := refreshFor(t, f, rt, fsB)
	if st != http.StatusOK || audOf(t, m["access_token"].(string)) != fsB {
		t.Fatalf("refresh for B: %d %v", st, m)
	}
	rt = m["refresh_token"].(string)

	// Without a resource: the client's whole audience, as before v0.21.0.
	st, m = refreshFor(t, f, rt, "")
	if st != http.StatusOK {
		t.Fatalf("refresh without resource: %d %v", st, m)
	}
	if got := fmt.Sprint(audOf(t, m["access_token"].(string))); got != fmt.Sprint([]any{fsA, fsB, "fileshare", fsFrag}) {
		t.Fatalf("aud without resource = %v", got)
	}
	rt = m["refresh_token"].(string)

	// Refused, and the refresh token is NOT spent: the next refresh works.
	for _, bad := range []string{"https://evil.example/", "fileshare", fsFrag} {
		if st, m := refreshFor(t, f, rt, bad); st != http.StatusBadRequest || m["error"] != "invalid_target" {
			t.Errorf("resource %q: %d %v", bad, st, m)
		}
	}
	if st, m := refreshFor(t, f, rt, fsA); st != http.StatusOK {
		t.Fatalf("the refused requests spent the refresh token: %d %v", st, m)
	}
}

// A grant bounded at the authorization request: the token endpoint can
// narrow it to one, never widen it.
func TestResourceBoundsTheGrant(t *testing.T) {
	f := portalFixture(t, false)
	// At the code exchange: outside the grant, refused.
	r0, code0 := portalLogin(t, f, oauth2.SetAuthURLParam("resource", fsA))
	// A raw request: x/oauth2 retries a refusal with the other client
	// authentication style, and the code is spent by the first answer.
	st, m := tokenPost(t, f, url.Values{"grant_type": {"authorization_code"}, "code": {code0},
		"redirect_uri": {"http://127.0.0.1:9/portal"}, "code_verifier": {r0.verifier}, "resource": {fsB}})
	if st != http.StatusBadRequest || m["error"] != "invalid_target" {
		t.Fatalf("a code exchange for a resource outside the grant: %d %v", st, m)
	}
	r, code := portalLogin(t, f, oauth2.SetAuthURLParam("resource", fsA))
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if got := audOf(t, tok.AccessToken); got != fsA {
		t.Fatalf("aud = %v, want the grant's %s", got, fsA)
	}
	if st, m := refreshFor(t, f, tok.RefreshToken, fsB); st != http.StatusBadRequest || m["error"] != "invalid_target" {
		t.Fatalf("a resource outside the grant: %d %v", st, m)
	}
	if st, m := refreshFor(t, f, tok.RefreshToken, ""); st != http.StatusOK || audOf(t, m["access_token"].(string)) != fsA {
		t.Fatalf("a refresh within the grant: %d %v", st, m)
	}
}

func TestResourceRefusedAtTheAuthorizationEndpoint(t *testing.T) {
	f := portalFixture(t, false)
	r := newRP(t, f, "portal", "a-secret-long-enough-to-pass", "http://127.0.0.1:9/portal")
	for _, bad := range []string{"https://evil.example/", "fileshare", fsFrag} {
		loc := location(t, newBrowser(t).get(r.authURL(oauth2.SetAuthURLParam("resource", bad))))
		if loc.Query().Get("error") != "invalid_target" {
			t.Errorf("resource %q: sent to %s", bad, loc)
		}
	}
}

// Refused, never ignored, where it is not implemented: a client asking for
// a token for one resource must not get one for another.
func TestResourceRefusedOnOtherGrants(t *testing.T) {
	f := portalFixture(t, false)
	for _, gt := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:device_code"} {
		st, m := tokenPost(t, f, url.Values{"grant_type": {gt}, "resource": {fsA}})
		if st != http.StatusBadRequest || m["error"] != "invalid_target" {
			t.Errorf("%s: %d %v", gt, st, m)
		}
	}
	// Twice is a repeated parameter, refused as every one is.
	st, m := tokenPost(t, f, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "resource": {fsA, fsB}})
	if st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("two resources: %d %v", st, m)
	}
}

// The grant's resources are kept with the refresh token, across a restart.
func TestResourceGrantSurvivesARestart(t *testing.T) {
	f := portalFixture(t, true)
	r, code := portalLogin(t, f, oauth2.SetAuthURLParam("resource", fsB))
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	if st, m := refreshFor(t, f, tok.RefreshToken, fsA); st != http.StatusBadRequest || m["error"] != "invalid_target" {
		t.Fatalf("after a restart the grant widened: %d %v", st, m)
	}
	if st, m := refreshFor(t, f, tok.RefreshToken, ""); st != http.StatusOK || audOf(t, m["access_token"].(string)) != fsB {
		t.Fatalf("after a restart: %d %v", st, m)
	}
}

// With a scope of this provider's own, the token is for the provider alone
// (accessAudience): the only resource that may be named is the issuer.
func TestResourceWithAProviderScope(t *testing.T) {
	f := portalFixture(t, false)
	c, _ := f.s.cfg.client("portal")
	scopes := []string{"openid", "ssh"}
	if err := f.s.checkResource(c, scopes, f.s.cfg.Issuer); err != nil {
		t.Fatalf("the issuer itself: %v", err)
	}
	if err := f.s.checkResource(c, scopes, fsA); err == nil {
		t.Fatal("a resource server, for a token carrying ssh")
	}
	if aud, err := f.s.targetAudience(c, scopes, []string{fsA}, "", false); err != nil || aud != f.s.cfg.Issuer {
		t.Fatalf("without resource, with ssh: %v %v", aud, err)
	}
}
