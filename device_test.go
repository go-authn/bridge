// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	authnoidc "github.com/go-authn/oidc"
	"golang.org/x/oauth2"
)

// The device side of these tests is golang.org/x/oauth2's DeviceAuth and
// DeviceAccessToken, which poll as RFC 8628 says, slow_down included.

const deviceClients = `
client "rclone" {
  device           = true
  audience         = ["fileshare"]
  refresh_lifetime = "720h"
  name             = "rclone (WebDAV)"
}
`

func deviceFixture(t *testing.T) (*fixture, *oauth2.Config) {
	f := newFixture(t, deviceClients)
	f.s.poll = time.Second
	ep, err := endpoints(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	return f, &oauth2.Config{ClientID: "rclone", Endpoint: ep, Scopes: []string{"openid", "groups"}}
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// approve is the person, in a browser on another device: the code, the
// confirmation, their institution.
func (f *fixture) approve(b *browser, verificationURI string, yes bool, o assertionOpts) *http.Response {
	f.t.Helper()
	page := b.get(verificationURI)
	body, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(body), "rclone (WebDAV)") || !strings.Contains(string(body), "Only continue if you started this") {
		f.t.Fatalf("the confirmation page does not say who is asking, or does not warn:\n%s", body)
	}
	m := csrfField.FindSubmatch(body)
	if m == nil {
		f.t.Fatalf("no csrf field:\n%s", body)
	}
	u, _ := url.Parse(verificationURI)
	answer := "no"
	if yes {
		answer = "yes"
	}
	r := b.post(f.s.cfg.Issuer+"/device", url.Values{"user_code": {u.Query().Get("user_code")}, "csrf": {string(m[1])}, "confirm": {answer}})
	if !yes {
		return r
	}
	next := location(f.t, r)
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	}
	reqID, relay := authnRequest(f.t, next)
	return b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(reqID, o)}, "RelayState": {relay}})
}

func TestDeviceFlow(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, err := cfg.DeviceAuth(t.Context())
	if err != nil {
		t.Fatalf("device authorization, as x/oauth2 asks it: %v", err)
	}
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(da.UserCode) {
		t.Errorf("user code %q is not RFC 8628 6.1's shape", da.UserCode)
	}
	done := f.approve(newBrowser(t), da.VerificationURIComplete, true, alice)
	if done.StatusCode != http.StatusOK {
		t.Fatalf("the person's page: %d", done.StatusCode)
	}
	tok, err := cfg.DeviceAccessToken(t.Context(), da)
	if err != nil {
		t.Fatalf("polling, as x/oauth2 does it: %v", err)
	}
	if tok.RefreshToken == "" || tok.Extra("id_token") == nil {
		t.Fatalf("no refresh token or no ID token: %+v", tok)
	}
	// The access token is what go-fileshare checks.
	v, _ := authnoidc.New(t.Context(), authnoidc.Config{Issuer: f.s.cfg.Issuer, Audience: "fileshare"})
	at, err := v.Verify(t.Context(), tok.AccessToken)
	if err != nil || at.Username() != "alice@"+idpScope {
		t.Fatalf("fileshare would refuse it, or call it %q: %v", at.Username(), err)
	}
	// The device code is spent.
	if _, err := cfg.DeviceAccessToken(t.Context(), da); err == nil {
		t.Error("a device code bought two sets of tokens")
	}

	// Refresh: expire the access token and let x/oauth2 rotate.
	old := *tok
	stale := *tok
	stale.Expiry = time.Now().Add(-time.Minute)
	fresh, err := cfg.TokenSource(t.Context(), &stale).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if fresh.RefreshToken == old.RefreshToken || fresh.AccessToken == old.AccessToken {
		t.Fatal("the refresh token was not rotated")
	}
	if _, err := v.Verify(t.Context(), fresh.AccessToken); err != nil {
		t.Fatalf("the refreshed access token: %v", err)
	}
	// ⛔ The retired refresh token, used again: the family is revoked, the
	// fresh refresh token stops working, and so does /userinfo for it.
	if _, err := cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: old.RefreshToken}).Token(); err == nil {
		t.Fatal("a rotated refresh token was accepted again")
	}
	if _, err := cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: fresh.RefreshToken}).Token(); err == nil {
		t.Error("the family survived the replay of one of its tokens")
	}
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+fresh.AccessToken)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusUnauthorized {
		t.Error("an access token of a revoked family still works at /userinfo")
	}
}

func TestDeviceDenied(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, err := cfg.DeviceAuth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.approve(newBrowser(t), da.VerificationURIComplete, false, alice)
	// Once refused, the code cannot be typed again -- asked BEFORE the device
	// polls, because the poll that learns access_denied ends the grant anyway.
	page := newBrowser(t).get(da.VerificationURIComplete)
	if page.StatusCode != http.StatusBadRequest {
		t.Errorf("a refused code opened the page again: %d", page.StatusCode)
	}
	if _, err := cfg.DeviceAccessToken(t.Context(), da); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("a refused device: %v", err)
	}
}

// An institution that said no: the device learns access_denied.
func TestDeviceInstitutionRefused(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, _ := cfg.DeviceAuth(t.Context())
	r := f.approve(newBrowser(t), da.VerificationURIComplete, true, assertionOpts{})
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("the person's page after a refusal: %d", r.StatusCode)
	}
	if _, err := cfg.DeviceAccessToken(t.Context(), da); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("%v", err)
	}
}

func poll(t *testing.T, f *fixture, v url.Values) (int, string) {
	t.Helper()
	r, err := http.PostForm(f.s.cfg.Issuer+"/token", v)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]string
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out["error"]
}

func TestDeviceRefusals(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, err := cfg.DeviceAuth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	grant := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.DeviceCode}, "client_id": {"rclone"}}
	if _, e := poll(t, f, grant); e != "authorization_pending" {
		t.Errorf("first poll: %q", e)
	}
	// Polling faster than the interval: slow_down (RFC 8628 3.5).
	if _, e := poll(t, f, grant); e != "slow_down" {
		t.Errorf("an immediate second poll: %q", e)
	}
	other := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.DeviceCode}, "client_id": {"cli"}}
	if _, e := poll(t, f, other); e != "invalid_grant" {
		t.Errorf("another client's device code: %q", e)
	}
	gone := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {"nothing"}, "client_id": {"rclone"}}
	if _, e := poll(t, f, gone); e != "expired_token" {
		t.Errorf("an unknown device code: %q", e)
	}
	if s, e := poll(t, f, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"nothing"}, "client_id": {"rclone"}}); s != 400 || e != "invalid_grant" {
		t.Errorf("an unknown refresh token: %d %q", s, e)
	}
	// A client not allowed the device grant.
	r, _ := http.PostForm(f.s.cfg.Issuer+"/device_authorization", url.Values{"client_id": {"cli"}})
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("a non-device client got a device code: %d", r.StatusCode)
	}
	r, _ = http.PostForm(f.s.cfg.Issuer+"/device_authorization", url.Values{"client_id": {"nobody"}})
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unknown client: %d", r.StatusCode)
	}

	b := newBrowser(t)
	// The empty page, then a wrong code.
	if p := b.get(f.s.cfg.Issuer + "/device"); p.StatusCode != http.StatusOK {
		t.Errorf("the code page: %d", p.StatusCode)
	}
	if p := b.post(f.s.cfg.Issuer+"/device", url.Values{"user_code": {"BCDF-GHJK"}}); p.StatusCode != http.StatusBadRequest {
		t.Errorf("a wrong code: %d", p.StatusCode)
	}
	// A confirmation without the page's token: another site posting it, into
	// a browser that HAS the page's cookie.
	b.get(f.s.cfg.Issuer + "/device?user_code=" + url.QueryEscape(da.UserCode))
	if p := b.post(f.s.cfg.Issuer+"/device", url.Values{"user_code": {da.UserCode}, "confirm": {"yes"}, "csrf": {"forged"}}); p.StatusCode != http.StatusBadRequest {
		t.Errorf("a forged confirmation: %d", p.StatusCode)
	}
	// Codes are read as people type them.
	if p := b.get(f.s.cfg.Issuer + "/device?user_code=" + url.QueryEscape(strings.ToLower(strings.ReplaceAll(da.UserCode, "-", " ")))); p.StatusCode != http.StatusOK {
		t.Errorf("a code typed in lower case with a space: %d", p.StatusCode)
	}
	// Right codes are not guesses: more of them than the limit, from one
	// address -- a building behind one NAT address -- all get through.
	for i := 0; i < codeAttempts+2; i++ {
		if p := b.get(f.s.cfg.Issuer + "/device?user_code=" + url.QueryEscape(da.UserCode)); p.StatusCode != http.StatusOK {
			t.Fatalf("right code %d from one address: %d", i+1, p.StatusCode)
		}
	}
	// Ten tries, then no more from this address (RFC 8628 5.1).
	limited := false
	for i := 0; i < 15; i++ {
		if b.post(f.s.cfg.Issuer+"/device", url.Values{"user_code": {"ZZZZ-ZZZZ"}}).StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("guessing codes is not limited")
	}
	// And once limited, a right code is refused too: otherwise the limit
	// would only slow the guessing, not stop it.
	if p := b.get(f.s.cfg.Issuer + "/device?user_code=" + url.QueryEscape(da.UserCode)); p.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a right code once limited: %d", p.StatusCode)
	}
}

// `bridge token`: the first run logs in with a code, the second is served
// from the cache, and a stale token is refreshed without anybody.
func TestTokenCommand(t *testing.T) {
	f, _ := deviceFixture(t)
	cache := t.TempDir()
	pr, pw := io.Pipe()
	type result struct {
		tok string
		err error
	}
	got := make(chan result, 1)
	go func() {
		tok, err := clientToken(context.Background(), f.s.cfg.Issuer+"/", "rclone", []string{"openid"}, cache, pw)
		pw.Close()
		got <- result{tok, err}
	}()
	// Read what the person is told, and do it.
	sc := bufio.NewScanner(pr)
	var complete string
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "(or open ") {
			complete = strings.TrimSuffix(strings.TrimPrefix(sc.Text(), "(or open "), ")")
			break
		}
	}
	go io.Copy(io.Discard, pr)
	if complete == "" {
		t.Fatal("the command did not say where to log in")
	}
	f.approve(newBrowser(t), complete, true, alice)
	var first result
	select {
	case first = <-got:
	case <-time.After(30 * time.Second):
		t.Fatal("the command never got its token")
	}
	if first.err != nil || first.tok == "" {
		t.Fatalf("%v", first.err)
	}

	// Cached.
	second, err := clientToken(t.Context(), f.s.cfg.Issuer, "rclone", []string{"openid"}, cache, io.Discard)
	if err != nil || second != first.tok {
		t.Fatalf("the cached token was not used: %v", err)
	}
	// Stale: refreshed quietly, and the cache now holds the new one.
	files, _ := filepath.Glob(filepath.Join(cache, "*.json"))
	if len(files) != 1 {
		t.Fatalf("%d cache files", len(files))
	}
	var tok oauth2.Token
	b, _ := os.ReadFile(files[0])
	json.Unmarshal(b, &tok)
	if st, _ := os.Stat(files[0]); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the cache holding a refresh token is readable by others: %v", st.Mode())
	}
	tok.Expiry = time.Now().Add(-time.Hour)
	b, _ = json.Marshal(tok)
	os.WriteFile(files[0], b, 0o600)
	third, err := clientToken(t.Context(), f.s.cfg.Issuer, "rclone", []string{"openid"}, cache, io.Discard)
	if err != nil || third == first.tok {
		t.Fatalf("the stale token was not refreshed: %v", err)
	}

	// The command's own refusals.
	if _, err := runCmd(t, "token"); err == nil {
		t.Error("token with no issuer")
	}
	if _, err := clientToken(t.Context(), "http://127.0.0.1:1", "rclone", nil, cache, io.Discard); err == nil {
		t.Error("a provider that is not there")
	}
	if _, err := endpoints(t.Context(), f.s.cfg.Issuer+"/other"); err == nil {
		t.Error("a discovery document fetched from elsewhere than its issuer")
	}
}

// "aud" is a string for one audience and a list for several, and
// go-authn/oidc -- what go-fileshare verifies with -- accepts both.
func TestAccessTokenAudience(t *testing.T) {
	for _, tc := range []struct {
		aud  []string
		want string
	}{
		{[]string{"fileshare"}, `"fileshare"`},
		{[]string{"fileshare", "motley-cue"}, `["fileshare","motley-cue"]`},
	} {
		b, _ := json.Marshal(audience(tc.aud))
		if string(b) != tc.want {
			t.Errorf("%v: %s, want %s", tc.aud, b, tc.want)
		}
	}
	f, _ := deviceFixture(t)
	tok := f.deviceToken("rclone", "openid")
	parts := strings.Split(tok.AccessToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]json.RawMessage
	json.Unmarshal(payload, &claims)
	if string(claims["aud"]) != `"fileshare"` {
		t.Errorf("aud %s in the access token", claims["aud"])
	}
}
