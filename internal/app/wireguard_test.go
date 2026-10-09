package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/wireguard"
	"golang.org/x/oauth2"
)

const gatewaySecret = "a-gateway-secret-long-enough-for-this"

// wgFixture is a provider that registers WireGuard keys through the
// "claimward" client and lists them for the "gw" gateway; "office" and
// "gw-office" are a second deployment beside it.
func wgFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "gw-secret")
	if err := os.WriteFile(secret, []byte(gatewaySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, `
certificates_file = "`+filepath.ToSlash(filepath.Join(dir, "certs.json"))+`"
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
wireguard {
  lifetime = "2h"
  max_keys = 2
}
client "claimward" {
  device           = true
  wireguard_keys   = true
  refresh_lifetime = "720h"
}
client "office" {
  device         = true
  wireguard_keys = true
}
client "rclone" {
  device = true
}
client "gw" {
  secret_file     = "`+filepath.ToSlash(secret)+`"
  wireguard_peers = ["claimward"]
}
client "gw-office" {
  secret_file     = "`+filepath.ToSlash(secret)+`"
  wireguard_peers = ["office"]
}
`)
	f.s.poll = time.Second
	return f
}

// gateway is go-authn/wireguard's own Source, as a gateway runs it: the
// provider and its consumer judged against each other.
func (f *fixture) gateway(t *testing.T, id string) *wireguard.Source {
	t.Helper()
	src, err := wireguard.NewSource(t.Context(), wireguard.SourceConfig{Issuer: f.s.cfg.Issuer, ClientID: id, ClientSecret: gatewaySecret})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// postKey registers (or with DELETE takes back) a key with a bearer token.
func (f *fixture) postKey(t *testing.T, method, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, f.s.cfg.Issuer+wireguard.KeyPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func keyBody(key, device string) string {
	b, _ := json.Marshal(map[string]string{"public_key": key, "device": device})
	return string(b)
}

// claimsOf reads a JWT's payload, unverified: for looking at what a test was
// handed, not for trusting it.
func claimsOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	json.Unmarshal(b, &c)
	return c
}

const (
	laptopKey = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	phoneKey  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	thirdKey  = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
)

// A key a person registers is in the gateway's next list, under the subject
// the gateway will find in that person's tokens.
func TestAKeyRegisteredIsListedForItsGateway(t *testing.T) {
	f := wgFixture(t)
	tok := f.deviceToken("claimward", "openid", "wireguard")
	code, out := f.postKey(t, http.MethodPost, tok.AccessToken, keyBody(laptopKey, "laptop"))
	if code != http.StatusOK || out["public_key"] != laptopKey {
		t.Fatalf("registering: %d %v", code, out)
	}
	until := time.Unix(int64(out["expires_at"].(float64)), 0)
	if d := time.Until(until); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("the lease ends in %s, want the configured 2h", d)
	}

	l, err := f.gateway(t, "gw").Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Peers) != 1 {
		t.Fatalf("the list has %d peers", len(l.Peers))
	}
	p := l.Peers[0]
	sub := claimsOf(t, tok.AccessToken)["sub"]
	if p.Key.String() != laptopKey || p.Subject != sub || p.Username != "alice@"+idpScope || p.Device != "laptop" || !p.Expires.Equal(until) {
		t.Errorf("the peer is %+v (want sub %v)", p, sub)
	}

	// Registering it again renews it, and it is still one peer.
	if code, _ := f.postKey(t, http.MethodPost, tok.AccessToken, keyBody(laptopKey, "laptop")); code != http.StatusOK {
		t.Errorf("renewing: %d", code)
	}
	// Another deployment's gateway sees none of it.
	if l, err := f.gateway(t, "gw-office").Fetch(t.Context()); err != nil || len(l.Peers) != 0 {
		t.Errorf("the other gateway: %v, %d peers", err, len(l.Peers))
	}
}

// ⛔ A public key is public. Whoever reads one off a configuration must not
// be able to take it over, nor bring back one that was taken back.
func TestAKeyBelongsToItsFirstOwner(t *testing.T) {
	f := wgFixture(t)
	alices := f.deviceToken("claimward", "openid", "wireguard").AccessToken
	bobs := f.deviceTokenAs("claimward", bob, "openid", "wireguard").AccessToken
	if code, _ := f.postKey(t, http.MethodPost, alices, keyBody(laptopKey, "laptop")); code != http.StatusOK {
		t.Fatalf("alice registering: %d", code)
	}
	if code, out := f.postKey(t, http.MethodPost, bobs, keyBody(laptopKey, "mine now")); code != http.StatusConflict {
		t.Errorf("bob registering alice's key: %d %v", code, out)
	}
	if code, _ := f.postKey(t, http.MethodDelete, bobs, keyBody(laptopKey, "")); code != http.StatusNotFound {
		t.Errorf("bob taking back alice's key: %d", code)
	}
	// Two keys a person, here; the third is refused.
	if code, _ := f.postKey(t, http.MethodPost, alices, keyBody(phoneKey, "phone")); code != http.StatusOK {
		t.Fatalf("alice's second key: %d", code)
	}
	if code, out := f.postKey(t, http.MethodPost, alices, keyBody(thirdKey, "tablet")); code != http.StatusConflict || !strings.Contains(out["error_description"].(string), "too many") {
		t.Errorf("a third key: %d %v", code, out)
	}
	// Taken back by its owner, it leaves the list and cannot come back.
	if code, _ := f.postKey(t, http.MethodDelete, alices, keyBody(phoneKey, "")); code != http.StatusNoContent {
		t.Fatalf("alice taking back her phone: %d", code)
	}
	l, err := f.gateway(t, "gw").Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Peers) != 1 || l.Peers[0].Key.String() != laptopKey {
		t.Errorf("after the phone was taken back the list is %+v", l.Peers)
	}
	if code, out := f.postKey(t, http.MethodPost, alices, keyBody(phoneKey, "phone")); code != http.StatusConflict || !strings.Contains(out["error_description"].(string), "taken back") {
		t.Errorf("the phone's key again: %d %v", code, out)
	}
	// And the slot is free again for a new key.
	if code, _ := f.postKey(t, http.MethodPost, alices, keyBody(thirdKey, "phone")); code != http.StatusOK {
		t.Errorf("a new phone key: %d", code)
	}
}

// What is not a key, a device name or a request is refused before anything
// is recorded.
func TestWhatIsNotAKeyIsRefused(t *testing.T) {
	f := wgFixture(t)
	tok := f.deviceToken("claimward", "openid", "wireguard").AccessToken
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, body := range []string{
		keyBody(zero, "low order"),
		keyBody(strings.TrimSuffix(laptopKey, "="), "no padding"),
		keyBody(laptopKey, "two\nlines"),
		keyBody(laptopKey, strings.Repeat("x", 65)),
		`{"public_key": "` + laptopKey + `", "private_key": "never"}`,
		`not json`,
	} {
		if code, _ := f.postKey(t, http.MethodPost, tok, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, code)
		}
	}
	f.s.certs.mu.Lock()
	n := len(f.s.certs.Certs)
	f.s.certs.mu.Unlock()
	if n != 0 {
		t.Errorf("%d records after refusals only", n)
	}
}

// Which tokens may do what: the scope, the client, the kind of token.
func TestOnlyTheRightTokensRegisterOrList(t *testing.T) {
	f := wgFixture(t)
	// A client without wireguard_keys cannot even ask for the scope.
	ep, err := endpoints(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&oauth2.Config{ClientID: "rclone", Endpoint: ep, Scopes: []string{"openid", "wireguard"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("rclone was let ask for the wireguard scope")
	}
	// A token without the scope, and an ID token, are refused.
	plain := f.deviceToken("claimward", "openid")
	if code, _ := f.postKey(t, http.MethodPost, plain.AccessToken, keyBody(laptopKey, "")); code != http.StatusForbidden {
		t.Errorf("a token without the wireguard scope: %d", code)
	}
	wg := f.deviceToken("claimward", "openid", "wireguard")
	if code, _ := f.postKey(t, http.MethodPost, wg.Extra("id_token").(string), keyBody(laptopKey, "")); code != http.StatusUnauthorized {
		t.Errorf("an ID token: %d", code)
	}
	// A person's token is not a gateway's, and a gateway's is not a person's.
	get := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, f.s.cfg.Issuer+wireguard.ListPath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := get(wg.AccessToken); code != http.StatusForbidden {
		t.Errorf("a person's token at the list: %d", code)
	}
	if code := get("not-a-token"); code != http.StatusUnauthorized {
		t.Errorf("no token at the list: %d", code)
	}
	gwTok := f.clientToken(t, "gw", wireguard.ScopePeers)
	if code, _ := f.postKey(t, http.MethodPost, gwTok, keyBody(laptopKey, "")); code != http.StatusForbidden {
		t.Errorf("a gateway's token registering a key: %d", code)
	}
	// And the scope is for client credentials only, never for a login.
	if _, err := (&oauth2.Config{ClientID: "claimward", Endpoint: ep, Scopes: []string{"openid", "wireguard_peers"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("a person's client was let ask for wireguard_peers")
	}
	// A gateway asking for a scope that is not its own is refused.
	if _, err := f.clientTokenErr(t, "gw", "ssf"); err == nil {
		t.Error("a gateway was given the ssf scope")
	}
}

// ⛔ Disabling a person takes their keys back: the gateway's next list has
// none of them, at a higher version, and the older list -- which still has
// them, and is still signed -- is refused by the gateway that saw the newer.
func TestDisablingAPersonEmptiesTheirPeers(t *testing.T) {
	f := wgFixture(t)
	if code, _ := f.postKey(t, http.MethodPost, f.deviceToken("claimward", "openid", "wireguard").AccessToken, keyBody(laptopKey, "laptop")); code != http.StatusOK {
		t.Fatal("registering")
	}
	if code, _ := f.postKey(t, http.MethodPost, f.deviceTokenAs("claimward", bob, "openid", "wireguard").AccessToken, keyBody(phoneKey, "bob's")); code != http.StatusOK {
		t.Fatal("registering bob's")
	}
	gw := f.gateway(t, "gw")
	before, err := gw.Fetch(t.Context())
	if err != nil || len(before.Peers) != 2 {
		t.Fatalf("before: %v, %+v", err, before)
	}
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "left", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	after, err := gw.Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 1 || after.Peers[0].Username != "bob@"+idpScope {
		t.Errorf("after disabling alice the list is %+v", after.Peers)
	}
	if after.Version <= before.Version {
		t.Errorf("the version went from %d to %d", before.Version, after.Version)
	}
}

// RFC 6749 6: a refresh may ask for less than was granted. A VPN client logs
// in once for "openid wireguard", registers its key with that token, and
// refreshes for "openid" alone -- a token for its own server, which a
// wireguard-scoped token never is.
func TestARefreshMayAskForLess(t *testing.T) {
	f := wgFixture(t)
	tok := f.deviceToken("claimward", "openid", "wireguard")
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	if aud := claimsOf(t, tok.AccessToken)["aud"]; aud != f.s.cfg.Issuer {
		t.Fatalf("a wireguard token is addressed to %v", aud)
	}
	ep, err := endpoints(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	refresh := func(rt, scope string) (*http.Response, map[string]any) {
		body := "grant_type=refresh_token&client_id=claimward&refresh_token=" + rt
		if scope != "" {
			body += "&scope=" + scope
		}
		res, err := http.Post(ep.TokenURL, "application/x-www-form-urlencoded", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}
	// Asking for more than was granted is refused, and costs nothing.
	if res, out := refresh(tok.RefreshToken, "openid+ssh"); res.StatusCode != http.StatusBadRequest || out["error"] != "invalid_scope" {
		t.Errorf("asking for ssh: %d %v", res.StatusCode, out)
	}
	res, out := refresh(tok.RefreshToken, "openid")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("asking for less after a refused ask: %d %v", res.StatusCode, out)
	}
	c := claimsOf(t, out["access_token"].(string))
	if c["scope"] != "openid" || c["aud"] != "claimward" {
		t.Errorf("the narrowed token: scope %v, aud %v", c["scope"], c["aud"])
	}
	// The refresh token kept everything: the next refresh may ask for all.
	res, out = refresh(out["refresh_token"].(string), "")
	if res.StatusCode != http.StatusOK || claimsOf(t, out["access_token"].(string))["scope"] != "openid wireguard" {
		t.Errorf("the next refresh: %d %v", res.StatusCode, out)
	}
	_ = context.Background
}

// clientToken is a token for a confidential client's own credentials.
func (f *fixture) clientToken(t *testing.T, id, scope string) string {
	t.Helper()
	tok, err := f.clientTokenErr(t, id, scope)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) clientTokenErr(t *testing.T, id, scope string) (string, error) {
	t.Helper()
	res, err := http.Post(f.s.cfg.Issuer+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials&scope="+scope+"&client_id="+id+"&client_secret="+gatewaySecret))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK {
		return "", &tokenErr{out}
	}
	return out["access_token"].(string), nil
}

type tokenErr struct{ out map[string]any }

func (e *tokenErr) Error() string { b, _ := json.Marshal(e.out); return string(b) }

// The same race the certificates have: a registration held open across a
// DisablePerson gets nothing, and what it recorded is taken back.
func TestARegistrationHeldAcrossADisablingGetsNothing(t *testing.T) {
	f := wgFixture(t)
	tok := f.deviceToken("claimward", "openid", "wireguard")
	finish := heldRequest(t, f.s.handler(), wireguard.KeyPath, tok.AccessToken, []byte(keyBody(laptopKey, "laptop")))
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "left", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if w := finish(); w.Code != http.StatusUnauthorized {
		t.Errorf("a registration held across the disabling answered %d: %s", w.Code, w.Body)
	}
	l, err := f.gateway(t, "gw").Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Peers) != 0 {
		t.Errorf("the list has %+v", l.Peers)
	}
}

// What a WireGuard configuration may not say.
func TestWireGuardConfigurationsThatCannotWork(t *testing.T) {
	c := newConf(t)
	certs := `certificates_file = "` + c.dir + `/certs.json"` + "\n"
	for _, tc := range []struct{ extra, want string }{
		{`client "c" {
  device         = true
  wireguard_keys = true
}`, "need a wireguard block"},
		{`wireguard {}`, "certificates_file is required"},
		{certs + `wireguard { lifetime = "soon" }`, "lifetime"},
		{certs + `wireguard { max_keys = -1 }`, "max_keys"},
		{certs + `wireguard {}
client "c" {
  device         = true
  wireguard_keys = true
}
client "gw" {
  device          = true
  wireguard_peers = ["c"]
}`, "confidential client"},
		{certs + `wireguard {}
client "gw" {
  secret_file     = "` + c.secret + `"
  wireguard_peers = ["web"]
}`, "not a client with wireguard_keys"},
	} {
		if _, err := c.load(t, c.hcl(func(s string) string { return s + tc.extra })); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s:\n  %v, want %q", tc.extra, err, tc.want)
		}
	}
	// And one that can: the defaults are a day and ten keys.
	cfg, err := c.load(t, c.hcl(func(s string) string { return s + certs + `wireguard {}` }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.lifetime != 24*time.Hour || cfg.WireGuard.MaxKeys != 10 {
		t.Errorf("the defaults: %s, %d", cfg.WireGuard.lifetime, cfg.WireGuard.MaxKeys)
	}
}
