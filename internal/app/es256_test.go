// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	authnoidc "github.com/go-authn/oidc"
)

// esFixture is a provider whose access tokens are ES256.
func esFixture(t *testing.T) *fixture {
	t.Helper()
	p := filepath.Join(t.TempDir(), "at.key")
	if err := generateECKey(p); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, deviceClients+`
access_token_key_file = "`+filepath.ToSlash(p)+`"
`)
	f.s.poll = 1e9
	return f
}

func jwtHeader(t *testing.T, raw string) map[string]string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	json.Unmarshal(b, &h)
	return h
}

// ES256 access tokens: under the 1023 characters OpenSSH takes as a
// keyboard-interactive answer with several AARC entitlements, verified by
// go-authn/oidc (go-fileshare's verifier) and by coreos/go-oidc against the
// published key set; ID tokens stay RS256; /userinfo takes them.
func TestES256AccessTokens(t *testing.T) {
	f := esFixture(t)
	someone := assertionOpts{
		eppn: "jean-baptiste.delaplace@" + idpScope,
		entitlement: []string{
			"urn:mace:univ-ex.example:fileshare:photos",
			"urn:geant:univ-ex.example:group:physique:calcul#login.example.org",
			"urn:geant:univ-ex.example:group:physique:calcul:admins#login.example.org",
		},
	}
	tok := f.deviceTokenAs("rclone", someone, "openid")
	if h := jwtHeader(t, tok.AccessToken); h["alg"] != "ES256" || h["typ"] != "at+jwt" {
		t.Errorf("access token header %v", h)
	}
	// The fixture's issuer is http://127.0.0.1:port and its scope a
	// placeholder; real ones are longer. The token is recomputed EXACTLY for
	// real lengths -- its payload with the issuer and every occurrence of the
	// scope (in the username, the entitlements, the IdP's entity ID) replaced
	// -- against the shibmd:Scope lengths of RENATER's metadata, measured on
	// go-authn/saml's testdata/fer-idps.xml.gz (743 scopes): median 13,
	// 95th percentile 22 (univ-grenoble-alpes.fr), 99th 29, longest 44.
	parts := strings.Split(tok.AccessToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	lengthFor := func(scopeLen int) int {
		p := strings.ReplaceAll(string(payload), f.s.cfg.Issuer, "https://login.renater-member.example")
		p = strings.ReplaceAll(p, idpScope, strings.Repeat("u", scopeLen))
		return len(parts[0]) + 1 + base64.RawURLEncoding.EncodedLen(len(p)) + 1 + len(parts[2])
	}
	if lengthFor(len(idpScope)) <= len(tok.AccessToken) {
		t.Fatal("the recomputation is not longer than the token it starts from: it does not measure")
	}
	t.Logf("ES256 access token: %d characters; with a real issuer and a scope of 13 / 22 / 29 / 44 characters: %d / %d / %d / %d",
		len(tok.AccessToken), lengthFor(13), lengthFor(22), lengthFor(29), lengthFor(44))
	// ⛔ The 99th percentile must fit. v0.21.1 read 1018 for a 15-character
	// scope and already overflowed at the 95th (22): auth_time and acr were in
	// the token, and nothing read them.
	if n := lengthFor(29); n > 1023 {
		t.Errorf("%d characters for a 29-character scope: over what OpenSSH reads as an answer", n)
	}
	if h := jwtHeader(t, tok.Extra("id_token").(string)); h["alg"] != "RS256" {
		t.Errorf("the ID token is %s; it stays RS256", h["alg"])
	}

	// go-authn/oidc, as go-fileshare verifies.
	v, err := authnoidc.New(t.Context(), authnoidc.Config{Issuer: f.s.cfg.Issuer, Audience: "fileshare"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), tok.AccessToken); err != nil {
		t.Errorf("go-authn/oidc: %v", err)
	}
	// coreos/go-oidc's key set, which is go-jose's ES256.
	ks := gooidc.NewRemoteKeySet(t.Context(), f.s.cfg.Issuer+"/jwks")
	if _, err := ks.VerifySignature(t.Context(), tok.AccessToken); err != nil {
		t.Errorf("coreos/go-oidc: %v", err)
	}
	// And the provider itself, at /userinfo.
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Errorf("/userinfo: %v %v", err, res.Status)
	}
	// One signature bit changed: refused.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[10] ^= 1
	if _, err := f.s.cfg.accessKey.verify("at+jwt", parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(sig)); err == nil {
		t.Error("an ES256 token with a changed signature verified")
	}
	// A token signed with the RSA key but claiming to be an access token
	// is not one: the access token key is the only one that makes them.
	forged, _ := f.s.cfg.signingKey.sign("at+jwt", map[string]any{"iss": f.s.cfg.Issuer, "aud": "fileshare", "exp": int64(4102444800)})
	if _, err := f.s.cfg.accessKey.verify("at+jwt", forged); err == nil {
		t.Error("an RS256 token passed for an access token")
	}
}

func base64Len(n int) int { return (n*4 + 2) / 3 }

func TestAccessTokenKeyRefusals(t *testing.T) {
	c := newConf(t)
	ec := filepath.ToSlash(filepath.Join(c.dir, "ec.key"))
	if err := generateECKey(ec); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want, edit string }{
		{"EC ID token key", "RS256", "signing_key_file  = \"" + ec + "\"\n"},
		{"same key twice", "of its own", "access_token_key_file = \"" + c.key + "\"\n"},
		{"retired is current", "current signing key", "access_token_key_file = \"" + ec + "\"\nretired_signing_key_files = [\"" + ec + "\"]\n"},
	} {
		body := c.hcl(func(s string) string {
			if strings.HasPrefix(tc.edit, "signing_key_file") {
				return strings.Replace(s, "signing_key_file  = \""+c.key+"\"\n", tc.edit, 1)
			}
			return s + tc.edit
		})
		if _, err := c.load(t, body); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// A P-384 key is not ES256.
	p384 := filepath.Join(c.dir, "p384.pem")
	os.WriteFile(p384, []byte(p384PEM), 0o600)
	if _, err := loadSigningKey(p384); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Errorf("P-384: %v", err)
	}
	// The key set: the RSA key, then the EC one with 32-byte coordinates.
	cfg, err := c.load(t, c.hcl(func(s string) string { return s + "access_token_key_file = \"" + ec + "\"\n" }))
	if err != nil {
		t.Fatal(err)
	}
	var set struct{ Keys []map[string]string }
	json.Unmarshal(jwks(cfg.publishedKeys()...), &set)
	if len(set.Keys) != 2 || set.Keys[0]["kty"] != "RSA" || set.Keys[1]["kty"] != "EC" || set.Keys[1]["crv"] != "P-256" || set.Keys[1]["alg"] != "ES256" {
		t.Fatalf("keys %v", set.Keys)
	}
	for _, c := range []string{"x", "y"} {
		if b, _ := base64.RawURLEncoding.DecodeString(set.Keys[1][c]); len(b) != 32 {
			t.Errorf("%s is %d bytes, not 32", c, len(b))
		}
	}
}

// openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt
const p384PEM = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCIwcyT+uZDOwb6Eg5g
gco0KZCKHBpom8K90shwzXxHb1HctWM/15exGq8aJRfNyTihZANiAAQ8XfZsBG6O
lOWsSdHGQXAjXbCtzIB+6UE1a3u/ffTUEuAkjXpgN5LoqECFe0pgd79ykRT6/hrK
rcXcbbJuVA1FSbhPZdQ2/fnko91egMYILIip7FKKCzi8XzJkXHWZxqU=
-----END PRIVATE KEY-----
`
