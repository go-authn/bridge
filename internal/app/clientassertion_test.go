// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// machineKeys are a machine's private keys, one per algorithm, and the JWK
// Set that registers their public halves.
type machineKeys struct {
	es  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
	ed  ed25519.PrivateKey
	set string
}

func newMachineKeys(t *testing.T) *machineKeys {
	t.Helper()
	k := &machineKeys{}
	var err error
	if k.es, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if k.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	var edPub ed25519.PublicKey
	if edPub, k.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &k.es.PublicKey, KeyID: "es", Algorithm: "ES256", Use: "sig"},
		{Key: &k.rsa.PublicKey, KeyID: "rs", Algorithm: "RS256", Use: "sig"},
		{Key: edPub, KeyID: "ed", Algorithm: "EdDSA", Use: "sig"},
	}})
	k.set = string(b)
	return k
}

// assertion signs claims with key, as a machine does.
func assertion(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func machineFixture(t *testing.T) (*fixture, *machineKeys) {
	t.Helper()
	k := newMachineKeys(t)
	jf := filepath.Join(t.TempDir(), "jwks.json")
	os.WriteFile(jf, []byte(k.set), 0o600)
	f := newFixture(t, deviceClients+`
client "winpc" {
  jwks_file = "`+filepath.ToSlash(jf)+`"
  audience  = ["fileshare-s3"]
}
`)
	return f, k
}

func (f *fixture) claims(client string, edit func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": client, "sub": client, "aud": f.s.cfg.Issuer + "/token",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": token(),
	}
	if edit != nil {
		edit(c)
	}
	return c
}

// post sends a token request, and returns the status and the body.
func (f *fixture) postToken(t *testing.T, v url.Values) (int, map[string]any) {
	t.Helper()
	res, err := http.PostForm(f.s.cfg.Issuer+"/token", v)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func assertionForm(a string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {a}}
}

// A machine proves itself with a key, with each of the three algorithms, and
// gets a token about the machine for the audience its block lists.
func TestPrivateKeyJWTValid(t *testing.T) {
	f, k := machineFixture(t)
	for name, a := range map[string]string{
		"ES256": assertion(t, jose.ES256, k.es, "es", f.claims("winpc", nil)),
		"RS256": assertion(t, jose.RS256, k.rsa, "rs", f.claims("winpc", nil)),
		"EdDSA": assertion(t, jose.EdDSA, k.ed, "ed", f.claims("winpc", nil)),
		// No kid: every registered key is tried.
		"ES256 without kid": assertion(t, jose.ES256, k.es, "", f.claims("winpc", nil)),
		// The issuer URL is an audience too (RFC 7523 3 ¶3 allows either).
		"aud issuer": assertion(t, jose.ES256, k.es, "es", f.claims("winpc", func(c map[string]any) { c["aud"] = f.s.cfg.Issuer })),
		"aud list": assertion(t, jose.ES256, k.es, "es", f.claims("winpc", func(c map[string]any) {
			c["aud"] = []string{"somebody-else", f.s.cfg.Issuer + "/token"}
		})),
	} {
		status, body := f.postToken(t, assertionForm(a))
		if status != http.StatusOK {
			t.Errorf("%s: %d %v", name, status, body)
			continue
		}
		claims, err := f.s.cfg.accessKey.verify("at+jwt", body["access_token"].(string))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if claims["sub"] != "winpc" || claims["azp"] != "winpc" || claims["aud"] != "fileshare-s3" || claims["scope"] != "machine" {
			t.Errorf("%s: the token says %v", name, claims)
		}
		if _, there := body["refresh_token"]; there {
			t.Errorf("%s: a machine was handed a refresh token", name)
		}
	}
}

func TestPrivateKeyJWTRefusals(t *testing.T) {
	f, k := machineFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := func(edit func(map[string]any)) string {
		return assertion(t, jose.ES256, k.es, "es", f.claims("winpc", edit))
	}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	payload := func() string { b, _ := json.Marshal(f.claims("winpc", nil)); return b64(string(b)) }

	// A replayed assertion: the first use is the control.
	replayed := good(nil)
	if status, body := f.postToken(t, assertionForm(replayed)); status != http.StatusOK {
		t.Fatalf("the control: %d %v", status, body)
	}

	hs, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	hs256, _ := jwt.Signed(hs).Claims(f.claims("winpc", nil)).Serialize()

	for name, a := range map[string]string{
		"replayed jti": replayed,
		"expired": good(func(c map[string]any) {
			c["iat"] = now.Add(-time.Hour).Unix()
			c["exp"] = now.Add(-30 * time.Minute).Unix()
		}),
		"lives an hour": good(func(c map[string]any) { c["exp"] = now.Add(time.Hour).Unix() }),
		"lifetime from iat": good(func(c map[string]any) {
			c["iat"] = now.Add(-time.Hour).Unix()
			c["exp"] = now.Add(time.Minute).Unix()
		}),
		"wrong aud":                good(func(c map[string]any) { c["aud"] = "https://elsewhere.example/token" }),
		"no aud":                   good(func(c map[string]any) { delete(c, "aud") }),
		"no exp":                   good(func(c map[string]any) { delete(c, "exp") }),
		"no jti":                   good(func(c map[string]any) { delete(c, "jti") }),
		"iss is not it":            good(func(c map[string]any) { c["iss"] = "rclone" }),
		"sub is not it":            good(func(c map[string]any) { c["sub"] = "rclone" }),
		"not yet valid":            good(func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }),
		"unregistered key":         assertion(t, jose.ES256, other, "es", f.claims("winpc", nil)),
		"unregistered key, no kid": assertion(t, jose.ES256, other, "", f.claims("winpc", nil)),
		"kid of another key":       assertion(t, jose.ES256, k.es, "rs", f.claims("winpc", nil)),
		"unknown client":           assertion(t, jose.ES256, k.es, "es", f.claims("nobody", nil)),
		// A client with a secret and no key has none to verify with.
		"client without keys": assertion(t, jose.ES256, k.es, "es", f.claims("rclone", nil)),
		"alg none":            b64(`{"alg":"none","typ":"JWT"}`) + "." + payload() + ".",
		"alg none, signature": b64(`{"alg":"none","typ":"JWT"}`) + "." + payload() + ".AAAA",
		"HS256":               hs256,
		// HS256 with the PUBLIC key as the secret: the oldest confusion.
		"HS256 by public key": func() string {
			pub, _ := json.Marshal(jose.JSONWebKey{Key: &k.es.PublicKey})
			sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: pub}, nil)
			s, _ := jwt.Signed(sg).Claims(f.claims("winpc", nil)).Serialize()
			return s
		}(),
		"garbage":  "not.a.jwt",
		"oversize": strings.Repeat("a", maxAssertionBytes+1),
		"tampered": func() string {
			p := strings.Split(good(nil), ".")
			return p[0] + "." + payload() + "." + p[2]
		}(),
	} {
		if status, body := f.postToken(t, assertionForm(a)); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("%s: ACCEPTED or wrong answer: %d %v", name, status, body)
		}
	}

	// The other ways in, for a client that has a key and no secret.
	v := url.Values{"grant_type": {"client_credentials"}, "client_id": {"winpc"}}
	if status, _ := f.postToken(t, v); status != http.StatusUnauthorized {
		t.Errorf("an empty secret for a key client: %d", status)
	}
	v.Set("client_secret", "")
	if status, _ := f.postToken(t, v); status != http.StatusUnauthorized {
		t.Errorf("an empty client_secret for a key client: %d", status)
	}
	// An assertion with a secret beside it, or the wrong type, or client_id of another.
	v = assertionForm(good(nil))
	v.Set("client_secret", "0123456789abcdef-long")
	if status, _ := f.postToken(t, v); status != http.StatusUnauthorized {
		t.Errorf("an assertion and a secret: %d", status)
	}
	v = assertionForm(good(nil))
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
	if status, _ := f.postToken(t, v); status != http.StatusUnauthorized {
		t.Errorf("another assertion type: %d", status)
	}
	v = assertionForm(good(nil))
	v.Set("client_id", "rclone")
	if status, _ := f.postToken(t, v); status != http.StatusUnauthorized {
		t.Errorf("another client_id: %d", status)
	}
	// What a machine may buy: the machine scope, nothing of a person's.
	v = assertionForm(good(nil))
	v.Set("scope", "openid")
	if status, body := f.postToken(t, v); status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("openid for a machine: %d %v", status, body)
	}
	// Its credentials do not make it a person's client: no code, no refresh.
	v = assertionForm(good(nil))
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", "x")
	if status, _ := f.postToken(t, v); status == http.StatusOK {
		t.Errorf("a refresh with an assertion: %d", status)
	}
}

// The replay cache is bounded, and a full one refuses rather than forgets.
func TestPrivateKeyJWTReplayCacheBounded(t *testing.T) {
	f, k := machineFixture(t)
	f.s.assertionJTIs.capped(2)
	for i := 0; i < 2; i++ {
		if status, body := f.postToken(t, assertionForm(assertion(t, jose.ES256, k.es, "es", f.claims("winpc", nil)))); status != http.StatusOK {
			t.Fatalf("assertion %d: %d %v", i, status, body)
		}
	}
	if status, _ := f.postToken(t, assertionForm(assertion(t, jose.ES256, k.es, "es", f.claims("winpc", nil)))); status != http.StatusUnauthorized {
		t.Errorf("a full replay cache accepted: %d", status)
	}
	// Time frees it: past the assertions' lives the cache has room again.
	later := time.Now().Add(10 * time.Minute)
	f.s.now = func() time.Time { return later }
	defer func() { f.s.now = time.Now }()
	c := f.claims("winpc", func(c map[string]any) { c["iat"] = later.Unix(); c["exp"] = later.Add(time.Minute).Unix() })
	if status, body := f.postToken(t, assertionForm(assertion(t, jose.ES256, k.es, "es", c))); status != http.StatusOK {
		t.Errorf("after the entries expired: %d %v", status, body)
	}
}

func TestPrivateKeyJWTDiscovery(t *testing.T) {
	f, _ := machineFixture(t)
	res, err := http.Get(f.s.cfg.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var d map[string][]string
	json.NewDecoder(res.Body).Decode(&d)
	if !strings.Contains(strings.Join(d["token_endpoint_auth_methods_supported"], " "), "private_key_jwt") ||
		!strings.Contains(strings.Join(d["grant_types_supported"], " "), "client_credentials") {
		t.Errorf("discovery does not offer it: %v", d)
	}
}

func TestPrivateKeyJWTConfigRefusals(t *testing.T) {
	c := newConf(t)
	k := newMachineKeys(t)
	priv, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.es, KeyID: "p"}}})
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &weak.PublicKey, KeyID: "w"}}})
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384Set, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p384.PublicKey, KeyID: "c"}}})
	hmacSet := `{"keys":[{"kty":"oct","k":"MDEyMzQ1Njc4OWFiY2RlZg","kid":"h"}]}`
	ps := `{"keys":[` + `{"kty":"RSA","alg":"PS256","n":"AQAB","e":"AQAB"}]}`
	const edKey = `{"kty":"OKP","crv":"Ed25519","kid":"d","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	block := func(attrs string) string {
		return c.hcl(nil) + "client \"m\" {\n" + attrs + "\n}\n"
	}
	hd := func(s string) string { return "jwks = <<EOT\n" + s + "\nEOT" }
	for name, body := range map[string]string{
		"secret and jwks": block(hd(k.set) + "\nsecret_file = \"" + c.secret + "\""),
		"jwks and file":   block(hd(k.set) + "\njwks_file = \"" + c.secret + "\""),
		"a private key":   block(hd(string(priv))),
		"a 1024-bit key":  block(hd(string(weakSet))),
		"P-384":           block(hd(string(p384Set))),
		"a symmetric key": block(hd(hmacSet)),
		"a PS256 key":     block(hd(ps)),
		"not JSON":        block(hd("nope")),
		"no key":          block(hd(`{"keys":[]}`)),
		"a missing file":  block("jwks_file = \"" + c.dir + "/absent.json\""),
		"duplicate kid":   block(hd(`{"keys":[` + edKey + `,` + edKey + `]}`)),
	} {
		if _, err := c.load(t, body); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	// The control, and the same client with a redirect URI for a code grant.
	if cfg, err := c.load(t, block(hd(k.set))); err != nil {
		t.Errorf("the control: %v", err)
	} else if cl, _ := cfg.client("m"); cl.public() {
		t.Error("a key client is public")
	}
	if _, err := c.load(t, block(hd(k.set)+"\nredirect_uris = [\"https://app.example.org/cb\"]")); err != nil {
		t.Errorf("a key client with a redirect URI: %v", err)
	}
}
