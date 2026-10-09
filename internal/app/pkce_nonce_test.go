// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// orNonce is a confidential client allowed to protect its code with the
// OpenID nonce instead of PKCE (RFC 9700 2.1.1).
func orNonce(t *testing.T) *fixture {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "rp.secret")
	os.WriteFile(secret, []byte("a-confidential-secret-long-enough"), 0o600)
	return newFixture(t, `
client "rp" {
  secret_file   = "`+filepath.ToSlash(secret)+`"
  redirect_uris = ["http://127.0.0.1:9/callback"]
  pkce          = "or_nonce"
}
`)
}

func TestAConfidentialClientMayUseTheNonceInsteadOfPKCE(t *testing.T) {
	f := orNonce(t)
	r := newRP(t, f, "rp", "a-confidential-secret-long-enough", f.redirect)
	back := f.login(newBrowser(t), r.cfg.AuthCodeURL(r.state, gooidc.Nonce(r.nonce)), alice)
	code := back.Query().Get("code")
	if code == "" {
		t.Fatalf("no code without PKCE for an or_nonce client: %s", back)
	}
	tok, err := r.cfg.Exchange(t.Context(), code)
	if err != nil {
		t.Fatalf("the exchange without a verifier: %v", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := r.provider.Verifier(&gooidc.Config{ClientID: "rp"}).Verify(t.Context(), raw)
	if err != nil || idt.Nonce != r.nonce {
		t.Fatalf("the ID token does not carry the nonce the client must check: %v %q", err, idt.Nonce)
	}
}

func TestWithoutPKCETheNonceIsRequired(t *testing.T) {
	f := orNonce(t)
	r := newRP(t, f, "rp", "a-confidential-secret-long-enough", f.redirect)
	loc, _ := authorizeRefused(t, f, r.cfg.AuthCodeURL(r.state))
	if loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("no PKCE and no nonce: %v", loc)
	}
	// A client left at the default still needs PKCE, nonce or not.
	d := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	loc, _ = authorizeRefused(t, f, d.cfg.AuthCodeURL(d.state, gooidc.Nonce(d.nonce)))
	if loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("a pkce = \"required\" client without PKCE: %v", loc)
	}
}

// RFC 9700 2.1.1: "if there was no code_challenge in the authorization
// request, a request to the token endpoint containing a code_verifier is
// rejected" -- or whoever stripped the challenge would go unnoticed.
func TestAVerifierWithoutAChallengeIsRefused(t *testing.T) {
	f := orNonce(t)
	r := newRP(t, f, "rp", "a-confidential-secret-long-enough", f.redirect)
	back := f.login(newBrowser(t), r.cfg.AuthCodeURL(r.state, gooidc.Nonce(r.nonce)), alice)
	if _, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier)); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("a code_verifier for a request without a challenge: %v", err)
	}
	// And an or_nonce client that DOES send PKCE is held to it.
	back = f.login(newBrowser(t), r.authURL(), alice)
	if _, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil {
		t.Error("a wrong verifier was accepted from an or_nonce client that sent a challenge")
	}
}

func TestOrNonceIsForConfidentialClients(t *testing.T) {
	c := newConf(t)
	for _, extra := range []string{
		"client \"pub\" {\n  redirect_uris = [\"http://127.0.0.1/cb\"]\n  pkce = \"or_nonce\"\n}\n",
		"client \"x\" {\n  redirect_uris = [\"http://127.0.0.1/cb\"]\n  pkce = \"plain\"\n}\n",
	} {
		if _, err := c.load(t, c.hcl(func(s string) string { return s + extra })); err == nil || !strings.Contains(err.Error(), "pkce") {
			t.Errorf("%q: %v", extra, err)
		}
	}
}
