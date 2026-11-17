// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// deviceLocal is a whole device-grant login with a local account.
func (f *fixture) deviceLocal(client, login, pw string, scopes ...string) *oauth2.Token {
	f.t.Helper()
	b, cfg, da, next := f.deviceStart(client, scopes...)
	if next.Path != "/login" {
		f.t.Fatalf("a device login was sent to %s, not to the choice of how to log in", next)
	}
	b.get(next.String())
	csrf := f.localForm(b)
	if res := f.postLocal(b, csrf, login, pw); res.StatusCode != http.StatusOK {
		f.t.Fatalf("the device's local login: status %d: %s", res.StatusCode, readBody(res))
	}
	tok, err := cfg.DeviceAccessToken(f.t.Context(), da)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// refreshed rotates a refresh token and returns the new one. The control for a
// refusal: the token tried after a change must be a LIVE one, or the refusal
// would be the rotation's (reuse revokes the family), not the change's.
func (f *fixture) refreshed(tok *oauth2.Token) (*oauth2.Token, error) {
	ep, _ := endpoints(f.t.Context(), f.s.cfg.Issuer)
	cfg := &oauth2.Config{ClientID: "files", Endpoint: ep}
	return cfg.TokenSource(f.t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
}

const localClients = `
client "files" {
  device           = true
  refresh_lifetime = "720h"
  redirect_uris    = ["http://127.0.0.1/cb"]
}
`

// The invariant of #87: every grant is held to its identity source NOW. Local
// accounts are one, so removing the block refuses every grant they bought --
// refresh, device, and a code not yet exchanged -- here with `idps` empty,
// where the SAML rule alone is true of every string.
func TestLocalGrantsRefusedAfterLocalBlockRemovedFromConfig(t *testing.T) {
	f, _, _, _ := adminFixture(t, localExtra(t)+localClients)
	tok := f.deviceLocal("files", "alice", localPW, "openid")
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	tok, err := f.refreshed(tok)
	if err != nil || tok.RefreshToken == "" {
		t.Fatalf("setup: the local grant does not refresh while the block is there: %v", err)
	}
	if len(f.s.cfg.SAML.IdPs) != 0 {
		t.Fatal("setup: idps is not empty")
	}

	// A code bought and not yet exchanged.
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	code := location(t, f.postLocal(b, csrf, "alice", localPW)).Query().Get("code")

	f.s.cfg.Local = nil
	if configuredIdP(f.s.cfg, f.s.cfg.Issuer+"/local") {
		t.Fatal("the local entity ID is configured with no local block")
	}
	if why := f.s.refused(&person{username: "alice", idp: f.s.cfg.Issuer + "/local"}); why == "" {
		t.Error("refused() lets a local person through without the block")
	}
	if _, err := f.refreshed(tok); err == nil {
		t.Error("a live refresh token bought with a local account still refreshes after the local block was removed")
	}
	if _, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier)); err == nil {
		t.Error("an authorization code bought with a local account still exchanges after the local block was removed")
	}
	// And the forms are gone with the block.
	if res := newBrowser(t).get(f.s.cfg.Issuer + "/local/login"); res.StatusCode != http.StatusNotFound {
		t.Errorf("/local/login without a block: status %d", res.StatusCode)
	}
}

// And the account itself: delete it from the file and what it bought stops.
func TestLocalGrantsRefusedAfterAccountRemovedFromFile(t *testing.T) {
	f, _, _, _ := adminFixture(t, localExtra(t)+localClients)
	tok := f.deviceLocal("files", "bob", localPW, "openid")
	tok, err := f.refreshed(tok)
	if err != nil {
		t.Fatalf("setup: no refresh: %v", err)
	}
	text := strings.Replace(localAccountsText(), "account \"bob\"", "account \"robert\"", 1)
	if err := os.WriteFile(f.s.cfg.Local.AccountsFile, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	if _, err := f.refreshed(tok); err == nil {
		t.Error("bob's live refresh token works after bob was removed from the accounts file")
	}
}
