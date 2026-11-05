// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"testing"

	"golang.org/x/oauth2"
)

// Security audit 2026-11-05 (untracked proof). The ACS refuses a login whose
// IdP was removed from saml { idps } while it was at the IdP (acs.go:45,
// TestASealedLoginIsHeldToTheConfigurationNow). A refresh token bought
// through that IdP keeps rotating after the removal: rotate -> issue ->
// refused() never asks configuredIdP.
func TestSecAuditRefreshAfterIdPRemovedFromConfig(t *testing.T) {
	f, _, _, _ := adminFixture(t, `
client "files" {
  device           = true
  refresh_lifetime = "720h"
}
`)
	tok := f.deviceToken("files", "openid")
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	f.s.cfg.SAML.IdPs = []string{"https://another-idp.example/idp"}
	if f.s.allowedIdP(idpEntity) {
		t.Fatal("setup: the IdP is still allowed")
	}
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	cfg := &oauth2.Config{ClientID: "files", Endpoint: ep}
	if nt, err := cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
		t.Errorf("a refresh token from an IdP no longer allowed still refreshes: new access token %d bytes", len(nt.AccessToken))
	}
}
