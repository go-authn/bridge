// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Third-party audit 2026-11-07 (HIGH in the chain): the bridge copied
// schacHomeOrganization as the IdP asserted it, so an IdP of one institution
// could state another's, and a relying party that filters on schac_home_
// organization (the gateway's accept) admitted it as that institution. go-authn/
// saml v0.6.0 drops a schacHomeOrganization that is not one of the IdP's
// shibmd:Scope values; this is the bridge end to end.
func TestSchacHomeOrganizationReleasedOnlyWhenItIsTheIdPsScope(t *testing.T) {
	for _, tc := range []struct {
		name, schac string
		released    bool
	}{
		{"the IdP's own scope", idpScope, true},
		{"another institution's", "univ-other.example", false},
		{"the IdP's scope in capitals", "UNIV-EX.EXAMPLE", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
			a := alice
			a.schac = tc.schac
			back := f.login(newBrowser(t), r.authURL(), a)
			tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
			if err != nil {
				t.Fatal(err)
			}
			ui, err := r.provider.UserInfo(t.Context(), oauth2.StaticTokenSource(tok))
			if err != nil {
				t.Fatal(err)
			}
			var uc map[string]any
			if err := ui.Claims(&uc); err != nil {
				t.Fatal(err)
			}
			got, has := uc["schac_home_organization"]
			if has != tc.released || (has && got != tc.schac) {
				t.Errorf("schac_home_organization = %v (present %v), released = %v want %v", got, has, has, tc.released)
			}
		})
	}
	_ = gooidc.ScopeOpenID
}
