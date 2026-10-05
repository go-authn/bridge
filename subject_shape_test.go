package main

import (
	"testing"
)

// ⛔ A person's sub must not change under them. It is an HMAC of the IdP's
// identifier as go-authn/saml hands it over, so a release of that library
// which qualifies an identifier differently renames people: every relying
// party then sees a new person, and their refresh grants, application
// passwords and disable-by-sub entries stop matching.
//
// go-authn/saml v0.3.0 did exactly that for the shapes below, and bridge
// v0.18.0 took it knowingly (README, "Upgrading to v0.18.0"): the shapes
// pinned here are v0.3.0's. The next change of shape fails here too, rather
// than passing and renaming people again.
func TestASubjectKeepsItsShape(t *testing.T) {
	const opaque = "a1b2c3"
	for _, tc := range []struct {
		name string
		o    func(sp string) assertionOpts
		want func(sp string) string
	}{
		{"an opaque eduPersonTargetedID",
			func(string) assertionOpts { return assertionOpts{eptid: opaque} },
			func(sp string) string { return idpEntity + "!" + idpEntity + "!" + sp + "!" + opaque }},
		{"an eduPersonTargetedID NameID with no NameQualifier",
			func(sp string) assertionOpts {
				return assertionOpts{eptid: `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="` + sp + `">` + opaque + `</saml:NameID>`}
			},
			func(sp string) string { return idpEntity + "!" + idpEntity + "!" + sp + "!" + opaque }},
		{"a persistent NameID with no NameQualifier",
			func(sp string) assertionOpts {
				return assertionOpts{nameID: `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="` + sp + `">` + opaque + `</saml:NameID>`}
			},
			func(sp string) string { return idpEntity + "!" + idpEntity + "!" + sp + "!" + opaque }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			sp := f.s.cfg.SAML.EntityID
			claims := f.accessClaims(t, idpEntity, tc.o(sp))
			var web *clientBlock
			for i := range f.s.cfg.Clients {
				if f.s.cfg.Clients[i].ID == "web" {
					web = &f.s.cfg.Clients[i]
				}
			}
			if web == nil {
				t.Fatal("the fixture has no client web")
			}
			want := (&person{subject: tc.want(sp)}).sub(f.s.cfg.salt, web)
			if claims["sub"] != want {
				t.Errorf("sub is %v, want the HMAC of %q: the identifier changed shape, and this person would be renamed",
					claims["sub"], tc.want(sp))
			}
		})
	}
}
