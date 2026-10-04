// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/saml"
	"golang.org/x/oauth2"
)

const otherIdP = "https://idp.other-univ.fr/idp"

// loginVia is f.login through an IdP of the caller's choosing.
func (f *fixture) loginVia(b *browser, authURL, entity string, o assertionOpts) *url.URL {
	f.t.Helper()
	next := location(f.t, b.get(authURL))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		io.Copy(io.Discard, b.get(next.String()).Body)
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(entity)))
	}
	reqID, relay := authnRequest(f.t, next)
	return location(f.t, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{
		"SAMLResponse": {f.respond(reqID, o)},
		"RelayState":   {relay},
	}))
}

// accessClaims logs in through entity and returns what the access token
// says.
func (f *fixture) accessClaims(t *testing.T, entity string, o assertionOpts) map[string]any {
	t.Helper()
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "eduperson", "groups")
	back := f.loginVia(newBrowser(t), r.authURL(), entity, o)
	tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func strs(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
}

// ⛔ The federation has hundreds of IdPs, and groups decide what a person
// may do: in the access token every resource server reads, in the SSH and
// X.509 certificates. Another university's IdP asserting a group in
// univ-example.fr's namespace must not grant it -- measured before this
// fix, mallory@other-univ.fr came out with univ-example.fr's photo share.
// Its own namespace it keeps.
func TestAGroupIsKeptOnlyFromTheIdPThatOwnsIt(t *testing.T) {
	f := newFixture(t, "")
	other := &party{keyFile: filepath.Join(f.dir, "other-idp.key"), certFile: filepath.Join(f.dir, "other-idp.crt")}
	mallory := assertionOpts{
		eppn:   "mallory@other-univ.fr",
		issuer: otherIdP, signer: other,
		entitlement: []string{
			"urn:mace:univ-example.fr:fileshare:photos",         // not its own
			"urn:geant:univ-example.fr:group:staff",             // not its own
			"urn:geant:other-univ.fr:group:x#login.example.org", // its own namespace; the authority is not one
			"https://univ-example.fr/groups/admins",             // not its own
			"urn:oid:1.2.3",                                     // no namespace at all
			"urn:mace:other-univ.fr:wiki:editors",               // its own
			"https://wiki.other-univ.fr/editors",                // under its own
		},
	}
	c := f.accessClaims(t, otherIdP, mallory)
	want := []string{"https://wiki.other-univ.fr/editors", "urn:geant:other-univ.fr:group:x#login.example.org", "urn:mace:other-univ.fr:wiki:editors"}
	if got := strs(c["groups"]); !slices.Equal(got, want) {
		t.Errorf("groups from other-univ.fr's IdP: %q, want %q", got, want)
	}
	if got := strs(c["entitlements"]); len(got) != 0 && !slices.Equal(got, want) {
		t.Errorf("entitlements carry another IdP's namespace: %q", got)
	}
	if c["idp"] != otherIdP {
		t.Errorf("idp claim %v, want %s: a resource server cannot tell who vouched", c["idp"], otherIdP)
	}

	// The university's own IdP keeps its own values.
	a := alice
	a.entitlement = []string{"urn:mace:univ-example.fr:fileshare:photos"}
	if got := strs(f.accessClaims(t, idpEntity, a)["groups"]); !slices.Equal(got, a.entitlement) {
		t.Errorf("the owning IdP's group was dropped: %q", got)
	}
}

func TestGroupAllowed(t *testing.T) {
	idp := &saml.IdP{EntityID: "https://idp.u.fr/idp", Scopes: []string{"u.fr"}}
	multi := &claimsBlock{TrustedGroups: map[string][]string{idp.EntityID: {"urn:geant:eduteams.org:"}}}
	for _, c := range []struct {
		v    string
		want bool
	}{
		{"urn:mace:u.fr:x", true},
		{"URN:MACE:U.FR:x", true},
		{"urn:mace:sub.u.fr:x", true},
		{"urn:mace:evilu.fr:x", false}, // a suffix, not a subdomain
		{"urn:mace:u.fr.evil.org:x", false},
		{"urn:mace:u.fr", false}, // no separator after the domain
		{"urn:geant:u.fr:group:g#u.fr", true},
		{"urn:geant:u.fr:group:g#login.example.org", true}, // the authority is not a namespace
		{"urn:geant:eduteams.org:group:g", true},           // trusted prefix
		{"urn:geant:eduteams.org.evil:group:g", false},     // the prefix ends with its separator
		{"https://u.fr/g", true},
		{"https://user@u.fr/g", false},
		{"ftp://u.fr/g", false},
		{"staff", false},
		{"", false},
	} {
		if got := multi.groupAllowed(idp, c.v); got != c.want {
			t.Errorf("%q: %v, want %v", c.v, got, c.want)
		}
	}
	if !(&claimsBlock{oneIdP: true}).groupAllowed(idp, "staff") {
		t.Error("with exactly one IdP, its values are not held to a namespace")
	}
}

// affiliation carries no institution: refused unless one IdP is allowed.
func TestUnscopedAffiliationNeedsOneIdP(t *testing.T) {
	c := newConf(t)
	cfg := c.hcl(func(s string) string {
		return strings.Replace(s, "saml {", "claims { groups = [\"affiliation\"] }\nsaml {", 1)
	})
	if _, err := c.load(t, cfg); err == nil || !strings.Contains(err.Error(), "affiliation") {
		t.Errorf("affiliation with any IdP: %v", err)
	}
	one := strings.Replace(cfg, "saml {", "saml {\n  idps = [\"https://idp.univ-example.fr/idp\"]", 1)
	if _, err := c.load(t, one); err != nil {
		t.Errorf("affiliation with one IdP: %v", err)
	}
}
