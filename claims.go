// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/saml"
)

var usernameAttributes = map[string]string{
	"eppn":       saml.EduPersonPrincipalName,
	"subject_id": saml.SubjectID,
	"uid":        saml.UID,
	"mail":       saml.Mail,
}

var groupAttributes = map[string]string{
	"entitlement":        saml.EduPersonEntitlement,
	"scoped_affiliation": saml.EduPersonScopedAffiliation,
	"affiliation":        saml.EduPersonAffiliation,
	"is_member_of":       saml.IsMemberOf,
}

// person is somebody the federation vouched for, as this provider will
// describe them.
type person struct {
	// subject is the IdP's persistent identifier for them, qualified by the
	// IdP, and never shown to anybody: sub is derived from it.
	subject string
	// idp is the entity ID of who vouched.
	idp string

	username string
	groups   []string

	authTime time.Time
	acr      string
	// sessionEnd is when the IdP's session ends, if it said.
	sessionEnd time.Time

	// claims are the profile claims, by scope.
	profile map[string]any // scope "profile"
	email   map[string]any // scope "email"
	edu     map[string]any // scope "eduperson"
}

// errNoIdentifier is an IdP that released nothing persistent: the person
// cannot be recognised twice, so there is nothing to call "sub".
var errNoIdentifier = errors.New("the identity provider released no persistent identifier (subject-id, pairwise-id, eppn, eduPersonTargetedID or a persistent NameID)")

// newPerson maps an assertion to claims, the way the configuration says.
//
// Claim names follow OIDC Core 5.1 for the profile and AARC-G056 for the
// research-and-education ones (snake_case: eduperson_principal_name,
// eduperson_scoped_affiliation, eduperson_entitlement,
// schac_home_organization, voperson_id), with "entitlements" as RFC 9068 and
// AARC-G069 name the groups-and-roles claim.
func newPerson(a *saml.Assertion, c *claimsBlock) (*person, error) {
	id, _ := a.Subject()
	if id == "" {
		return nil, errNoIdentifier
	}
	p := &person{
		subject:    a.IdP.EntityID + "!" + id,
		idp:        a.IdP.EntityID,
		authTime:   a.AuthnInstant,
		acr:        a.AuthnContext,
		sessionEnd: a.SessionNotOnOrAfter,
		profile:    map[string]any{},
		email:      map[string]any{},
		edu:        map[string]any{},
	}
	p.username = a.First(usernameAttributes[c.Username])
	if c.Username == "subject_id" {
		p.username = strings.ToLower(p.username)
	}
	for _, g := range c.Groups {
		for _, v := range a.Attributes[groupAttributes[g]] {
			if g == "scoped_affiliation" || c.groupAllowed(a.IdP, v) {
				p.groups = append(p.groups, v)
			}
		}
	}
	slices.Sort(p.groups)
	p.groups = slices.Compact(p.groups)

	set := func(m map[string]any, claim, attr string) {
		if v := a.First(attr); v != "" {
			m[claim] = v
		}
	}
	setAll := func(m map[string]any, claim, attr string) {
		if v := a.Attributes[attr]; len(v) > 0 {
			m[claim] = v
		}
	}
	set(p.profile, "name", saml.DisplayName)
	if _, ok := p.profile["name"]; !ok {
		set(p.profile, "name", saml.CommonName)
	}
	set(p.profile, "given_name", saml.GivenName)
	set(p.profile, "family_name", saml.Surname)
	if p.username != "" {
		p.profile["preferred_username"] = p.username
	}
	// ⛔ No email_verified. The IdP asserted an address, which is not the
	// same thing as anybody having verified that the person reads it, and a
	// relying party that trusts email_verified to link accounts would be
	// trusting a claim nobody made.
	set(p.email, "email", saml.Mail)

	set(p.edu, "eduperson_principal_name", saml.EduPersonPrincipalName)
	setAll(p.edu, "eduperson_scoped_affiliation", saml.EduPersonScopedAffiliation)
	// Entitlements are authorization data (RFC 9068 2.2.3.1, AARC-G069), held
	// to the asserting IdP's namespaces as the groups claim is.
	var ents []string
	for _, v := range a.Attributes[saml.EduPersonEntitlement] {
		if c.groupAllowed(a.IdP, v) {
			ents = append(ents, v)
		}
	}
	if len(ents) > 0 {
		p.edu["eduperson_entitlement"] = ents
		p.edu["entitlements"] = ents
	}
	setAll(p.edu, "eduperson_assurance", saml.EduPersonAssurance)
	set(p.edu, "eduperson_orcid", saml.EduPersonOrcid)
	set(p.edu, "schac_home_organization", saml.SchacHomeOrganization)
	if v := a.First(saml.SubjectID); v != "" {
		p.edu["voperson_id"] = strings.ToLower(v)
	}
	return p, nil
}

// sub is what this person is called for one client (OIDC Core 8).
//
// Public: the same for every client, derived from the IdP's identifier and
// the salt -- stable, not reversible, and not the raw identifier, which may
// be an address. Pairwise: the same, keyed also by the client, so that two
// clients cannot tell they are looking at one person (8.1). Both are HMACs
// under the salt, so the salt is what must never change.
func (p *person) sub(salt []byte, c *clientBlock) string {
	m := hmac.New(sha256.New, salt)
	if c.Subject == "pairwise" {
		m.Write([]byte("pairwise\x00" + c.ID + "\x00"))
	} else {
		m.Write([]byte("public\x00"))
	}
	m.Write([]byte(p.subject))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// claimsFor are the claims a scope list releases.
func (p *person) claimsFor(scopes []string) map[string]any {
	out := map[string]any{}
	for _, s := range scopes {
		var m map[string]any
		switch s {
		case "profile":
			m = p.profile
		case "email":
			m = p.email
		case "eduperson":
			m = p.edu
		case "groups":
			if len(p.groups) > 0 {
				out["groups"] = p.groups
			}
		}
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// scopedUsername is the username attributes go-authn/saml holds to the
// scopes the federation grants each IdP: a login in one of them was
// vouched for by an IdP that holds the scope.
var scopedUsername = map[string]bool{"eppn": true, "subject_id": true}

// groupAllowed says whether idp may assert v, a group or entitlement value.
//
// With exactly one IdP allowed to log in, it may assert anything. With more,
// a value is kept only if its namespace is one the asserting IdP owns: one
// of its shibmd scopes or a subdomain of one, which is what the federation
// vouches for. The namespace of
//
//	urn:mace:<domain>:...                     (the MACE URN registry)
//	urn:geant:<domain>:...[#<authority>]      (AARC-G002)
//	https://<host>/...
//
// is the domain; any other value has none, and is dropped. The AARC-G002
// authority is not a namespace: it names the system that manages the group,
// and a value under another namespace never equals one of this IdP's anyway. TrustedGroups
// widens an IdP's namespaces by prefix.
func (c *claimsBlock) groupAllowed(idp *saml.IdP, v string) bool {
	if c.oneIdP {
		return true
	}
	for _, p := range c.TrustedGroups[idp.EntityID] {
		if p != "" && strings.HasPrefix(v, p) {
			return true
		}
	}
	domains := groupDomains(v)
	if len(domains) == 0 {
		return false
	}
	for _, d := range domains {
		if !ownsDomain(idp.Scopes, d) {
			return false
		}
	}
	return true
}

// groupDomains are the domains a group value is issued under; nil when it
// names none.
func groupDomains(v string) []string {
	lv := strings.ToLower(v)
	for _, nid := range []string{"urn:mace:", "urn:geant:"} {
		if !strings.HasPrefix(lv, nid) {
			continue
		}
		rest := lv[len(nid):]
		i := strings.IndexAny(rest, ":#")
		if i <= 0 {
			return nil
		}
		return []string{rest[:i]}
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Hostname() == "" {
		return nil
	}
	return []string{strings.ToLower(u.Hostname())}
}

// ownsDomain says whether d is one of scopes or under one.
func ownsDomain(scopes []string, d string) bool {
	if d == "" {
		return false
	}
	for _, s := range scopes {
		s = strings.ToLower(s)
		if s != "" && (d == s || strings.HasSuffix(d, "."+s)) {
			return true
		}
	}
	return false
}
