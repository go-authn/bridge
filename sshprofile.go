// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// A client's SSH certificate profile: which claim names the person, which
// permit-* extensions and source-address it carries, how long it lives, and
// which hosting entities it is meant for. Everything is per client and
// opt-in: a client that sets none of it gets the certificate sshca.go has
// always issued, byte for byte apart from serial, nonce, times and
// signature (TestSSHProfileLeavesTheDefaultAlone).
//
// Together these give the EuroHPC Federation Platform SSH CA's profile
// (https://integration.docs.my-eurohpc.eu/aai/ssh-ca-overview/): Ed25519,
// one hour, ONE principal that is the MyAccessID CUID -- here voperson_id,
// from the SAML subject-id -- and GÉANT's ssh-domain-grant extension naming
// the hosting entity's domain.

// DomainGrantExtension is GÉANT's extension naming the domains a certificate
// is meant for (ssh-cert-tool, docs/ssh-domain-grant-ext.md).
const DomainGrantExtension = "ssh-domain-grant@core.aai.geant.org"

// sshPrincipalClaims are the claims a certificate's principal may come from,
// and the scope that releases each one beyond the access token itself.
var sshPrincipalClaims = map[string]string{
	"preferred_username":       "", // in the access token
	"sub":                      "", // in the access token
	"voperson_id":              "eduperson",
	"eduperson_principal_name": "eduperson",
}

// sshPermits are the extensions a client may grant: OpenSSH's own
// (PROTOCOL.certkeys), each a permission sshd otherwise withholds from a
// certificate login.
//
// Not no-touch-required: it waives the user-presence test of the person's
// OWN security key, which is the person's protection against malware
// signing with it unseen. That is not the provider's to give away for
// everybody of a client, and no profile asked for it.
var sshPermits = []string{
	"permit-X11-forwarding",
	"permit-agent-forwarding",
	"permit-port-forwarding",
	"permit-pty",
	"permit-user-rc",
}

// checkSSHProfile validates the client's ssh_* keys at load, and fixes its
// validity. ca is nil when there is no ssh_ca block.
func (cl *clientBlock) checkSSHProfile(ca *sshCABlock) error {
	if !cl.SSHCertificates {
		if cl.SSHPrincipalClaim != "" || len(cl.SSHExtensions) > 0 || len(cl.SSHSourceAddress) > 0 ||
			cl.SSHValidity != "" || len(cl.SSHDomainGrants) > 0 {
			return errors.New("ssh_principal_claim, ssh_extensions, ssh_source_address, ssh_validity and ssh_domain_grants shape SSH certificates: they need ssh_certificates = true")
		}
		return nil
	}
	if cl.SSHPrincipalClaim == "" {
		cl.SSHPrincipalClaim = "preferred_username"
	}
	if _, ok := sshPrincipalClaims[cl.SSHPrincipalClaim]; !ok {
		return fmt.Errorf("ssh_principal_claim = %q: one of preferred_username, voperson_id, eduperson_principal_name, sub", cl.SSHPrincipalClaim)
	}
	for i, e := range cl.SSHExtensions {
		if !slices.Contains(sshPermits, e) {
			return fmt.Errorf("ssh_extensions: %q is not one of %s", e, strings.Join(sshPermits, ", "))
		}
		if slices.Contains(cl.SSHExtensions[:i], e) {
			return fmt.Errorf("ssh_extensions: %q twice", e)
		}
	}
	for i, a := range cl.SSHSourceAddress {
		canon, err := sourceAddress(a)
		if err != nil {
			return fmt.Errorf("ssh_source_address: %w", err)
		}
		cl.SSHSourceAddress[i] = canon
	}
	cl.sshValidity = ca.validity
	if cl.SSHValidity != "" {
		d, err := time.ParseDuration(cl.SSHValidity)
		if err != nil || d <= 0 {
			return fmt.Errorf("ssh_validity = %q: a positive duration like \"1h\"", cl.SSHValidity)
		}
		if d > ca.validity {
			return fmt.Errorf("ssh_validity = %s: longer than the ssh_ca validity, %s", d, ca.validity)
		}
		cl.sshValidity = d
	}
	for i, g := range cl.SSHDomainGrants {
		if err := domainPattern(g); err != nil {
			return fmt.Errorf("ssh_domain_grants: %w", err)
		}
		if slices.Contains(cl.SSHDomainGrants[:i], g) {
			return fmt.Errorf("ssh_domain_grants: %q twice", g)
		}
	}
	if len(cl.SSHDomainGrants) > 0 {
		// Refused here rather than at the first certificate: a client
		// configured for domain grants must never be handed one without.
		if _, _, err := domainGrantExtension(cl.SSHDomainGrants); err != nil {
			return fmt.Errorf("ssh_domain_grants: %w", err)
		}
	}
	return nil
}

// sourceAddress is one source-address entry, as OpenSSH's
// addr_match_cidr_list reads it: an address or a CIDR prefix, nothing else
// -- no name, no zone, no host bits under the mask -- written canonically.
func sourceAddress(a string) (string, error) {
	if strings.Contains(a, "/") {
		p, err := netip.ParsePrefix(a)
		if err != nil || p.Addr().Zone() != "" {
			return "", fmt.Errorf("%q is not an address or a CIDR prefix", a)
		}
		if p != p.Masked() {
			return "", fmt.Errorf("%q has bits set under its mask: %s?", a, p.Masked())
		}
		return p.String(), nil
	}
	ip, err := netip.ParseAddr(a)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("%q is not an address or a CIDR prefix", a)
	}
	return ip.String(), nil
}

// domainPattern checks one domain pattern of the domain-grant extension, by
// the syntax GÉANT's specification gives: dot-separated labels of letters,
// digits and hyphens, where "*" stands for one or more characters inside a
// label. Lower case, as the hosting entities' domains are compared. A
// pattern must name a domain under a fixed top-level label: "*" or "*.eu"
// alone would grant every host of a federation.
func domainPattern(p string) error {
	if p == "" || len(p) > 253 {
		return fmt.Errorf("%q: a domain pattern of 1 to 253 characters", p)
	}
	labels := strings.Split(p, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q: a domain, with at least two labels", p)
	}
	for i, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%q: an empty label, or one over 63 characters", p)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q: a label starts or ends with a hyphen", p)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '*') {
				return fmt.Errorf("%q: %q is not a lower-case letter, a digit, a hyphen or *", p, r)
			}
		}
		if strings.Contains(l, "**") {
			return fmt.Errorf("%q: ** in a label", p)
		}
		if i >= len(labels)-2 && strings.Contains(l, "*") {
			return fmt.Errorf("%q: a wildcard in the last two labels grants a whole top-level domain", p)
		}
	}
	return nil
}

// errDomainGrantsNotWired is domainGrantExtension before go-authn/sshcert.
var errDomainGrantsNotWired = errors.New("the ssh-domain-grant extension is not available in this build yet (it waits for go-authn/sshcert v0.1.0)")

// domainGrantExtension is the ssh-domain-grant@core.aai.geant.org extension
// for grants: its name, and its value as Certificate.Permissions.Extensions
// holds it (the extension data -- an SSH string around the compact JSON
// array, GÉANT's Appendix B test vectors).
//
// TODO(go-authn/sshcert v0.1.0): the encoding is go-authn/sshcert's, judged
// against GÉANT's test vectors there, and is deliberately NOT written here.
// Once v0.1.0 is tagged, this function becomes:
//
//	return sshcert.DomainGrantExtension, <sshcert's encoder>(grants), err
//
// and errDomainGrantsNotWired goes. Until then every client with
// ssh_domain_grants is refused at load (checkSSHProfile), so no certificate
// is ever issued without the grant its configuration asked for.
func domainGrantExtension(grants []string) (name, value string, err error) {
	_ = grants
	return DomainGrantExtension, "", errDomainGrantsNotWired
}

// sshPrincipal is the one principal the client's certificates name: the
// claim ssh_principal_claim says, from the access token, or from what the
// token's scopes released (the issued token's info) for the eduperson ones.
// An error is a 403 to give the caller.
func sshPrincipal(cl *clientBlock, claims map[string]any, it issuedToken) (string, error) {
	claim := cl.SSHPrincipalClaim
	if claim == "" {
		claim = "preferred_username"
	}
	var v string
	switch scope := sshPrincipalClaims[claim]; scope {
	case "":
		v, _ = claims[claim].(string)
	default:
		granted, _ := claims["scope"].(string)
		if !slices.Contains(strings.Fields(granted), scope) {
			return "", fmt.Errorf("this client's certificates name the person by %s, which the %q scope releases: the token was not granted it", claim, scope)
		}
		v, _ = it.info[claim].(string)
	}
	if v == "" {
		if claim == "preferred_username" {
			return "", errors.New("the institution released no username to put in a certificate")
		}
		return "", fmt.Errorf("the institution released no %s to put in a certificate", claim)
	}
	return v, nil
}

// sshPermissions are the certificate's critical options and extensions: the
// groups (sshca.go), then what the client's profile adds. Nil maps when
// there is nothing, as a default client's certificate has always had.
func sshPermissions(cl *clientBlock, groups []string) (ssh.Permissions, error) {
	var p ssh.Permissions
	ext := map[string]string{}
	if len(groups) > 0 {
		ext[GroupsExtension] = strings.Join(groups, "\n")
	}
	for _, e := range cl.SSHExtensions {
		ext[e] = ""
	}
	if len(cl.SSHDomainGrants) > 0 {
		name, value, err := domainGrantExtension(cl.SSHDomainGrants)
		if err != nil {
			return p, err
		}
		ext[name] = value
	}
	if len(ext) > 0 {
		p.Extensions = ext
	}
	if len(cl.SSHSourceAddress) > 0 {
		p.CriticalOptions = map[string]string{"source-address": strings.Join(cl.SSHSourceAddress, ",")}
	}
	return p, nil
}

// sshConfig is GET /ssh/config: the CA's public key in the EuroHPC
// Federation Platform's shape, {"PublicKey":"ssh-ed25519 AAAA..."}, so that
// a site's documented
//
//	curl -s https://<issuer>/ssh/config | jq -r '.PublicKey' > ca.pub
//
// writes the TrustedUserCAKeys line unchanged. The key alone, no comment,
// as EFP's own is published.
func (s *server) sshConfig(w http.ResponseWriter, r *http.Request) {
	ca := s.cfg.SSHCA
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())))
	body, err := json.Marshal(struct{ PublicKey string }{line})
	if err != nil {
		http.Error(w, "the CA key could not be written", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Write(append(body, '\n'))
}
