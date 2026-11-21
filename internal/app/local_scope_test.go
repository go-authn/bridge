// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// A local scope equal to a federated IdP's scope must never let a federated
// person and a local account of the same login be one Kerberos principal (or
// eduperson_principal_name, hence SSH principal).
func localScopeFixture(t *testing.T) (*fixture, *stubKDC) {
	t.Helper()
	dir := t.TempDir()
	k, kdcURL := newStubKDC(t, dir)
	local := fmt.Sprintf("local {\n  accounts_file = %q\n  scope = %q\n  passkey_removal_delay = \"0\"\n}\n",
		filepath.ToSlash(writeAccountsFile(t, "account \"alice\" {\n  name = \"Another Alice\"\n}\n")), idpScope) + stateExtra(t)
	return newFixture(t, local+`
kerberos {
  kdc_url   = "`+kdcURL+`"
  ca_file   = "`+filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem"))+`"
  cert_file = "`+filepath.ToSlash(filepath.Join(dir, "bridge.pem"))+`"
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "bridge.key"))+`"
}
client "kinit" {
  redirect_uris    = ["http://127.0.0.1/callback"]
  kerberos_tickets = true
}
`), k
}

func TestFederatedNameInTheLocalScopeIsRefusedAndLocalKeepsItsPrincipal(t *testing.T) {
	f, k := localScopeFixture(t)
	// The local account "alice": a passkey, no relation to the university.
	a := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "kinit", "", "http://127.0.0.1/callback", "kerberos")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.passkeyLogin(b, a, "alice", csrf, webauthntest.Options{}))
	localTok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	// The university's alice, through SAML: her name is in the local scope.
	r2 := newRP(t, f, "kinit", "", "http://127.0.0.1/callback", "kerberos")
	b2 := newBrowser(t)
	if next := location(t, b2.get(r2.authURL())); next.Path != "/login" {
		t.Fatalf("sent to %s", next)
	}
	next := location(t, b2.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	reqID, relay := authnRequest(t, next)
	back2 := location(t, b2.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}}))
	if back2.Query().Get("code") != "" || back2.Query().Get("error") != "access_denied" {
		t.Fatalf("a federated name in the local scope was given a code: %s", back2)
	}
	// The local account still gets its own ticket.
	if st, body, _ := postTGT(t, f, localTok.AccessToken); st != http.StatusOK {
		t.Fatalf("TGT: %d %s", st, body)
	}
	if len(k.asked) != 1 || k.asked[0]["principal"] != "alice@"+idpScope {
		t.Fatalf("the KDC was asked %v", k.asked)
	}
}

// A federated token that exists anyway (a refresh grant minted before the
// local scope was set, a metadata scope that changed) gets no principal.
func TestKerberosPrincipalRefusesAFederatedNameInTheLocalScope(t *testing.T) {
	f, _ := localScopeFixture(t)
	fed := map[string]any{"idp": idpEntity, "preferred_username": "alice@" + idpScope}
	if p := f.s.kerberosPrincipal(fed); p != "" {
		t.Errorf("federated alice@%s was given the principal %q", idpScope, p)
	}
	fed["preferred_username"] = "alice@" + "OTHER.example"
	if p := f.s.kerberosPrincipal(fed); p != "alice@OTHER.example" {
		t.Errorf("a federated name outside the local scope: %q", p)
	}
	local := map[string]any{"idp": f.s.cfg.localEntityID(), "preferred_username": "alice"}
	if p := f.s.kerberosPrincipal(local); p != "alice@"+idpScope {
		t.Errorf("the local account's principal: %q", p)
	}
}

func TestInLocalScope(t *testing.T) {
	for _, c := range []struct {
		scope, v string
		want     bool
	}{
		{"u.example", "alice@u.example", true},
		{"u.example", "alice@U.EXAMPLE", true},
		{"u.example", "alice@sub.u.example", false},
		{"u.example", "alice@other.example", false},
		{"u.example", "alice", false},
		{"u.example", "", false},
		{"", "alice@u.example", false},
	} {
		if got := inLocalScope(c.scope, c.v); got != c.want {
			t.Errorf("inLocalScope(%q, %q) = %v", c.scope, c.v, got)
		}
	}
}

// The scope of a usable IdP's metadata that is the local scope is reported by
// check ahead of the first login.
func TestLocalScopeClashNamesTheIdP(t *testing.T) {
	f, _ := localScopeFixture(t)
	if err := f.s.localScopeClash(); err == nil {
		t.Error("the IdP's scope is the local scope and nothing said so")
	}
	f.s.cfg.Local.Scope = "another-scope.example"
	if err := f.s.localScopeClash(); err != nil {
		t.Errorf("no clash: %v", err)
	}
}
