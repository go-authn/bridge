// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

// The sections of "Mon compte" that are not passkeys: identity, application
// sessions, technical access, and the confirmation through an institution.

var (
	openHandleField = regexp.MustCompile(`name="h" value="([^"]+)"`)
	appsRevokeArg   = regexp.MustCompile(`data-post="account/apps/revoke" data-json="(\{&#34;id&#34;[^"]*)"`)
)

// openAccount is the POST that turns an institution's handle into the cookie.
func (f *fixture) openAccount(h string, hdr ...string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/account/open", strings.NewReader(url.Values{"h": {h}}.Encode()))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := newBrowser(f.t).c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

// federatedConfirm walks a browser from /account/federation to the ACS with an
// answer made by o, and returns the browser and the ACS's response.
func (f *fixture) federatedConfirm(o assertionOpts) (*browser, *http.Response) {
	f.t.Helper()
	b := newBrowser(f.t)
	next := location(f.t, b.get(f.s.cfg.Issuer+"/account/federation"))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	}
	if next.Host != idpScope {
		f.t.Fatalf("sent to %s, not to the IdP", next)
	}
	if !forceAuthn(f.t, next) {
		f.t.Fatal("the confirmation did not ask the institution to authenticate the person again (no ForceAuthn)")
	}
	id, relay := authnRequest(f.t, next)
	return b, b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(id, o)}, "RelayState": {relay}})
}

// federatedSession is a whole confirmation through the institution.
func (f *fixture) federatedSession(o assertionOpts) *accountSess {
	f.t.Helper()
	_, res := f.federatedConfirm(o)
	body := readBody(res)
	m := openHandleField.FindStringSubmatch(body)
	if res.StatusCode != http.StatusOK || m == nil {
		f.t.Fatalf("the ACS after a confirmation: %d\n%s", res.StatusCode, body)
	}
	op := f.openAccount(m[1], "Origin", "null", "Sec-Fetch-Site", "same-origin")
	readBody(op)
	c := accountCookieOf(op)
	if op.StatusCode != http.StatusSeeOther || c == "" || op.Header.Get("Location") != f.s.cfg.Issuer+"/account" {
		f.t.Fatalf("opening the session: %d, cookie %q, to %q", op.StatusCode, c, op.Header.Get("Location"))
	}
	return &accountSess{cookie: c, csrf: f.accountPageCSRF(c)}
}

func (f *fixture) acctPost(s *accountSess, path string, body map[string]any, hdr ...string) (int, string) {
	f.t.Helper()
	b := map[string]any{"csrf": s.csrf}
	for k, v := range body {
		b[k] = v
	}
	res := f.accountReq("POST", path, s.cookie, b, hdr...)
	return res.StatusCode, readBody(res)
}

func TestAccountIdentityIsReadOnlyExceptTheLocalName(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")

	_, page := f.accountPage(s.cookie)
	page = html.UnescapeString(page)
	for _, want := range []string{"alice", "Alice Martin", "alice@mesocentre.example", localGroup, "Compte local", "l'administrateur du service", `id="name"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the identity section lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `id="mail"`) || strings.Contains(page, `name="mail"`) {
		t.Error("the page has a field for the mail")
	}

	// Mail and groups are refused, by name, saying who changes them, and
	// change nothing.
	for name, body := range map[string]map[string]any{
		"mail":   {"mail": "mallory@evil.example"},
		"groups": {"groups": []string{"urn:geant:mesocentre.example:hpc:admins"}},
		"both":   {"name": "Mallory", "mail": "mallory@evil.example"},
	} {
		f.resetThrottle()
		st, msg := f.acctPost(s, "/account/profile", body)
		if st != http.StatusForbidden || !strings.Contains(msg, "administrator") {
			t.Errorf("editing %s: %d %q, want 403 naming the administrator", name, st, msg)
		}
	}
	if n, ok := f.s.displayNameOf("alice"); ok {
		t.Errorf("a refused edit stored a name: %q", n)
	}
	if _, page := f.accountPage(s.cookie); !strings.Contains(page, "alice@mesocentre.example") || strings.Contains(page, "mallory") {
		t.Error("the mail on the page changed")
	}

	// The display name is the one thing that is theirs, and what they chose is
	// what the next sign-in describes them as.
	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/profile", map[string]any{"name": "  Alice M.  "}); st != http.StatusOK {
		t.Fatalf("setting the name: %d %s", st, msg)
	}
	if n, ok := f.s.displayNameOf("alice"); !ok || n != "Alice M." {
		t.Errorf("stored name %q %v", n, ok)
	}
	acct, _ := f.s.cfg.Local.store.get("alice")
	recs, _ := f.s.passkeys.passkeys("alice")
	if got := f.s.localPerson(acct, recs[0]).profile["name"]; got != "Alice M." {
		t.Errorf("the next login names her %q", got)
	}
	if _, page := f.accountPage(s.cookie); !strings.Contains(page, "Alice M.") {
		t.Error("the page does not show the new name")
	}
	// Control: bob, who set nothing, keeps the file's.
	bobAcct, _ := f.s.cfg.Local.store.get("bob")
	if got := f.s.localPerson(bobAcct, &passkeyRecord{Login: "bob"}).profile["name"]; got != "Bob Durand" {
		t.Errorf("bob is named %q", got)
	}
	for name, v := range map[string]string{"empty": "  ", "too long": strings.Repeat("x", maxNameLen+1), "a control character": "Al\x00ice"} {
		f.resetThrottle()
		if st, _ := f.acctPost(s, "/account/profile", map[string]any{"name": v}); st != http.StatusBadRequest {
			t.Errorf("a name that is %s: %d, want 400", name, st)
		}
	}
	if st, _ := f.acctPost(s, "/account/profile", map[string]any{}); st != http.StatusBadRequest {
		t.Errorf("an empty edit: %d, want 400", st)
	}
}

func TestAccountApplicationsAreListedAndRevoked(t *testing.T) {
	f, _, _, _ := adminFixture(t, localExtra(t)+localClients)
	laptop := f.enrolled("alice", webauthn.AlgES256)
	phone := f.enrolled("alice", webauthn.AlgEdDSA)
	bob := f.enrolled("bob", webauthn.AlgES256)

	laptopTok, err := f.refreshed(f.deviceLocal("files", "alice", laptop, "openid"))
	if err != nil {
		t.Fatal(err)
	}
	phoneTok, err := f.refreshed(f.deviceLocal("files", "alice", phone, "openid"))
	if err != nil {
		t.Fatal(err)
	}
	bobTok, err := f.refreshed(f.deviceLocal("files", "bob", bob, "openid"))
	if err != nil {
		t.Fatal(err)
	}
	family := func(rt string) string {
		g, ok := f.s.refresh.get(hashToken(rt))
		if !ok {
			t.Fatal("no such refresh token")
		}
		return familyID(g.family)
	}

	f.resetThrottle()
	s := f.signedIn(phone, "alice")
	_, page := f.accountPage(s.cookie)
	args := appsRevokeArg.FindAllStringSubmatch(page, -1)
	if len(args) != 2 || strings.Contains(page, familyID("x")) {
		t.Fatalf("alice's applications: %d rows, want 2 (and none of bob's):\n%s", len(args), page)
	}
	for _, a := range args {
		if strings.Contains(html.UnescapeString(a[1]), "refresh") {
			t.Error("a row carries something of the token")
		}
	}
	if strings.Count(page, "files") < 2 || !strings.Contains(page, "jamais renouvelée") && !strings.Contains(page, "dernière utilisation") {
		t.Errorf("the rows do not name the client or when:\n%s", page)
	}
	if strings.Contains(page, family(bobTok.RefreshToken)) {
		t.Error("bob's session is on alice's page")
	}

	// Another person's session, and one that does not exist, are not hers.
	for _, id := range []string{family(bobTok.RefreshToken), "0123456789abcdef", ""} {
		f.resetThrottle()
		if st, _ := f.acctPost(s, "/account/apps/revoke", map[string]any{"id": id}); st != http.StatusNotFound {
			t.Errorf("revoking %q: %d, want 404", id, st)
		}
	}
	// (The new token is kept: a rotated one used again would revoke its family.)
	if bobTok, err = f.refreshed(bobTok); err != nil {
		t.Fatalf("control: refusing alice a revocation ended bob's grant: %v", err)
	}

	// Revoke the laptop's: its refresh token fails, the phone's still works.
	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/apps/revoke", map[string]any{"id": family(laptopTok.RefreshToken)}); st != http.StatusOK {
		t.Fatalf("revoking: %d %s", st, msg)
	}
	if _, err := f.refreshed(laptopTok); err == nil {
		t.Error("a refresh token of a session revoked from the account page still refreshes")
	}
	phoneTok, err = f.refreshed(phoneTok)
	if err != nil {
		t.Errorf("control: revoking the laptop's session ended the phone's: %v", err)
	}
	if _, page := f.accountPage(s.cookie); len(appsRevokeArg.FindAllStringSubmatch(page, -1)) != 1 || !strings.Contains(page, "dernière utilisation") {
		t.Errorf("after one revocation and one renewal:\n%s", page)
	}

	// All of them: hers only.
	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/apps/revoke", map[string]any{"all": true}); st != http.StatusOK {
		t.Fatalf("revoking all: %d %s", st, msg)
	}
	if _, err := f.refreshed(phoneTok); err == nil {
		t.Error("a refresh token still works after \"revoke all\"")
	}
	if _, err := f.refreshed(bobTok); err != nil {
		t.Errorf("control: \"revoke all\" ended bob's grant: %v", err)
	}
	// The confirmation itself is not an application session.
	if status, page := f.accountPage(s.cookie); status != http.StatusOK || !strings.Contains(page, "data-post") {
		t.Error("revoking applications ended the confirmation")
	}
}

func TestAccountTechnicalAccess(t *testing.T) {
	dir := t.TempDir()
	f := localFixture(t, fmt.Sprintf("certificates_file = %q\n", filepath.ToSlash(filepath.Join(dir, "certs.json"))))
	idp := f.s.cfg.localEntityID()
	now := time.Now()
	for _, c := range []issuedCert{
		{Kind: "ssh", Serial: "111", KeyID: "alice-laptop", Principal: "alice", IdP: idp, NotAfter: now.Add(time.Hour)},
		{Kind: "wireguard", Serial: "wgkeyalice", KeyID: "alice-wg", Principal: "alice", IdP: idp, NotAfter: now.Add(time.Hour)},
		{Kind: "ssh", Serial: "222", KeyID: "bob-laptop", Principal: "bob", IdP: idp, NotAfter: now.Add(time.Hour)},
		{Kind: "ssh", Serial: "333", KeyID: "alice-expired", Principal: "alice", IdP: idp, NotAfter: now.Add(-time.Hour)},
	} {
		if err := f.s.certs.add(c, now); err != nil {
			t.Fatal(err)
		}
	}
	alice := f.enrolled("alice", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")

	_, page := f.accountPage(s.cookie)
	page = html.UnescapeString(page)
	for _, want := range []string{"alice-laptop", "alice-wg"} {
		if !strings.Contains(page, want) {
			t.Errorf("the technical access lacks %q:\n%s", want, page)
		}
	}
	for _, not := range []string{"bob-laptop", "alice-expired"} {
		if strings.Contains(page, not) {
			t.Errorf("the technical access shows %q", not)
		}
	}

	revoked := func(serial string) bool {
		for _, c := range f.s.certs.Certs {
			if c.Serial == serial {
				return !c.Revoked.IsZero()
			}
		}
		t.Fatalf("no certificate %s", serial)
		return false
	}
	// Somebody else's, an expired one, one of another kind: not hers.
	for name, body := range map[string]map[string]any{
		"bob's certificate":      {"kind": "ssh", "id": "222"},
		"a wrong kind":           {"kind": "wireguard", "id": "111"},
		"an expired certificate": {"kind": "ssh", "id": "333"},
		"an unknown one":         {"kind": "ssh", "id": "999"},
		"an unknown kind":        {"kind": "nfs", "id": "111"},
	} {
		f.resetThrottle()
		if st, _ := f.acctPost(s, "/account/access/revoke", body); st != http.StatusNotFound {
			t.Errorf("revoking %s: %d, want 404", name, st)
		}
	}
	if revoked("222") || revoked("111") || revoked("wgkeyalice") {
		t.Error("a refused revocation revoked something")
	}
	v0 := f.s.certs.Version

	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/access/revoke", map[string]any{"kind": "ssh", "id": "111"}); st != http.StatusOK {
		t.Fatalf("revoking her SSH certificate: %d %s", st, msg)
	}
	if !revoked("111") || revoked("222") || revoked("wgkeyalice") || f.s.certs.Version != v0+1 {
		t.Error("revoking one SSH certificate: it is not the only one revoked, or the KRL version did not move")
	}
	if st, _ := f.acctPost(s, "/account/access/revoke", map[string]any{"kind": "wireguard", "id": "wgkeyalice"}); st != http.StatusOK || !revoked("wgkeyalice") {
		t.Errorf("revoking her WireGuard key: %d", st)
	}
	// Application passwords no longer exist: the kind is an unknown one.
	f.resetThrottle()
	if st, _ := f.acctPost(s, "/account/access/revoke", map[string]any{"kind": "app_password", "id": "-"}); st != http.StatusNotFound {
		t.Errorf("revoking an application password: %d, want 404", st)
	}
	if _, page := f.accountPage(s.cookie); strings.Contains(page, "alice-laptop") || strings.Contains(page, "alice-wg") {
		t.Error("what was revoked is still listed")
	}
}

func TestAccountThroughTheInstitution(t *testing.T) {
	// No local block: the page is every person's, whatever the deployment.
	f := newFixture(t, localClients+fmt.Sprintf("disabled_file = %q\n", filepath.ToSlash(filepath.Join(t.TempDir(), "disabled.json"))))

	// An institution that ignores ForceAuthn and answers with a session ten
	// minutes old does not open the page.
	stale := alice
	stale.authnAt = time.Now().Add(-10 * time.Minute)
	_, res := f.federatedConfirm(stale)
	body := readBody(res)
	if res.StatusCode < 400 || openHandleField.MatchString(body) || accountCookieOf(res) != "" {
		t.Errorf("an authentication ten minutes old: %d\n%s", res.StatusCode, body)
	}
	// An authentication that has not happened yet, past the skew.
	future := alice
	future.authnAt = time.Now().Add(time.Hour)
	if _, res := f.federatedConfirm(future); res.StatusCode < 400 {
		t.Errorf("an authentication an hour ahead: %d", res.StatusCode)
	}
	// An institution that declines.
	declined := alice
	declined.status = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	if _, res := f.federatedConfirm(declined); res.StatusCode < 400 {
		t.Errorf("a declined authentication: %d", res.StatusCode)
	}

	// The handle: one use, from this origin, by POST.
	_, res = f.federatedConfirm(alice)
	h := openHandleField.FindStringSubmatch(readBody(res))
	if res.StatusCode != http.StatusOK || h == nil {
		t.Fatalf("a fresh confirmation: %d", res.StatusCode)
	}
	if r := f.openAccount(h[1], "Sec-Fetch-Site", "cross-site"); r.StatusCode != http.StatusForbidden || accountCookieOf(r) != "" {
		t.Errorf("a cross-site open: %d", r.StatusCode)
	}
	if r := f.openAccount(h[1], "Origin", "https://evil.example"); r.StatusCode != http.StatusForbidden {
		t.Errorf("an open from another origin: %d", r.StatusCode)
	}
	if r := f.accountReq("GET", "/account/open?h="+h[1], "", nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("GET /account/open: %d", r.StatusCode)
	}
	op := f.openAccount(h[1], "Origin", "null", "Sec-Fetch-Site", "same-origin")
	readBody(op)
	cookie := accountCookieOf(op)
	if op.StatusCode != http.StatusSeeOther || cookie == "" {
		t.Fatalf("opening: %d", op.StatusCode)
	}
	if r := f.openAccount(h[1], "Origin", "null", "Sec-Fetch-Site", "same-origin"); r.StatusCode != http.StatusForbidden {
		t.Errorf("a handle used twice: %d", r.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range op.Cookies() {
		if c.Name == accountCookieName {
			ck = c
		}
	}
	if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" || ck.MaxAge != int(accountTTL.Seconds()) {
		t.Errorf("the cookie: %+v", ck)
	}

	s := &accountSess{cookie: cookie, csrf: f.accountPageCSRF(cookie)}
	_, page := f.accountPage(cookie)
	for _, want := range []string{"alice@" + idpScope, idpEntity, "votre établissement"} {
		if !strings.Contains(page, want) {
			t.Errorf("a federated person's identity lacks %q:\n%s", want, page)
		}
	}
	// No passkeys for them, and no way to edit what their institution says.
	for _, not := range []string{"passkey-button", "data-remove", `id="name"`} {
		if strings.Contains(page, not) {
			t.Errorf("a federated person's page has %q", not)
		}
	}
	for _, p := range []string{"/account/add/begin", "/account/remove"} {
		f.resetThrottle()
		if st, _ := f.acctPost(s, p, map[string]any{"key": "0123456789abcdef"}); st != http.StatusNotFound && st != http.StatusForbidden {
			t.Errorf("%s as a federated person: %d", p, st)
		}
	}
	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/profile", map[string]any{"name": "Mallory"}); st != http.StatusForbidden || !strings.Contains(msg, "institution") {
		t.Errorf("a federated person editing their name: %d %q", st, msg)
	}
	f.resetThrottle()
	if st, msg := f.acctPost(s, "/account/profile", map[string]any{"mail": "x@evil.example"}); st != http.StatusForbidden || !strings.Contains(msg, "institution") {
		t.Errorf("a federated person editing their mail: %d %q", st, msg)
	}

	// Their application sessions are theirs to end.
	tok, err := f.refreshed(f.deviceTokenAs("files", alice, "openid"))
	if err != nil {
		t.Fatal(err)
	}
	f.resetThrottle()
	if _, page := f.accountPage(cookie); len(appsRevokeArg.FindAllStringSubmatch(page, -1)) != 1 {
		t.Fatalf("the federated person's sessions:\n%s", page)
	}
	g, _ := f.s.refresh.get(hashToken(tok.RefreshToken))
	if st, msg := f.acctPost(s, "/account/apps/revoke", map[string]any{"id": familyID(g.family)}); st != http.StatusOK {
		t.Fatalf("revoking: %d %s", st, msg)
	}
	if _, err := f.refreshed(tok); err == nil {
		t.Error("a federated person's revoked session still refreshes")
	}

	// A disabled person's confirmation ends with their access.
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if status, page := f.accountPage(cookie); status != http.StatusOK || strings.Contains(page, "data-post") {
		t.Errorf("a disabled person's confirmation still opens the page:\n%s", page)
	}
}

// A confirmation for the account page is a login of its own kind: it is not an
// application's, and the local pages refuse to continue it.
func TestAccountConfirmationIsNotAnApplicationLogin(t *testing.T) {
	f := localFixture(t, "")
	f.enrolled("alice", webauthn.AlgES256)
	b := newBrowser(t)
	location(t, b.get(f.s.cfg.Issuer+"/account/federation")) // the browser now holds a login of kind "account"
	if res := b.get(f.s.cfg.Issuer + "/local/login"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("the local login page continued a confirmation: %d", res.StatusCode)
	}
	if res := b.get(f.s.cfg.Issuer + "/login"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("the method page continued a confirmation: %d", res.StatusCode)
	}
	// And a passkey step-up opens no OIDC session: the cookie it sets is the
	// account's alone, and /authorize does not take it for a login.
	a := mustAuth(t, webauthn.AlgES256)
	if st := f.addKey(&accountSess{cookie: "", csrf: ""}, a, webauthntest.Options{}); st != http.StatusUnauthorized {
		t.Errorf("adding a passkey with no confirmation: %d", st)
	}
}
