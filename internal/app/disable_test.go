// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/go-authn/bridge/proto/bridge/admin/v1"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// disableFixture is a provider with an admin socket, application passwords,
// a device client and, unless noFile, a disabled file.
func disableFixture(t *testing.T, noFile bool) (*fixture, adminv1.AdminServiceClient, string, string) {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.ToSlash(filepath.Join(dir, "dsn"))
	db := "file:" + filepath.ToSlash(filepath.Join(dir, "app.db"))
	os.WriteFile(dsn, []byte(db), 0o600)
	file := filepath.ToSlash(filepath.Join(dir, "disabled.json"))
	extra := `
app_passwords {
  driver   = "sqlite"
  dsn_file = "` + dsn + `"
}
client "files" {
  device           = true
  app_passwords    = true
  refresh_lifetime = "720h"
}
client "plain" {
  device = true
}
`
	if !noFile {
		extra += "disabled_file = \"" + file + "\"\n"
	}
	f, c, _, _ := adminFixture(t, extra)
	return f, c, db, file
}

// deviceStart takes a device grant as far as choosing an institution.
func (f *fixture) deviceStart(client string, scopes ...string) (*browser, *oauth2.Config, *oauth2.DeviceAuthResponse, *url.URL) {
	f.t.Helper()
	ep, err := endpoints(f.t.Context(), f.s.cfg.Issuer)
	if err != nil {
		f.t.Fatal(err)
	}
	cfg := &oauth2.Config{ClientID: client, Endpoint: ep, Scopes: append([]string{"openid"}, scopes...)}
	da, err := cfg.DeviceAuth(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	b := newBrowser(f.t)
	body, _ := io.ReadAll(b.get(da.VerificationURIComplete).Body)
	m := csrfField.FindSubmatch(body)
	if m == nil {
		f.t.Fatalf("no confirmation page:\n%s", body)
	}
	next := location(f.t, b.post(f.s.cfg.Issuer+"/device", map[string][]string{"user_code": {da.UserCode}, "csrf": {string(m[1])}, "confirm": {"yes"}}))
	return b, cfg, da, next
}

// deviceLogin is a whole device-grant login as o, through the university's
// IdP; it returns the token endpoint's answer.
func (f *fixture) deviceLogin(o assertionOpts, scopes ...string) (*oauth2.Token, error) {
	f.t.Helper()
	return f.deviceLoginAs("files", o, scopes...)
}

func (f *fixture) deviceLoginAs(client string, o assertionOpts, scopes ...string) (*oauth2.Token, error) {
	f.t.Helper()
	b, cfg, da, next := f.deviceStart(client, scopes...)
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
	}
	reqID, relay := authnRequest(f.t, next)
	b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, o)}, "RelayState": {relay}})
	return cfg.DeviceAccessToken(f.t.Context(), da)
}

func (f *fixture) refreshWorks(tok *oauth2.Token) bool {
	ep, _ := endpoints(f.t.Context(), f.s.cfg.Issuer)
	cfg := &oauth2.Config{ClientID: "files", Endpoint: ep}
	_, err := cfg.TokenSource(f.t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
	return err == nil
}

func (f *fixture) userinfoWorks(tok *oauth2.Token) bool {
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode == http.StatusOK
}

var bob = assertionOpts{eppn: "bob@" + idpScope}

func TestAdminDisablePerson(t *testing.T) {
	f, c, db, file := disableFixture(t, false)
	aliceName := "alice@" + idpScope
	tok, err := f.deviceLogin(alice, "app_password")
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodPost); s != http.StatusOK {
		t.Fatalf("setting a password: %d", s)
	}
	// A client without refresh tokens: its access token is revoked on its
	// own, not with a family.
	plain, err := f.deviceLoginAs("plain", alice)
	if err != nil || plain.RefreshToken != "" {
		t.Fatalf("plain client: %v %q", err, plain.RefreshToken)
	}
	bobTok, err := f.deviceLogin(bob)
	if err != nil {
		t.Fatal(err)
	}

	r, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: aliceName, Reason: "compromised laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Revoked.RefreshFamilies != 1 || r.Revoked.AccessTokens < 1 || r.Revoked.AppPasswords != 1 {
		t.Errorf("revoked %+v", r.Revoked)
	}
	if !strings.HasPrefix(r.Disabled.By, "uid=") || r.Disabled.Reason != "compromised laptop" || r.Disabled.Until != nil {
		t.Errorf("disabling %+v", r.Disabled)
	}

	// What she held is gone; what bob holds is not.
	if f.refreshWorks(tok) || f.userinfoWorks(tok) {
		t.Error("a disabled person's tokens still work")
	}
	if _, ok := people(t, db)[aliceName]; ok {
		t.Error("a disabled person's application password is still there")
	}
	if !f.refreshWorks(bobTok) {
		t.Error("disabling alice broke bob's refresh token")
	}

	// She cannot log in again; bob, through the same IdP and the same
	// flow, can -- so the refusal is the disabling, not a broken login.
	if _, err := f.deviceLogin(alice); err == nil {
		t.Error("a disabled person logged in")
	} else if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("refused with %v, want access_denied", err)
	}
	if _, err := f.deviceLogin(bob); err != nil {
		t.Errorf("bob could not log in: %v", err)
	}

	// A grant the revocation did not find -- one being made while it ran --
	// meets the disabling in issue().
	client, _ := f.s.cfg.client("files")
	if _, _, err := f.s.issue(client, &person{username: aliceName, idp: idpEntity}, []string{"openid"}, "", "files"); !errors.Is(err, errDisabled) {
		t.Errorf("issue() for a disabled person: %v", err)
	}
	if _, _, err := f.s.issue(client, &person{username: "bob@" + idpScope, idp: idpEntity}, []string{"openid"}, "", "files"); err != nil {
		t.Errorf("issue() for bob: %v", err)
	}

	// Listed, and on disk.
	l, err := c.ListDisabled(t.Context(), &adminv1.ListDisabledRequest{})
	if err != nil || len(l.People) != 1 || l.People[0].Username != aliceName || len(l.Idps) != 0 {
		t.Fatalf("listed %v %+v", err, l)
	}
	rec := httptest.NewRecorder()
	f.s.metricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `bridge_disabled{kind="person"} 1`) {
		t.Errorf("/metrics does not count her:\n%s", rec.Body)
	}
	again, err := loadDisabled(file)
	if err != nil || !again.person(aliceName, "", time.Now()) {
		t.Errorf("the file does not hold the disabling: %v", err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the file is readable by others: %v %v", fi.Mode(), err)
	}

	// Enabled again, she logs in.
	if res, err := c.EnablePerson(t.Context(), &adminv1.EnablePersonRequest{Username: aliceName}); err != nil || !res.WasDisabled {
		t.Fatalf("enabling: %v %+v", err, res)
	}
	if _, err := f.deviceLogin(alice); err != nil {
		t.Errorf("a person enabled again could not log in: %v", err)
	}
	if res, err := c.EnablePerson(t.Context(), &adminv1.EnablePersonRequest{Username: aliceName}); err != nil || res.WasDisabled {
		t.Errorf("enabling twice: %v %+v", err, res)
	}
}

func TestAdminDisableLapses(t *testing.T) {
	f, c, _, _ := disableFixture(t, false)
	until := time.Now().Add(time.Hour)
	if _, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: "alice@" + idpScope, Until: timestamppb.New(until)}); err != nil {
		t.Fatal(err)
	}
	who := &person{username: "alice@" + idpScope, idp: idpEntity}
	if f.s.refused(who) == "" {
		t.Fatal("not disabled")
	}
	// An hour on, read from the store: the provider's clock is not moved
	// under its running goroutines.
	later := until.Add(time.Second)
	if f.s.disabled.person(who.username, "", later) {
		t.Error("still refused after it lapsed")
	}
	if people, _ := f.s.disabled.list(later); len(people) != 0 {
		t.Errorf("a lapsed disabling is listed: %+v", people)
	}

	for _, req := range []*adminv1.DisablePersonRequest{
		{},
		{Username: "x@y", Until: timestamppb.New(time.Now().Add(-time.Minute))},
	} {
		if _, err := c.DisablePerson(t.Context(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%+v: %v, want InvalidArgument", req, err)
		}
	}
}

// With no file to keep it in, a disabling is refused, not kept in memory
// until the next restart.
func TestAdminDisableNeedsAFile(t *testing.T) {
	f, c, _, _ := disableFixture(t, true)
	_, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: "alice@" + idpScope})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "disabled_file") {
		t.Errorf("%v, want FailedPrecondition naming disabled_file", err)
	}
	if _, err := c.DisableIdP(t.Context(), &adminv1.DisableIdPRequest{EntityId: idpEntity}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("%v, want FailedPrecondition", err)
	}
	if f.s.refused(&person{username: "alice@" + idpScope, idp: idpEntity}) != "" {
		t.Error("a refused disabling is in force anyway")
	}
}

func TestAdminDisableIdP(t *testing.T) {
	f, c, db, _ := disableFixture(t, false)
	tok, err := f.deviceLogin(alice, "app_password")
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodPost); s != http.StatusOK {
		t.Fatalf("setting a password: %d", s)
	}
	// Two rows from before the idp column: one in the university's scope,
	// one in another IdP's.
	sq, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for _, l := range []string{"carol@" + idpScope, "dave@other-univ.fr"} {
		if _, err := sq.Exec(`INSERT INTO app_passwords (login, nt_hash, expires) VALUES (?, ?, ?)`, l, strings.Repeat("0", 32), time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}

	r, err := c.DisableIdP(t.Context(), &adminv1.DisableIdPRequest{EntityId: idpEntity, Reason: "IdP compromised"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Revoked.RefreshFamilies != 1 || r.Revoked.AppPasswords != 2 {
		t.Errorf("revoked %+v", r.Revoked)
	}
	if f.refreshWorks(tok) || f.userinfoWorks(tok) {
		t.Error("tokens from a disabled IdP still work")
	}
	left := people(t, db)
	for l, want := range map[string]bool{"alice@" + idpScope: false, "carol@" + idpScope: false, "dave@other-univ.fr": true} {
		if _, ok := left[l]; ok != want {
			t.Errorf("%s's application password: present %v, want %v", l, ok, want)
		}
	}

	// Its people cannot log in, nor even be sent to it; the institution
	// list says so.
	b, _, _, _ := f.deviceStart("files")
	res := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + idpEntity)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "cannot be used") {
		t.Errorf("sent to a disabled IdP: %d %s", res.StatusCode, body)
	}
	if _, _, err := f.s.issue(func() *clientBlock { c, _ := f.s.cfg.client("files"); return c }(), &person{username: "zoe@" + idpScope, idp: idpEntity}, nil, "", "files"); !errors.Is(err, errDisabled) {
		t.Errorf("issue() for somebody of a disabled IdP: %v", err)
	}
	ls, err := c.ListIdPs(t.Context(), &adminv1.ListIdPsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ls.Idps {
		if disabled := i.EntityId == idpEntity; i.Disabled != disabled || i.Allowed == disabled {
			t.Errorf("%s: disabled %v allowed %v", i.EntityId, i.Disabled, i.Allowed)
		}
	}

	if res, err := c.EnableIdP(t.Context(), &adminv1.EnableIdPRequest{EntityId: idpEntity}); err != nil || !res.WasDisabled {
		t.Fatalf("enabling: %v %+v", err, res)
	}
	if _, err := f.deviceLogin(alice); err != nil {
		t.Errorf("after the IdP was enabled again: %v", err)
	}
}

// A failed save leaves nothing in force: what is enforced is what a restart
// would read.
func TestDisabledSaveFails(t *testing.T) {
	s, err := loadDisabled(filepath.Join(t.TempDir(), "missing-dir", "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.set(false, "alice", disabledEntry{Since: now}, now); err == nil {
		t.Fatal("saved into a directory that does not exist")
	}
	if s.person("alice", "", now) {
		t.Error("in force although it could not be saved")
	}
}

func TestDisabledFileUnreadable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(file, []byte("{not json"), 0o600)
	if _, err := loadDisabled(file); err == nil {
		t.Error("a corrupt disabled file was accepted: the people it held would be let back in")
	}
}

// A device grant approved at the IdP and not yet collected is a login in
// progress: disabling ends it, and the device gets nothing.
func TestAdminDisableEndsPendingDevice(t *testing.T) {
	f, c, _, _ := disableFixture(t, false)
	b, cfg, da, next := f.deviceStart("files")
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
	}
	reqID, relay := authnRequest(t, next)
	b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}})

	r, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: "alice@" + idpScope})
	if err != nil || r.Revoked.Logins != 1 {
		t.Fatalf("disabling: %v %+v", err, r.GetRevoked())
	}
	if _, err := cfg.DeviceAccessToken(t.Context(), da); err == nil {
		t.Error("a device approved before the person was disabled got a token after")
	}
}

// An institution the metadata does not list can be disabled ahead of the
// metadata that brings it; it is listed with its end.
func TestAdminDisableUnknownIdP(t *testing.T) {
	_, c, _, _ := disableFixture(t, false)
	until := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	if _, err := c.DisableIdP(t.Context(), &adminv1.DisableIdPRequest{EntityId: "https://idp.not-yet.example/idp", Until: timestamppb.New(until)}); err != nil {
		t.Fatal(err)
	}
	l, err := c.ListDisabled(t.Context(), &adminv1.ListDisabledRequest{})
	if err != nil || len(l.Idps) != 1 || !l.Idps[0].Until.AsTime().Equal(until) {
		t.Fatalf("listed %v %+v", err, l)
	}
	for _, req := range []*adminv1.DisableIdPRequest{{}, {EntityId: "x", Until: timestamppb.New(time.Now().Add(-time.Hour))}} {
		if _, err := c.DisableIdP(t.Context(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if r, err := c.EnableIdP(t.Context(), &adminv1.EnableIdPRequest{EntityId: "https://idp.never.example/idp"}); err != nil || r.WasDisabled {
		t.Errorf("enabling one never disabled: %v %+v", err, r)
	}
}

// A disabled_file that cannot be written: the admin API says so, and nothing
// is in force.
func TestAdminDisableFileUnwritable(t *testing.T) {
	f, c, _, file := disableFixture(t, false)
	if _, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: "alice@" + idpScope}); err != nil {
		t.Fatal(err)
	}
	// The file's directory replaced by a file: neither a write nor a lift
	// can be saved.
	dir := filepath.Dir(file)
	f.s.disabled.mu.Lock()
	f.s.disabled.path = filepath.Join(file, "under-a-file.json")
	f.s.disabled.mu.Unlock()
	if _, err := c.DisablePerson(t.Context(), &adminv1.DisablePersonRequest{Username: "bob@" + idpScope}); status.Code(err) != codes.Internal {
		t.Errorf("disabling with an unwritable file: %v", err)
	}
	if _, err := c.EnablePerson(t.Context(), &adminv1.EnablePersonRequest{Username: "alice@" + idpScope}); status.Code(err) != codes.Internal {
		t.Errorf("enabling with an unwritable file: %v", err)
	}
	if _, err := c.EnableIdP(t.Context(), &adminv1.EnableIdPRequest{EntityId: idpEntity}); err != nil {
		t.Errorf("enabling an IdP never disabled needs no write: %v", err)
	}
	if !f.s.disabled.person("alice@"+idpScope, "", time.Now()) || f.s.disabled.person("bob@"+idpScope, "", time.Now()) {
		t.Error("what is in force is not what is on disk")
	}
	if _, err := loadDisabled(dir); err == nil {
		t.Error("a directory was read as a disabled_file")
	}
}

// Disabling compares usernames without case: subject-id, eppn, uid and mail
// all compare so (caseIgnoreMatch), and an IdP that sends "Alice" today and
// "alice" tomorrow names one person.
func TestNormUsername(t *testing.T) {
	for _, c := range []struct{ attr, in, want string }{
		{"subject_id", "Alice@Univ-Example.FR", "alice@univ-example.fr"},
		{"eppn", "Alice@univ-example.fr", "alice@univ-example.fr"},
	} {
		s := &server{cfg: &config{Claims: &claimsBlock{Username: c.attr}}}
		if got := s.normUsername(c.in); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.attr, c.in, got, c.want)
		}
	}
}

// A table from before the idp column gets it, keeps its rows, and a
// password set afterwards records its IdP.
func TestAppPasswordsTableGainsIdP(t *testing.T) {
	dir := t.TempDir()
	db := "file:" + filepath.ToSlash(filepath.Join(dir, "app.db"))
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte(db), 0o600)
	sq, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	if _, err := sq.Exec(`CREATE TABLE app_passwords (login VARCHAR(255) NOT NULL PRIMARY KEY, password VARCHAR(255), nt_hash VARCHAR(32), expires BIGINT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	sq.Exec(`INSERT INTO app_passwords (login, expires) VALUES ('old@` + idpScope + `', 1)`)
	b := &appPasswordsBlock{Driver: "sqlite", DSNFile: dsn}
	if err := b.check(); err != nil {
		t.Fatal(err)
	}
	defer b.db.Close()
	// A second start, the column already there. Its own handle, closed: on
	// Windows an open handle keeps the file from being removed.
	again := &appPasswordsBlock{Driver: "sqlite", DSNFile: dsn}
	if err := again.check(); err != nil {
		t.Fatalf("a second start, the column already there: %v", err)
	}
	again.db.Close()
	if err := b.set("new@"+idpScope, idpEntity, "pw", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var idp sql.NullString
	sq.QueryRow(`SELECT idp FROM app_passwords WHERE login = 'new@` + idpScope + `'`).Scan(&idp)
	if idp.String != idpEntity {
		t.Errorf("idp recorded %q", idp.String)
	}
	n, err := b.removeIdP(idpEntity, []string{idpScope})
	if err != nil || n != 2 {
		t.Errorf("removed %d %v, want the new row by its IdP and the old by its scope", n, err)
	}
}
