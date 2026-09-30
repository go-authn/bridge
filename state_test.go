// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// stateFixture is a provider with a state database, and the database's
// file.
//
// With BRIDGE_TEST_POSTGRES set to a DSN, the database is that PostgreSQL
// instead (the CI lane that has one), emptied first; the file is then "".
func stateFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	dbFile := filepath.Join(dir, "state.db")
	dsn := filepath.Join(dir, "dsn")
	driver := "sqlite"
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(dbFile)), 0o600)
	if pg := os.Getenv("BRIDGE_TEST_POSTGRES"); pg != "" {
		driver, dbFile = "postgres", ""
		os.WriteFile(dsn, []byte(pg), 0o600)
		if db, err := sql.Open("pgx", pg); err == nil {
			db.Exec(`DELETE FROM bridge_state`)
			db.Close()
		}
	}
	f := newFixture(t, deviceClients+`
state {
  driver   = "`+driver+`"
  dsn_file = "`+filepath.ToSlash(dsn)+`"
}
`)
	f.s.poll = 1e9
	return f, dbFile
}

// restart puts a new provider behind the same URL, with the same
// configuration and database and nothing in memory: what a restart is.
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	s, err := newServer(f.s.cfg, io.Discard)
	if err != nil {
		t.Fatalf("restarting: %v", err)
	}
	s.poll = f.s.poll
	if err := s.refreshMetadata(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.s = s
	f.setHandler(s.handler())
}

func (f *fixture) refreshWith(t *testing.T, rt string) (*oauth2.Token, error) {
	t.Helper()
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	return (&oauth2.Config{ClientID: "rclone", Endpoint: ep}).TokenSource(t.Context(), &oauth2.Token{RefreshToken: rt}).Token()
}

func (f *fixture) userinfoStatus(t *testing.T, at string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// A restart logs nobody out: the access token still answers at /userinfo
// (what motley-cue checks every ssh-oidc login against), and the refresh
// token still rotates. Without a state block, the same restart refuses both
// -- the control that shows the test can see a restart.
func TestStateSurvivesARestart(t *testing.T) {
	f, _ := stateFixture(t)
	tok := f.deviceToken("rclone", "openid", "profile")
	f.restart(t)
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusOK {
		t.Errorf("/userinfo after a restart: %d", s)
	}
	next, err := f.refreshWith(t, tok.RefreshToken)
	if err != nil {
		t.Fatalf("refresh after a restart: %v", err)
	}
	// And the new one, after another.
	f.restart(t)
	if _, err := f.refreshWith(t, next.RefreshToken); err != nil {
		t.Errorf("the rotated refresh token after a second restart: %v", err)
	}

	// The control: no state block, and the same restart forgets.
	g := newFixture(t, deviceClients)
	g.s.poll = 1e9
	tok = g.deviceToken("rclone", "openid")
	g.restart(t)
	if s := g.userinfoStatus(t, tok.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("without state, /userinfo after a restart: %d", s)
	}
	if _, err := g.refreshWith(t, tok.RefreshToken); err == nil {
		t.Error("without state, a refresh token survived the restart")
	}
}

// What was revoked stays revoked across a restart; a retired refresh token
// used again after a restart still revokes its family.
func TestStateKeepsRevocations(t *testing.T) {
	f, _ := stateFixture(t)
	tok := f.deviceToken("rclone", "openid")
	if _, err := f.s.revokePerson("alice@" + idpScope); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("a revoked access token after a restart: %d", s)
	}
	if _, err := f.refreshWith(t, tok.RefreshToken); err == nil {
		t.Error("a revoked refresh token came back with the restart")
	}

	tok = f.deviceToken("rclone", "openid")
	next, err := f.refreshWith(t, tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	// The retired one, again: reuse. The family goes, the new one with it.
	if _, err := f.refreshWith(t, tok.RefreshToken); err == nil {
		t.Error("a retired refresh token was accepted after a restart")
	}
	if _, err := f.refreshWith(t, next.RefreshToken); err == nil {
		t.Error("reuse after a restart did not revoke the family")
	}
	if s := f.userinfoStatus(t, next.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("the family's access token after reuse: %d", s)
	}
}

// The database holds no token anybody could use: refresh tokens as their
// hashes only.
func TestStateHoldsNoRefreshToken(t *testing.T) {
	f, _ := stateFixture(t)
	tok := f.deviceToken("rclone", "openid")
	db := f.s.cfg.State.db
	var dump strings.Builder
	rows, err := db.Query(`SELECT kind, k, v FROM bridge_state`)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for rows.Next() {
		var kind, k, v string
		rows.Scan(&kind, &k, &v)
		kinds[kind]++
		dump.WriteString(k + " " + v + "\n")
	}
	rows.Close()
	if kinds["refresh"] != 1 || kinds["family"] != 1 || kinds["issued"] != 1 {
		t.Errorf("stored %v", kinds)
	}
	if strings.Contains(dump.String(), tok.RefreshToken) {
		t.Error("the refresh token itself is in the database")
	}
	if !strings.Contains(dump.String(), hashToken(tok.RefreshToken)) {
		t.Error("the refresh token\x27s hash is not the key it is kept under")
	}
}

// A revocation the database would not take: not ready until it does.
func TestStateRevocationNotTaken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not make a SQLite file read-only there")
	}
	f, dbFile := stateFixture(t)
	if dbFile == "" {
		t.Skip("made read-only through its file: SQLite only")
	}
	f.deviceToken("rclone", "openid")
	if err := f.s.readiness(); err != nil {
		t.Fatalf("not ready before anything happened: %v", err)
	}
	// Read-only, from the next connection on.
	f.s.cfg.State.db.Close()
	os.Chmod(dbFile, 0o400)
	var err error
	f.s.cfg.State.db, err = sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.revokePerson("alice@" + idpScope); err != nil {
		t.Fatal(err)
	}
	if err := f.s.readiness(); err != errStateBehind {
		t.Errorf("readiness with a revocation the database refused: %v", err)
	}
	// Writable again: the next check takes it, and it is ready.
	f.s.cfg.State.db.Close()
	os.Chmod(dbFile, 0o600)
	f.s.cfg.State.db, _ = sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile))
	if err := f.s.readiness(); err != nil {
		t.Errorf("readiness once the database takes it: %v", err)
	}
	f.restart(t)
	if n := f.s.issued.count(); n != 0 {
		t.Errorf("%d access tokens came back after the restart", n)
	}
}

// A row for a client the configuration no longer has is dropped at start,
// not fatal.
func TestStateDropsAnUnknownClient(t *testing.T) {
	f, _ := stateFixture(t)
	f.deviceToken("rclone", "openid")
	for i := range f.s.cfg.Clients {
		if f.s.cfg.Clients[i].ID == "rclone" {
			f.s.cfg.Clients[i].ID = "renamed"
		}
	}
	f.restart(t)
	if n := f.s.refresh.count(); n != 0 {
		t.Errorf("%d refresh tokens of a client that is gone", n)
	}
}

// A state block that cannot work stops the provider from starting.
func TestStateConfigRefusals(t *testing.T) {
	c := newConf(t)
	dsn := filepath.ToSlash(filepath.Join(c.dir, "dsn"))
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(c.dir, "s.db"))), 0o600)
	for name, block := range map[string]string{
		"a driver it has not":  `state {` + "\n" + `driver = "oracle"` + "\n" + `dsn_file = "` + dsn + `"` + "\n}",
		"no dsn file":          `state {` + "\n" + `driver = "sqlite"` + "\n" + `dsn_file = "` + c.dir + `/none"` + "\n}",
		"a database it cannot": `state {` + "\n" + `driver = "sqlite"` + "\n" + `dsn_file = "` + c.salt + `"` + "\n}",
	} {
		if _, err := c.load(t, c.hcl(nil)+block); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	cfg, err := c.load(t, c.hcl(nil)+`state {`+"\n"+`driver = "sqlite"`+"\n"+`dsn_file = "`+dsn+`"`+"\n}")
	if err != nil {
		t.Fatalf("the control: %v", err)
	}
	if err := cfg.close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// A write the database refuses is logged and the request still answered:
// that token is not kept past a restart, nothing else changes.
func TestStateWriteRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not make a SQLite file read-only there")
	}
	f, dbFile := stateFixture(t)
	if dbFile == "" {
		t.Skip("made read-only through its file: SQLite only")
	}
	f.s.cfg.State.db.Close()
	os.Chmod(dbFile, 0o400)
	defer os.Chmod(dbFile, 0o600)
	f.s.cfg.State.db, _ = sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	tok := f.deviceToken("rclone", "openid")
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusOK {
		t.Errorf("a token whose record the database refused: %d", s)
	}
}

// A row that does not decode -- written by another version, or damaged --
// is dropped at start, not fatal, and removed from the database.
func TestStateDropsACorruptRow(t *testing.T) {
	f, _ := stateFixture(t)
	db := f.s.cfg.State.db
	for _, kind := range []string{"refresh", "family", "rotated", "issued"} {
		if _, err := db.Exec(`INSERT INTO bridge_state (kind, k, v, expires) VALUES ('`+kind+`', 'bad', '{not json', 4102444800)`); err != nil {
			t.Fatal(err)
		}
	}
	f.restart(t)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM bridge_state WHERE k = 'bad'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d corrupt rows left in the database", n)
	}
}
