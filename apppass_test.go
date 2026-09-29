// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// The database is read back by go-authn/directory's sqldir, with the query a
// go-fileshare `users "sql"` block would use: what SMB and S3 see is what
// this test sees.

func appFixture(t *testing.T, store string) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	dbFile := filepath.ToSlash(filepath.Join(dir, "app.db"))
	dsn := filepath.ToSlash(filepath.Join(dir, "dsn"))
	os.WriteFile(dsn, []byte("file:"+dbFile), 0o600)
	f := newFixture(t, fmt.Sprintf(`
app_passwords {
  driver   = "sqlite"
  dsn_file = %q
  store    = %s
  lifetime = "720h"
}
client "files" {
  device        = true
  app_passwords = true
}
client "rclone" {
  device = true
}
`, dsn, store))
	f.s.poll = 1e9
	return f, "file:" + dbFile
}

func setPassword(t *testing.T, f *fixture, token, method string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, f.s.cfg.Issuer+"/app-password", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

// people is what go-fileshare would read.
func people(t *testing.T, dsn string) map[string]*directory.Identity {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src, err := sqldir.New(db, sqldir.Queries{People: `select login, password, nt_hash from app_passwords where expires > strftime('%s','now')`})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*directory.Identity{}
	for _, i := range ids {
		out[i.Name()] = i
	}
	return out
}

func TestAppPasswordSMBOnly(t *testing.T) {
	f, dsn := appFixture(t, `["nt_hash"]`)
	tok := f.deviceToken("files", "openid", "app_password")
	status, out := setPassword(t, f, tok.AccessToken, http.MethodPost)
	if status != http.StatusOK || out["username"] != "alice@"+idpScope {
		t.Fatalf("%d %v", status, out)
	}
	pw, _ := out["password"].(string)
	if len(pw) != 24 {
		t.Fatalf("password %q", pw)
	}
	id := people(t, dsn)["alice@"+idpScope]
	if id == nil {
		t.Fatal("go-fileshare would not find alice")
	}
	k, err := id.NTKey()
	if err != nil || !bytes.Equal(k, directory.NTHashOf(pw)) {
		t.Fatalf("the NT hash is not the password's: %v", err)
	}
	// ⛔ SMB only: the password itself is not held, so S3 cannot use it.
	if id.Can(directory.Password) {
		t.Error("the cleartext password was stored although store = [\"nt_hash\"]")
	}

	// A new one replaces the old.
	_, again := setPassword(t, f, tok.AccessToken, http.MethodPost)
	id = people(t, dsn)["alice@"+idpScope]
	if k, _ := id.NTKey(); bytes.Equal(k, directory.NTHashOf(pw)) || !bytes.Equal(k, directory.NTHashOf(again["password"].(string))) {
		t.Error("the old password still works")
	}
	// Removed.
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodDelete); s != http.StatusNoContent {
		t.Fatalf("delete: %d", s)
	}
	if _, ok := people(t, dsn)["alice@"+idpScope]; ok {
		t.Error("a removed password is still there")
	}
}

func TestAppPasswordS3(t *testing.T) {
	f, dsn := appFixture(t, `["nt_hash", "password"]`)
	tok := f.deviceToken("files", "openid", "app_password")
	_, out := setPassword(t, f, tok.AccessToken, http.MethodPost)
	id := people(t, dsn)["alice@"+idpScope]
	if id == nil || !id.Can(directory.Password) || id.Verify(out["password"].(string)) != nil {
		t.Fatal("S3 could not use the password")
	}
	if id.Verify("wrong") == nil {
		t.Error("a wrong password verified")
	}
}

func TestAppPasswordRefusals(t *testing.T) {
	f, _ := appFixture(t, `["nt_hash"]`)
	if s, _ := setPassword(t, f, "", http.MethodPost); s != http.StatusUnauthorized {
		t.Errorf("no token: %d", s)
	}
	plain := f.deviceToken("files", "openid")
	if s, _ := setPassword(t, f, plain.AccessToken, http.MethodPost); s != http.StatusForbidden {
		t.Errorf("no app_password scope: %d", s)
	}
	tok := f.deviceToken("files", "openid", "app_password")
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodGet); s != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", s)
	}
	c, _ := f.s.cfg.client("files")
	c.AppPasswords = false
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodPost); s != http.StatusForbidden {
		t.Errorf("a withdrawn client: %d", s)
	}
	r, _ := http.PostForm(f.s.cfg.Issuer+"/device_authorization", map[string][]string{"client_id": {"rclone"}, "scope": {"openid app_password"}})
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("app_password scope for a client without it: %d", r.StatusCode)
	}
	if s, _ := setPassword(t, newFixture(t, ""), "x", http.MethodPost); s != http.StatusNotFound {
		t.Errorf("no app_passwords block: %d", s)
	}
}

func TestAppPasswordConfig(t *testing.T) {
	c := newConf(t)
	dsn := filepath.ToSlash(filepath.Join(c.dir, "dsn"))
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(c.dir, "x.db"))), 0o600)
	block := func(extra string) string {
		return "app_passwords {\ndriver = \"sqlite\"\ndsn_file = \"" + dsn + "\"\n" + extra + "\n}"
	}
	for name, extra := range map[string]string{
		"a driver":               `app_passwords {` + "\n" + `driver = "oracle"` + "\n" + `dsn_file = "` + dsn + `"` + "\n}",
		"a table name":           block(`table = "t(login varchar(255)); create table u"`),
		"a store":                block(`store = ["plaintext"]`),
		"a lifetime":             block(`lifetime = "forever"`),
		"no dsn file":            `app_passwords {` + "\n" + `driver = "sqlite"` + "\n" + `dsn_file = "` + c.dir + `/none"` + "\n}",
		"a client with no block": `client "f" {` + "\n" + `device = true` + "\n" + `app_passwords = true` + "\n}",
	} {
		if _, err := c.load(t, c.hcl(nil)+extra); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	cfg, err := c.load(t, c.hcl(nil)+block(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppPasswords.Table != "app_passwords" || strings.Join(cfg.AppPasswords.Store, ",") != "nt_hash" || cfg.AppPasswords.lifetime.Hours() != 2160 {
		t.Errorf("defaults: %+v", cfg.AppPasswords)
	}
	if (&appPasswordsBlock{Driver: "postgres"}).arg(2) != "$2" || (&appPasswordsBlock{Driver: "mysql"}).arg(2) != "?" {
		t.Error("placeholders")
	}
}
