// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An IdP that writes the eppn "Alice@..." -- eppn compares without case,
// and the bridge keeps it as written, in her application password's row and
// in her tokens. Disabling her (whatever case the operator types) removes
// that row, and tells the SSF receivers her account as their tokens spell
// it: the review found v0.11.0's lower-casing left the row in place, and
// sent acct:alice@..., which go-fileshare -- comparing exactly -- matched to
// nobody.
func TestDisablingAMixedCaseNameReachesEverySpelling(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "app.db"))), 0o600)
	f := newFixture(t, fmt.Sprintf(`
disabled_file = %q
app_passwords {
  driver   = "sqlite"
  dsn_file = %q
}
client "files" {
  device        = true
  app_passwords = true
}
`, filepath.ToSlash(filepath.Join(dir, "disabled.json")), filepath.ToSlash(dsn)))
	f.s.poll = 1e9
	mixed := alice
	mixed.eppn = "Alice@" + idpScope
	tok := f.deviceTokenAs("files", mixed, "openid", "app_password")
	if code, _ := setPassword(t, f, tok.AccessToken, "POST"); code != 200 {
		t.Fatalf("setting the application password: %d", code)
	}
	rows := func() int {
		var n int
		if err := f.s.cfg.AppPasswords.db.QueryRow(`SELECT COUNT(*) FROM ` + f.s.cfg.AppPasswords.Table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rows() != 1 {
		t.Fatalf("%d rows before", rows())
	}
	if got := f.s.spellingsOf("alice@" + idpScope); len(got) != 2 || got[0] != "Alice@"+idpScope {
		t.Errorf("spellings held: %q, want Alice@ and alice@", got)
	}
	if _, r, err := f.s.disablePerson("alice@"+idpScope, "compromised", "test", time.Time{}); err != nil || r.appPasswords != 1 {
		t.Fatalf("disabling: %v, %d application passwords removed", err, r.appPasswords)
	}
	if rows() != 0 {
		t.Errorf("the application password survived disabling: %d rows", rows())
	}
}
