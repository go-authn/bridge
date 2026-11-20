// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// An IdP that writes the eppn "Alice@..." -- eppn compares without case, and
// the bridge keeps it as written, in her tokens. Disabling her (whatever case
// the operator types) tells the SSF receivers her account as their tokens
// spell it: the review found v0.11.0's lower-casing sent acct:alice@..., which
// go-fileshare -- comparing exactly -- matched to nobody.
func TestDisablingAMixedCaseNameReachesEverySpelling(t *testing.T) {
	dir := t.TempDir()
	f := newFixture(t, fmt.Sprintf(`
disabled_file = %q
client "files" {
  device = true
}
`, filepath.ToSlash(filepath.Join(dir, "disabled.json"))))
	f.s.poll = 1e9
	mixed := alice
	mixed.eppn = "Alice@" + idpScope
	f.deviceTokenAs("files", mixed, "openid")
	if got := f.s.spellingsOf("alice@" + idpScope); len(got) != 2 || got[0] != "Alice@"+idpScope {
		t.Errorf("spellings held: %q, want Alice@ and alice@", got)
	}
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "compromised", "test", time.Time{}); err != nil {
		t.Fatalf("disabling: %v", err)
	}
}
