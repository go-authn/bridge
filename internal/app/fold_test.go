// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"testing"
	"time"
)

// Second-pass audit. Usernames are scoped names, which go-authn/oidc folds
// ASCII-only (a Kelvin sign U+212A is not a "k"). The bridge folded them with
// strings.ToLower and EqualFold, which fold Unicode, so two distinct accounts
// at an IdP, kate@scope and (Kelvin)ate@scope, became one username: disabling
// one disabled the other, and a certificate principal of one matched the other.
func TestTwoAccountsThatDifferByTheKelvinSignAreTwoPeople(t *testing.T) {
	const kelvin = "Kate@" + idpScope
	f, _ := sshFixture(t)

	if got, other := f.s.normUsername("kate@"+idpScope), f.s.normUsername(kelvin); got == other {
		t.Errorf("normUsername merges kate and the Kelvin account into %q", got)
	}
	if got := f.s.normUsername("KATE@" + idpScope); got != "kate@"+idpScope {
		t.Errorf("an ASCII upper-case name is not folded: %q", got)
	}

	if _, _, err := f.s.disablePerson("kate@"+idpScope, "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if why := f.s.refused(&person{username: "KATE@" + idpScope, idp: idpEntity, subject: idpEntity + "!x"}); why == "" {
		t.Error("kate, spelled in capitals, is not refused")
	}
	if why := f.s.refused(&person{username: kelvin, idp: idpEntity, subject: idpEntity + "!other"}); why != "" {
		t.Errorf("a different account (Kelvin sign) was refused because kate is disabled: %s", why)
	}
}
