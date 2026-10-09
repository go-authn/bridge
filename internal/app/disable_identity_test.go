// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net/http"
)

// A person is disabled as who they ARE, not as how their IdP spells them
// today. Measured before this fix: alice disabled, her IdP sent
// "Alice@univ-example.fr" -- eppn compares without case (caseIgnoreMatch)
// -- and she got new tokens with the same sub, and an SSH certificate.
func TestADisabledPersonStaysDisabledUnderAnotherSpelling(t *testing.T) {
	f, _ := sshFixture(t)
	f.deviceTokenAs("sftp", alice, "openid", "ssh") // she is known here now
	subject := idpEntity + "!" + strings.ToLower(alice.subjectID)

	e, _, err := f.s.disablePerson("alice@"+idpScope, "compromised", "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Subjects) != 1 || e.Subjects[0] != subject {
		t.Fatalf("the entry records %q, want her subject %q", e.Subjects, subject)
	}
	for _, who := range []*person{
		{username: "Alice@" + idpScope, idp: idpEntity, subject: subject},     // another case
		{username: "a.martin@" + idpScope, idp: idpEntity, subject: subject},  // renamed
		{username: "ALICE@UNIV-EXAMPLE.FR", idp: idpEntity, subject: "other"}, // the name alone
	} {
		if f.s.refused(who) == "" {
			t.Errorf("%s (%s) was not refused", who.username, who.subject)
		}
	}
	if why := f.s.refused(&person{username: "bob@" + idpScope, idp: idpEntity, subject: idpEntity + "!bob"}); why != "" {
		t.Errorf("bob was refused: %s", why)
	}
	// Enabling her again lifts all of it.
	if _, err := f.s.enablePerson("ALICE@"+idpScope, "test"); err != nil {
		t.Fatal(err)
	}
	if why := f.s.refused(&person{username: "a.martin@" + idpScope, idp: idpEntity, subject: subject}); why != "" {
		t.Errorf("still refused once enabled: %s", why)
	}
}

// A person whose IdP releases no username can still be disabled, by the
// sub a relying party knows them by -- before this fix, nothing short of
// disabling their whole institution refused them.
func TestAPersonWithoutUsernameIsDisabledByTheirSub(t *testing.T) {
	f, _ := sshFixture(t)
	anon := alice
	anon.eppn = ""
	anon.subjectID = "Z9Y8X7@" + idpScope
	tok := f.deviceTokenAs("rclone", anon, "openid")
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := claims["sub"].(string)
	if _, ok := claims["preferred_username"]; ok || sub == "" {
		t.Fatalf("the fixture has a username, or no sub: %v", claims)
	}

	e, r, err := f.s.disablePerson(sub, "compromised", "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	subject := idpEntity + "!" + strings.ToLower(anon.subjectID)
	if len(e.Subjects) != 1 || e.Subjects[0] != subject {
		t.Fatalf("disabling sub %s recorded %q", sub, e.Subjects)
	}
	if r.tokens == 0 {
		t.Error("their access token was not revoked")
	}
	if f.s.refused(&person{idp: idpEntity, subject: subject}) == "" {
		t.Error("a later login of theirs would not be refused")
	}
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("their access token still opens /userinfo: %d", s)
	}
}

// A file written before usernames compared without case may hold one
// person twice; loaded, they are one entry, never-ending if either was,
// with both entries' identities.
func TestAnOldDisabledFileIsFoldedOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disabled.json")
	later := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	os.WriteFile(path, []byte(`{"people":{
		"Alice@u.fr":{"since":"2026-01-01T00:00:00Z","until":"`+later.Format(time.RFC3339)+`","subjects":["idp!a1"]},
		"alice@u.fr":{"since":"2026-01-01T00:00:00Z","subjects":["idp!a2"]}
	}}`), 0o600)
	d, err := loadDisabled(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.People) != 1 {
		t.Fatalf("%d entries, want 1: %v", len(d.People), d.People)
	}
	e := d.People["alice@u.fr"]
	if !e.Until.IsZero() {
		t.Errorf("until %v: one of the two never ended", e.Until)
	}
	for _, s := range []string{"idp!a1", "idp!a2"} {
		if !d.person("", s, time.Now().Add(48*time.Hour)) {
			t.Errorf("%s not refused", s)
		}
	}
}

func TestAddressedHere(t *testing.T) {
	s := &server{cfg: &config{Issuer: "https://bridge.example"}}
	for _, c := range []struct {
		aud  any
		want bool
	}{
		{"https://bridge.example", true},
		{[]any{"fileshare", "https://bridge.example"}, true},
		{"fileshare", false},
		{[]any{"fileshare"}, false},
		{nil, false},
		{42.0, false},
	} {
		if got := s.addressedHere(map[string]any{"aud": c.aud}); got != c.want {
			t.Errorf("aud %v: %v", c.aud, got)
		}
	}
}

// Disabled by their sub, a person nothing of whom is live here is refused
// all the same: the review found disabling by sub recorded nothing usable
// once their tokens had lapsed, and reported success.
func TestASubDisablesSomeoneWithNothingLive(t *testing.T) {
	f, _ := sshFixture(t)
	subject := idpEntity + "!" + strings.ToLower("Q1W2E3@"+idpScope)
	sub := (&person{subject: subject}).sub(f.s.cfg.salt, &clientBlock{Subject: "public"})
	if _, _, err := f.s.disablePerson(sub, "compromised", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if why := f.s.refused(&person{idp: idpEntity, subject: subject}); why == "" {
		t.Error("a person disabled by their public sub, with nothing live, was not refused")
	}
	if why := f.s.refused(&person{idp: idpEntity, subject: idpEntity + "!someone-else"}); why != "" {
		t.Errorf("somebody else was refused: %s", why)
	}
}
