// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"strings"
	"testing"
	"time"
)

// Both sides of each guard of mail.go that the transport
// tests do not reach (found by mutsweep).

func TestMailAddrBothSidesOfEachRule(t *testing.T) {
	long := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(long) != 254 {
		t.Fatalf("fixture is %d bytes", len(long))
	}
	for _, ok := range []string{"alice@example.org", "a.b+c@example.org", long} {
		if _, err := mailAddr(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	tooLong := long + "d"
	for _, bad := range []string{
		"", tooLong, "alice @example.org", "alice@example.org ", "ali\x7fce@example.org",
		"alicé@example.org", "Alice <alice@example.org>", "<alice@example.org>",
		"alice@example.org,bob@example.org", "\"a b\"@example.org", "alice", "@example.org",
	} {
		if _, err := mailAddr(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBuildMessageRefusesAnAddressThatIsNotBare(t *testing.T) {
	d := time.Unix(0, 0)
	if _, err := buildMessage("a@b.org", "c@d.org", "s", d, "x"); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := buildMessage("Bridge <a@b.org>", "c@d.org", "s", d, "x"); err == nil {
		t.Error("a display name in From was accepted")
	}
	if _, err := buildMessage("a@b.org", "C <c@d.org>", "s", d, "x"); err == nil {
		t.Error("a display name in To was accepted")
	}
}

func TestMailAuthAnswersTheChallengesItShould(t *testing.T) {
	l := &mailAuth{mech: "LOGIN", user: "u", pass: "p"}
	for _, c := range []struct{ in, want string }{{"Username:", "u"}, {"password", "p"}, {"USERNAME: ", "u"}} {
		got, err := l.Next([]byte(c.in), true)
		if err != nil || string(got) != c.want {
			t.Errorf("LOGIN %q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := l.Next([]byte("something else"), true); err == nil {
		t.Error("an unknown LOGIN challenge was answered")
	}
	if got, err := l.Next(nil, false); got != nil || err != nil {
		t.Errorf("no challenge: %q, %v", got, err)
	}
	// PLAIN has no second step: a challenge is a protocol error, never an answer
	// with the password.
	p := &mailAuth{mech: "PLAIN", user: "u", pass: "p"}
	if got, err := p.Next([]byte("password"), true); err == nil || len(got) != 0 {
		t.Errorf("PLAIN answered a challenge: %q, %v", got, err)
	}
}
