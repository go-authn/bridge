// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Both sides of each guard of mail.go and secretfile_unix.go that the transport
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

func TestReadSecretFileEdges(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("no mode or owner check there (secretfile_other.go)")
	}
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok", "s3cret\n", 0o600)
	if b, err := readSecretFile(ok, 100); err != nil || string(b) != "s3cret\n" {
		t.Fatalf("control: %q, %v", b, err)
	}
	if _, err := readSecretFile(filepath.Join(dir, "absent"), 100); err == nil {
		t.Error("a missing file was read")
	}
	if _, err := readSecretFile(dir, 100); err == nil {
		t.Error("a directory was read")
	}
	// The limit is on the byte: exactly limit passes, limit+1 does not.
	if _, err := readSecretFile(write("exact", "12345", 0o600), 5); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
	if _, err := readSecretFile(write("over", "123456", 0o600), 5); err == nil {
		t.Error("one byte over the limit was read")
	}
	if _, err := readSecretFile(write("grp", "x", 0o640), 100); err == nil {
		t.Error("a group-readable file was read")
	}
	if _, err := readSecretFile(write("oth", "x", 0o604), 100); err == nil {
		t.Error("a world-readable file was read")
	}
	if _, err := readSecretFile(write("ro", "x", 0o400), 100); err != nil {
		t.Errorf("0400: %v", err)
	}
}
