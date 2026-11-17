// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// localCLI is a configuration with a local block (and nothing else: the
// command reads that block alone) and the accounts file it names.
func localCLI(t *testing.T, accounts string) (cfg, file string) {
	t.Helper()
	dir := t.TempDir()
	file = filepath.Join(dir, "accounts.hcl")
	if accounts != "" {
		os.WriteFile(file, []byte(accounts), 0o640)
		os.Chmod(file, 0o640)
	}
	cfg = filepath.Join(dir, "bridge.hcl")
	os.WriteFile(cfg, []byte(fmt.Sprintf("issuer = \"https://login.mesocentre.example\"\nlocal {\n accounts_file = %q\n scope = %q\n}\n", filepath.ToSlash(file), localScope)), 0o644)
	return cfg, file
}

func runLocal(stdin string, args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	cmd := newRootCmd(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func TestLocalAccountCLI(t *testing.T) {
	cfg, file := localCLI(t, "")
	const pw1, pw2 = "first password, long enough", "second password, long enough"

	// add: creates the file (0640), from stdin, with groups.
	out, _, err := runLocal(pw1+"\n", "local-account", "add", "--config", cfg, "--name", "Alice Martin",
		"--mail", "alice@mesocentre.example", "--group", localGroup, "alice")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(out, "add alice") {
		t.Errorf("add said %q", out)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o640 {
			t.Errorf("the new file is %04o", fi.Mode().Perm())
		}
	}
	text, _ := os.ReadFile(file)
	if strings.Contains(string(text), pw1) || !strings.Contains(string(text), "$argon2id$") {
		t.Errorf("the file holds the password, or no argon2id hash:\n%s", text)
	}
	accts, err := parseAccounts(text, file, localScope, nil)
	if err != nil {
		t.Fatalf("the provider refuses what add wrote: %v", err)
	}
	if accts.ids["alice"].Verify(pw1) != nil || accts.ids["alice"].Verify(pw2) == nil {
		t.Error("alice's hash is not pw1's")
	}

	// A second add of the same login is refused, and the file is as it was.
	if _, _, err := runLocal(pw2+"\n", "local-account", "add", "--config", cfg, "--name", "Other", "alice"); err == nil {
		t.Error("add of an existing login succeeded")
	}
	if now, _ := os.ReadFile(file); !bytes.Equal(now, text) {
		t.Error("a refused add changed the file")
	}

	// bob, then passwd for alice changes alice only.
	if _, _, err := runLocal(pw1+"\r\n", "local-account", "add", "--config", cfg, "--name", "Bob", "bob"); err != nil {
		t.Fatalf("add bob (CRLF input): %v", err)
	}
	if _, _, err := runLocal(pw2, "local-account", "passwd", "--config", cfg, "alice"); err != nil { // no trailing newline
		t.Fatalf("passwd: %v", err)
	}
	text, _ = os.ReadFile(file)
	accts, err = parseAccounts(text, file, localScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accts.ids["alice"].Verify(pw2) != nil || accts.ids["alice"].Verify(pw1) == nil {
		t.Error("passwd did not replace alice's password")
	}
	if accts.ids["bob"].Verify(pw1) != nil {
		t.Error("passwd touched bob")
	}
	if g := accts.ids["alice"].Groups(); len(g) != 1 {
		t.Errorf("passwd lost alice's groups: %v", g)
	}

	// remove.
	if _, _, err := runLocal("", "local-account", "remove", "--config", cfg, "bob"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	text, _ = os.ReadFile(file)
	if strings.Contains(string(text), `"bob"`) {
		t.Errorf("bob is still in the file:\n%s", text)
	}
	for _, args := range [][]string{
		{"remove", "ghost"}, {"passwd", "ghost"},
	} {
		if _, _, err := runLocal(pw1+"\n", append([]string{"local-account"}, append(args[:1:1], "--config", cfg, args[1])...)...); err == nil {
			t.Errorf("%v of nobody succeeded", args)
		}
	}
}

func TestLocalAccountCLIRefuses(t *testing.T) {
	cfg, file := localCLI(t, localAccountsText())
	before, _ := os.ReadFile(file)
	good := "a long enough password"
	for name, c := range map[string]struct {
		stdin string
		args  []string
	}{
		"a short password":         {"short\n", []string{"add", "--name", "C", "carol"}},
		"no password":              {"", []string{"add", "--name", "C", "carol"}},
		"no name":                  {good + "\n", []string{"add", "carol"}},
		"a login with an @":        {good + "\n", []string{"add", "--name", "C", "carol@univ.example"}},
		"an upper-case login":      {good + "\n", []string{"add", "--name", "C", "Carol"}},
		"a group outside scope":    {good + "\n", []string{"add", "--name", "C", "--group", "urn:geant:other.example:x", "carol"}},
		"a bare group":             {good + "\n", []string{"add", "--name", "C", "--group", "admins", "carol"}},
		"a password on the argv":   {"", []string{"add", "--name", "C", "--password", good, "carol"}},
		"a password as argument":   {"", []string{"add", "--name", "C", "carol", good}},
		"a hash given by the user": {"", []string{"add", "--name", "C", "--hash", "x", "carol"}},
		"no login":                 {good + "\n", []string{"add", "--name", "C"}},
	} {
		_, _, err := runLocal(c.stdin, append([]string{"local-account", c.args[0], "--config", cfg}, c.args[1:]...)...)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if now, _ := os.ReadFile(file); !bytes.Equal(now, before) {
			t.Errorf("%s: the file changed", name)
		}
	}
	// No local block: nothing to manage.
	empty := filepath.Join(t.TempDir(), "x.hcl")
	os.WriteFile(empty, []byte("issuer = \"https://x.example\"\n"), 0o644)
	if _, _, err := runLocal(good+"\n", "local-account", "add", "--config", empty, "--name", "C", "carol"); err == nil {
		t.Error("add with no local block succeeded")
	}
	// A world-readable file is not edited: it is not trusted.
	if runtime.GOOS != "windows" {
		os.Chmod(file, 0o644)
		if _, _, err := runLocal(good+"\n", "local-account", "add", "--config", cfg, "--name", "C", "carol"); err == nil {
			t.Error("add into a world-readable file succeeded")
		}
	}
}

// Comments, and the order of what was there, survive an edit.
func TestLocalAccountCLIKeepsTheFileAsItWas(t *testing.T) {
	cfg, file := localCLI(t, localAccountsText())
	if _, _, err := runLocal("a long enough password\n", "local-account", "add", "--config", cfg, "--name", "Carol", "carol"); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(file)
	s := string(text)
	if !strings.HasPrefix(s, "# the mésocentre's people\n") {
		t.Errorf("the comment is gone:\n%s", s)
	}
	if strings.Index(s, `"alice"`) > strings.Index(s, `"bob"`) || strings.Index(s, `"bob"`) > strings.Index(s, `"carol"`) {
		t.Errorf("the order changed:\n%s", s)
	}
	// And a provider reads what the command wrote, end to end.
	f := newFixture(t, fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n}\n", filepath.ToSlash(file), localScope))
	if _, ok := f.s.cfg.Local.store.get("carol"); !ok {
		t.Error("the provider does not know the account the command added")
	}
}
