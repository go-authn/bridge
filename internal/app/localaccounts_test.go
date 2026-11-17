// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseLocalAccounts(t *testing.T) {
	acct := func(body string) string {
		return fmt.Sprintf("account \"alice\" {\n  name = \"Alice\"\n%s}\n", body)
	}
	good, err := parseAccounts([]byte(localAccountsText()), "f", localScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if good.len() != 2 {
		t.Errorf("%d accounts", good.len())
	}
	id := good.ids["alice"]
	if g := id.Groups(); len(g) != 1 || g[0] != localGroup {
		t.Errorf("groups %v", g)
	}

	for name, src := range map[string]string{
		"not HCL":             "account {{{",
		"no name":             "account \"a\" {\n}\n",
		"unknown attribute":   acct("  shell = \"/bin/sh\"\n"),
		"a nested block":      acct("  key {\n  }\n"),
		"an @ in the login":   strings.Replace(acct(""), `"alice"`, `"alice@univ.example"`, 1),
		"an upper-case one":   strings.Replace(acct(""), `"alice"`, `"Alice"`, 1),
		"an empty login":      strings.Replace(acct(""), `"alice"`, `""`, 1),
		"a long login":        strings.Replace(acct(""), `"alice"`, `"`+strings.Repeat("a", 65)+`"`, 1),
		"a login with a dot":  strings.Replace(acct(""), `"alice"`, `".alice"`, 1),
		"a duplicate":         acct("") + acct(""),
		"a control in name":   strings.Replace(acct(""), `"Alice"`, `"Al\nice"`, 1),
		"a bad mail":          acct("  mail = \"not an address\"\n"),
		"a group elsewhere":   acct("  groups = [\"urn:geant:univ-ex.example:hpc:users\"]\n"),
		"a bare group":        acct("  groups = [\"admins\"]\n"),
		"a lookalike group":   acct("  groups = [\"urn:geant:evil-mesocentre.example:x\"]\n"),
		"too many":            strings.Repeat(strings.Replace(acct(""), `"alice"`, `"a"`, 1), 3),
		"a password":          acct("  password = \"hunter2hunter2\"\n"),
		"a password_hash":     acct("  password_hash = \"$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA\"\n"),
		"an empty hash field": acct("  password_hash = \"\"\n"),
	} {
		if _, err := parseAccounts([]byte(src), "f", localScope, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A password_hash is refused with a message that says what changed, not
	// "an unexpected argument".
	_, err = parseAccounts([]byte(acct("  password_hash = \"x\"\n")), "accounts.hcl", localScope, nil)
	if err == nil || !strings.Contains(err.Error(), "password_hash is not accepted") || !strings.Contains(err.Error(), "passkey-only") || !strings.Contains(err.Error(), `account "alice"`) {
		t.Errorf("the refusal of a password_hash: %v", err)
	}
	if _, err = parseAccounts([]byte(acct("  shell = \"x\"\n")), "f", localScope, nil); err == nil || !strings.Contains(err.Error(), `"shell"`) {
		t.Errorf("an unknown argument: %v", err)
	}
	// A subdomain of the scope, a https group of a host under it, and a
	// trusted prefix are kept.
	for _, g := range []string{"urn:geant:hpc.mesocentre.example:x", "https://iam.mesocentre.example/groups/hpc", "urn:mace:mesocentre.example:x"} {
		if _, err := parseAccounts([]byte(acct("  groups = ["+fmt.Sprintf("%q", g)+"]\n")), "f", localScope, nil); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	if _, err := parseAccounts([]byte(acct("  groups = [\"plain-group\"]\n")), "f", localScope, []string{"plain-"}); err != nil {
		t.Errorf("a trusted_groups prefix: %v", err)
	}
	if _, err := parseAccounts([]byte(strings.Repeat("#", maxAccountsFile+1)), "f", localScope, nil); err == nil {
		t.Error("a file past the bound")
	}
}

func TestLocalAccountsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits")
	}
	// The file holds no secret now: it is read by anybody, and written by its
	// owner alone.
	for mode, ok := range map[os.FileMode]bool{
		0o640: true, 0o600: true, 0o440: true, 0o400: true, 0o644: true, 0o604: true,
		0o660: false, 0o664: false, 0o666: false, 0o602: false, 0o620: false,
	} {
		p := filepath.Join(t.TempDir(), "accounts.hcl")
		if err := os.WriteFile(p, []byte(localAccountsText()), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		_, _, err := readAccountsFile(p)
		if (err == nil) != ok {
			t.Errorf("mode %04o: err = %v", mode, err)
		}
	}
	if _, _, err := readAccountsFile(t.TempDir()); err == nil {
		t.Error("a directory was read as the accounts file")
	}
}

// config: what a `local` block may not be.
func TestLocalConfigRefusals(t *testing.T) {
	f := newFixture(t, "")
	good := writeAccountsFile(t, localAccountsText())
	base, err := os.ReadFile(f.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	state := stateExtra(t)
	try := func(extra string) error {
		p := filepath.Join(t.TempDir(), "bridge.hcl")
		os.WriteFile(p, append(base, []byte(extra)...), 0o644)
		c, err := loadConfig([]string{p})
		if err == nil {
			c.close()
		}
		return err
	}
	block := func(file, scope string) string {
		return fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n}\n", filepath.ToSlash(file), scope)
	}
	if err := try(block(good, localScope) + state); err != nil {
		t.Fatalf("a good local block: %v", err)
	}
	for name, extra := range map[string]string{
		"a missing file":    block(filepath.Join(t.TempDir(), "none.hcl"), localScope) + state,
		"a relative path":   block("accounts.hcl", localScope) + state,
		"an upper scope":    block(good, "Mesocentre.Example") + state,
		"an empty scope":    block(good, "") + state,
		"a scope with a /":  block(good, "a/b") + state,
		"no scope":          fmt.Sprintf("local {\n accounts_file = %q\n}\n", good) + state,
		"no file":           fmt.Sprintf("local {\n scope = %q\n}\n", localScope) + state,
		"two local blocks":  block(good, localScope) + block(good, localScope) + state,
		"an unknown option": fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n entity_id = \"x\"\n}\n", good, localScope) + state,
		// ⛔ There is no switch that brings passwords back.
		"allow_passwords":   fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n allow_passwords = true\n}\n", good, localScope) + state,
		"allow_passwords 2": fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n allow_passwords = false\n}\n", good, localScope) + state,
		"a password_hash":   fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n password_hash = \"x\"\n}\n", good, localScope) + state,
		// The credentials need somewhere to live.
		"no state block": block(good, localScope),
	} {
		if err := try(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := try(block(good, localScope)); err == nil || !strings.Contains(err.Error(), "state") {
		t.Errorf("a local block with no state: %v", err)
	}
	// An accounts file that still has a password_hash is a refusal that says why.
	old := writeAccountsFile(t, "account \"alice\" {\n  password_hash = \"x\"\n  name = \"Alice\"\n}\n")
	if err := try(block(old, localScope) + state); err == nil || !strings.Contains(err.Error(), "passkey-only") {
		t.Errorf("an accounts file with a password_hash: %v", err)
	}
	if runtime.GOOS != "windows" {
		open := writeAccountsFile(t, localAccountsText())
		os.Chmod(open, 0o666)
		err := try(block(open, localScope) + state)
		if err == nil || !strings.Contains(err.Error(), "0666") {
			t.Errorf("a world-writable accounts file: %v", err)
		}
	}
	// uid and mail are not scoped, and two kinds of person now share names.
	cfg := strings.Replace(string(base), `username = "eppn"`, `username = "uid"`, 1)
	p := filepath.Join(t.TempDir(), "bridge.hcl")
	os.WriteFile(p, []byte(cfg+block(good, localScope)+state), 0o644)
	if _, err := loadConfig([]string{p}); err == nil || !strings.Contains(err.Error(), "local") {
		t.Errorf("username = uid with a local block: %v", err)
	}
	cfg = strings.Replace(string(base), `groups   = ["entitlement"]`, `groups   = ["affiliation"]`, 1)
	os.WriteFile(p, []byte(cfg+block(good, localScope)+state), 0o644)
	if _, err := loadConfig([]string{p}); err == nil {
		t.Error("groups = affiliation with a local block was accepted")
	}
	// The same without the block still loads (nothing here changed for it).
	os.WriteFile(p, []byte(cfg), 0o644)
	c, err := loadConfig([]string{p})
	if err == nil {
		c.close()
	}
}

// The code that checked a password is gone, not switched off: nothing in this
// package imports an argon2 or reads a password.
func TestNoPasswordCodeRemains(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") || e.Name() == "apppass.go" || e.Name() == "apppasscmd.go" {
			continue
		}
		src, _ := os.ReadFile(e.Name())
		for _, bad := range []string{"argon2", "ReadPassword", "hashPassword", "dummyHash", "PostForm.Get(\"password\")", "FormValue(\"password\")", "allow_passwords", "PasswordProtectedTransport"} {
			if strings.Contains(string(src), bad) {
				// A comment saying what was removed is the one allowed mention.
				for _, line := range strings.Split(string(src), "\n") {
					if strings.Contains(line, bad) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
						t.Errorf("%s: %q: %s", e.Name(), bad, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}
