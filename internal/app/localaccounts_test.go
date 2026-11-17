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

func TestLocalPHC(t *testing.T) {
	h, err := parsePHC(localPWHash())
	if err != nil {
		t.Fatal(err)
	}
	if !h.verify([]byte(localPW)) || h.verify([]byte(localPW+"x")) || h.verify(nil) {
		t.Error("verify: the right password, a wrong one, none")
	}
	salt := "AAAAAAAAAAAAAAAAAAAAAA" // 16 bytes
	key := "AAAAAAAAAAAAAAAAAAAAAA"
	for name, s := range map[string]string{
		"empty":           "",
		"bcrypt":          "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"argon2i":         "$argon2i$v=19$m=65536,t=3,p=2$" + salt + "$" + key,
		"old version":     "$argon2id$v=16$m=65536,t=3,p=2$" + salt + "$" + key,
		"too weak m":      "$argon2id$v=19$m=1024,t=3,p=2$" + salt + "$" + key,
		"too weak t":      "$argon2id$v=19$m=65536,t=1,p=2$" + salt + "$" + key,
		"memory bomb":     "$argon2id$v=19$m=4194304,t=3,p=2$" + salt + "$" + key,
		"time bomb":       "$argon2id$v=19$m=65536,t=4000000000,p=2$" + salt + "$" + key,
		"lanes bomb":      "$argon2id$v=19$m=65536,t=3,p=255$" + salt + "$" + key,
		"zero lanes":      "$argon2id$v=19$m=65536,t=3,p=0$" + salt + "$" + key,
		"signed":          "$argon2id$v=19$m=+65536,t=3,p=2$" + salt + "$" + key,
		"wrong order":     "$argon2id$v=19$t=3,m=65536,p=2$" + salt + "$" + key,
		"padded base64":   "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "==$" + key,
		"short salt":      "$argon2id$v=19$m=65536,t=3,p=2$AAAA$" + key,
		"short hash":      "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$AAAA",
		"extra field":     "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$" + key + "$x",
		"no leading $":    "argon2id$v=19$m=65536,t=3,p=2$" + salt + "$" + key,
		"not base64":      "$argon2id$v=19$m=65536,t=3,p=2$!!!!!!!!!!!!!!!!!!!!!!$" + key,
		"plaintext":       "hunter2hunter2",
		"giant parameter": "$argon2id$v=19$m=99999999999999999999,t=3,p=2$" + salt + "$" + key,
	} {
		if _, err := parsePHC(s); err == nil {
			t.Errorf("%s: %q was accepted", name, s)
		}
	}
	if _, err := parsePHC("$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$" + key); err != nil {
		t.Errorf("a well-formed hash: %v", err)
	}
}

func TestLocalNewPasswordPolicy(t *testing.T) {
	for pw, ok := range map[string]bool{
		"": false, "short": false, "elevenchars": false, "twelvechars!": true,
		strings.Repeat("x", maxPasswordLen): true, strings.Repeat("x", maxPasswordLen+1): false,
		"has\x00nul-and-is-long": false, "bad\xffutf8-and-is-long": false,
	} {
		if err := checkNewPassword(pw); (err == nil) != ok {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

func TestParseLocalAccounts(t *testing.T) {
	h := localPWHash()
	acct := func(body string) string {
		return fmt.Sprintf("account \"alice\" {\n  password_hash = %q\n  name = \"Alice\"\n%s}\n", h, body)
	}
	good, err := parseAccounts([]byte(localAccountsText()), "f", localScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if good.len() != 2 {
		t.Errorf("%d accounts", good.len())
	}
	id := good.ids["alice"]
	if id.Verify(localPW) != nil || id.Verify("nope") == nil {
		t.Error("the identity does not verify through the directory model")
	}
	if g := id.Groups(); len(g) != 1 || g[0] != localGroup {
		t.Errorf("groups %v", g)
	}

	for name, src := range map[string]string{
		"not HCL":            "account {{{",
		"no hash":            "account \"a\" {\n name = \"A\"\n}\n",
		"no name":            fmt.Sprintf("account \"a\" {\n password_hash = %q\n}\n", h),
		"unknown attribute":  acct("  shell = \"/bin/sh\"\n"),
		"password in clear":  acct("  password = \"hunter2hunter2\"\n"),
		"an @ in the login":  strings.Replace(acct(""), `"alice"`, `"alice@univ.example"`, 1),
		"an upper-case one":  strings.Replace(acct(""), `"alice"`, `"Alice"`, 1),
		"an empty login":     strings.Replace(acct(""), `"alice"`, `""`, 1),
		"a long login":       strings.Replace(acct(""), `"alice"`, `"`+strings.Repeat("a", 65)+`"`, 1),
		"a login with a dot": strings.Replace(acct(""), `"alice"`, `".alice"`, 1),
		"a duplicate":        acct("") + acct(""),
		"a control in name":  strings.Replace(acct(""), `"Alice"`, `"Al\nice"`, 1),
		"a bad mail":         acct("  mail = \"not an address\"\n"),
		"a group elsewhere":  acct("  groups = [\"urn:geant:univ-ex.example:hpc:users\"]\n"),
		"a bare group":       acct("  groups = [\"admins\"]\n"),
		"a lookalike group":  acct("  groups = [\"urn:geant:evil-mesocentre.example:x\"]\n"),
		"a bad hash":         strings.Replace(acct(""), h, "plaintext-password", 1),
		"too many":           strings.Repeat(strings.Replace(acct(""), `"alice"`, `"a"`, 1), 3),
	} {
		if _, err := parseAccounts([]byte(src), "f", localScope, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
	// Names that are neither the hash nor the groups are not in an error.
	_, err = parseAccounts([]byte(strings.Replace(acct(""), h, "$argon2id$v=19$m=1,t=1,p=1$x$y", 1)), "f", localScope, nil)
	if err != nil && strings.Contains(err.Error(), h) {
		t.Error("an error repeats the hash")
	}
}

func TestLocalAccountsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits")
	}
	for mode, ok := range map[os.FileMode]bool{
		0o640: true, 0o600: true, 0o440: true, 0o400: true,
		0o644: false, 0o604: false, 0o660: false, 0o664: false, 0o666: false, 0o602: false, 0o641: false,
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
	if err := try(block(good, localScope)); err != nil {
		t.Fatalf("a good local block: %v", err)
	}
	for name, extra := range map[string]string{
		"a missing file":    block(filepath.Join(t.TempDir(), "none.hcl"), localScope),
		"a relative path":   block("accounts.hcl", localScope),
		"an upper scope":    block(good, "Mesocentre.Example"),
		"an empty scope":    block(good, ""),
		"a scope with a /":  block(good, "a/b"),
		"no scope":          fmt.Sprintf("local {\n accounts_file = %q\n}\n", good),
		"no file":           fmt.Sprintf("local {\n scope = %q\n}\n", localScope),
		"two local blocks":  block(good, localScope) + block(good, localScope),
		"an unknown option": fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n entity_id = \"x\"\n}\n", good, localScope),
	} {
		if err := try(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		open := writeAccountsFile(t, localAccountsText())
		os.Chmod(open, 0o644)
		err := try(block(open, localScope))
		if err == nil || !strings.Contains(err.Error(), "0644") {
			t.Errorf("a world-readable accounts file: %v", err)
		}
	}
	// uid and mail are not scoped, and two kinds of person now share names.
	cfg := strings.Replace(string(base), `username = "eppn"`, `username = "uid"`, 1)
	p := filepath.Join(t.TempDir(), "bridge.hcl")
	os.WriteFile(p, []byte(cfg+block(good, localScope)), 0o644)
	if _, err := loadConfig([]string{p}); err == nil || !strings.Contains(err.Error(), "local") {
		t.Errorf("username = uid with a local block: %v", err)
	}
	cfg = strings.Replace(string(base), `groups   = ["entitlement"]`, `groups   = ["affiliation"]`, 1)
	os.WriteFile(p, []byte(cfg+block(good, localScope)), 0o644)
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
