// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go-authn/bridge#99, as docs/install.md v0.24.0 led to it: the accounts file
// in the configuration directory, empty at first (check passed), then holding
// the first account (the next start failed). Every step is now refused, and
// the same files outside the directory -- or not matching *.hcl -- pass.

// configDir writes DIR/bridge.hcl naming accounts as its accounts_file.
func configDir(t *testing.T, accounts string) string {
	t.Helper()
	dir := t.TempDir()
	// The arguments the decoder requires, so that loadConfig reaches the
	// placement check (it runs before check(), which would open these).
	body := fmt.Sprintf("issuer = %q\nsigning_key_file = \"/unread/oidc.key\"\nsubject_salt_file = \"/unread/salt\"\nlocal {\n accounts_file = %q\n scope = %q\n}\n%s", cliIssuer, filepath.ToSlash(accounts), localScope, stateExtra(t))
	if err := os.WriteFile(filepath.Join(dir, "bridge.hcl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeAt writes an accounts file at path, 0640.
func writeAt(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
}

// settings runs the command's loader and closes what it opened.
func settings(dir string) error {
	_, st, _, _, err := localSettings([]string{dir})
	if st != nil {
		st.db.Close()
	}
	return err
}

func TestAccountsFileReadAsConfigurationIsRefused(t *testing.T) {
	const placed = "is read as configuration through --config"

	t.Run("empty, in the directory", func(t *testing.T) {
		// Step 1 of the doc: the file exists, empty, and the configuration
		// parses. It used to pass check with "0 accounts".
		cfg := configDir(t, "/placeholder")
		accounts := filepath.Join(cfg, "accounts.hcl")
		cfg = rewriteAccounts(t, cfg, accounts)
		writeAt(t, accounts, "")
		if _, err := loadConfig([]string{cfg}); err == nil || !strings.Contains(err.Error(), placed) {
			t.Errorf("loadConfig: %v", err)
		}
		if err := settings(cfg); err == nil || !strings.Contains(err.Error(), placed) {
			t.Errorf("localSettings: %v", err)
		}
	})

	t.Run("missing, in the directory: invite does not create it", func(t *testing.T) {
		cfg := configDir(t, "/placeholder")
		accounts := filepath.Join(cfg, "accounts.hcl")
		cfg = rewriteAccounts(t, cfg, accounts)
		_, _, err := runLocal("local-account", "invite", "--config", cfg, "--name", "Alice Martin", "alice")
		if err == nil || !strings.Contains(err.Error(), placed) {
			t.Errorf("invite: %v", err)
		}
		if _, err := os.Stat(accounts); !os.IsNotExist(err) {
			t.Errorf("invite wrote the accounts file into the configuration directory (%v)", err)
		}
	})

	t.Run("holding an account, in the directory", func(t *testing.T) {
		// Step 3 of the doc: the decoding fails first; the error now names
		// the file and the remedy instead of "Unsupported block type".
		cfg := configDir(t, "/placeholder")
		accounts := filepath.Join(cfg, "accounts.hcl")
		cfg = rewriteAccounts(t, cfg, accounts)
		writeAt(t, accounts, localAccountsText())
		_, err := loadConfig([]string{cfg})
		if err == nil || !strings.Contains(err.Error(), "accounts.hcl holds account blocks") ||
			!strings.Contains(err.Error(), "/etc/authn-bridge-local/accounts.hcl") {
			t.Errorf("loadConfig: %v", err)
		}
		// The command's decoder keeps what it does not know (remain), so it
		// reaches the placement check instead.
		if err := settings(cfg); err == nil || !strings.Contains(err.Error(), placed) {
			t.Errorf("localSettings: %v", err)
		}
	})

	t.Run("named as a configuration file", func(t *testing.T) {
		dir := t.TempDir()
		accounts := filepath.Join(dir, "accounts.hcl")
		writeAt(t, accounts, "")
		if p, ok := readAsConfiguration(accounts, []string{accounts}); !ok || p != accounts {
			t.Errorf("the accounts file given to --config: %q %v", p, ok)
		}
		// Through a symbolic link: the same file under another name.
		link := filepath.Join(t.TempDir(), "link.hcl")
		if err := os.Symlink(accounts, link); err != nil {
			t.Skip(err)
		}
		if _, ok := readAsConfiguration(accounts, []string{link}); !ok {
			t.Error("the accounts file given to --config through a link")
		}
	})

	// Controls: the same configuration with the file where the workaround put
	// it, and in the directory under a name the *.hcl glob does not match.
	for name, place := range map[string]func(cfg string) string{
		"outside the directory": func(string) string { return filepath.Join(t.TempDir(), "accounts.hcl") },
		"not *.hcl":             func(cfg string) string { return filepath.Join(cfg, "accounts.conf") },
	} {
		t.Run("control: "+name, func(t *testing.T) {
			cfg := configDir(t, "/placeholder")
			accounts := place(cfg)
			cfg = rewriteAccounts(t, cfg, accounts)
			writeAt(t, accounts, localAccountsText())
			if err := settings(cfg); err != nil {
				t.Errorf("localSettings: %v", err)
			}
			if _, ok := readAsConfiguration(accounts, []string{cfg}); ok {
				t.Error("readAsConfiguration says yes")
			}
		})
	}
}

// rewriteAccounts points DIR/bridge.hcl's accounts_file at accounts.
func rewriteAccounts(t *testing.T, dir, accounts string) string {
	t.Helper()
	p := filepath.Join(dir, "bridge.hcl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "accounts_file") {
			lines[i] = fmt.Sprintf(" accounts_file = %q", filepath.ToSlash(accounts))
		}
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
