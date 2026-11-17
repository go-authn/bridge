// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

const cliIssuer = "https://login.mesocentre.example"

// cliConfig writes a configuration with an issuer, a local block and a state
// block (and nothing else: the command reads those alone).
func cliConfig(t *testing.T, issuer, accountsFile, state string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "bridge.hcl")
	body := fmt.Sprintf("issuer = %q\nlocal {\n accounts_file = %q\n scope = %q\n}\n%s", issuer, filepath.ToSlash(accountsFile), localScope, state)
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// localCLI is a configuration of its own and the accounts file it names.
func localCLI(t *testing.T, accounts string) (cfg, file string) {
	t.Helper()
	file = filepath.Join(t.TempDir(), "accounts.hcl")
	if accounts != "" {
		os.WriteFile(file, []byte(accounts), 0o640)
		os.Chmod(file, 0o640)
	}
	return cliConfig(t, cliIssuer, file, stateExtra(t)), file
}

func runLocal(args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	cmd := newRootCmd(&out)
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// tokenOf is the token in an invitation URL, which must be
// <issuer>/local/enroll#<token> and nothing else on standard output.
func tokenOf(t *testing.T, issuer, out string) string {
	t.Helper()
	u, err := url.Parse(strings.TrimSpace(out))
	if err != nil || u.Scheme+"://"+u.Host != issuer || u.Path != "/local/enroll" || u.RawQuery != "" || len(u.Fragment) != 43 {
		t.Fatalf("not an invitation URL: %q (%v)", out, err)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("more than the URL on standard output: %q", out)
	}
	return u.Fragment
}

func openStore(t *testing.T, cfg string) *passkeyStore {
	t.Helper()
	_, st, _, _, err := localSettings([]string{cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.db.Close() })
	return &passkeyStore{b: st, now: time.Now}
}

func TestLocalAccountInvite(t *testing.T) {
	cfg, file := localCLI(t, "")

	// invite --name creates the file (0640) and the account.
	out, errOut, err := runLocal("local-account", "invite", "--config", cfg, "--name", "Alice Martin",
		"--mail", "alice@mesocentre.example", "--group", localGroup, "alice")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	tok := tokenOf(t, cliIssuer, out)
	if !strings.Contains(errOut, "invitation for alice") || strings.Contains(errOut, tok) {
		t.Errorf("stderr: %q", errOut)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o640 {
			t.Errorf("the new file is %04o", fi.Mode().Perm())
		}
	}
	text, _ := os.ReadFile(file)
	accts, err := parseAccounts(text, file, localScope, nil)
	if err != nil {
		t.Fatalf("the provider refuses what invite wrote: %v", err)
	}
	if accts.ids["alice"] == nil || strings.Contains(string(text), "password") || strings.Contains(string(text), tok) {
		t.Errorf("the accounts file:\n%s", text)
	}

	// The invitation is in the state database, as a hash, for 24 hours.
	store := openStore(t, cfg)
	inv, err := store.peekInvite(tok)
	if err != nil || inv.Login != "alice" || inv.Expires.Sub(inv.Created) != inviteDefaultTTL {
		t.Fatalf("stored invitation: %+v %v", inv, err)
	}
	var raw string
	if err := store.b.db.QueryRow(`SELECT v FROM bridge_state WHERE kind = 'invite'`).Scan(&raw); err != nil || strings.Contains(raw, tok) {
		t.Errorf("the stored row: %q %v", raw, err)
	}

	// A second invitation replaces the first; --ttl is honoured and bounded.
	out, _, err = runLocal("local-account", "invite", "--config", cfg, "--ttl", "72h", "alice")
	if err != nil {
		t.Fatalf("re-invite: %v", err)
	}
	tok2 := tokenOf(t, cliIssuer, out)
	if tok2 == tok {
		t.Error("two invitations with one token")
	}
	if _, err := store.peekInvite(tok); err == nil {
		t.Error("the first invitation survived the second")
	}
	if inv, err := store.peekInvite(tok2); err != nil || inv.Expires.Sub(inv.Created) != 72*time.Hour {
		t.Errorf("the 72h invitation: %+v %v", inv, err)
	}
	for _, ttl := range []string{"73h", "0s", "-1h"} {
		if _, _, err := runLocal("local-account", "invite", "--config", cfg, "--ttl", ttl, "alice"); err == nil {
			t.Errorf("--ttl %s was accepted", ttl)
		}
	}

	// revoke-invite.
	if out, _, err := runLocal("local-account", "revoke-invite", "--config", cfg, "alice"); err != nil || !strings.Contains(out, "revoke-invite alice: 1") {
		t.Errorf("revoke-invite: %q %v", out, err)
	}
	if _, _, err := runLocal("local-account", "revoke-invite", "--config", cfg, "alice"); err == nil {
		t.Error("revoke-invite with nothing pending succeeded")
	}
	if _, err := store.peekInvite(tok2); err == nil {
		t.Error("a revoked invitation still works")
	}
}

func TestLocalAccountInviteRefuses(t *testing.T) {
	cfg, file := localCLI(t, localAccountsText())
	before, _ := os.ReadFile(file)
	for name, args := range map[string][]string{
		"a new account with no name":        {"invite", "carol"},
		"a login with an @":                 {"invite", "--name", "C", "carol@univ.example"},
		"an upper-case login":               {"invite", "--name", "C", "Carol"},
		"a group outside scope":             {"invite", "--name", "C", "--group", "urn:geant:other.example:x", "carol"},
		"a bare group":                      {"invite", "--name", "C", "--group", "admins", "carol"},
		"no login":                          {"invite", "--name", "C"},
		"a name for an existing account":    {"invite", "--name", "Other", "alice"},
		"a group for an existing account":   {"invite", "--group", localGroup, "alice"},
		"a password flag":                   {"invite", "--name", "C", "--password", "a long enough password", "carol"},
		"a hash flag":                       {"invite", "--name", "C", "--password-hash", "x", "carol"},
		"a password as an argument":         {"invite", "--name", "C", "carol", "a long enough password"},
		"a command that sets a password":    {"passwd", "alice"},
		"a command that adds with password": {"add", "--name", "C", "carol"},
	} {
		_, _, err := runLocal(append([]string{"local-account", args[0], "--config", cfg}, args[1:]...)...)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if now, _ := os.ReadFile(file); !bytes.Equal(now, before) {
			t.Errorf("%s: the file changed", name)
		}
	}
	if st := openStore(t, cfg); true {
		var n int
		st.b.db.QueryRow(`SELECT COUNT(*) FROM bridge_state WHERE kind = 'invite'`).Scan(&n)
		if n != 0 {
			t.Errorf("%d invitations after nothing but refusals", n)
		}
	}
	// No local block, no state block: nothing to manage.
	empty := filepath.Join(t.TempDir(), "x.hcl")
	os.WriteFile(empty, []byte("issuer = \"https://x.example\"\n"), 0o644)
	if _, _, err := runLocal("local-account", "invite", "--config", empty, "--name", "C", "carol"); err == nil {
		t.Error("invite with no local block succeeded")
	}
	noState := filepath.Join(t.TempDir(), "y.hcl")
	os.WriteFile(noState, []byte(fmt.Sprintf("issuer = \"https://x.example\"\nlocal {\n accounts_file = %q\n scope = %q\n}\n", filepath.ToSlash(file), localScope)), 0o644)
	if _, _, err := runLocal("local-account", "invite", "--config", noState, "alice"); err == nil || !strings.Contains(err.Error(), "state") {
		t.Errorf("invite with no state block: %v", err)
	}
	// A group-writable file is not edited: it is not trusted.
	if runtime.GOOS != "windows" {
		os.Chmod(file, 0o666)
		if _, _, err := runLocal("local-account", "invite", "--config", cfg, "--name", "C", "carol"); err == nil {
			t.Error("invite into a world-writable file succeeded")
		}
	}
}

// Comments, and the order of what was there, survive an edit.
func TestLocalAccountInviteKeepsTheFileAsItWas(t *testing.T) {
	cfg, file := localCLI(t, localAccountsText())
	if _, _, err := runLocal("local-account", "invite", "--config", cfg, "--name", "Carol", "carol"); err != nil {
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
}

// The CLI and the running provider share the state database: what the CLI
// does is seen at once, with no restart.
func TestLocalAccountCLIAgainstARunningProvider(t *testing.T) {
	f := localFixture(t, "")
	st := f.s.cfg.State
	cfg := cliConfig(t, f.s.cfg.Issuer, f.s.cfg.Local.AccountsFile, fmt.Sprintf("state {\n driver = %q\n dsn_file = %q\n}\n", st.Driver, filepath.ToSlash(st.DSNFile)))

	// An invitation made by the CLI is usable by the provider at once.
	out, _, err := runLocal("local-account", "invite", "--config", cfg, "--name", "Carol Petit", "carol")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenOf(t, f.s.cfg.Issuer, out)
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	b := newBrowser(t)
	status, h, ch, _ := f.enrollBegin(b, tok)
	if status != http.StatusOK {
		t.Fatalf("an invitation made by the CLI: begin status %d", status)
	}
	carol, _ := webauthntest.New(webauthn.AlgES256)
	if got := f.enrollFinish(b, carol, h, ch, webauthntest.Options{}); got != http.StatusOK {
		t.Fatalf("finish: status %d", got)
	}
	second := f.enrolled("carol", webauthn.AlgEdDSA)

	// passkeys lists them: ID, created, last used, backup-eligible.
	listing, _, err := runLocal("local-account", "passkeys", "--config", cfg, "carol")
	if err != nil {
		t.Fatalf("passkeys: %v", err)
	}
	for _, want := range []string{"ID", "CREATED", "LAST USED", "BACKUP-ELIGIBLE", passkeyKey(carol.ID), passkeyKey(second.ID), "never", "true"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the listing lacks %q:\n%s", want, listing)
		}
	}
	if strings.Contains(listing, b64(carol.ID)) || strings.Contains(listing, string(carol.COSE)) {
		t.Error("the listing shows the credential ID or the key, not its hash")
	}
	// A use shows in `last used`.
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	bb := newBrowser(t)
	csrf := f.openLocal(bb, r.authURL())
	if res := f.passkeyLogin(bb, carol, "carol", csrf, webauthntest.Options{}); res.StatusCode != http.StatusFound {
		t.Fatalf("carol's login: status %d", res.StatusCode)
	}
	listing, _, _ = runLocal("local-account", "passkeys", "--config", cfg, "carol")
	if strings.Count(listing, "never") != 1 {
		t.Errorf("after one login, one key is still unused:\n%s", listing)
	}
	if out, _, _ := runLocal("local-account", "passkeys", "--config", cfg, "nobody"); strings.Count(out, "\n") != 1 {
		t.Errorf("an account with no passkeys: %q", out)
	}

	// remove-passkey, by a prefix, stops that key at once.
	for name, id := range map[string]string{"too short": passkeyKey(carol.ID)[:7], "unknown": "AAAAAAAAAA", "another account's": passkeyKey(carol.ID)} {
		login := "carol"
		if name == "another account's" {
			login = "alice"
		}
		if _, _, err := runLocal("local-account", "remove-passkey", "--config", cfg, login, id); err == nil {
			t.Errorf("remove-passkey with %s ID succeeded", name)
		}
	}
	if out, _, err := runLocal("local-account", "remove-passkey", "--config", cfg, "carol", passkeyKey(carol.ID)[:12]); err != nil || !strings.Contains(out, passkeyKey(carol.ID)) {
		t.Fatalf("remove-passkey: %q %v", out, err)
	}
	b2 := newBrowser(t)
	csrf2 := f.openLocal(b2, r.authURL())
	if res := f.passkeyLogin(b2, carol, "carol", csrf2, webauthntest.Options{}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a passkey removed by the CLI: status %d, want 401", res.StatusCode)
	}
	b3 := newBrowser(t)
	csrf3 := f.openLocal(b3, r.authURL())
	if res := f.passkeyLogin(b3, second, "carol", csrf3, webauthntest.Options{}); res.StatusCode != http.StatusFound {
		t.Errorf("the other passkey: status %d", res.StatusCode)
	}

	// revoke-invite, seen at once.
	out, _, _ = runLocal("local-account", "invite", "--config", cfg, "carol")
	tok = tokenOf(t, f.s.cfg.Issuer, out)
	if _, _, err := runLocal("local-account", "revoke-invite", "--config", cfg, "carol"); err != nil {
		t.Fatal(err)
	}
	if status, _, _, _ := f.enrollBegin(newBrowser(t), tok); status != http.StatusForbidden {
		t.Errorf("an invitation revoked by the CLI: status %d", status)
	}

	// remove takes the account, its passkeys and its invitations.
	runLocal("local-account", "invite", "--config", cfg, "carol")
	if _, _, err := runLocal("local-account", "remove", "--config", cfg, "carol"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if text, _ := os.ReadFile(f.s.cfg.Local.AccountsFile); strings.Contains(string(text), `"carol"`) {
		t.Errorf("carol is still in the file:\n%s", text)
	}
	recs, err := f.s.passkeys.passkeys("carol")
	if err != nil || len(recs) != 0 {
		t.Errorf("passkeys left after remove: %d %v", len(recs), err)
	}
	var n int
	f.s.cfg.State.db.QueryRow(`SELECT COUNT(*) FROM bridge_state WHERE kind = 'invite'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d invitations left after remove", n)
	}
	for _, args := range [][]string{{"remove", "ghost"}, {"remove-passkey", "ghost", "AAAAAAAAAAAA"}} {
		if _, _, err := runLocal(append([]string{"local-account", args[0], "--config", cfg}, args[1:]...)...); err == nil {
			t.Errorf("%v of nobody succeeded", args)
		}
	}
}
