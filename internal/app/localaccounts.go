// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-authn/directory"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Local accounts: people this provider knows itself, for a deployment that
// is not (yet) registered with a federation. They are ONE more configured
// identity source, not a bypass: they log in under their own entity ID
// (<issuer>/local), and every grant they buy is held to it by refused() --
// remove the `local` block and every local grant is refused (disable.go).
//
// ⛔ Local accounts are PASSKEY-ONLY. There is no password, no password form
// and no password check anywhere in this provider, and no switch that brings
// them back: a password is a secret both sides know, phishable and guessable,
// and a provider that holds none has none to lose. An account is made by an
// administrator's one-time invitation (`authn-bridge local-account invite`)
// and proves itself with a WebAuthn credential (passkeys.go).
//
// The accounts file says WHO exists, and nothing secret:
//
//	account "alice" {
//	  name   = "Alice Martin"
//	  mail   = "alice@example.org"                       # optional
//	  groups = ["urn:geant:example.org:hpc:users"]       # optional
//	}
//
// The credentials are in the provider's state database, not in this file:
// their signature counters change at every login.

// localBlock is the `local` block of the configuration.
type localBlock struct {
	// AccountsFile is the file above. It is refused when anybody but its owner
	// can write it: it decides who is in which group.
	AccountsFile string `hcl:"accounts_file"`

	// Scope is the domain these accounts are in, as an institution's scope is
	// for a federated person. Their groups are held to it, exactly as the
	// groups an IdP asserts are held to the scopes the federation gave it
	// (groupAllowed): a group is kept only if its namespace -- the domain in
	// urn:mace:<domain>:..., urn:geant:<domain>:... or https://<host>/... --
	// is this scope or a subdomain of it. eduperson_principal_name is
	// <login>@<scope>.
	Scope string `hcl:"scope"`

	// PasskeyRemovalDelay is how long the removal of a passkey, other than the
	// one the person is signed in with, waits on /account (a Go duration; the
	// default is 24h, "0" removes at once). It is the guard against a stolen,
	// unlocked device wiping the person's other keys: for the delay the key
	// still works, any of the person's keys can cancel the removal, and the
	// account page says so (account_removal.go).
	PasskeyRemovalDelay string `hcl:"passkey_removal_delay,optional"`

	// Admins are the local accounts that may invite another local account from
	// the web (admininvite.go). Only a LOCAL account is ever one: a federated
	// session of the same name is not. Each must be in accounts_file; the one
	// that gets notified of every invitation has a mail address there.
	Admins []string `hcl:"admins,optional"`

	// AdminAAGUIDs are the authenticator models an administrator's passkey must
	// be, as UUIDs ("9dd8d593-2213-438a-97f8-d6b813d51c27" is a YubiKey Bio).
	// It counts only for a passkey whose AAGUID came from a VERIFIED
	// attestation (passkeyRecord.AttestedAAGUID): the AAGUID a passkey reports
	// about itself under attestation "none" is a claim, not evidence, and is
	// never compared with this list. Required with admins.
	AdminAAGUIDs []string `hcl:"admin_aaguids,optional"`

	store        *localStore
	removalDelay time.Duration
	adminSet     map[string]bool
	aaguidSet    map[string]bool
}

// localEntityID is the identity source local accounts log in under. It is
// derived, not configurable, so that a configuration which no longer has the
// block still knows which grants WERE local and refuses them.
func (c *config) localEntityID() string { return c.Issuer + "/local" }

// localACR says how a local account authenticated: with a WebAuthn credential
// the person unlocked by a PIN or a biometric (user verification is required,
// so it is always set), bound to this provider's origin, so a look-alike site
// gets nothing to replay.
//
// It is REFEDS MFA (https://refeds.org/profile/mfa), the value a federation's
// relying parties already ask for: two factors of different kinds -- the
// authenticator the person holds, and the PIN or biometric that unlocks it --
// and resistance to phishing and replay, which a signature over this origin
// and a fresh challenge provide. The SAML class urn:oasis:names:tc:SAML:2.0:
// ac:classes:PasswordProtectedTransport it replaces said the opposite.
const localACR = "https://refeds.org/profile/mfa"

// What one account file may hold.
const (
	maxAccountsFile = 1 << 20
	maxAccounts     = 10000
	maxLoginLen     = 64
)

var (
	loginSyntax = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	scopeSyntax = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// An accountsFile is the file as HCL reads it.
type accountsFile struct {
	Accounts []accountBlock `hcl:"account,block"`
}

type accountBlock struct {
	// Login is what the person is called, and what preferred_username says.
	// Lowercase ASCII, and never an "@": a federated person's names -- eppn,
	// subject-id -- all contain one, so no local login can be mistaken for
	// one of theirs by a relying party that matches on preferred_username
	// (go-fileshare, an SSH principal).
	Login  string   `hcl:"login,label"`
	Name   string   `hcl:"name"`
	Mail   string   `hcl:"mail,optional"`
	Groups []string `hcl:"groups,optional"`
	// Remain catches every other attribute, so that a refusal can say what it
	// is: a password_hash is not "an unexpected argument", it is a file written
	// for a version of this provider that had passwords.
	Remain hcl.Body `hcl:",remain"`
}

// localAccounts is a parsed accounts file, as the directory model holds it.
type localAccounts struct {
	src *directory.Static
	ids map[string]*directory.Identity
}

func (a *localAccounts) len() int { return len(a.ids) }

// errPasswordHash is what a file that still carries a password says.
const errPasswordHash = "password_hash is not accepted: local accounts are passkey-only, and no password is stored, read or checked by this provider. Remove the line and run `authn-bridge local-account invite` to enrol a passkey"

// parseAccounts reads an accounts file. Anything it cannot vouch for is an
// error naming the account, never a silently dropped one: an account that
// vanished is a person who cannot log in, and a group that vanished is a
// person with less access, with nothing saying why.
func parseAccounts(src []byte, name, scope string, trusted []string) (*localAccounts, error) {
	if len(src) > maxAccountsFile {
		return nil, fmt.Errorf("%s: %d bytes, where %d are the most", name, len(src), maxAccountsFile)
	}
	f, diags := hclparse.NewParser().ParseHCL(src, name)
	if diags.HasErrors() {
		return nil, diags
	}
	var af accountsFile
	if diags := gohcl.DecodeBody(f.Body, nil, &af); diags.HasErrors() {
		return nil, diags
	}
	if len(af.Accounts) > maxAccounts {
		return nil, fmt.Errorf("%s: %d accounts, where %d are the most", name, len(af.Accounts), maxAccounts)
	}
	out := &localAccounts{src: &directory.Static{Name: name}, ids: map[string]*directory.Identity{}}
	for _, a := range af.Accounts {
		if !loginSyntax.MatchString(a.Login) {
			return nil, fmt.Errorf("%s: account %q: a login is 1-%d characters of a-z, 0-9, \".\", \"_\" and \"-\", starting with a letter or digit, and never an \"@\"", name, a.Login, maxLoginLen)
		}
		if _, dup := out.ids[a.Login]; dup {
			return nil, fmt.Errorf("%s: account %q is declared twice", name, a.Login)
		}
		extra, d := a.Remain.JustAttributes()
		if d.HasErrors() {
			return nil, fmt.Errorf("%s: account %q: unexpected block (an account has name, mail and groups)", name, a.Login)
		}
		for _, k := range sortedKeys(extra) {
			if k == "password_hash" || k == "password" {
				return nil, fmt.Errorf("%s: account %q: %s", name, a.Login, errPasswordHash)
			}
			return nil, fmt.Errorf("%s: account %q: unexpected argument %q (an account has name, mail and groups)", name, a.Login, k)
		}
		if err := plainText(a.Name, 200); err != nil || a.Name == "" {
			return nil, fmt.Errorf("%s: account %q: name: a display name of at most 200 characters, no control characters", name, a.Login)
		}
		attrs := []directory.Attribute{{Name: "displayName", Values: []string{a.Name}}}
		if a.Mail != "" {
			if err := plainText(a.Mail, 254); err != nil || !strings.Contains(a.Mail, "@") || strings.ContainsAny(a.Mail, " \t") {
				return nil, fmt.Errorf("%s: account %q: mail %q is not an address", name, a.Login, a.Mail)
			}
			attrs = append(attrs, directory.Attribute{Name: "mail", Values: []string{a.Mail}})
		}
		for _, g := range a.Groups {
			if err := plainText(g, 256); err != nil || g == "" || strings.ContainsAny(g, " \t") {
				return nil, fmt.Errorf("%s: account %q: group %q is not a plain value of at most 256 characters", name, a.Login, g)
			}
			if !localGroupAllowed(scope, trusted, g) {
				return nil, fmt.Errorf("%s: account %q: group %q is not in this provider's local scope %q (urn:mace:%[4]s:..., urn:geant:%[4]s:... or https://<host under %[4]s>/...)", name, a.Login, g, scope)
			}
		}
		at, err := directory.NewAttributes(attrs...)
		if err != nil {
			return nil, fmt.Errorf("%s: account %q: %w", name, a.Login, err)
		}
		groups := slices.Clone(a.Groups)
		slices.Sort(groups)
		id := directory.NewIdentity(a.Login,
			directory.From(name),
			directory.WithGroups(slices.Compact(groups)...),
			directory.WithAttributes(at))
		out.ids[a.Login] = id
		out.src.People = append(out.src.People, id)
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// plainText says whether s is at most n bytes of valid text with no control
// character: what can be put in a log line, a token and an HCL file as it is.
func plainText(s string, n int) error {
	if len(s) > n || !utf8.ValidString(s) {
		return errors.New("too long, or not UTF-8")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return errors.New("a control character")
		}
	}
	return nil
}

// localGroupAllowed holds a local account's group to the local scope: the
// same rule groupAllowed applies to an IdP's, with the scope as the one
// namespace the accounts own. trusted are claims { trusted_groups } prefixes
// for the local entity ID.
func localGroupAllowed(scope string, trusted []string, v string) bool {
	for _, p := range trusted {
		if p != "" && strings.HasPrefix(v, p) {
			return true
		}
	}
	domains := groupDomains(v)
	if len(domains) == 0 {
		return false
	}
	for _, d := range domains {
		if !ownsDomain([]string{scope}, d) {
			return false
		}
	}
	return true
}

// checkAccountsMode refuses a file anybody but its owner can write: it says
// who is in which group. It holds no secret, so it may be read.
func checkAccountsMode(fi os.FileInfo, name string) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if runtime.GOOS == "windows" {
		return nil // Unix permission bits mean nothing there
	}
	if p := fi.Mode().Perm(); p&0o022 != 0 {
		return fmt.Errorf("%s has mode %04o: the accounts decide who is in which group, so it is written by its owner alone (chmod 0640)", name, p)
	}
	return nil
}

// readAccountsFile opens the file, checks the mode of what it opened -- not of
// what the name pointed at a moment before -- and reads it, bounded.
func readAccountsFile(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if err := checkAccountsMode(fi, path); err != nil {
		return nil, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAccountsFile+1))
	if err != nil {
		return nil, nil, err
	}
	return b, fi, nil
}

// A localStore is the accounts file as the server holds it: read at start,
// and read again when it changes, so that `authn-bridge local-account` works
// on a running provider. A file that no longer parses is logged and the last
// good one stays: a typo must not log everybody out, and it does not log
// anybody IN either, because what stays is what was already allowed.
type localStore struct {
	path    string
	scope   string
	trusted []string
	logf    func(string, ...any)
	now     func() time.Time

	mu      sync.Mutex
	cur     *localAccounts
	mod     time.Time
	size    int64
	checked time.Time
}

func newLocalStore(path, scope string, trusted []string) (*localStore, error) {
	st := &localStore{path: path, scope: scope, trusted: trusted, now: time.Now, logf: func(string, ...any) {}}
	b, fi, err := readAccountsFile(path)
	if err != nil {
		return nil, err
	}
	if st.cur, err = parseAccounts(b, path, scope, trusted); err != nil {
		return nil, err
	}
	st.mod, st.size, st.checked = fi.ModTime(), fi.Size(), st.now()
	return st, nil
}

// current is the accounts, brought up to date at most once a second.
func (st *localStore) current() *localAccounts {
	st.mu.Lock()
	defer st.mu.Unlock()
	if now := st.now(); now.Sub(st.checked) >= time.Second || now.Before(st.checked) {
		st.checked = now
		if seen, err := os.Stat(st.path); err == nil && (!seen.ModTime().Equal(st.mod) || seen.Size() != st.size) {
			b, _, err := readAccountsFile(st.path)
			if err == nil {
				var next *localAccounts
				if next, err = parseAccounts(b, st.path, st.scope, st.trusted); err == nil {
					st.cur = next
				}
			}
			if err != nil {
				// Not again until it changes: one line, not one a second.
				st.mod, st.size = seen.ModTime(), seen.Size()
				st.logf("local: %s changed and was refused, the accounts read before stay in force: %v", st.path, err)
			}
		}
	}
	return st.cur
}

func (st *localStore) get(login string) (*directory.Identity, bool) {
	id, ok := st.current().ids[login]
	return id, ok
}
