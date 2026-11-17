// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-authn/directory"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"golang.org/x/crypto/argon2"
)

// Local accounts: people this provider knows itself, for a deployment that
// is not (yet) registered with a federation. They are ONE more configured
// identity source, not a bypass: they log in under their own entity ID
// (<issuer>/local), and every grant they buy is held to it by refused() --
// remove the `local` block and every local grant is refused (disable.go).
//
// The accounts live in a file the operator writes with `authn-bridge
// local-account`, which never sees a password on a command line:
//
//	account "alice" {
//	  password_hash = "$argon2id$v=19$m=65536,t=3,p=2$...$..."
//	  name          = "Alice Martin"
//	  mail          = "alice@example.org"                       # optional
//	  groups        = ["urn:geant:example.org:hpc:users"]       # optional
//	}

// localBlock is the `local` block of the configuration.
type localBlock struct {
	// AccountsFile is the file above. It is root:authn-bridge 0640, and is
	// refused when anybody else can read it or anybody but its owner can
	// write it: a hash is an offline guessing target.
	AccountsFile string `hcl:"accounts_file"`

	// Scope is the domain these accounts are in, as an institution's scope is
	// for a federated person. Their groups are held to it, exactly as the
	// groups an IdP asserts are held to the scopes the federation gave it
	// (groupAllowed): a group is kept only if its namespace -- the domain in
	// urn:mace:<domain>:..., urn:geant:<domain>:... or https://<host>/... --
	// is this scope or a subdomain of it. eduperson_principal_name is
	// <login>@<scope>.
	Scope string `hcl:"scope"`

	store *localStore
}

// localEntityID is the identity source local accounts log in under. It is
// derived, not configurable, so that a configuration which no longer has the
// block still knows which grants WERE local and refuses them.
func (c *config) localEntityID() string { return c.Issuer + "/local" }

// localACR says how a local account authenticated: a password, over TLS, and
// nothing else -- no second factor. It is the SAML class every password IdP
// of a federation names the same thing by.
const localACR = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

// What one account file may hold.
const (
	maxAccountsFile = 1 << 20
	maxAccounts     = 10000
	maxLoginLen     = 64
	maxPasswordLen  = 1024
	minPasswordLen  = 12
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
	// Login is what the person types, and what preferred_username says.
	// Lowercase ASCII, and never an "@": a federated person's names -- eppn,
	// subject-id -- all contain one, so no local login can be mistaken for
	// one of theirs by a relying party that matches on preferred_username
	// (go-fileshare, an SSH principal).
	Login        string   `hcl:"login,label"`
	PasswordHash string   `hcl:"password_hash"`
	Name         string   `hcl:"name"`
	Mail         string   `hcl:"mail,optional"`
	Groups       []string `hcl:"groups,optional"`
}

// localAccounts is a parsed accounts file, as the directory model holds it.
type localAccounts struct {
	src *directory.Static
	ids map[string]*directory.Identity
}

func (a *localAccounts) len() int { return len(a.ids) }

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
		h, err := parsePHC(a.PasswordHash)
		if err != nil {
			return nil, fmt.Errorf("%s: account %q: password_hash: %w", name, a.Login, err)
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
			directory.WithVerifier(func(pw string) error {
				if h.verify([]byte(pw)) {
					return nil
				}
				return directory.ErrWrongPassword
			}),
			directory.WithGroups(slices.Compact(groups)...),
			directory.WithAttributes(at))
		out.ids[a.Login] = id
		out.src.People = append(out.src.People, id)
	}
	return out, nil
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

// checkAccountsMode refuses a file anybody but root and the service's group
// can read, or anybody but its owner can write.
func checkAccountsMode(fi os.FileInfo, name string) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if runtime.GOOS == "windows" {
		return nil // Unix permission bits mean nothing there
	}
	if p := fi.Mode().Perm(); p&0o007 != 0 || p&0o020 != 0 {
		return fmt.Errorf("%s has mode %04o: a file of password hashes is readable by its owner and group at most, and written by its owner alone (chmod 0640)", name, p)
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

// ---- argon2id, as a PHC string ----

// The cost of a new hash: RFC 9106 5.4's second recommendation, 64 MiB and
// three passes, on two lanes.
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonSalt    = 16
	argonKey     = 32
)

// phcHash is a parsed $argon2id$ string.
type phcHash struct {
	m, t    uint32
	p       uint8
	salt, k []byte
}

// parsePHC reads $argon2id$v=19$m=..,t=..,p=..$salt$hash, strictly, and
// refuses what is too weak to be worth checking against or so costly that a
// file could be used to exhaust the host: a hash is an input the operator
// wrote, and a login runs it.
func parsePHC(s string) (*phcHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("not an argon2id PHC string ($argon2id$v=19$m=...,t=...,p=...$salt$hash)")
	}
	if parts[2] != "v=19" {
		return nil, fmt.Errorf("argon2 version %q: only v=19 (0x13) exists", parts[2])
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, errors.New("parameters are m=..,t=..,p=.. in that order")
	}
	num := func(prefix, v string, lo, hi uint64) (uint64, error) {
		raw, ok := strings.CutPrefix(v, prefix)
		if !ok || raw == "" || len(raw) > 9 {
			return 0, fmt.Errorf("parameter %q is not %s<number>", v, prefix)
		}
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("%s%d is outside what is accepted here (%d to %d)", prefix, n, lo, hi)
		}
		return n, nil
	}
	m, err := num("m=", params[0], 19456, 1<<18) // 19 MiB (OWASP's floor) to 256 MiB
	if err != nil {
		return nil, err
	}
	t, err := num("t=", params[1], 2, 10)
	if err != nil {
		return nil, err
	}
	p, err := num("p=", params[2], 1, 16)
	if err != nil {
		return nil, err
	}
	enc := base64.RawStdEncoding.Strict()
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return nil, errors.New("the salt is 16 to 64 bytes of unpadded base64")
	}
	k, err := enc.DecodeString(parts[5])
	if err != nil || len(k) < 16 || len(k) > 64 {
		return nil, errors.New("the hash is 16 to 64 bytes of unpadded base64")
	}
	return &phcHash{m: uint32(m), t: uint32(t), p: uint8(p), salt: salt, k: k}, nil
}

// verify is a constant-time comparison of the argon2id of pw with the hash.
func (h *phcHash) verify(pw []byte) bool {
	got := argon2.IDKey(pw, h.salt, h.t, h.m, h.p, uint32(len(h.k)))
	return subtle.ConstantTimeCompare(got, h.k) == 1
}

// hashPassword is pw as a new PHC string, with a salt of its own.
func hashPassword(pw string) (string, error) {
	salt := make([]byte, argonSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKey)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(k)), nil
}

// dummyHash is what an unknown login is checked against, so that a login that
// does not exist costs what one that does. It is made once, with the cost new
// hashes have.
var dummyHash = sync.OnceValue(func() *phcHash {
	s, err := hashPassword(token())
	if err != nil {
		panic(err)
	}
	h, err := parsePHC(s)
	if err != nil {
		panic(err)
	}
	return h
})

// checkPassword says whether a password is acceptable for a NEW hash.
func checkNewPassword(pw string) error {
	switch {
	case len(pw) < minPasswordLen:
		return fmt.Errorf("a password of %d characters is one somebody can guess: at least %d", len(pw), minPasswordLen)
	case len(pw) > maxPasswordLen:
		return fmt.Errorf("a password of at most %d bytes", maxPasswordLen)
	case !utf8.ValidString(pw) || strings.ContainsRune(pw, 0):
		return errors.New("a password is UTF-8 text without NUL")
	}
	return nil
}
