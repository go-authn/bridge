// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// FuzzParseAccounts holds one property: whatever the bytes, parseAccounts
// returns, and what it accepts is what the rest of the provider assumes of an
// account -- a login of the syntax, a hash it can verify against within the
// cost bounds, plain text, groups in the scope. The corpus under
// testdata/fuzz/FuzzParseAccounts is committed and is replayed by `go test`.
func FuzzParseAccounts(f *testing.F) {
	f.Add([]byte(localAccountsText()))
	f.Add([]byte(""))
	f.Add([]byte("account \"a\" {\n"))
	f.Add([]byte(`account "alice@x" { password_hash = "x" name = "n" }`))
	f.Add([]byte(strings.Repeat("account \"a\" {}\n", 50)))
	f.Fuzz(func(t *testing.T, src []byte) {
		a, err := parseAccounts(src, "fuzz", localScope, nil)
		if err != nil {
			if a != nil {
				t.Fatal("an error and accounts")
			}
			return
		}
		if a.len() > maxAccounts {
			t.Fatalf("%d accounts", a.len())
		}
		for login, id := range a.ids {
			if !loginSyntax.MatchString(login) || id.Name() != login || strings.Contains(login, "@") {
				t.Fatalf("login %q accepted", login)
			}
			for _, g := range id.Groups() {
				if !localGroupAllowed(localScope, nil, g) || plainText(g, 256) != nil {
					t.Fatalf("group %q of %q accepted", g, login)
				}
			}
			if n := id.Attributes().Get("displayName"); len(n) != 1 || n[0] == "" || plainText(n[0], 200) != nil {
				t.Fatalf("name of %q: %q", login, n)
			}
			// Never verified here (an argon2id is 64 MiB): its parameters are what
			// parsePHC bounded, and every account carries a verifier.
			if !id.Can(directory.Verifier) {
				t.Fatalf("%q has no way to be verified", login)
			}
		}
	})
}

// FuzzParsePHC: a hash string from a file never panics, and what it accepts
// is inside the bounds that keep a login from exhausting the host.
func FuzzParsePHC(f *testing.F) {
	f.Add(localPWHash())
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("$argon2id$v=19$m=4194304,t=3,p=2$AA$AA")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		h, err := parsePHC(s)
		if err != nil {
			return
		}
		if h.m < 19456 || h.m > 1<<18 || h.t < 2 || h.t > 10 || h.p < 1 || h.p > 16 || len(h.salt) < 16 || len(h.k) < 16 {
			t.Fatalf("%q accepted with m=%d t=%d p=%d", s, h.m, h.t, h.p)
		}
	})
}
