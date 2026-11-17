// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"strings"
	"testing"
)

// FuzzParseAccounts holds one property: whatever the bytes, parseAccounts
// returns, and what it accepts is what the rest of the provider assumes of an
// account -- a login of the syntax, plain text, groups in the scope -- and
// NEVER a password, whatever the file calls it. The corpus under
// testdata/fuzz/FuzzParseAccounts is committed and is replayed by `go test`.
func FuzzParseAccounts(f *testing.F) {
	f.Add([]byte(localAccountsText()))
	f.Add([]byte(""))
	f.Add([]byte("account \"a\" {\n"))
	f.Add([]byte(`account "alice@x" { name = "n" }`))
	f.Add([]byte(`account "alice" { name = "n" password_hash = "x" }`))
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
		}
	})
}
