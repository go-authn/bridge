// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A username that would not stay one name in a certificate is not
// certified: sshd splits principals="..." and AuthorizedPrincipalsFile
// entries at commas and spaces. Measured before this fix: eppn
// "root,x@univ-example.fr" became that very principal.
func TestAUsernameThatSplitsIsNotCertified(t *testing.T) {
	f, _ := sshFixture(t)
	evil := alice
	evil.eppn = "root,x@" + idpScope
	tok := f.deviceTokenAs("sftp", evil, "openid", "ssh")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	if code, body := certify(t, f, tok.AccessToken, ssh.MarshalAuthorizedKey(k)); code != http.StatusForbidden {
		t.Errorf("certified %q: %d %s", evil.eppn, code, body)
	}
	// The ordinary name still is.
	ok := f.deviceTokenAs("sftp", alice, "openid", "ssh")
	if code, body := certify(t, f, ok.AccessToken, ssh.MarshalAuthorizedKey(k)); code != http.StatusOK {
		t.Errorf("alice: %d %s", code, body)
	}
}

func TestCertifiableName(t *testing.T) {
	for _, c := range []struct {
		u  string
		ok bool
	}{
		{"alice@univ-example.fr", true},
		{"jean-paul.o'neil@univ-example.fr", true},
		{"élodie@univ-example.fr", true},
		{"root,x@univ-example.fr", false},
		{"root x@univ-example.fr", false},
		{"root\tx@u.fr", false},
		{"root\nx@u.fr", false},
		{"a\"b@u.fr", false},
		{"a\\b@u.fr", false},
		{"a b@u.fr", false}, // a line separator, not a control character
		{"a\x00b@u.fr", false},
	} {
		if err := certifiableName(c.u); (err == nil) != c.ok {
			t.Errorf("%q: %v", c.u, err)
		}
	}
}
