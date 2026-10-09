// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

// An RSA key under 2048 bits is not certified, whatever its length in bytes:
// strongEnough read Size() -- (bits+7)/8 bytes -- times 8, so a 2047-bit key
// counted as 2048. x509ca.go and keys.go count the modulus's bits.
func TestAnRSAKeyOneBitShortIsNotCertified(t *testing.T) {
	for _, c := range []struct {
		bits int
		ok   bool
	}{{2047, false}, {2048, true}} {
		k, err := rsa.GenerateKey(rand.Reader, c.bits)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.N.BitLen(); got != c.bits {
			t.Fatalf("asked for %d bits, got %d", c.bits, got)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := strongEnough(pub); (err == nil) != c.ok {
			t.Errorf("%d bits: %v", c.bits, err)
		}
	}
}
