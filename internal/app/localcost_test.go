// SPDX-License-Identifier: BSD-3-Clause

package app

import "testing"

// Every hash this test binary makes is the cheapest parsePHC accepts (19 MiB,
// two passes, one lane): see argonMemory. What a provider runs with is the
// defaults, checked below by value.
func init() {
	argonMemory, argonTime, argonThreads = 19456, 2, 1
}

func TestLocalHashCostIsRFC9106s(t *testing.T) {
	if defaultArgonMemory != 64*1024 || defaultArgonTime != 3 || defaultArgonThreads != 2 {
		t.Errorf("the default cost is m=%d t=%d p=%d, not RFC 9106 5.4's second recommendation (64 MiB, 3 passes, 2 lanes)",
			defaultArgonMemory, defaultArgonTime, defaultArgonThreads)
	}
	// And the test cost is itself inside what a file may hold.
	h, err := hashPassword("a password long enough")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePHC(h); err != nil {
		t.Errorf("the cheapest hash is refused by the parser: %v", err)
	}
}
