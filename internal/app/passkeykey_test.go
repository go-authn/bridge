// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"strings"
	"testing"
)

// TestPasskeyKeyIsNeverAFlag holds the property `local-account passkeys` and
// `remove-passkey` depend on: the ID the CLI shows can always be typed back as
// an argument. With base64url one key in 64 began with '-' and was parsed as a
// flag (TestLocalAccountCLIAgainstARunningProvider, 7fd1ed1).
func TestPasskeyKeyIsNeverAFlag(t *testing.T) {
	const n = 4096
	oldDash := 0
	for i := range n {
		id := []byte{byte(i), byte(i >> 8), 0xa5, byte(i * 7)}
		k := passkeyKey(id)
		if len(k) != 64 || strings.Trim(k, "0123456789abcdef") != "" {
			t.Fatalf("passkeyKey(%x) = %q: not 64 lowercase hex characters", id, k)
		}
		// The control: the same IDs under the former key (hashToken, base64url)
		// begin with '-' often enough that this sample would have caught it.
		if strings.HasPrefix(hashToken(string(id)), "-") {
			oldDash++
		}
	}
	if oldDash == 0 {
		t.Fatalf("control: none of %d IDs gave a base64url key starting with '-'; the sample cannot tell the two encodings apart", n)
	}
}
