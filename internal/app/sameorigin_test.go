// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"net/http/httptest"
	"testing"
)

// TestSameOriginNullOriginFromAFormPost: this provider's pages send
// Referrer-Policy: no-referrer, so a browser's form post from them carries
// Origin: null (Fetch, "serialize a request origin"). Every passkey login in
// production was refused on it (2026-11-18), because the HTTP-level tests
// posted with no Origin at all. The rows on either side of that boundary:
func TestSameOriginNullOriginFromAFormPost(t *testing.T) {
	s := &server{cfg: &config{Issuer: "https://login.example.org"}}
	for _, c := range []struct {
		name, site, origin string
		want               bool
	}{
		{"the production form post", "same-origin", "null", true},
		{"a same-origin fetch", "same-origin", "https://login.example.org", true},
		{"no header at all (curl, an old browser)", "", "", true},
		{"null on its own (a sandboxed iframe, a data: page)", "", "null", false},
		{"null with Sec-Fetch-Site none", "none", "null", false},
		{"a typed URL", "none", "", true},
		// Refused: what the check exists for.
		{"a cross-site post whose origin is null", "cross-site", "null", false},
		{"a cross-site post", "cross-site", "https://evil.example", false},
		{"a same-site, other-origin post", "same-site", "https://other.example.org", false},
		{"another origin, no Sec-Fetch-Site", "", "https://evil.example", false},
		{"the issuer's host on another scheme", "", "http://login.example.org", false},
	} {
		r := httptest.NewRequest("POST", "https://login.example.org/local/login/finish", nil)
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := s.sameOrigin(r); got != c.want {
			t.Errorf("%s (Sec-Fetch-Site %q, Origin %q): sameOrigin = %v, want %v", c.name, c.site, c.origin, got, c.want)
		}
	}
}
