package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ⛔ The wrong-code limit is per host, and an IPv6 host is a /64: changing
// the interface identifier used to bring ten fresh guesses each time, and
// one /64 typed 2000 wrong codes in one device lifetime with none refused.
// The /48 around it shares a bucket coarseFactor times as large, as the rate
// limiter's does. Found by a security review (RFC 8628 5.1).
func TestTheUserCodeLimitIsPerHost(t *testing.T) {
	f, cfg := deviceFixture(t)
	da, err := cfg.DeviceAuth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	h := f.s.handler()
	try := func(addr, code string) int {
		r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(url.Values{"user_code": {code}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// codeAttempts wrong codes, each from another address of one /64.
	for i := 0; i < codeAttempts; i++ {
		if got := try(fmt.Sprintf("[2001:db8:1:2::%x]:4000", i+1), "ZZZZ-ZZZY"); got != http.StatusBadRequest {
			t.Fatalf("wrong code %d answered %d", i, got)
		}
	}
	// Then nothing more from that /64, not even the right code.
	if got := try("[2001:db8:1:2::ffff]:4000", da.UserCode); got != http.StatusTooManyRequests {
		t.Errorf("an eleventh code from the same /64 answered %d, want 429", got)
	}
	// Another host of the same site is its own: the right code works there.
	if got := try("[2001:db8:1:3::1]:4000", da.UserCode); got != http.StatusOK {
		t.Errorf("the right code from another /64 of the /48 answered %d", got)
	}
	// And two IPv4 hosts behind one /24 are two hosts.
	for i := 0; i < codeAttempts; i++ {
		try("192.0.2.10:4000", "ZZZZ-ZZZY")
	}
	if got := try("192.0.2.11:4000", da.UserCode); got != http.StatusOK {
		t.Errorf("a neighbouring IPv4 host was blocked by another's wrong codes: %d", got)
	}

	// The site as a whole: codeAttempts*coarseFactor wrong codes across its
	// /64s, and then the /48 is blocked too.
	g, cfg2 := deviceFixture(t)
	da2, err := cfg2.DeviceAuth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	h = g.s.handler()
	for i := 0; i < codeAttempts*coarseFactor; i++ {
		try(fmt.Sprintf("[2001:db8:9:%x::1]:4000", i/codeAttempts+1), "ZZZZ-ZZZY")
	}
	if got := try("[2001:db8:9:ffff::1]:4000", da2.UserCode); got != http.StatusTooManyRequests {
		t.Errorf("after %d wrong codes across one /48, a fresh /64 of it answered %d, want 429", codeAttempts*coarseFactor, got)
	}
}
