// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"testing"
	"time"

	"github.com/go-authn/saml"
)

// ⛔ The next refresh must come before the metadata in use expires, and a
// provider left with none must try again soon. The loop used to wait
// three quarters of cacheDuration, or twelve hours without one, whatever
// was left of validUntil and whether or not it still had metadata: a
// federation server down at the one refresh before validUntil left every
// IdP gone for up to twelve hours after it came back (audit, 2026-11).
// The schedule is go-authn/saml's Federation.Run (federation.go, Run).
func TestNextRefreshComesBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name      string
		md        *saml.Metadata
		retry     time.Duration
		max       time.Duration // the wait may not exceed this
		min       time.Duration // nor be shorter than this
		nextRetry time.Duration
	}{
		{"no cacheDuration, six hours left", &saml.Metadata{ValidUntil: now.Add(6 * time.Hour)}, time.Minute, 3 * time.Hour, 3 * time.Hour, time.Minute},
		{"a day of cacheDuration, two hours left", &saml.Metadata{ValidUntil: now.Add(2 * time.Hour), CacheDuration: 24 * time.Hour}, time.Minute, time.Hour, time.Hour, time.Minute},
		{"two weeks left, cacheDuration 6h", &saml.Metadata{ValidUntil: now.Add(14 * 24 * time.Hour), CacheDuration: 6 * time.Hour}, time.Minute, 270 * time.Minute, 270 * time.Minute, time.Minute},
		{"two weeks left, no cacheDuration", &saml.Metadata{ValidUntil: now.Add(14 * 24 * time.Hour)}, time.Minute, 12 * time.Hour, 12 * time.Hour, time.Minute},
		{"five minutes left: never under the floor", &saml.Metadata{ValidUntil: now.Add(5 * time.Minute)}, time.Minute, 5 * time.Minute, 5 * time.Minute, time.Minute},
		{"no metadata: try again within a minute", nil, time.Minute, time.Minute, time.Minute, 2 * time.Minute},
		{"no metadata: back off", nil, 16 * time.Minute, 16 * time.Minute, 16 * time.Minute, 32 * time.Minute},
		{"no metadata: an hour at most", nil, time.Hour, time.Hour, time.Hour, time.Hour},
	} {
		wait, next := nextRefresh(c.md, now, c.retry)
		if wait > c.max || wait < c.min {
			t.Errorf("%s: wait %s, want between %s and %s", c.name, wait, c.min, c.max)
		}
		if next != c.nextRetry {
			t.Errorf("%s: next retry %s, want %s", c.name, next, c.nextRetry)
		}
	}
}
