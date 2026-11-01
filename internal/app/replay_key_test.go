// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"strings"
	"testing"
	"time"
)

// ⛔ The state table's key is VARCHAR(128) (state.go). The replay key
// go-authn/saml hands over is the IdP's entity ID, a space and the
// assertion's ID -- both the IdP's to choose, and an entity ID may be 1024
// characters (saml-metadata 2.3.2). PostgreSQL and MySQL in strict mode
// refuse a longer key, the write stays "unwritten", and every later flush
// stops at it: the provider is not ready again, and the revocations queued
// behind it never reach the database (audit, 2026-11). SQLite ignores the
// length, which is why the tests on SQLite never saw it.
func TestReplayKeyFitsTheStateTable(t *testing.T) {
	now := time.Now()
	r := ttlReplay{newTTL[bool](func() time.Time { return now })}
	long := "https://" + strings.Repeat("idp.", 250) + "example/idp/shibboleth " + "_" + strings.Repeat("f", 64)
	if !r.Use(long, now.Add(time.Minute)) {
		t.Fatal("a first use was refused")
	}
	if r.Use(long, now.Add(time.Minute)) {
		t.Fatal("a second use of the same assertion was accepted")
	}
	if !r.Use(long+"x", now.Add(time.Minute)) {
		t.Fatal("another assertion was taken for the first")
	}
	r.t.each(func(k string, _ bool) {
		if len(k) > 128 {
			t.Errorf("a replay key of %d bytes, more than the state table's 128", len(k))
		}
	})
}

// What a login's replay check costs, in allocations (exact, unlike time).
func BenchmarkReplayUse(b *testing.B) {
	now := time.Now()
	r := ttlReplay{newTTL[bool](func() time.Time { return now })}
	ids := make([]string, b.N)
	for i := range ids {
		ids[i] = "https://idp.univ-ex.example/idp/shibboleth _" + strings.Repeat("a", 30) + string(rune('a'+i%26)) + time.Duration(i).String()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		r.Use(ids[i], now.Add(time.Minute))
	}
}
