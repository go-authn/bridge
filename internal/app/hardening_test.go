// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ssf "github.com/hstern/go-ssf"
	"golang.org/x/oauth2"
)

// What an adversarial review of v0.8.1 measured, each held here so that it
// does not come back. The review's proofs were throwaway; these are not.

// A flood of anonymous /authorize costs this provider nothing it keeps:
// each login is sealed in its cookie, and the browser holds it. Measured
// before: 20,000 from one /64 filled the store and locked everybody out.
// Past an address's allowance it is told 429.
func TestLoginsAreNotHeldHere(t *testing.T) {
	f := newFixture(t, "")
	f.s.limiter = nil
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	for i := range 2000 {
		if res := newBrowser(t).get(r.authURL()); res.StatusCode >= 400 {
			t.Fatalf("login %d refused: %d", i+1, res.StatusCode)
		}
	}
	if n := f.s.usedLogins.count(); n != 0 {
		t.Errorf("%d logins recorded before any IdP answered", n)
	}
	if n := f.s.logins.inProgress(time.Now()); n != 2000 {
		t.Errorf("estimated %d logins in progress, want 2000", n)
	}

	f.s.limiter = newRateLimiter(2, time.Now)
	for i := range 2 {
		if res := newBrowser(t).get(r.authURL()); res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d of an allowance of 2 refused", i+1)
		}
	}
	if res := newBrowser(t).get(r.authURL()); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("past the allowance: %d", res.StatusCode)
	}
}

// Expired entries are not counted, nor walked, between two sweeps.
func TestTTLSweepsAtMostOnceASecond(t *testing.T) {
	now := time.Now()
	tt := newTTL[int](func() time.Time { return now })
	// The first put sweeps; the others, within the second, do not.
	for i := range 100 {
		tt.put(string(rune('a'+i%26))+strings.Repeat("x", i), i, now.Add(500*time.Millisecond))
	}
	now = now.Add(600 * time.Millisecond) // all expired, and no sweep since
	if n := tt.count(); n != 0 {
		t.Errorf("count %d of expired entries", n)
	}
	seen := 0
	tt.each(func(string, int) { seen++ })
	if seen != 0 {
		t.Errorf("each walked %d expired entries", seen)
	}
	if err := tt.putNew("k", 1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := tt.putNew("k", 2, now.Add(time.Minute)); err != errTaken {
		t.Errorf("putNew over a live key: %v", err)
	}
}

// The wrong-code counter forgets an address that does not come back.
func TestWrongCodeCounterForgets(t *testing.T) {
	now := time.Now()
	a := &attempts{m: map[string][]time.Time{}, now: func() time.Time { return now }}
	for i := range 1000 {
		a.failed(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String())
	}
	now = now.Add(deviceLifetime + time.Second)
	a.blocked("192.0.2.1")
	if len(a.m) != 0 {
		t.Errorf("%d addresses remembered after their window", len(a.m))
	}
}

// Behind a trusted proxy, the client is the last untrusted hop in
// X-Forwarded-For; from anybody else the header names nobody.
func TestClientAddressBehindAProxy(t *testing.T) {
	s := &server{cfg: &config{TrustedProxies: []string{"10.0.0.0/8", "::1"}}}
	if err := s.cfg.checkLimits(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ remote, xff, want string }{
		{"10.1.2.3:4", "203.0.113.9", "203.0.113.9"},
		{"10.1.2.3:4", "198.51.100.1, 203.0.113.9, 10.9.9.9", "203.0.113.9"}, // the client wrote the first
		{"[::1]:4", "203.0.113.9", "203.0.113.9"},
		{"192.0.2.7:4", "203.0.113.9", "192.0.2.7"}, // not a proxy: its header is ignored
		{"10.1.2.3:4", "not-an-address", "10.1.2.3"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		r.Header.Set("X-Forwarded-For", c.xff)
		if got := s.clientAddr(r); got != c.want {
			t.Errorf("%s %q: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	bad := &config{TrustedProxies: []string{"a proxy"}}
	if err := bad.checkLimits(); err == nil {
		t.Error("a trusted proxy that is not an address")
	}
}

// A write the state database refuses is retried, and the provider is not
// ready until it is taken -- an SSF event among them is a revocation.
func TestStateWriteNotTakenIsNotReady(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not make a SQLite file read-only there")
	}
	f, dbFile := stateFixture(t)
	if dbFile == "" {
		t.Skip("made read-only through its file: SQLite only")
	}
	f.s.cfg.State.db.Close()
	os.Chmod(dbFile, 0o400)
	f.s.cfg.State.db, _ = sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	tok := f.deviceToken("rclone", "openid")
	if err := f.s.readiness(); err != errStateBehind {
		t.Errorf("readiness with writes the database refused: %v", err)
	}
	f.s.cfg.State.db.Close()
	os.Chmod(dbFile, 0o600)
	f.s.cfg.State.db, _ = sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile))
	if err := f.s.readiness(); err != nil {
		t.Fatalf("readiness once the database takes them: %v", err)
	}
	f.restart(t)
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusOK {
		t.Errorf("the token written late is not there after a restart: %d", s)
	}
}

// A failing step of a revocation does not keep the receivers uninformed.
func TestSSFToldEvenWhenARevocationStepFails(t *testing.T) {
	f := ssfFixture(t)
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "ap.db"))), 0o600)
	ap := &appPasswordsBlock{Driver: "sqlite", DSNFile: dsn}
	if err := ap.check(); err != nil {
		t.Fatal(err)
	}
	defer ap.db.Close()
	ap.db.Exec(`DROP TABLE app_passwords`)
	f.s.cfg.AppPasswords = ap
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssfStreamConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.revokePerson("alice@" + idpScope); err == nil {
		t.Fatal("the application password table is gone, and nothing said so")
	}
	if got := pollAll(t, c, f.setVerifier(t), stream.StreamID); len(got) != 1 {
		t.Errorf("%d events: the receivers were not told", len(got))
	}
}

// uid and mail name anybody: refused unless one IdP is allowed.
func TestUnscopedUsernameNeedsOneIdP(t *testing.T) {
	c := newConf(t)
	for _, u := range []string{"uid", "mail"} {
		cfg := c.hcl(func(s string) string {
			return strings.Replace(s, "saml {", "claims { username = \""+u+"\" }\nsaml {", 1)
		})
		if _, err := c.load(t, cfg); err == nil || !strings.Contains(err.Error(), "scopes") {
			t.Errorf("%s with any IdP: %v", u, err)
		}
		one := strings.Replace(cfg, "saml {", "saml {\n  idps = [\"https://idp.univ-example.fr/idp\"]", 1)
		if _, err := c.load(t, one); err != nil {
			t.Errorf("%s with one IdP: %v", u, err)
		}
	}
}

// Every request is bounded in time and size.
func TestServerIsBounded(t *testing.T) {
	f := newFixture(t, "")
	srv := f.s.httpServer(nil)
	if srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 || srv.ReadHeaderTimeout == 0 {
		t.Errorf("timeouts %v %v %v %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()
	res, err := http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("x="+strings.Repeat("a", 2*maxBody)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// Cut off at the limit, so not read -- rather than read whole and
	// then refused for its client, which is what an unbounded server says.
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "could not be read") {
		t.Errorf("a body twice the limit: %d %s", res.StatusCode, b)
	}
}

// A newline in what was sent does not make a log line of its own.
func TestLogLinesCannotBeForged(t *testing.T) {
	var b bytes.Buffer
	s := &server{log: &b}
	s.logf("acs: said no: %v", "denied\nlogin: alice@univ-example.fr via idp for web")
	if lines := strings.Count(b.String(), "\n"); lines != 1 {
		t.Errorf("%d lines: %q", lines, b.String())
	}
}

// The ssf scope is for client credentials, never a login.
func TestSSFScopeNotForALogin(t *testing.T) {
	f := ssfFixture(t)
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	if _, err := (&oauth2.Config{ClientID: "rclone", Endpoint: ep, Scopes: []string{"openid", "ssf"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("a device grant for the ssf scope")
	}
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "ssf")
	if loc, _ := authorizeRefused(t, f, r.authURL()); loc == nil || loc.Query().Get("error") != "invalid_scope" {
		t.Errorf("a login for the ssf scope: %v", loc)
	}
}

// Two requests with the same refresh token at once: one rotates, the
// other is reuse, and the family goes -- every time, whichever wins.
func TestConcurrentRotationRevokesTheFamily(t *testing.T) {
	f := newFixture(t, deviceClients)
	f.s.poll = 1e9
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	cfg := &oauth2.Config{ClientID: "rclone", Endpoint: ep}
	for round := range 10 {
		tok := f.deviceToken("rclone", "openid")
		var wg sync.WaitGroup
		got := make([]*oauth2.Token, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[i], _ = cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
			}()
		}
		wg.Wait()
		for _, g := range got {
			if g == nil {
				continue
			}
			if _, err := cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: g.RefreshToken}).Token(); err == nil {
				t.Fatalf("round %d: the family survived the same refresh token used twice", round)
			}
		}
	}
}

var ssfStreamConfig = ssf.StreamConfig{EventsRequested: []string{eventSessionRevoked}, Delivery: ssf.Delivery{Method: deliveryPoll}}

// A full store pushes out its oldest entry, and keeps its ceiling.
func TestAFullStoreEvictsTheOldest(t *testing.T) {
	now := time.Now()
	tt := newTTL[int](func() time.Time { return now }).capped(3).evicting()
	for i, k := range []string{"a", "b", "c", "d"} {
		if err := tt.put(k, i, now.Add(time.Minute)); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	if _, ok := tt.get("a"); ok {
		t.Error("the oldest entry is still there")
	}
	for _, k := range []string{"b", "c", "d"} {
		if _, ok := tt.get(k); !ok {
			t.Errorf("%s was evicted", k)
		}
	}
	if n := tt.count(); n != 3 {
		t.Errorf("%d entries held, ceiling 3", n)
	}
	// An entry taken before it is evicted is not counted twice.
	tt.take("b")
	tt.put("e", 5, now.Add(time.Minute))
	tt.put("f", 6, now.Add(time.Minute))
	if _, ok := tt.get("c"); ok {
		t.Error("c should have gone, the oldest once b was taken")
	}
	if _, ok := tt.get("d"); !ok {
		t.Error("d went though b's taking had made room")
	}
	// Without evicting, the ceiling still refuses.
	plain := newTTL[int](func() time.Time { return now }).capped(1)
	plain.put("x", 1, now.Add(time.Minute))
	if err := plain.put("y", 2, now.Add(time.Minute)); err != errFull {
		t.Errorf("a store that does not evict: %v", err)
	}
}

// One host holds a whole IPv6 /64, and one site a /48 or an IPv4 /24: the
// limit is theirs, not each address's. Measured before: 20,000 logins from
// one /64 in 134 ms.
func TestTheLimitIsPerNetwork(t *testing.T) {
	now := time.Now()
	l := newRateLimiter(120, func() time.Time { return now })
	allowed := func(addrs func(i int) string, n int) int {
		ok := 0
		for i := range n {
			if l.allow(addrs(i)) {
				ok++
			}
		}
		return ok
	}
	// Distinct addresses of one /64.
	if n := allowed(func(i int) string { return fmt.Sprintf("2001:db8:1:2::%x", i+1) }, 1000); n != 120 {
		t.Errorf("one /64: %d of 1000 allowed, want 120", n)
	}
	// Distinct /64s of one /48: ten allowances, then nothing.
	if n := allowed(func(i int) string { return fmt.Sprintf("2001:db8:1:%x::1", i+3) }, 5000); n != 120*coarseFactor-120 {
		t.Errorf("one /48: %d allowed, want %d", n, 120*coarseFactor-120)
	}
	// Another network is unaffected.
	if !l.allow("2001:db8:2::1") || !l.allow("192.0.2.1") {
		t.Error("another network was refused")
	}
	// IPv4: each address its own, a /24 shared at ten times.
	if n := allowed(func(i int) string { return fmt.Sprintf("198.51.100.%d", i%250+1) }, 5000); n != 120*coarseFactor {
		t.Errorf("one /24: %d allowed, want %d", n, 120*coarseFactor)
	}
	// A minute later, refilled.
	now = now.Add(time.Minute)
	if !l.allow("2001:db8:1:2::1") {
		t.Error("not refilled after a minute")
	}
}
