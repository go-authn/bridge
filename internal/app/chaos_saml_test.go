// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Chaos: the clocks disagree, and the federation's metadata server is slow,
// down, or serving something else. The provider must keep logging people in
// on the last good metadata, refuse what the clocks make invalid, and say so.

// The bridge's clock against the IdP's: within ClockSkew (three minutes)
// either way a login goes through; an hour either way it is refused, and
// refused cleanly -- a page, not a code.
func TestClockSkewAgainstTheIdP(t *testing.T) {
	f := newFixture(t, "")
	defer func() { f.s.now = time.Now }()
	for _, c := range []struct {
		offset time.Duration
		ok     bool
	}{
		{2 * time.Minute, true},
		{-2 * time.Minute, true},
		{time.Hour, false},
		{-time.Hour, false},
	} {
		t.Run(c.offset.String(), func(t *testing.T) {
			f.s.now = func() time.Time { return time.Now().Add(c.offset) }
			defer func() { f.s.now = time.Now }()
			b, reqID, relay := f.begin(t)
			raw, err := base64.StdEncoding.DecodeString(f.respond(reqID, assertionOpts{eppn: mallory}))
			if err != nil {
				t.Fatal(err)
			}
			who, st := f.post(t, b, relay, string(raw))
			switch {
			case c.ok && who != mallory:
				t.Fatalf("clock %s off: a login within the skew was refused (status %d)", c.offset, st)
			case !c.ok && who != "":
				t.Fatalf("clock %s off: logged %q in", c.offset, who)
			case !c.ok && st != http.StatusBadRequest:
				t.Fatalf("clock %s off: status %d, want a 400 page", c.offset, st)
			}
		})
	}
}

// A clock that steps back does not drain the rate limiter: before the fix,
// one hour back cost every known address 7,200 tokens (120 a minute) and
// its /24 ten times that, an hour of 429s.
func TestRateLimiterSurvivesAClockStepBack(t *testing.T) {
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	l := newRateLimiter(120, func() time.Time { return at })
	for range 3 {
		if !l.allow("192.0.2.7") {
			t.Fatal("refused before any step")
		}
	}
	at = at.Add(-time.Hour)
	if !l.allow("192.0.2.7") {
		t.Fatal("an address was locked out by the clock stepping back an hour")
	}
	if !l.allow("192.0.2.8") {
		t.Fatal("its network was locked out by the clock stepping back an hour")
	}
}

// chaosMetadata stands in front of the federation's metadata server and
// misbehaves on demand.
type chaosMetadata struct {
	srv  *httptest.Server
	good []byte
	mode atomic.Value // string
	hung chan struct{}
	once sync.Once
}

func newChaosMetadata(t *testing.T, f *fixture) *chaosMetadata {
	r, err := http.Get(f.metadata.URL)
	if err != nil {
		t.Fatal(err)
	}
	good, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	c := &chaosMetadata{good: good, hung: make(chan struct{})}
	c.mode.Store("ok")
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch c.mode.Load().(string) {
		case "ok":
			w.Write(c.good)
		case "slow":
			// Headers, a few bytes, then nothing until the client gives up.
			w.Write(c.good[:64])
			w.(http.Flusher).Flush()
			c.once.Do(func() { close(c.hung) })
			<-r.Context().Done()
		case "500":
			http.Error(w, "upstream down", http.StatusInternalServerError)
		case "garbage":
			w.Write([]byte("\x00\xff<not xml at all"))
		case "html":
			io.WriteString(w, "<html><body>maintenance</body></html>")
		case "truncated":
			w.Write(c.good[:len(c.good)/2])
		case "tampered":
			io.WriteString(w, strings.Replace(string(c.good), idpScope+"</shibmd:Scope>", "evil.example</shibmd:Scope>", 1))
		case "empty":
		}
	}))
	t.Cleanup(c.srv.Close)
	f.s.fed.URL = c.srv.URL
	return c
}

func TestMetadataServerChaos(t *testing.T) {
	f := newFixture(t, "")
	c := newChaosMetadata(t, f)
	ctx := t.Context()
	if err := f.s.refreshMetadata(ctx); err != nil {
		t.Fatalf("the metadata, unharmed, through the chaos server: %v", err)
	}
	loginWorks := func(when string) {
		t.Helper()
		r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
		if u := f.login(newBrowser(t), r.authURL(), assertionOpts{eppn: mallory}); u.Query().Get("code") == "" {
			t.Fatalf("%s: no login: %s", when, u)
		}
		if !f.s.ready() {
			t.Fatalf("%s: the provider says it is not ready", when)
		}
	}
	loginWorks("before")

	for _, mode := range []string{"500", "garbage", "html", "truncated", "tampered", "empty"} {
		c.mode.Store(mode)
		if err := f.s.refreshMetadata(ctx); err == nil {
			t.Errorf("%s: a refresh succeeded", mode)
		}
		loginWorks(mode)
	}
	// Down: nothing listens there.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	f.s.fed.URL = dead.URL
	if err := f.s.refreshMetadata(ctx); err == nil {
		t.Error("down: a refresh succeeded")
	}
	loginWorks("down")
	f.s.fed.URL = c.srv.URL

	// Slow: a refresh hanging on the server does not hold logins up, and
	// gives up with its context.
	c.mode.Store("slow")
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	done := make(chan error, 1)
	go func() { done <- f.s.refreshMetadata(hctx) }()
	select {
	case <-c.hung:
	case <-time.After(10 * time.Second):
		t.Fatal("the slow server was never reached")
	}
	loginWorks("during a hung refresh")
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("slow: a refresh succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a refresh did not end with its context")
	}
	loginWorks("after a hung refresh")

	// Back: the next refresh succeeds, and the failures were counted.
	c.mode.Store("ok")
	if err := f.s.refreshMetadata(ctx); err != nil {
		t.Fatalf("the server is back and the refresh still fails: %v", err)
	}
	f.s.fedState.mu.Lock()
	failed, ok := f.s.fedState.refreshes["failed"], f.s.fedState.refreshes["ok"]
	f.s.fedState.mu.Unlock()
	if failed != 8 || ok < 2 {
		t.Errorf("refreshes recorded: %d failed, %d ok; want 8 failed and at least 2 ok", failed, ok)
	}
}
