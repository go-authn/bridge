// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ssf "github.com/hstern/go-ssf"
	"golang.org/x/oauth2"
)

// A code used twice takes back the refresh token its first use bought, not
// only the access token: that one outlives it by a month.
func TestCodeUsedTwiceRevokesTheFamily(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "s")
	os.WriteFile(secret, []byte("a-secret-long-enough-to-pass"), 0o600)
	f := newFixture(t, `
client "webr" {
  secret_file      = "`+filepath.ToSlash(secret)+`"
  redirect_uris    = ["http://127.0.0.1:9/callback"]
  refresh_lifetime = "720h"
}
`)
	r := newRP(t, f, "webr", "a-secret-long-enough-to-pass", f.redirect)
	code := f.login(newBrowser(t), r.authURL(), alice).Query().Get("code")
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil || tok.RefreshToken == "" {
		t.Fatalf("exchange: %v, refresh %q", err, tok.RefreshToken)
	}
	if _, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier)); err == nil {
		t.Fatal("a code was exchanged twice")
	}
	if _, err := r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
		t.Error("the refresh token a replayed code bought still works")
	}
}

// What a receiver can make this provider keep is bounded: set errors for
// events that are not there are not counted; verification events do not
// pile up; streams are few per receiver.
func TestSSFReceiverCannotGrowState(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssfStreamConfig)
	if err != nil {
		t.Fatal(err)
	}
	setErrsMu.Lock()
	before := len(setErrs)
	setErrsMu.Unlock()
	errs := map[string]ssf.SetErr{}
	for i := range 500 {
		errs[fmt.Sprintf("never-%d", i)] = ssf.SetErr{Err: "invalid_key"}
	}
	ret := true
	if _, err := c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{SetErrs: errs, ReturnImmediately: &ret}); err != nil {
		t.Fatal(err)
	}
	setErrsMu.Lock()
	after := len(setErrs)
	setErrsMu.Unlock()
	if after != before {
		t.Errorf("%d set errors counted for events that never were", after-before)
	}

	for range 20 {
		if err := c.Verify(t.Context(), stream.StreamID, &ssf.VerificationRequest{State: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := pollAll(t, c, f.setVerifier(t), stream.StreamID); len(got) != 1 {
		t.Errorf("%d verification events waiting after 20 asks, want the last one", len(got))
	}

	for i := 1; i < maxStreamsPerReceiver; i++ {
		if _, err := c.CreateConfig(t.Context(), &ssfStreamConfig); err != nil {
			t.Fatalf("stream %d: %v", i+1, err)
		}
	}
	if _, err := c.CreateConfig(t.Context(), &ssfStreamConfig); err == nil {
		t.Errorf("stream %d made: a receiver has at most %d", maxStreamsPerReceiver+1, maxStreamsPerReceiver)
	}
}
