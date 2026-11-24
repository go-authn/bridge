package app

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// A SUCCESSFUL login leaves one line in the journal -- the operator who looks
// for who signed in, and from where, finds it -- and that line carries no
// secret: no code, no token, no assertion, no attribute of the person.

// logLine returns the one line of log that matches re, failing when none, or
// more than one, does.
func logLine(t *testing.T, log string, re string) string {
	t.Helper()
	rx := regexp.MustCompile(re)
	var got []string
	for _, l := range strings.Split(log, "\n") {
		if rx.MatchString(l) {
			got = append(got, l)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly one log line matching %q, got %d, in:\n%s", re, len(got), log)
	}
	return got[0]
}

// noneOf fails when the log holds any of the secrets.
func noneOf(t *testing.T, log string, secrets map[string]string) {
	t.Helper()
	for what, s := range secrets {
		if s == "" {
			t.Fatalf("the test has no %s to look for", what)
		}
		if strings.Contains(log, s) {
			t.Errorf("the log holds the %s:\n%s", what, log)
		}
	}
}

func TestLocalPasskeyLoginIsLogged(t *testing.T) {
	f := localFixture(t, "")
	var logs bytes.Buffer
	f.s.log = &logs
	alice := f.enrolled("alice", webauthn.AlgES256)
	web, _ := f.s.cfg.client("web")
	web.refreshTTL = time.Hour // the fixture's client holds no refresh token otherwise
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	res := f.passkeyLogin(b, alice, "alice", csrf, webauthntest.Options{})
	code := location(t, res).Query().Get("code")
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token to rotate")
	}
	rotated, err := r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := f.s.passkeys.passkeys("alice")
	if len(recs) != 1 {
		t.Fatalf("passkeys: %+v", recs)
	}
	log := logs.String()
	if tl := logLine(t, log, `^token: refresh_token issued `); tl != "token: refresh_token issued to web for alice" {
		t.Errorf("the refresh line is %q", tl)
	}

	line := logLine(t, log, `^login: `)
	want := "login: alice via " + f.s.cfg.Issuer + "/local with passkey " + recs[0].key()[:8] + " for web from "
	if !strings.HasPrefix(line, want) || strings.Contains(line, " from  ") || strings.HasSuffix(line, " from ") {
		t.Errorf("the login line is %q, want it to start with %q and end with an address", line, want)
	}
	if tl := logLine(t, log, `^token: authorization_code issued `); tl != "token: authorization_code issued to web for alice" {
		t.Errorf("the token line is %q", tl)
	}
	secrets := map[string]string{
		"code": code, "access token": tok.AccessToken, "ID token": tok.Extra("id_token").(string),
		"csrf": csrf, "credential key": recs[0].key(), "mail": "alice@mesocentre.example", "name": "Alice Martin",
	}
	secrets["refresh token"] = tok.RefreshToken
	secrets["rotated refresh token"] = rotated.RefreshToken
	secrets["rotated access token"] = rotated.AccessToken
	noneOf(t, log, secrets)
}

func TestFederatedLoginIsLogged(t *testing.T) {
	f := newFixture(t, "")
	var logs bytes.Buffer
	f.s.log = &logs
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
	back := f.login(newBrowser(t), r.authURL(), alice)
	code := back.Query().Get("code")
	tok, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	log := logs.String()

	line := logLine(t, log, `^login: `)
	if !strings.Contains(line, " via "+idpEntity+" for web from ") || strings.HasSuffix(line, " from ") {
		t.Errorf("the login line is %q: want the IdP, the client and an address", line)
	}
	if tl := logLine(t, log, `^token: authorization_code issued `); !strings.HasPrefix(tl, "token: authorization_code issued to web for ") {
		t.Errorf("the token line is %q", tl)
	}
	noneOf(t, log, map[string]string{
		"code": code, "access token": tok.AccessToken, "ID token": tok.Extra("id_token").(string),
		"name": "Alice Martin", "SAMLResponse": "PHNhbWw",
	})
}

func TestAccountSignInsAreLogged(t *testing.T) {
	f := localFixture(t, "")
	var logs bytes.Buffer
	f.s.log = &logs
	laptop := f.enrolled("alice", webauthn.AlgES256)

	// A passkey step-up.
	res := f.stepUpRaw(laptop, "alice", webauthntest.Options{})
	readBody(res)
	cookie := accountCookieOf(res)
	line := logLine(t, logs.String(), `^account: audit: alice stepup `)
	if !strings.Contains(line, " from ") || strings.HasSuffix(line, " from ") {
		t.Errorf("the step-up line is %q", line)
	}

	// The confirmation through an institution.
	sess := f.federatedSession(alice)
	log := logs.String()
	line = logLine(t, log, `^account: .* confirmed through `)
	if !strings.Contains(line, " confirmed through "+idpEntity+" from ") || strings.HasSuffix(line, " from ") {
		t.Errorf("the ACS line is %q", line)
	}
	logLine(t, log, `^account: audit: .* confirm federation from `)
	noneOf(t, log, map[string]string{
		"step-up session cookie": cookie, "federated session cookie": sess.cookie, "csrf": sess.csrf, "name": "Alice Martin",
	})
}
