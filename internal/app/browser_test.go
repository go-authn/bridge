// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	wa "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"golang.org/x/oauth2"
)

// The real-browser lane. Everything else in this repository drives the
// provider with a Go client that fills in the forms and builds the WebAuthn
// messages itself, which is how #100's bug shipped: a browser serialises the
// Origin of a form post as "null", no Go client does. This lane drives a
// headless Chrome through the provider's REAL pages and the REAL passkey.js,
// with the DevTools WebAuthn domain's virtual authenticator as the person's
// device. No request is made on the browser's behalf.
//
// BRIDGE_REQUIRE_BROWSER=1 turns "no Chrome" from a skip into a failure, as
// BRIDGE_REQUIRE_JUDGE does for the judges (ci.yml sets it). BRIDGE_CHROME
// names a binary; otherwise chromedp looks for Chrome or Chromium itself.

const browserTimeout = 3 * time.Minute

// startChrome returns a context on a fresh headless Chrome, or skips (fails,
// when BRIDGE_REQUIRE_BROWSER is set) if there is none.
func startChrome(t *testing.T) context.Context {
	t.Helper()
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Flag("headless", true))
	if p := os.Getenv("BRIDGE_CHROME"); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}
	// A CI container runs as root, or on a kernel that refuses Chrome's
	// sandbox its user namespace; the pages are this repository's own.
	if os.Geteuid() == 0 || os.Getenv("CI") != "" {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancel)
	ctx, cancel2 := chromedp.NewContext(actx)
	t.Cleanup(cancel2)
	ctx, cancel3 := context.WithTimeout(ctx, browserTimeout)
	t.Cleanup(cancel3)
	if _, err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		if os.Getenv("BRIDGE_REQUIRE_BROWSER") != "" {
			t.Fatalf("BRIDGE_REQUIRE_BROWSER is set and there is no Chrome to run the pages in: %v", err)
		}
		t.Skipf("no Chrome to run the pages in: %v", err)
	}
	return ctx
}

// page is a browser and what a test says to it.
type page struct {
	t   *testing.T
	ctx context.Context
}

func (p *page) eval(js string, into any) error {
	switch v := into.(type) {
	case *bool:
		r, err := chromedp.Run(p.ctx, chromedp.Evaluate[bool](js))
		*v = r
		return err
	case *int:
		r, err := chromedp.Run(p.ctx, chromedp.Evaluate[int](js))
		*v = r
		return err
	case *string:
		r, err := chromedp.Run(p.ctx, chromedp.Evaluate[string](js))
		*v = r
		return err
	case *[]string:
		r, err := chromedp.Run(p.ctx, chromedp.Evaluate[[]string](js))
		*v = r
		return err
	}
	panic("eval: unsupported result type")
}

// dump says where the browser is and what it shows, for a failure.
func (p *page) dump() {
	var href, text string
	p.eval(`location.href`, &href)
	p.eval(`document.body ? document.body.innerText : "(no body)"`, &text)
	p.t.Logf("the browser is at %s and shows:\n%s", href, text)
}

func (p *page) fatalf(format string, a ...any) {
	p.t.Helper()
	p.dump()
	p.t.Fatalf(format, a...)
}

// waitFor polls a JavaScript predicate for up to thirty seconds. Right after a
// navigation the old execution context can answer with an error: that is
// retried, not reported.
func (p *page) waitFor(what, js string) {
	p.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		var ok bool
		if err := p.eval(js, &ok); err == nil && ok {
			return
		}
		if time.Now().After(deadline) {
			p.fatalf("timed out waiting for %s", what)
		}
	}
}

func (p *page) goTo(u string) {
	p.t.Helper()
	if _, err := chromedp.Run(p.ctx, chromedp.Navigate(u)); err != nil {
		p.fatalf("navigating to %s: %v", u, err)
	}
}

// click waits until the element is there and enabled, then clicks it with a
// real mouse event.
func (p *page) click(sel string) {
	p.t.Helper()
	p.waitFor(sel+" to be enabled", fmt.Sprintf(`(() => { const e = document.querySelector(%q); return !!e && !e.disabled; })()`, sel))
	if _, err := chromedp.Run(p.ctx, chromedp.Click(sel)); err != nil {
		p.fatalf("clicking %s: %v", sel, err)
	}
}

func (p *page) count(sel string) int {
	p.t.Helper()
	var n int
	if err := p.eval(fmt.Sprintf(`document.querySelectorAll(%q).length`, sel), &n); err != nil {
		p.fatalf("counting %s: %v", sel, err)
	}
	return n
}

// ---- the virtual authenticator ----

func (p *page) call(f func(ctx context.Context, t *chromedp.Target) error) {
	p.t.Helper()
	if _, err := chromedp.Run(p.ctx, chromedp.Func(f)); err != nil {
		p.fatalf("a DevTools call: %v", err)
	}
}

func (p *page) enableWebAuthn() {
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		no := false
		_, err := cdp.Call(ctx, t, wa.Enable, wa.EnableParams{EnableUI: &no})
		return err
	})
}

// device adds a virtual CTAP2 authenticator that holds discoverable
// credentials and performs user verification.
func (p *page) device() wa.AuthenticatorID {
	p.t.Helper()
	var id wa.AuthenticatorID
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		r, err := cdp.Call(ctx, t, wa.AddVirtualAuthenticator, wa.AddVirtualAuthenticatorParams{Options: &wa.VirtualAuthenticatorOptions{
			Protocol:                    wa.AuthenticatorProtocolCtap2,
			Ctap2version:                wa.Ctap2versionCtap21,
			Transport:                   wa.AuthenticatorTransportInternal,
			HasResidentKey:              true,
			HasUserVerification:         true,
			IsUserVerified:              true,
			AutomaticPresenceSimulation: true,
		}})
		id = r.AuthenticatorID
		return err
	})
	return id
}

func (p *page) credentials(id wa.AuthenticatorID) []*wa.Credential {
	p.t.Helper()
	var out []*wa.Credential
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		r, err := cdp.Call(ctx, t, wa.GetCredentials, wa.GetCredentialsParams{AuthenticatorID: id})
		out = r.Credentials
		return err
	})
	return out
}

func (p *page) removeDevice(id wa.AuthenticatorID) {
	p.t.Helper()
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		_, err := cdp.Call(ctx, t, wa.RemoveVirtualAuthenticator, wa.RemoveVirtualAuthenticatorParams{AuthenticatorID: id})
		return err
	})
}

func (p *page) putCredential(id wa.AuthenticatorID, c *wa.Credential) {
	p.t.Helper()
	// Sent by hand: the generated type always writes generateCmtgKeyOnNextOperation,
	// which a device without the CMTG extension refuses even when false.
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		return t.Call(ctx, wa.CommandAddCredential, map[string]any{
			"authenticatorId": id,
			"credential": map[string]any{
				"credentialId": c.CredentialID, "isResidentCredential": c.IsResidentCredential, "rpId": c.RpID,
				"privateKey": c.PrivateKey, "userHandle": c.UserHandle, "signCount": c.SignCount,
				"backupEligibility": c.BackupEligibility, "backupState": c.BackupState,
			},
		}, nil)
	})
}

func (p *page) cookies() []*network.Cookie {
	p.t.Helper()
	var out []*network.Cookie
	p.call(func(ctx context.Context, t *chromedp.Target) error {
		r, err := cdp.Call(ctx, t, network.GetCookies, network.GetCookiesParams{})
		out = r.Cookies
		return err
	})
	return out
}

// ---- the lane ----

// TestRealBrowserPasskeyLifecycle is one person's whole story, in Chrome:
// enrol from an invitation, sign in to an OIDC client, confirm with the passkey
// (the step-up), add a second passkey from the account page, sign in with it,
// remove the first one, and be refused when the first one tries.
func TestRealBrowserPasskeyLifecycle(t *testing.T) {
	ctx := startChrome(t)
	p := &page{t: t, ctx: ctx}

	// The OIDC client's redirect URI is a server this test runs: what reaches it
	// is what the browser was sent to.
	callbacks := make(chan url.Values, 8)
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" { // Chrome asks for /favicon.ico too
			http.NotFound(w, r)
			return
		}
		callbacks <- r.URL.Query()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "signed in")
	}))
	t.Cleanup(cb.Close)
	redirect := cb.URL + "/callback"

	fixtureAsLocalhost = true
	defer func() { fixtureAsLocalhost = false }()
	f := newFixture(t, localExtra(t)+fmt.Sprintf("client \"browser\" {\n  redirect_uris = [%q]\n}\n", redirect))
	issuer := f.s.cfg.Issuer
	if !strings.HasPrefix(issuer, "http://localhost:") {
		t.Fatalf("the provider is at %s: a browser takes only a name as an RP ID", issuer)
	}
	t.Cleanup(func() {
		if t.Failed() {
			p.dump()
		}
	})
	p.enableWebAuthn()

	// signIn is an OIDC login through the pages: the choice between the
	// federation and a local account, the passkey page, the form post that ends
	// it. It returns the ID token's subject, or "" when the page refused.
	signIn := func(wantRefused bool) string {
		t.Helper()
		for len(callbacks) > 0 {
			<-callbacks
		}
		r := newRP(t, f, "browser", "", redirect)
		p.goTo(r.authURL())
		p.click(`a[href="local/login"]`)
		p.click("#passkey-button")
		if wantRefused {
			p.waitFor("the refusal", `document.body.innerText.includes("Passkey refused")`)
			select {
			case q := <-callbacks:
				p.fatalf("a refused passkey reached the client: %v", q)
			case <-time.After(750 * time.Millisecond):
			}
			return ""
		}
		var q url.Values
		select {
		case q = <-callbacks:
		case <-time.After(30 * time.Second):
			p.fatalf("the login never reached the client's redirect URI")
		}
		if q.Get("state") != r.state || q.Get("iss") != issuer || q.Get("code") == "" {
			t.Fatalf("what reached the client: %v", q)
		}
		tok, err := r.cfg.Exchange(t.Context(), q.Get("code"), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatalf("the code exchange: %v", err)
		}
		id := jwtClaims(t, tok.Extra("id_token").(string))
		if id["acr"] != localACR || id["nonce"] != r.nonce {
			t.Errorf("id token acr/nonce = %v/%v", id["acr"], id["nonce"])
		}
		if at := jwtClaims(t, tok.AccessToken); at["preferred_username"] != "alice" {
			t.Errorf("access token preferred_username = %v", at["preferred_username"])
		}
		return fmt.Sprint(id["sub"])
	}
	keysOf := func() []*passkeyRecord {
		t.Helper()
		keys, err := f.s.passkeys.passkeys("alice")
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}

	// 1. Enrolment from an invitation, with the first device.
	laptop := p.device()
	p.goTo(issuer + "/local/enroll#" + f.invite("alice"))
	p.click("#passkey-button")
	p.waitFor("the enrolment to finish", `document.getElementById("passkey-status").textContent.includes("registered")`)
	var href string
	p.eval(`location.href`, &href)
	if strings.Contains(href, "#") {
		t.Errorf("the invitation token is still in the address bar: %s", href)
	}
	creds1 := p.credentials(laptop)
	if len(creds1) != 1 || len(keysOf()) != 1 {
		t.Fatalf("after the enrolment the device holds %d credentials and the account %d", len(creds1), len(keysOf()))
	}
	key1 := passkeyKey(creds1[0].CredentialID)
	if keysOf()[0].key() != key1 {
		t.Fatalf("the stored key is not the device's credential")
	}

	// 2. An OIDC login with that passkey, to a client.
	sub := signIn(false)
	if sub == "" || strings.Contains(sub, "alice") {
		t.Fatalf("subject = %q", sub)
	}
	if rec, _, _ := f.s.passkeys.passkey(key1); rec == nil || rec.LastUsed.IsZero() {
		t.Error("the login did not record the passkey's use")
	}

	// 3. The step-up: the account page asks for a fresh assertion first.
	p.goTo(issuer + "/local/account")
	if p.count("[data-remove]") != 0 || p.count(`#passkey-button[data-mode="stepup"]`) != 1 {
		p.fatalf("the account page shows more than a confirmation before the step-up")
	}
	p.click("#passkey-button")
	p.waitFor("the key list", `!!document.getElementById("account")`)
	var cookie *network.Cookie
	for _, c := range p.cookies() {
		if c.Name == accountCookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HTTPOnly || cookie.SameSite != network.CookieSameSiteStrict || cookie.Path != "/" {
		t.Errorf("the session cookie in the browser: %+v", cookie)
	}
	var visible string
	var stored int
	p.eval(`document.cookie`, &visible)
	p.eval(`localStorage.length + sessionStorage.length`, &stored)
	if strings.Contains(visible, "bridge-account") || stored != 0 {
		t.Errorf("the page can read the session (document.cookie=%q) or stores something (%d items)", visible, stored)
	}
	var rows []string
	p.eval(`Array.from(document.querySelectorAll("#account li")).map(li => li.innerText)`, &rows)
	if len(rows) != 1 || !strings.Contains(rows[0], key1[:16]) || !strings.Contains(rows[0], "this confirmation") {
		t.Fatalf("the key list after the step-up: %q", rows)
	}

	// 4. Add a second passkey. The first device is taken away for it: its
	// credential is excluded, so one device holds one key per account. The
	// session is the browser's, and outlives the device.
	p.removeDevice(laptop)
	phone := p.device()
	p.click(`#passkey-button[data-mode="add"]`)
	p.waitFor("the second key", `document.querySelectorAll("[data-remove]").length === 2`)
	creds2 := p.credentials(phone)
	if len(creds2) != 1 || len(keysOf()) != 2 {
		t.Fatalf("after the add the phone holds %d credentials and the account %d", len(creds2), len(keysOf()))
	}
	key2 := passkeyKey(creds2[0].CredentialID)
	if key2 == key1 {
		t.Fatal("the second passkey is the first")
	}
	p.eval(`Array.from(document.querySelectorAll("#account li")).map(li => li.innerText)`, &rows)
	for _, r := range rows {
		if strings.Contains(r, key1[:16]) != strings.Contains(r, "this confirmation") {
			t.Errorf("the current key is not the one the step-up was made with:\n%s", r)
		}
	}

	// 5. A login with the second passkey: the same person.
	if got := signIn(false); got != sub {
		t.Errorf("the second passkey signed in as another subject: %q vs %q", got, sub)
	}
	if rec, _, _ := f.s.passkeys.passkey(key2); rec == nil || rec.LastUsed.IsZero() {
		t.Error("the second passkey's use was not recorded")
	}

	// 6. Remove the first passkey from the page (its confirmation was made with
	// it, so the confirmation ends with it).
	p.goTo(issuer + "/local/account")
	p.waitFor("the key list", `!!document.getElementById("account")`)
	p.eval(`(window.confirm = () => true, true)`, new(bool))
	p.click(fmt.Sprintf(`[data-remove=%q]`, key1))
	p.waitFor("the confirmation to end", `!!document.querySelector('#passkey-button[data-mode="stepup"]')`)
	if keys := keysOf(); len(keys) != 1 || keys[0].key() != key2 {
		t.Fatalf("after the removal alice's keys are %d, not just the second", len(keys))
	}

	// 7. The control: the remaining passkey still signs in. 8. The removed
	// one is refused, from a device that really holds it.
	if got := signIn(false); got != sub {
		t.Errorf("control: the remaining passkey signed in as %q, want %q", got, sub)
	}
	p.removeDevice(phone)
	old := p.device()
	p.putCredential(old, creds1[0])
	if len(p.credentials(old)) != 1 {
		t.Fatal("the removed credential could not be put back on a device")
	}
	signIn(true)
}
