// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

// OpenPubkey, judged by the openpubkey library itself: its client makes a
// PK Token through this provider -- the user's key committed in the nonce --
// and its verifier checks it, the way opkssh verify does on an SSH server.

func opkOp(f *fixture, clientID string, device, gq bool, redirect string) providers.BrowserOpenIdProvider {
	opts := providers.GetDefaultStandardOpOptions(f.s.cfg.Issuer, clientID)
	opts.Scopes = []string{"openid profile"}
	opts.DeviceFlow = device
	opts.GQSign = gq
	opts.OpenBrowser = false
	if redirect != "" {
		opts.RedirectURIs = []string{redirect}
	}
	return providers.NewStandardOpWithOptions(opts)
}

// deviceApprove is the person on another device, for any client.
func (f *fixture) deviceApprove(complete string) {
	f.t.Helper()
	b := newBrowser(f.t)
	body, _ := io.ReadAll(b.get(complete).Body)
	m := csrfField.FindSubmatch(body)
	if m == nil {
		f.t.Fatalf("no confirmation page:\n%s", body)
	}
	u, _ := url.Parse(complete)
	next := location(f.t, b.post(f.s.cfg.Issuer+"/device", url.Values{"user_code": {u.Query().Get("user_code")}, "csrf": {string(m[1])}, "confirm": {"yes"}}))
	if strings.HasSuffix(next.Path, "/saml/choose") {
		next = location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+url.QueryEscape(idpEntity)))
	}
	reqID, relay := authnRequest(f.t, next)
	b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}})
}

// deviceAuth runs the openpubkey client's device flow to a PK Token.
func (f *fixture) deviceAuth(op providers.BrowserOpenIdProvider) *pktoken.PKToken {
	f.t.Helper()
	pr, pw := io.Pipe()
	if err := providers.SetOutWriter(op, pw); err != nil {
		f.t.Fatal(err)
	}
	c, err := client.New(op)
	if err != nil {
		f.t.Fatal(err)
	}
	type result struct {
		pkt *pktoken.PKToken
		err error
	}
	got := make(chan result, 1)
	go func() {
		pkt, err := c.Auth(context.Background())
		pw.Close()
		got <- result{pkt, err}
	}()
	sc := bufio.NewScanner(pr)
	var complete string
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Complete URL: "); ok {
			complete = strings.TrimSpace(rest)
			break
		}
	}
	go io.Copy(io.Discard, pr)
	if complete == "" {
		f.t.Fatal("the openpubkey client said nowhere to log in")
	}
	f.deviceApprove(complete)
	select {
	case r := <-got:
		if r.err != nil {
			f.t.Fatalf("the openpubkey client: %v", r.err)
		}
		return r.pkt
	case <-time.After(60 * time.Second):
		f.t.Fatal("the openpubkey client never got its PK Token")
	}
	return nil
}

const opkClients = `
client "opk" {
  device = true
  name   = "opkssh"
}
`

func TestOpenPubkeyDeviceFlow(t *testing.T) {
	f := newFixture(t, opkClients)
	f.s.poll = time.Second
	op := opkOp(f, "opk", true, false, "")
	pkt := f.deviceAuth(op)

	v, err := verifier.New(opkOp(f, "opk", true, false, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPKToken(t.Context(), pkt); err != nil {
		t.Fatalf("the openpubkey verifier refused the PK Token: %v", err)
	}
	// The PK Token is about alice, and its sub is this provider's.
	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.PreferredUsername != "alice@"+idpScope || claims.Sub == "" {
		t.Errorf("PK Token claims %+v", claims)
	}
}

// GQ signatures replace the provider's RSA signature by a proof of it, so
// that the ID token inside cannot be replayed elsewhere. They need RS256,
// which is what this provider signs with.
func TestOpenPubkeyGQ(t *testing.T) {
	f := newFixture(t, opkClients)
	f.s.poll = time.Second
	pkt := f.deviceAuth(opkOp(f, "opk", true, true, ""))
	v, err := verifier.New(opkOp(f, "opk", true, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPKToken(t.Context(), pkt); err != nil {
		t.Fatalf("a GQ-signed PK Token was refused: %v", err)
	}
}

// The authorization code flow on a loopback redirect, which is what opkssh
// login uses.
func TestOpenPubkeyCodeFlow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	redirect := fmt.Sprintf("http://localhost:%d/login-callback", port)
	f := newFixture(t, fmt.Sprintf(`
client "opkssh" {
  redirect_uris = [%q]
}
`, redirect))
	op := opkOp(f, "opkssh", false, false, redirect)
	providers.SetOutWriter(op, io.Discard)
	c, err := client.New(op)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *pktoken.PKToken, 1)
	fail := make(chan error, 1)
	go func() {
		pkt, err := c.Auth(context.Background())
		if err != nil {
			fail <- err
			return
		}
		got <- pkt
	}()
	// The client listens on its loopback port; the person's browser goes
	// to /login there, which sends it here.
	b := newBrowser(t)
	var start *http.Response
	for i := 0; i < 100; i++ {
		if r, err := b.c.Get(fmt.Sprintf("http://localhost:%d/login", port)); err == nil {
			start = r
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if start == nil {
		t.Fatal("the openpubkey client never listened")
	}
	authz := location(t, start)
	if authz.Query().Get("nonce") == "" || authz.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("the openpubkey client asked %s", authz)
	}
	back := f.login(b, authz.String(), alice)
	if back.Query().Get("code") == "" {
		t.Fatalf("no code: %s", back)
	}
	b.get(back.String())
	select {
	case pkt := <-got:
		v, err := verifier.New(opkOp(f, "opkssh", false, false, redirect))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyPKToken(t.Context(), pkt); err != nil {
			t.Fatalf("the openpubkey verifier refused the PK Token: %v", err)
		}
	case err := <-fail:
		t.Fatalf("the openpubkey client: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("no PK Token")
	}
}

// ⛔ A PK Token outlives the ID token inside it, and the openpubkey
// verifier fetches only the keys published NOW. After a rotation, a PK Token
// signed by the old key verifies while that key is listed as retired, and
// not once it is dropped.
func TestOpenPubkeyAfterRotation(t *testing.T) {
	f := newFixture(t, opkClients)
	f.s.poll = time.Second
	pkt := f.deviceAuth(opkOp(f, "opk", true, false, ""))

	old := f.s.cfg.signingKey
	p := filepath.Join(t.TempDir(), "new.key")
	if err := generateKey(p, 2048); err != nil {
		t.Fatal(err)
	}
	fresh, _ := loadSigningKey(p)
	f.s.cfg.signingKey, f.s.cfg.accessKey = fresh, fresh
	f.s.cfg.retiredKeys = []*signingKey{old}

	v, _ := verifier.New(opkOp(f, "opk", true, false, ""))
	if err := v.VerifyPKToken(t.Context(), pkt); err != nil {
		t.Fatalf("with the old key retired but published: %v", err)
	}
	f.s.cfg.retiredKeys = nil
	v, _ = verifier.New(opkOp(f, "opk", true, false, ""))
	if err := v.VerifyPKToken(t.Context(), pkt); err == nil {
		t.Fatal("a PK Token verified against a key nobody publishes: the test cannot see the rotation")
	}
}
