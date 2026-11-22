// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// The suspicions of the 2026-11-21 security audit, each stated as what must
// hold.

// kerberosLocal is a local account "alice" with two passkeys, a Kerberos
// block and a client for it. It returns the fixture, the stub KDC, and a
// token bought with the first key.
func kerberosLocal(t *testing.T) (*fixture, *stubKDC, *webauthntest.Authenticator, string) {
	t.Helper()
	dir := t.TempDir()
	k, kdcURL := newStubKDC(t, dir)
	f := localFixture(t, `
kerberos {
  kdc_url   = "`+kdcURL+`"
  ca_file   = "`+filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem"))+`"
  cert_file = "`+filepath.ToSlash(filepath.Join(dir, "bridge.pem"))+`"
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "bridge.key"))+`"
}
client "kinit" {
  redirect_uris    = ["http://127.0.0.1/callback"]
  kerberos_tickets = true
}
`)
	a := f.enrolled("alice", webauthn.AlgES256)
	f.enrolled("alice", webauthn.AlgES256) // the key that stays
	r := newRP(t, f, "kinit", "", "http://127.0.0.1/callback", "kerberos")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.passkeyLogin(b, a, "alice", csrf, webauthntest.Options{}))
	tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	return f, k, a, tok.AccessToken
}

func removeKey(t *testing.T, f *fixture, a *webauthntest.Authenticator) {
	t.Helper()
	if _, err := f.s.passkeys.del(kindPasskey, passkeyKey(a.ID)); err != nil {
		t.Fatal(err)
	}
}

// 1: a token bought with a passkey stops minting when that passkey is gone,
// though the account has another one. Refresh grants are held to the key
// (localAccountGone); a Kerberos ticket must be too.
func TestSuspicion1KerberosRefusesATokenWhosePasskeyWasRemoved(t *testing.T) {
	f, k, a, tok := kerberosLocal(t)
	removeKey(t, f, a)
	if st, body, _ := postTGT(t, f, tok); st != http.StatusUnauthorized {
		t.Errorf("a token of a removed passkey bought a ticket: %d %.40q", st, body)
	}
	if len(k.asked) != 0 {
		t.Errorf("the KDC was asked %d times for a token whose passkey is gone", len(k.asked))
	}
}

// 1, the recheck: the key goes while the KDC is being asked.
func TestSuspicion1KerberosRecheckAfterMintingHoldsTheTokenToItsPasskey(t *testing.T) {
	f, k, a, tok := kerberosLocal(t)
	k.during = func() { removeKey(t, f, a) }
	if st, body, _ := postTGT(t, f, tok); st != http.StatusUnauthorized {
		t.Errorf("a ticket left after its passkey was removed during minting: %d %.40q", st, body)
	}
}

// 1, control: a token of the key that stays still buys one.
func TestSuspicion1KerberosControlTheOtherKeyStillBuys(t *testing.T) {
	f, _, _, _ := kerberosLocal(t)
	other := f.enrolled("alice", webauthn.AlgEdDSA)
	r := newRP(t, f, "kinit", "", "http://127.0.0.1/callback", "kerberos")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.passkeyLogin(b, other, "alice", csrf, webauthntest.Options{}))
	tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if st, body, _ := postTGT(t, f, tok.AccessToken); st != http.StatusOK {
		t.Errorf("control: %d %.40q", st, body)
	}
}

// 3: the ticket's lifetime is taken from the provider's clock, like every
// other time here. A clock an hour behind the wall's sees a session that ends in
// 30 minutes.
func TestSuspicion3KerberosLifetimeUsesTheProvidersClock(t *testing.T) {
	f, k := kerberosFixture(t)
	tok := f.deviceTokenAs("kinit", alice, "openid", "kerberos")
	claims := jwtClaims(t, tok.AccessToken)
	jti := token()
	wall := time.Now()
	at := wall.Add(-time.Hour)
	forged, err := f.s.cfg.accessKey.sign("at+jwt", map[string]any{
		"iss": f.s.cfg.Issuer, "sub": claims["sub"], "aud": f.s.cfg.Issuer, "client_id": "kinit",
		"exp": wall.Add(time.Hour).Unix(), "iat": wall.Unix(), "jti": jti, "scope": "openid kerberos",
		"preferred_username": "alice@" + idpScope, "idp": idpEntity,
		"session_end": at.Add(30 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.issued.put(jti, issuedToken{info: map[string]any{"sub": claims["sub"]}, username: "alice@" + idpScope, idp: idpEntity}, wall.Add(time.Hour))
	f.s.now = func() time.Time { return at }
	defer func() { f.s.now = time.Now }()
	if st, body, _ := postTGT(t, f, forged); st != http.StatusOK {
		t.Fatalf("%d %.40q", st, body)
	}
	if secs, _ := k.asked[0]["lifetime_seconds"].(float64); secs < 29*60 || secs > 30*60 {
		t.Errorf("lifetime %v s, want the 30 minutes the provider's clock leaves", secs)
	}
}

// 4: a display name holds no character that reorders or hides text.
func TestSuspicion4DisplayNameRefusesBidiAndInvisibleCharacters(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	s := f.signedIn(alice, "alice")
	u := func(r rune) string { return string(r) }
	for name, v := range map[string]string{
		"a right-to-left override":  "Alice " + u(0x202E) + "evil",
		"an isolate":                "Alice " + u(0x2066) + "x",
		"a left-to-right mark":      "Alice" + u(0x200E),
		"a zero-width space":        "Al" + u(0x200B) + "ice",
		"a word joiner":             "Al" + u(0x2060) + "ice",
		"a byte order mark":         u(0xFEFF) + "Alice",
		"a line separator":          "Alice" + u(0x2028) + "Bob",
		"an Arabic letter mark":     "Alice" + u(0x061C),
		"a soft hyphen (invisible)": "Al" + u(0x00AD) + "ice",
	} {
		f.resetThrottle()
		if st, _ := f.acctPost(s, "/account/profile", map[string]any{"name": v}); st != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, st)
		}
	}
	if n, ok := f.s.displayNameOf("alice"); ok {
		t.Errorf("a refused name was stored: %q", n)
	}
	// Controls: a script that needs its joiner, and ordinary names.
	for name, v := range map[string]string{
		"Persian, with a ZWNJ": "mi" + u(0x200C) + "khahem",
		"Hindi":                "क्षत्रिय",
		"plain":                "Alice Martin",
		"accents":              "Zoë Durand-Ñu",
	} {
		f.resetThrottle()
		if st, msg := f.acctPost(s, "/account/profile", map[string]any{"name": v}); st != http.StatusOK {
			t.Errorf("%s: %d %s, want 200", name, st, msg)
		}
	}
}

// 6: an enrolment that began under the cap does not finish over it.
func TestSuspicion6EnrolmentFinishHoldsTheCap(t *testing.T) {
	f := localFixture(t, "")
	for i := 0; i < maxPasskeys-1; i++ {
		f.enrolled("alice", webauthn.AlgES256)
	}
	b := newBrowser(t)
	st, handle, ch, _ := f.enrollBegin(b, f.invite("alice"))
	if st != http.StatusOK {
		t.Fatalf("begin under the cap: %d", st)
	}
	// The account page adds the tenth key meanwhile.
	x := mustAuth(t, webauthn.AlgES256)
	if err := f.s.passkeys.savePasskey(&passkeyRecord{Login: "alice", ID: x.ID, PublicKey: x.COSE, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := f.enrollFinish(b, mustAuth(t, webauthn.AlgES256), handle, ch, webauthntest.Options{}); got != http.StatusConflict {
		t.Errorf("an eleventh passkey was enrolled: %d, want 409", got)
	}
	if keys, _ := f.s.passkeys.passkeys("alice"); len(keys) != maxPasskeys {
		t.Errorf("alice has %d passkeys, want %d", len(keys), maxPasskeys)
	}
}

// 8: a parameter NAME is shown escaped.
func TestSuspicion8AuthorizeEscapesAParameterName(t *testing.T) {
	f := localFixture(t, "")
	b := newBrowser(t)
	res := b.get(f.s.cfg.Issuer + "/authorize?%3Cscript%3Ealert(1)%3C/script%3E=1&%3Cscript%3Ealert(1)%3C/script%3E=2")
	body := readBody(res)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "appears more than once") {
		t.Fatalf("premise: %d %.200q", res.StatusCode, body)
	}
	if strings.Contains(body, "<script>alert") {
		t.Errorf("the parameter name came out as markup:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the name is not shown escaped:\n%s", body)
	}
}
