// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

const (
	localScope = "mesocentre.example"
	localGroup = "urn:geant:mesocentre.example:hpc:users"
)

func localAccountsText() string {
	return fmt.Sprintf(`# the mésocentre's people
account "alice" {
  name   = "Alice Martin"
  mail   = "alice@mesocentre.example"
  groups = [%q]
}

account "bob" {
  name = "Bob Durand"
}
`, localGroup)
}

// writeAccountsFile writes an accounts file, 0640.
func writeAccountsFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "accounts.hcl")
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// stateExtra is a state block over a SQLite file of its own.
func stateExtra(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	if err := os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "state.db"))+"?_pragma=busy_timeout(5000)"), 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("state {\n  driver = \"sqlite\"\n  dsn_file = %q\n}\n", filepath.ToSlash(dsn))
}

// localExtra is the local block (and the state it needs) for a fixture's
// configuration.
func localExtra(t *testing.T) string {
	t.Helper()
	// The fixtures remove a key at once (the delay is 0), as before the delay
	// existed; the tests of the delay set f.s.cfg.Local.removalDelay.
	return fmt.Sprintf("local {\n  accounts_file = %q\n  scope = %q\n  passkey_removal_delay = \"0\"\n}\n", filepath.ToSlash(writeAccountsFile(t, localAccountsText())), localScope) + stateExtra(t)
}

func localFixture(t *testing.T, extra string) *fixture {
	t.Helper()
	return newFixture(t, localExtra(t)+extra)
}

func readBody(r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// ---- a person's browser, as far as WebAuthn goes ----

func (f *fixture) postJSON(b *browser, path string, v any, hdr ...string) *http.Response {
	f.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := b.c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func decB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resetThrottle forgets the failures counted so far: a test that makes many
// refusals from one address would otherwise be refused for its volume.
func (f *fixture) resetThrottle() {
	f.s.localLimit = newLocalThrottle(func() time.Time { return f.s.now() })
}

// invite issues an invitation straight into the store, as the CLI does.
func (f *fixture) invite(login string) string {
	f.t.Helper()
	tok, _, err := f.s.passkeys.invite(login, time.Hour, "test")
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// enrollBegin posts the token and returns the status, the handle and challenge.
func (f *fixture) enrollBegin(b *browser, tok string) (int, string, []byte, map[string]any) {
	f.t.Helper()
	res := f.postJSON(b, "/local/enroll/begin", map[string]string{"token": tok})
	body := readBody(res)
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, "", nil, nil
	}
	var o struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &o); err != nil {
		f.t.Fatalf("%v: %s", err, body)
	}
	return res.StatusCode, o.Handle, decB64(f.t, o.PublicKey["challenge"].(string)), o.PublicKey
}

func (f *fixture) enrollFinish(b *browser, a *webauthntest.Authenticator, handle string, challenge []byte, o webauthntest.Options, hdr ...string) int {
	f.t.Helper()
	cd, ao := a.Register(f.s.cfg.rpID(), f.s.cfg.origin(), challenge, o)
	res := f.postJSON(b, "/local/enroll/finish", map[string]any{
		"handle": handle, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(ao), "transports": []string{"internal"},
	}, hdr...)
	readBody(res)
	return res.StatusCode
}

// enrolled runs a whole enrolment for login with a new authenticator.
func (f *fixture) enrolled(login string, alg int64) *webauthntest.Authenticator {
	f.t.Helper()
	a, err := webauthntest.New(alg)
	if err != nil {
		f.t.Fatal(err)
	}
	b := newBrowser(f.t)
	status, h, ch, _ := f.enrollBegin(b, f.invite(login))
	if status != http.StatusOK {
		f.t.Fatalf("enrol %s: begin: status %d", login, status)
	}
	if status := f.enrollFinish(b, a, h, ch, webauthntest.Options{}); status != http.StatusOK {
		f.t.Fatalf("enrol %s: finish: status %d", login, status)
	}
	return a
}

// openLocal walks a browser from the authorization URL to the local login
// page, and returns the page's CSRF token.
func (f *fixture) openLocal(b *browser, authURL string) string {
	f.t.Helper()
	next := location(f.t, b.get(authURL))
	if next.Path != "/login" {
		f.t.Fatalf("sent to %s, where the choice between the federation and a local account was expected", next)
	}
	page := readBody(b.get(next.String()))
	if !strings.Contains(page, `href="local/login"`) || !strings.Contains(page, "saml/") {
		f.t.Fatalf("the choice does not offer both ways in:\n%s", page)
	}
	return f.localForm(b)
}

func (f *fixture) localForm(b *browser) string {
	f.t.Helper()
	res := b.get(f.s.cfg.Issuer + "/local/login")
	body := readBody(res)
	m := csrfField.FindStringSubmatch(body)
	if res.StatusCode != http.StatusOK || m == nil {
		f.t.Fatalf("the local login page: status %d:\n%s", res.StatusCode, body)
	}
	return m[1]
}

// loginBegin asks for the options and returns the handle and the challenge.
func (f *fixture) loginBegin(b *browser, csrf string, hdr ...string) (int, string, []byte) {
	f.t.Helper()
	res := f.postJSON(b, "/local/login/begin", map[string]string{"csrf": csrf}, hdr...)
	body := readBody(res)
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, "", nil
	}
	var o struct {
		Handle    string         `json:"handle"`
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &o); err != nil {
		f.t.Fatalf("%v: %s", err, body)
	}
	return res.StatusCode, o.Handle, decB64(f.t, o.PublicKey["challenge"].(string))
}

// loginFields are the form fields of the finish post, as the page's script
// fills them.
func (f *fixture) loginFields(a *webauthntest.Authenticator, login, csrf, handle string, challenge []byte, o webauthntest.Options) url.Values {
	cd, ad, sig := a.Assert(f.s.cfg.rpID(), f.s.cfg.origin(), challenge, o)
	return url.Values{
		"csrf": {csrf}, "handle": {handle}, "id": {b64(a.ID)}, "clientDataJSON": {b64(cd)},
		"authenticatorData": {b64(ad)}, "signature": {b64(sig)}, "userHandle": {b64(f.s.userHandle(login))},
	}
}

// postFinish posts the finish form, with extra request headers.
func (f *fixture) postFinish(b *browser, v url.Values, hdr ...string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/local/login/finish", strings.NewReader(v.Encode()))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := b.c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

// passkeyLogin is begin and finish: the whole sign-in on a page already open.
func (f *fixture) passkeyLogin(b *browser, a *webauthntest.Authenticator, login, csrf string, o webauthntest.Options, hdr ...string) *http.Response {
	f.t.Helper()
	status, h, ch := f.loginBegin(b, csrf)
	if status != http.StatusOK {
		f.t.Fatalf("login/begin: status %d", status)
	}
	return f.postFinish(b, f.loginFields(a, login, csrf, h, ch, o), hdr...)
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *fixture) userinfo(t *testing.T, at string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(readBody(res)), &m); err != nil || res.StatusCode != 200 {
		t.Fatalf("userinfo: status %d, %v", res.StatusCode, err)
	}
	return m
}

// ---- enrolment ----

func TestEnrolmentEndToEnd(t *testing.T) {
	f := localFixture(t, "")
	tok := f.invite("alice")
	b := newBrowser(t)

	// The page is static, the same for everybody, and the token is nowhere in
	// the request line: the script reads it from the fragment.
	page := b.get(f.s.cfg.Issuer + "/local/enroll")
	body := readBody(page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, `src="passkey.js"`) || strings.Contains(body, tok) {
		t.Fatalf("the enrolment page: status %d:\n%s", page.StatusCode, body)
	}

	status, handle, ch, pk := f.enrollBegin(b, tok)
	if status != http.StatusOK {
		t.Fatalf("begin: status %d", status)
	}
	// What the browser is asked to create.
	if rp := pk["rp"].(map[string]any); rp["id"] != f.s.cfg.rpID() {
		t.Errorf("rp.id = %v, want the issuer's host %s", rp["id"], f.s.cfg.rpID())
	}
	sel := pk["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["userVerification"] != "required" || sel["requireResidentKey"] != true {
		t.Errorf("authenticatorSelection = %v", sel)
	}
	if pk["attestation"] != "none" {
		t.Errorf("attestation = %v", pk["attestation"])
	}
	var algs []float64
	for _, p := range pk["pubKeyCredParams"].([]any) {
		algs = append(algs, p.(map[string]any)["alg"].(float64))
	}
	if fmt.Sprint(algs) != "[-7 -8 -257]" {
		t.Errorf("algorithms %v, want ES256, EdDSA, RS256", algs)
	}
	user := pk["user"].(map[string]any)
	if user["name"] != "alice" || user["displayName"] != "Alice Martin" {
		t.Errorf("user = %v", user)
	}
	if !bytes.Equal(decB64(t, user["id"].(string)), f.s.userHandle("alice")) || strings.Contains(string(decB64(t, user["id"].(string))), "alice") {
		t.Error("the user handle is not the opaque one of the account")
	}
	if ex := pk["excludeCredentials"].([]any); len(ex) != 0 {
		t.Errorf("excludeCredentials = %v with no key yet", ex)
	}

	a, _ := webauthntest.New(webauthn.AlgES256)
	if status := f.enrollFinish(b, a, handle, ch, webauthntest.Options{}); status != http.StatusOK {
		t.Fatalf("finish: status %d", status)
	}
	recs, err := f.s.passkeys.passkeys("alice")
	if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].ID, a.ID) || recs[0].Login != "alice" || !recs[0].BackupEligible {
		t.Fatalf("stored: %+v %v", recs, err)
	}

	// The invitation is burnt: the same token buys nothing, and the same
	// ceremony cannot be finished twice.
	if status, _, _, _ := f.enrollBegin(b, tok); status != http.StatusForbidden {
		t.Errorf("a used invitation: begin status %d, want 403", status)
	}
	other, _ := webauthntest.New(webauthn.AlgES256)
	if status := f.enrollFinish(b, other, handle, ch, webauthntest.Options{}); status == http.StatusOK {
		t.Error("a ceremony was finished twice")
	}

	// A second key, with a new invitation, excludes the first.
	_, _, _, pk = f.enrollBegin(b, f.invite("alice"))
	ex := pk["excludeCredentials"].([]any)
	if len(ex) != 1 || ex[0].(map[string]any)["id"] != b64(a.ID) {
		t.Errorf("excludeCredentials = %v, want the first key", ex)
	}
}

func TestEnrolmentIsStoredAsAHashAndOnlyOnce(t *testing.T) {
	f := localFixture(t, "")
	tok := f.invite("alice")
	rows, err := f.s.cfg.State.db.Query(`SELECT kind, k, v FROM bridge_state WHERE kind = 'invite'`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var kind, k, v string
		rows.Scan(&kind, &k, &v)
		n++
		if strings.Contains(k, tok) || strings.Contains(v, tok) || k != hashToken(tok) {
			t.Errorf("the invitation is stored as %q / %q, not as the hash of its token", k, v)
		}
	}
	rows.Close()
	if n != 1 {
		t.Fatalf("%d invitations stored", n)
	}

	// Two enrolments racing on one token: exactly one wins.
	var wg sync.WaitGroup
	results := make([]int, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := newBrowser(t)
			a, _ := webauthntest.New(webauthn.AlgES256)
			status, h, ch, _ := f.enrollBegin(b, tok)
			if status != http.StatusOK {
				results[i] = status
				return
			}
			results[i] = f.enrollFinish(b, a, h, ch, webauthntest.Options{})
		}()
	}
	wg.Wait()
	won := 0
	for _, s := range results {
		if s == http.StatusOK {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d enrolments with one invitation succeeded (%v)", won, results)
	}
	if recs, _ := f.s.passkeys.passkeys("alice"); len(recs) != 1 {
		t.Errorf("%d passkeys stored", len(recs))
	}
}

func TestEnrolmentRefusals(t *testing.T) {
	f := localFixture(t, "")
	b := newBrowser(t)
	tok := f.invite("alice")

	// begin
	for name, tk := range map[string]string{"an unknown token": token(), "an empty token": "", "a guess": "AAAA"} {
		if status, _, _, _ := f.enrollBegin(b, tk); status != http.StatusForbidden {
			t.Errorf("begin with %s: status %d, want 403", name, status)
		}
	}

	// finish: each refusal is aimed at one field, with a control that the same
	// enrolment works.
	try := func(name string, o webauthntest.Options, want int) {
		t.Helper()
		f.resetThrottle()
		tk := f.invite("alice")
		status, h, ch, _ := f.enrollBegin(b, tk)
		if status != http.StatusOK {
			t.Fatalf("%s: begin %d", name, status)
		}
		a, _ := webauthntest.New(webauthn.AlgES256)
		if got := f.enrollFinish(b, a, h, ch, o); got != want {
			t.Errorf("%s: status %d, want %d", name, got, want)
		}
		if want != http.StatusOK {
			// A refused enrolment stored nothing and the invitation is still there.
			if recs, _ := f.s.passkeys.passkeys("alice"); len(recs) != 0 {
				t.Errorf("%s: a passkey was stored", name)
			}
			if _, err := f.s.passkeys.peekInvite(tk); err != nil {
				t.Errorf("%s: a refused enrolment burnt the invitation: %v", name, err)
			}
		}
	}
	try("a wrong origin", webauthntest.Options{Origin: "https://evil.example"}, http.StatusForbidden)
	try("a wrong rpIdHash", webauthntest.Options{RPID: "evil.example"}, http.StatusForbidden)
	try("a wrong type", webauthntest.Options{Type: "webauthn.get"}, http.StatusForbidden)
	try("user verification not set", webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUP | webauthn.FlagBE | webauthn.FlagBS}, http.StatusForbidden)
	try("user presence not set", webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUV}, http.StatusForbidden)
	try("a cross-origin ceremony", webauthntest.Options{ClientExtra: `,"topOrigin":"https://x.example"`}, http.StatusForbidden)
	_ = tok
	f.resetThrottle()

	// the challenge is the ceremony's: another's does not do.
	_, h1, _, _ := f.enrollBegin(b, f.invite("alice"))
	_, _, ch2, _ := f.enrollBegin(b, f.invite("alice"))
	a, _ := webauthntest.New(webauthn.AlgES256)
	if got := f.enrollFinish(b, a, h1, ch2, webauthntest.Options{}); got != http.StatusForbidden {
		t.Errorf("another ceremony's challenge: status %d", got)
	}

	// a credential ID that is not the one signed.
	{
		status, h, ch, _ := f.enrollBegin(b, f.invite("alice"))
		if status != http.StatusOK {
			t.Fatal(status)
		}
		a, _ := webauthntest.New(webauthn.AlgES256)
		cd, ao := a.Register(f.s.cfg.rpID(), f.s.cfg.origin(), ch, webauthntest.Options{})
		res := f.postJSON(b, "/local/enroll/finish", map[string]any{"handle": h, "id": b64([]byte("not the credential id")), "clientDataJSON": b64(cd), "attestationObject": b64(ao)})
		if readBody(res); res.StatusCode != http.StatusForbidden {
			t.Errorf("an ID that is not the signed one: status %d", res.StatusCode)
		}
	}

	// a key already registered cannot be registered again (here, by bob).
	f.resetThrottle()
	good := f.enrolled("alice", webauthn.AlgEdDSA)
	status, h, ch, _ := f.enrollBegin(b, f.invite("bob"))
	if status != http.StatusOK {
		t.Fatal(status)
	}
	if got := f.enrollFinish(b, good, h, ch, webauthntest.Options{}); got != http.StatusConflict {
		t.Errorf("a credential registered twice: status %d, want 409", got)
	}

	// an account that left the file between the invitation and the enrolment.
	tk := f.invite("bob")
	text := strings.Replace(localAccountsText(), `account "bob"`, `account "robert"`, 1)
	if err := os.WriteFile(f.s.cfg.Local.AccountsFile, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	f.s.cfg.Local.store.mu.Lock()
	f.s.cfg.Local.store.checked = time.Time{}
	f.s.cfg.Local.store.mu.Unlock()
	if status, _, _, _ := f.enrollBegin(b, tk); status != http.StatusForbidden {
		t.Errorf("an invitation for an account that was removed: status %d", status)
	}
}

func TestEnrolmentExpiredAndRevokedInvitations(t *testing.T) {
	f := localFixture(t, "")
	b := newBrowser(t)

	tok := f.invite("alice")
	real := time.Now()
	f.s.now = func() time.Time { return real.Add(2 * time.Hour) }
	if status, _, _, _ := f.enrollBegin(b, tok); status != http.StatusForbidden {
		t.Errorf("an expired invitation: status %d, want 403", status)
	}
	f.s.now = time.Now

	// Control: the same invitation, not yet expired, works; revoked, it does not.
	tok = f.invite("alice")
	if status, _, _, _ := f.enrollBegin(b, tok); status != http.StatusOK {
		t.Fatalf("control: begin %d", status)
	}
	if n, err := f.s.passkeys.revokeInvites("alice"); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if status, _, _, _ := f.enrollBegin(b, tok); status != http.StatusForbidden {
		t.Errorf("a revoked invitation: status %d", status)
	}

	// A ceremony begun with a good invitation does not outlive its revocation.
	tok = f.invite("alice")
	_, h, ch, _ := f.enrollBegin(b, tok)
	f.s.passkeys.revokeInvites("alice")
	a, _ := webauthntest.New(webauthn.AlgES256)
	if got := f.enrollFinish(b, a, h, ch, webauthntest.Options{}); got != http.StatusForbidden {
		t.Errorf("finishing under a revoked invitation: status %d", got)
	}
	// And a new invitation replaces the pending one.
	first := f.invite("alice")
	second := f.invite("alice")
	if _, err := f.s.passkeys.peekInvite(first); err == nil {
		t.Error("an old invitation survived a new one")
	}
	if _, err := f.s.passkeys.peekInvite(second); err != nil {
		t.Error(err)
	}
	// The bounds.
	for _, ttl := range []time.Duration{0, -time.Hour, inviteMaxTTL + time.Second} {
		if _, _, err := f.s.passkeys.invite("alice", ttl, "t"); err == nil {
			t.Errorf("an invitation of %s was issued", ttl)
		}
	}
	if _, _, err := f.s.passkeys.invite("alice", inviteMaxTTL, "t"); err != nil {
		t.Errorf("the longest invitation: %v", err)
	}
}

func TestEnrolmentIsBoundedPerAccount(t *testing.T) {
	f := localFixture(t, "")
	for i := 0; i < maxPasskeys; i++ {
		f.enrolled("alice", webauthn.AlgES256)
	}
	if status, _, _, _ := f.enrollBegin(newBrowser(t), f.invite("alice")); status != http.StatusConflict {
		t.Errorf("an eleventh passkey: status %d, want 409", status)
	}
}

func TestEnrolmentRefusesWhatDidNotComeFromThePage(t *testing.T) {
	f := localFixture(t, "")
	b := newBrowser(t)
	tok := f.invite("alice")
	for name, hdr := range map[string][]string{
		"cross-site": {"Sec-Fetch-Site", "cross-site"},
		"same-site":  {"Sec-Fetch-Site", "same-site"},
		"an origin":  {"Origin", "https://evil.example"},
	} {
		res := f.postJSON(b, "/local/enroll/begin", map[string]string{"token": tok}, hdr...)
		if readBody(res); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (a good token and all)", name, res.StatusCode)
		}
	}
	// A form post cannot carry JSON, and a JSON endpoint takes no form.
	res, err := b.c.PostForm(f.s.cfg.Issuer+"/local/enroll/begin", url.Values{"token": {tok}})
	if err != nil {
		t.Fatal(err)
	}
	if readBody(res); res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a form post: status %d, want 415", res.StatusCode)
	}
	// Unknown members and trailing data are not tolerated.
	for name, body := range map[string]string{
		"an unknown member": `{"token":"` + tok + `","next":"https://evil.example"}`,
		"trailing data":     `{"token":"` + tok + `"} {}`,
		"not JSON":          `token=` + tok,
	} {
		req, _ := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/local/enroll/begin", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := b.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if readBody(res); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, res.StatusCode)
		}
	}
	// A GET of an API route is nothing.
	if res := b.get(f.s.cfg.Issuer + "/local/enroll/begin"); res.StatusCode != http.StatusNotFound {
		t.Errorf("GET /local/enroll/begin: status %d", res.StatusCode)
	}
	// Control: the page's own headers work.
	if status, _, _, _ := f.enrollBegin(b, tok); status != http.StatusOK {
		t.Errorf("control: status %d", status)
	}
	big := bytes.Repeat([]byte("a"), maxJSONBody+10)
	req, _ := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/local/enroll/begin", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	if res, err := b.c.Do(req); err != nil {
		t.Fatal(err)
	} else if readBody(res); res.StatusCode < 400 {
		t.Errorf("an oversized body: status %d", res.StatusCode)
	}
}

// ---- login ----

func TestPasskeyLoginEndToEnd(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile", "email", "eduperson", "groups")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	res := f.passkeyLogin(b, alice, "alice", csrf, webauthntest.Options{})
	back := location(t, res)
	if got := back.String(); !strings.HasPrefix(got, f.redirect+"?") {
		t.Fatalf("sent to %s, not to the registered redirect URI", got)
	}
	q := back.Query()
	if q.Get("state") != r.state || q.Get("iss") != f.s.cfg.Issuer {
		t.Errorf("state/iss = %q/%q", q.Get("state"), q.Get("iss"))
	}
	tok, err := r.cfg.Exchange(t.Context(), q.Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatalf("the code exchange: %v", err)
	}
	id := jwtClaims(t, tok.Extra("id_token").(string))
	if id["acr"] != localACR || localACR != "https://refeds.org/profile/mfa" {
		t.Errorf("acr = %v, want REFEDS MFA", id["acr"])
	}
	if id["nonce"] != r.nonce {
		t.Errorf("nonce %v", id["nonce"])
	}
	client, _ := f.s.cfg.client("web")
	want := (&person{subject: "local:alice"}).sub(f.s.cfg.salt, client)
	if id["sub"] != want || strings.Contains(fmt.Sprint(id["sub"]), "alice") {
		t.Errorf("sub = %v, want the HMAC of \"local:alice\" under the salt: %s", id["sub"], want)
	}
	at := jwtClaims(t, tok.AccessToken)
	if at["idp"] != f.s.cfg.Issuer+"/local" || at["preferred_username"] != "alice" {
		t.Errorf("access token idp/preferred_username = %v/%v", at["idp"], at["preferred_username"])
	}
	if g, _ := at["groups"].([]any); len(g) != 1 || g[0] != localGroup {
		t.Errorf("access token groups = %v", at["groups"])
	}
	ui := f.userinfo(t, tok.AccessToken)
	for k, v := range map[string]string{
		"preferred_username":       "alice",
		"name":                     "Alice Martin",
		"email":                    "alice@mesocentre.example",
		"eduperson_principal_name": "alice@" + localScope,
	} {
		if ui[k] != v {
			t.Errorf("userinfo %s = %v, want %s", k, ui[k], v)
		}
	}
	if _, ok := ui["email_verified"]; ok {
		t.Error("userinfo says email_verified: nobody verified it")
	}

	// The credential's use is recorded; the counter advanced.
	recs, _ := f.s.passkeys.passkeys("alice")
	if len(recs) != 1 || recs[0].SignCount != 1 || recs[0].LastUsed.IsZero() {
		t.Errorf("after one login: %+v", recs)
	}
	// A login is single-use: the same finish, posted again, finds it spent.
	if res := f.postFinish(b, url.Values{"csrf": {csrf}}); res.StatusCode == http.StatusFound {
		t.Error("a second post of an answered login was accepted")
	}
}

func TestPasskeyLoginWithEachAlgorithm(t *testing.T) {
	f := localFixture(t, "")
	for _, alg := range []int64{webauthn.AlgES256, webauthn.AlgEdDSA, webauthn.AlgRS256} {
		login := map[int64]string{webauthn.AlgES256: "alice", webauthn.AlgEdDSA: "bob", webauthn.AlgRS256: "alice"}[alg]
		a := f.enrolled(login, alg)
		r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		back := location(t, f.passkeyLogin(b, a, login, csrf, webauthntest.Options{}))
		if _, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier)); err != nil {
			t.Errorf("alg %d: %v", alg, err)
		}
	}
}

func TestPasskeySubjectsAreStablePerAccount(t *testing.T) {
	f := localFixture(t, "")
	alice1, alice2, bob := f.enrolled("alice", webauthn.AlgES256), f.enrolled("alice", webauthn.AlgEdDSA), f.enrolled("bob", webauthn.AlgES256)
	sub := func(a *webauthntest.Authenticator, login string) string {
		r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		back := location(t, f.passkeyLogin(b, a, login, csrf, webauthntest.Options{}))
		tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatal(err)
		}
		return jwtClaims(t, tok.Extra("id_token").(string))["sub"].(string)
	}
	a1, a2, b1 := sub(alice1, "alice"), sub(alice2, "alice"), sub(bob, "bob")
	if a1 != a2 || a1 == b1 {
		t.Errorf("subjects: alice %s, alice by another key %s, bob %s", a1, a2, b1)
	}
}

// Each refusal aimed at one thing, each with a control that the same login
// works: the first line of every table is the control.
func TestPasskeyLoginRefusals(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	bob := f.enrolled("bob", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)

	type attempt struct {
		name string
		a    *webauthntest.Authenticator
		as   string // the login the user handle names
		opts webauthntest.Options
		edit func(url.Values)
		hdr  []string
		want int
	}
	flags := func(fl byte) webauthntest.Options { return webauthntest.Options{NoDefaultFlags: true, Flags: fl} }
	for _, tc := range []attempt{
		{name: "control", a: alice, as: "alice", want: http.StatusFound},
		{name: "a wrong origin", a: alice, as: "alice", opts: webauthntest.Options{Origin: "https://evil.example"}, want: http.StatusUnauthorized},
		{name: "a wrong rpIdHash", a: alice, as: "alice", opts: webauthntest.Options{RPID: "evil.example"}, want: http.StatusUnauthorized},
		{name: "a wrong type", a: alice, as: "alice", opts: webauthntest.Options{Type: "webauthn.create"}, want: http.StatusUnauthorized},
		{name: "user presence not set", a: alice, as: "alice", opts: flags(webauthn.FlagUV | webauthn.FlagBE | webauthn.FlagBS), want: http.StatusUnauthorized},
		{name: "user verification not set", a: alice, as: "alice", opts: flags(webauthn.FlagUP | webauthn.FlagBE | webauthn.FlagBS), want: http.StatusUnauthorized},
		{name: "backup eligibility changed", a: alice, as: "alice", opts: flags(webauthn.FlagUP | webauthn.FlagUV), want: http.StatusUnauthorized},
		{name: "a cross-origin ceremony", a: alice, as: "alice", opts: webauthntest.Options{ClientExtra: `,"topOrigin":"https://x.example"`}, want: http.StatusUnauthorized},
		{name: "a duplicate member in clientData", a: alice, as: "alice", opts: webauthntest.Options{ClientExtra: `,"crossOrigin":true`}, want: http.StatusUnauthorized},
		{name: "another account's user handle", a: alice, as: "bob", want: http.StatusUnauthorized},
		{name: "a bad signature", a: alice, as: "alice", edit: func(v url.Values) { v.Set("signature", b64([]byte("not a signature"))) }, want: http.StatusUnauthorized},
		{name: "an unknown credential", a: alice, as: "alice", edit: func(v url.Values) { v.Set("id", b64([]byte("some other credential"))) }, want: http.StatusUnauthorized},
		{name: "no user handle", a: alice, as: "alice", edit: func(v url.Values) { v.Del("userHandle") }, want: http.StatusUnauthorized},
		{name: "garbage encodings", a: alice, as: "alice", edit: func(v url.Values) { v.Set("authenticatorData", "!!!") }, want: http.StatusUnauthorized},
		{name: "padded base64", a: alice, as: "alice", edit: func(v url.Values) { v.Set("id", v.Get("id")+"=") }, want: http.StatusUnauthorized},
		{name: "another key of the same account", a: bob, as: "alice", want: http.StatusUnauthorized},
		{name: "no CSRF token", a: alice, as: "alice", edit: func(v url.Values) { v.Del("csrf") }, want: http.StatusForbidden},
		{name: "a forged CSRF token", a: alice, as: "alice", edit: func(v url.Values) { v.Set("csrf", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") }, want: http.StatusForbidden},
		{name: "cross-site", a: alice, as: "alice", hdr: []string{"Sec-Fetch-Site", "cross-site"}, want: http.StatusForbidden},
		{name: "same-site", a: alice, as: "alice", hdr: []string{"Sec-Fetch-Site", "same-site"}, want: http.StatusForbidden},
		{name: "another origin", a: alice, as: "alice", hdr: []string{"Origin", "https://evil.example"}, want: http.StatusForbidden},
		{name: "a null origin", a: alice, as: "alice", hdr: []string{"Origin", "null"}, want: http.StatusForbidden},
		{name: "an origin prefix", a: alice, as: "alice", hdr: []string{"Origin", f.s.cfg.Issuer + ".evil.example"}, want: http.StatusForbidden},
		{name: "a cross-site null origin", a: alice, as: "alice", hdr: []string{"Sec-Fetch-Site", "cross-site", "Origin", "null"}, want: http.StatusForbidden},
		{name: "a same-origin fetch's headers", a: alice, as: "alice", hdr: []string{"Sec-Fetch-Site", "same-origin", "Origin", f.s.cfg.Issuer}, want: http.StatusFound},
		// ⛔ What a browser REALLY sends for the page's form.submit(): the page is
		// served with Referrer-Policy: no-referrer, so the Origin of a navigation
		// is "null" (Fetch, "serialize a request origin"). The row above was the
		// only "accepted" row until 2026-11-18, and every passkey login in
		// production was refused.
		{name: "the page's own form post", a: alice, as: "alice", hdr: []string{"Sec-Fetch-Site", "same-origin", "Origin", "null"}, want: http.StatusFound},
	} {
		f.resetThrottle()
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		status, h, ch := f.loginBegin(b, csrf)
		if status != http.StatusOK {
			t.Fatalf("%s: begin %d", tc.name, status)
		}
		v := f.loginFields(tc.a, tc.as, csrf, h, ch, tc.opts)
		if tc.edit != nil {
			tc.edit(v)
		}
		res := f.postFinish(b, v, tc.hdr...)
		if res.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, res.StatusCode, tc.want)
		}
		if tc.want != http.StatusFound && (res.Header.Get("Location") != "" || strings.Contains(readBody(res), "code=")) {
			t.Errorf("%s: a refusal redirected or carried a code", tc.name)
		}
	}
}

func TestPasskeyChallengeIsSingleUseAndBoundToItsLogin(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)

	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	_, h, ch := f.loginBegin(b, csrf)
	v := f.loginFields(alice, "alice", csrf, h, ch, webauthntest.Options{})
	if res := f.postFinish(b, v); res.StatusCode != http.StatusFound {
		t.Fatalf("control: status %d", res.StatusCode)
	}
	// The assertion, replayed on a fresh login of the same browser.
	b2 := newBrowser(t)
	csrf2 := f.openLocal(b2, r.authURL())
	v2 := url.Values{}
	for k, x := range v {
		v2[k] = x
	}
	v2.Set("csrf", csrf2)
	if res := f.postFinish(b2, v2); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a replayed assertion: status %d, want 401", res.StatusCode)
	}

	// Another login's challenge does not do.
	b3, b4 := newBrowser(t), newBrowser(t)
	csrf3, csrf4 := f.openLocal(b3, r.authURL()), f.openLocal(b4, r.authURL())
	_, h3, ch3 := f.loginBegin(b3, csrf3)
	v3 := f.loginFields(alice, "alice", csrf4, h3, ch3, webauthntest.Options{})
	if res := f.postFinish(b4, v3); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("another login's challenge: status %d, want 401", res.StatusCode)
	}
	// An expired challenge does not.
	b5 := newBrowser(t)
	csrf5 := f.openLocal(b5, r.authURL())
	_, h5, ch5 := f.loginBegin(b5, csrf5)
	real := time.Now()
	f.s.now = func() time.Time { return real.Add(ceremonyTTL + time.Second) }
	res := f.postFinish(b5, f.loginFields(alice, "alice", csrf5, h5, ch5, webauthntest.Options{}))
	f.s.now = time.Now
	if res.StatusCode == http.StatusFound {
		t.Error("an expired challenge was answered")
	}
}

func TestPasskeyCounterRegressionIsRefused(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	login := func() int {
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		return f.passkeyLogin(b, alice, "alice", csrf, webauthntest.Options{}).StatusCode
	}
	for i := 0; i < 3; i++ {
		if got := login(); got != http.StatusFound {
			t.Fatalf("login %d: status %d", i+1, got)
		}
	}
	// A clone: the same key, whose counter is behind.
	alice.Counter = 1
	if got := login(); got != http.StatusUnauthorized {
		t.Errorf("a counter that went back: status %d, want 401", got)
	}
	// Control: the real authenticator, ahead again, is let in.
	alice.Counter = 10
	if got := login(); got != http.StatusFound {
		t.Errorf("the counter ahead again: status %d", got)
	}
	// A passkey that never counts (a synced one) is not refused.
	bob := f.enrolled("bob", webauthn.AlgES256)
	bob.NoCounter, bob.Counter = true, 0
	for i := 0; i < 2; i++ {
		b := newBrowser(t)
		csrf := f.openLocal(b, r.authURL())
		if got := f.passkeyLogin(b, bob, "bob", csrf, webauthntest.Options{}).StatusCode; got != http.StatusFound {
			t.Errorf("a passkey with no counter, login %d: status %d", i+1, got)
		}
	}
}

// No destination from the request: where a login ends is in the sealed login,
// which authorize matched against the registered URIs.
func TestPasskeyLoginTakesNoDestinationFromTheRequest(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	_, h, ch := f.loginBegin(b, csrf)
	v := f.loginFields(alice, "alice", csrf, h, ch, webauthntest.Options{})
	v.Set("redirect_uri", "https://evil.example/cb")
	v.Set("next", "https://evil.example")
	v.Set("return_to", "https://evil.example")
	req, _ := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+"/local/login/finish?redirect_uri=https://evil.example/cb&next=//evil.example", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if loc := location(t, res).String(); !strings.HasPrefix(loc, f.redirect+"?") || strings.Contains(loc, "evil") {
		t.Errorf("sent to %s", loc)
	}
}

func TestLocalPagesAreStrict(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	f.openLocal(b, r.authURL())

	for name, c := range map[string]struct {
		url   string
		form  string
		fresh bool
	}{
		"login":  {f.s.cfg.Issuer + "/local/login", "form-action 'self' http://127.0.0.1:9", false},
		"enroll": {f.s.cfg.Issuer + "/local/enroll", "form-action 'self'", true},
	} {
		bb := b
		if c.fresh {
			bb = newBrowser(t)
		}
		res := bb.get(c.url)
		csp := res.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "base-uri 'none'", "frame-ancestors 'none'", c.form} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", name, csp, want)
			}
		}
		for _, bad := range []string{"unsafe-eval", "unsafe-inline'; script", "script-src *", "data:"} {
			if strings.Contains(csp, bad) {
				t.Errorf("%s: CSP %q has %q", name, csp, bad)
			}
		}
		if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers: %v", name, res.Header)
		}
		body := readBody(res)
		// No inline script, no password field, one external script from this origin.
		if strings.Count(strings.ReplaceAll(body, `<script src="/ui.js"></script>`, ""), "<script") != 1 || !strings.Contains(body, `<script src="passkey.js"></script>`) {
			t.Errorf("%s: scripts:\n%s", name, body)
		}
		if strings.Contains(strings.ToLower(body), "password") || strings.Contains(body, "mot de passe") || strings.Contains(body, `type="password"`) {
			t.Errorf("%s: the page mentions a password:\n%s", name, body)
		}
	}
	// The script is the same for everybody, from this origin, and holds no secret.
	js := b.get(f.s.cfg.Issuer + "/local/passkey.js")
	if js.Header.Get("Content-Type") != "text/javascript; charset=utf-8" || js.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("script headers: %v", js.Header)
	}
	if body := readBody(js); !strings.Contains(body, "navigator.credentials") || strings.Contains(strings.ToLower(body), "password") || !strings.Contains(body, "location.hash") {
		t.Errorf("the script:\n%s", body)
	}
	// Without a login in progress there is no login page.
	if res := newBrowser(t).get(f.s.cfg.Issuer + "/local/login"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("no login in progress: status %d", res.StatusCode)
	}
}

// ⛔ No route accepts a password. Every local route, with a username and a
// password in a form and in JSON, with a good CSRF token and a live login: a
// refusal, no redirect, no code.
func TestNoLocalRouteAcceptsAPassword(t *testing.T) {
	f := localFixture(t, "")
	f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())

	routes := []string{"/local/login", "/local/login/begin", "/local/login/finish", "/local/enroll", "/local/enroll/begin", "/local/enroll/finish", "/local/passkey.js", "/local/password", "/local/passwd"}
	form := url.Values{"csrf": {csrf}, "login": {"alice"}, "username": {"alice"}, "password": {"correct horse battery staple"}, "passwd": {"x"}}
	asJSON, _ := json.Marshal(map[string]string{"csrf": csrf, "login": "alice", "username": "alice", "password": "correct horse battery staple"})
	for _, route := range routes {
		for name, do := range map[string]func() *http.Response{
			"a form": func() *http.Response {
				res, err := b.c.PostForm(f.s.cfg.Issuer+route, form)
				if err != nil {
					t.Fatal(err)
				}
				return res
			},
			"JSON": func() *http.Response {
				req, _ := http.NewRequest(http.MethodPost, f.s.cfg.Issuer+route, bytes.NewReader(asJSON))
				req.Header.Set("Content-Type", "application/json")
				res, err := b.c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				return res
			},
			"a query": func() *http.Response {
				return b.get(f.s.cfg.Issuer + route + "?login=alice&password=correct+horse+battery+staple")
			},
		} {
			res := do()
			body := readBody(res)
			if route == "/local/passkey.js" && name == "a query" {
				continue // a static script: it takes nothing and gives nothing
			}
			if res.StatusCode == http.StatusFound || res.Header.Get("Location") != "" || strings.Contains(body, "code=") {
				t.Errorf("%s with %s: status %d, Location %q: a password bought something", route, name, res.StatusCode, res.Header.Get("Location"))
			}
			if route == "/local/login" || route == "/local/enroll" {
				if name != "a query" && res.StatusCode != http.StatusMethodNotAllowed && res.StatusCode != http.StatusNotFound {
					t.Errorf("%s with %s: status %d, want 405", route, name, res.StatusCode)
				}
				continue
			}
			if res.StatusCode < 400 && !(route == "/local/passkey.js") {
				t.Errorf("%s with %s: status %d, want a refusal", route, name, res.StatusCode)
			}
		}
	}
	// And the login is still unanswered: the password bought nothing.
	if res := f.passkeyLogin(b, mustAuth(t, webauthn.AlgES256), "alice", csrf, webauthntest.Options{}); res.StatusCode == http.StatusFound {
		t.Error("an authenticator nobody enrolled signed in")
	}
}

func mustAuth(t *testing.T, alg int64) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---- throttling ----

func TestLocalLoginThrottlePerHost(t *testing.T) {
	f := localFixture(t, "")
	alice := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	// A key nobody enrolled, ten times from one host.
	ghost := mustAuth(t, webauthn.AlgES256)
	for i := range localHostMax {
		if res := f.passkeyLogin(b, ghost, "alice", csrf, webauthntest.Options{}); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d", i+1, res.StatusCode)
		}
	}
	// The eleventh, with the right key: refused BEFORE it is looked at.
	status, _, _ := f.loginBegin(b, csrf)
	if status != http.StatusTooManyRequests {
		t.Errorf("begin after ten failures: status %d, want 429", status)
	}
	res := f.postFinish(b, f.loginFields(alice, "alice", csrf, "x", []byte("x"), webauthntest.Options{}))
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Location") != "" || res.Header.Get("Retry-After") == "" {
		t.Errorf("finish after ten failures: status %d, Location %q, Retry-After %q", res.StatusCode, res.Header.Get("Location"), res.Header.Get("Retry-After"))
	}
	// Enrolment shares the host's count: guessing tokens is a failure too.
	if status, _, _, _ := f.enrollBegin(newBrowser(t), f.invite("bob")); status != http.StatusTooManyRequests {
		t.Errorf("enrolment from a host over its limit: status %d, want 429", status)
	}
}

func TestLocalThrottleWindowAndBounds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newLocalThrottle(func() time.Time { return now })
	for range localLoginMax {
		th.failed("192.0.2.1", "alice")
	}
	if !th.blocked("198.51.100.7", "alice") {
		t.Error("five failures for a key did not block it from another host")
	}
	if !th.blocked("198.51.100.7", "ALICE") {
		t.Error("the key limit is case-sensitive")
	}
	if th.blocked("198.51.100.7", "carol") {
		t.Error("carol is blocked")
	}
	th.succeeded("alice")
	if th.blocked("198.51.100.7", "alice") {
		t.Error("a success did not forget the failures")
	}
	for range localLoginMax {
		th.failed("192.0.2.1", "alice")
	}
	now = now.Add(localWindow + time.Second)
	if th.blocked("192.0.2.1", "alice") {
		t.Error("still blocked after the window")
	}
	// A clock that goes back is no time elapsed: nothing is blocked for ever by it.
	now = now.Add(-24 * time.Hour)
	if th.blocked("192.0.2.1", "alice") {
		t.Error("blocked by failures from the future")
	}
	// An empty key counts the host alone.
	th = newLocalThrottle(func() time.Time { return now })
	th.failed("192.0.2.9", "")
	if len(th.logins) != 0 || th.blocked("192.0.2.9", "") {
		t.Error("an empty key was counted as a login")
	}

	// The table is capped, and past it a key nobody failed is refused rather
	// than evicting one somebody did.
	th = newLocalThrottle(func() time.Time { return now })
	th.perHost = 1 << 30
	for i := range localTracked {
		th.failed(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), fmt.Sprintf("u%d", i))
	}
	if len(th.logins) != localTracked {
		t.Fatalf("%d keys tracked", len(th.logins))
	}
	th.failed("192.0.2.2", "one-more")
	if len(th.logins) != localTracked {
		t.Errorf("the table grew to %d", len(th.logins))
	}
	if !th.blocked("192.0.2.3", "never-seen") {
		t.Error("a new key was let through a full table")
	}
}

// prompt=none cannot be answered by a page: it goes the federation's way, as
// it did before local accounts, and the choice page is not in its way.
func TestLocalLoginDoesNotInterceptPromptNone(t *testing.T) {
	f := localFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	next := location(t, newBrowser(t).get(r.authURL(oauth2.SetAuthURLParam("prompt", "none"))))
	if next.Path == "/login" {
		t.Errorf("prompt=none was sent to the choice page: %s", next)
	}
}

func TestLocalDisabledPersonIsRefused(t *testing.T) {
	f := localFixture(t, "disabled_file = "+fmt.Sprintf("%q", filepath.ToSlash(filepath.Join(t.TempDir(), "disabled.json")))+"\n")
	alice := f.enrolled("alice", webauthn.AlgES256)
	if _, _, err := f.s.disablePerson("alice", "test", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.passkeyLogin(b, alice, "alice", csrf, webauthntest.Options{}))
	if back.Query().Get("error") != "access_denied" || back.Query().Get("code") != "" {
		t.Errorf("a disabled local account got %s", back)
	}
}

// The federation does not reach the local entity ID, and a local grant does
// not reach the federation's rule.
func TestLocalEntityIDIsNotAFederationIdP(t *testing.T) {
	f := localFixture(t, "")
	local := f.s.cfg.Issuer + "/local"
	if f.s.allowedIdP(local) {
		t.Error("the local entity ID is an allowed SAML IdP")
	}
	if !configuredIdP(f.s.cfg, local) {
		t.Error("the local entity ID is not configured, with a local block")
	}
	// An account with no passkey stands behind nothing; with one, behind its grants.
	if why := f.s.refused(&person{username: "alice", idp: local}); why != "account removed" {
		t.Errorf("an account with no passkey: %q", why)
	}
	a := f.enrolled("alice", webauthn.AlgES256)
	if why := f.s.refused(&person{username: "alice", idp: local}); why != "" {
		t.Errorf("alice, with a passkey: refused: %s", why)
	}
	if why := f.s.refused(&person{username: "ghost", idp: local}); why != "account removed" {
		t.Errorf("a login the file does not have: %q", why)
	}
	// A grant bought with a passkey is held to THAT passkey.
	key := passkeyKey(a.ID)
	if why := f.s.refused(&person{username: "alice", idp: local, credential: key}); why != "" {
		t.Errorf("alice by her own passkey: %s", why)
	}
	if why := f.s.refused(&person{username: "alice", idp: local, credential: passkeyKey([]byte("another"))}); why != "account removed" {
		t.Errorf("a passkey that is not there: %q", why)
	}
	if why := f.s.refused(&person{username: "bob", idp: local, credential: key}); why != "account removed" {
		t.Errorf("alice's passkey presented as bob's: %q", why)
	}
}

func TestLocalAccountsReloadWithoutARestart(t *testing.T) {
	f := localFixture(t, "")
	path := f.s.cfg.Local.AccountsFile
	reload := func() {
		f.s.cfg.Local.store.mu.Lock()
		f.s.cfg.Local.store.checked = time.Time{}
		f.s.cfg.Local.store.mu.Unlock()
	}
	// bob is removed and carol added, from outside.
	text := strings.Replace(localAccountsText(), `account "bob"`, `account "carol"`, 1)
	if err := os.WriteFile(path, []byte(text+"\n# changed\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reload()
	if _, ok := f.s.cfg.Local.store.get("carol"); !ok {
		t.Error("carol, added to the file, is not known")
	}
	if _, ok := f.s.cfg.Local.store.get("bob"); ok {
		t.Error("bob, removed from the file, is still known")
	}
	// A file that no longer parses leaves the accounts that were.
	if err := os.WriteFile(path, []byte("account \"x\" {\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reload()
	if _, ok := f.s.cfg.Local.store.get("alice"); !ok {
		t.Error("a broken file logged alice out")
	}
	// And so does one a password_hash was put back in: it is refused, said so.
	if err := os.WriteFile(path, []byte(strings.Replace(localAccountsText(), `name = "Bob Durand"`, "name = \"Bob Durand\"\n  password_hash = \"$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA\"", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	reload()
	if _, ok := f.s.cfg.Local.store.get("bob"); ok {
		t.Error("a file with a password_hash was read")
	}
	// A file somebody made group- or world-writable is not read either.
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.WriteFile(path, []byte(strings.Replace(localAccountsText(), `account "bob"`, `account "dave"`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o666)
	reload()
	if _, ok := f.s.cfg.Local.store.get("dave"); ok {
		t.Error("a world-writable accounts file was read")
	}
}
