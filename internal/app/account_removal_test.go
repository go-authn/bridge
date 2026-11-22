// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

// The guardrails against somebody who holds ONE of a person's passkeys (an
// unlocked, stolen phone) removing the others (account_removal.go).

const testNotifySecret = "a-shared-secret-of-enough-length-0123456789"

// A webhook that records what it receives.
type hook struct {
	mu     sync.Mutex
	events []keyEvent
	raw    [][]byte
	heads  []http.Header
	srv    *httptest.Server
}

func newHook(t *testing.T) *hook {
	h := &hook{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev keyEvent
		if err := json.Unmarshal(b, &ev); err != nil {
			t.Errorf("the webhook got %q: %v", b, err)
		}
		h.mu.Lock()
		h.events, h.raw, h.heads = append(h.events, ev), append(h.raw, b), append(h.heads, r.Header.Clone())
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) kinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var k []string
	for _, e := range h.events {
		k = append(k, e.Event)
	}
	return k
}

// guarded is a fixture whose removals are deferred by delay, with the clock in
// the test's hands and a webhook listening.
type guarded struct {
	*fixture
	clock   *time.Time
	clockMu sync.Mutex
	hook    *hook
	logs    *bytes.Buffer
}

func newGuarded(t *testing.T, delay time.Duration) *guarded {
	f := localFixture(t, "")
	g := &guarded{fixture: f, hook: newHook(t), logs: &bytes.Buffer{}}
	now := time.Now()
	g.clock = &now
	f.s.now = func() time.Time { g.clockMu.Lock(); defer g.clockMu.Unlock(); return *g.clock }
	t.Cleanup(func() {
		g.s.notifyWG.Wait() // the mail goroutines read the clock
		f.s.now = time.Now
	})
	f.s.cfg.Local.removalDelay = delay
	f.s.log = g.logs
	f.s.cfg.Notify = &notifyBlock{URL: g.hook.srv.URL, secret: []byte(testNotifySecret)}
	return g
}

func (g *guarded) advance(d time.Duration) {
	g.clockMu.Lock()
	*g.clock = g.clock.Add(d)
	g.clockMu.Unlock()
	g.resetThrottle()
}

func (g *guarded) log() string { return g.fixture.logs(g.logs) }

// settle waits for the webhook deliveries that were started.
func (g *guarded) settle() { g.s.notifyWG.Wait() }

// reqPost is a POST of the account page's own to path with a key.
func (g *guarded) reqPost(s *accountSess, path string, a *webauthntest.Authenticator) (int, string) {
	g.t.Helper()
	res := g.accountReq("POST", path, s.cookie, map[string]string{"csrf": s.csrf, "key": passkeyKey(a.ID)})
	return res.StatusCode, readBody(res)
}

func (g *guarded) keyCount(login string) int {
	g.t.Helper()
	keys, err := g.s.passkeys.passkeys(login)
	if err != nil {
		g.t.Fatal(err)
	}
	return len(keys)
}

func (g *guarded) pending(a *webauthntest.Authenticator) bool {
	g.t.Helper()
	r, ok, err := g.s.passkeys.passkey(passkeyKey(a.ID))
	if err != nil || !ok {
		g.t.Fatalf("the key is not stored: %v", err)
	}
	return r.pending()
}

// twoKeys is alice with a laptop and a phone, signed in with the laptop.
func (g *guarded) twoKeys() (laptop, phone *webauthntest.Authenticator, s *accountSess) {
	laptop = g.enrolled("alice", webauthn.AlgES256)
	s = g.signedIn(laptop, "alice")
	phone = mustAuth(g.t, webauthn.AlgEdDSA)
	if st := g.addKey(s, phone, webauthntest.Options{}); st != http.StatusOK {
		g.t.Fatalf("adding the phone: %d", st)
	}
	return
}

// (1) A deferred removal still lets the key log in until the delay ends, and
// is carried out when it ends; the control is the same key before and after.
func TestDeferredRemovalKeepsTheKeyWorkingUntilTheDelayEnds(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	laptop, phone, s := g.twoKeys()

	st, body := g.reqPost(s, "/account/remove", phone)
	if st != http.StatusOK || !strings.Contains(body, `"pending":true`) || !strings.Contains(body, `"signedOut":false`) {
		t.Fatalf("removing the phone: %d %s", st, body)
	}
	if g.keyCount("alice") != 2 || !g.pending(phone) || g.pending(laptop) {
		t.Fatal("the phone should be marked, and both keys stored")
	}
	// Until the delay ends the phone signs in, as does the laptop (the control).
	g.advance(23*time.Hour + 59*time.Minute)
	if st := g.loginWith(phone, "alice"); st != http.StatusFound {
		t.Errorf("the phone one minute before its removal: %d, want 302", st)
	}
	if st := g.loginWith(laptop, "alice"); st != http.StatusFound {
		t.Errorf("control: the laptop: %d", st)
	}
	// The removal takes effect with the clock, with nobody having looked.
	g.advance(2 * time.Minute)
	if st := g.loginWith(phone, "alice"); st != http.StatusUnauthorized {
		t.Errorf("the phone after its removal: %d, want 401", st)
	}
	if st := g.loginWith(laptop, "alice"); st != http.StatusFound {
		t.Errorf("control: the laptop after the phone's removal: %d", st)
	}
	if g.keyCount("alice") != 1 {
		t.Error("the phone is still stored")
	}
	g.settle()
	// Each delivery is its own goroutine: the order they arrive in is not the
	// order they were sent in, so the set is what is asserted.
	k := g.hook.kinds()
	sort.Strings(k)
	if strings.Join(k, ",") != "key.added,removal.done,removal.requested" {
		t.Errorf("the events: %v", k)
	}
	out := g.log()
	for _, want := range []string{"alice remove-requested " + passkeyKey(phone.ID)[:16], "alice remove-done " + passkeyKey(phone.ID)[:16]} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
}

// The removal is carried out with nobody looking, by the sweep, and reported.
func TestARemovalThatComesDueIsCarriedOutBySweeping(t *testing.T) {
	g := newGuarded(t, time.Hour)
	_, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.advance(30 * time.Minute)
	g.s.sweepRemovals()
	if g.keyCount("alice") != 2 {
		t.Fatal("swept before the time")
	}
	g.advance(31 * time.Minute)
	g.s.sweepRemovals()
	g.settle()
	rows := 0
	g.s.passkeys.each(kindPasskey, func(string, []byte) { rows++ })
	if rows != 1 {
		t.Errorf("%d keys after the sweep, want 1", rows)
	}
	if k := g.hook.kinds(); k[len(k)-1] != "removal.done" {
		t.Errorf("the events: %v", k)
	}
	// Once: a second sweep reports nothing more.
	n := len(g.hook.kinds())
	g.s.sweepRemovals()
	g.settle()
	if len(g.hook.kinds()) != n {
		t.Error("the removal was reported twice")
	}
}

// (2) Another key cancels it. The control: the same request, not cancelled,
// is carried out.
func TestAnotherKeyCancelsAPendingRemoval(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	laptop, phone, s := g.twoKeys()
	// Somebody holding the phone asks for the laptop's removal.
	attacker := g.signedIn(phone, "alice")
	st, body := g.reqPost(attacker, "/account/remove", laptop)
	if st != http.StatusOK || !strings.Contains(body, `"pending":true`) {
		t.Fatalf("the phone removing the laptop: %d %s", st, body)
	}
	// An hour later the person's laptop (a new step-up: the page's session
	// lasts minutes) sees the banner and cancels.
	g.advance(time.Hour)
	s = g.signedIn(laptop, "alice")
	_, page := g.accountPage(s.cookie)
	for _, want := range []string{`data-pending="` + passkeyKey(laptop.ID)[:16] + `"`, "Suppression d&#39;une clé d&#39;accès en attente", `data-post="account/removal/cancel"`, "Annuler la suppression"} {
		if !strings.Contains(page, want) {
			t.Errorf("the banner lacks %q:\n%s", want, page)
		}
	}
	if st, body := g.reqPost(s, "/account/removal/cancel", laptop); st != http.StatusOK || !strings.Contains(body, `"cancelled"`) {
		t.Fatalf("cancelling: %d %s", st, body)
	}
	if g.pending(laptop) {
		t.Error("the removal is still pending")
	}
	if _, page := g.accountPage(s.cookie); strings.Contains(page, "data-pending=") {
		t.Errorf("the banner stays after the cancellation:\n%s", page)
	}
	g.advance(48 * time.Hour)
	if g.keyCount("alice") != 2 {
		t.Error("the cancelled removal was carried out")
	}
	// Cancelling what is not pending is refused.
	s = g.signedIn(laptop, "alice")
	if st, _ := g.reqPost(s, "/account/removal/cancel", laptop); st != http.StatusNotFound {
		t.Errorf("cancelling nothing: %d", st)
	}
	// The control: the same request, left alone, takes the laptop.
	s = g.signedIn(phone, "alice")
	if st, _ := g.reqPost(s, "/account/remove", laptop); st != http.StatusOK {
		t.Fatal(st)
	}
	g.advance(25 * time.Hour)
	if g.keyCount("alice") != 1 {
		t.Error("control: the uncancelled removal was not carried out")
	}
	g.settle()
	if k := strings.Join(g.hook.kinds(), ","); k != "key.added,removal.requested,removal.cancelled,removal.requested,removal.done" {
		t.Errorf("the events: %s", k)
	}
}

// Cancelling is the key's account's and nobody else's: bob's session cannot
// reach alice's removal.
func TestCancellingIsForTheAccountsOwnKeys(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	_, phone, s := g.twoKeys()
	bobKey := g.enrolled("bob", webauthn.AlgES256)
	bob := g.signedIn(bobKey, "bob")
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	if st, _ := g.reqPost(bob, "/account/removal/cancel", phone); st != http.StatusNotFound {
		t.Errorf("bob cancelling alice's removal: %d", st)
	}
	if !g.pending(phone) {
		t.Error("alice's removal was cancelled through bob's session")
	}
	// Without the page's token, nothing is cancelled either.
	res := g.accountReq("POST", "/account/removal/cancel", s.cookie, map[string]string{"csrf": "x", "key": passkeyKey(phone.ID)})
	readBody(res)
	if res.StatusCode != http.StatusForbidden || !g.pending(phone) {
		t.Errorf("a cancellation without the token: %d", res.StatusCode)
	}
}

// (3) The current key's removal is immediate; the control is the other key's.
func TestTheCurrentKeysRemovalIsImmediate(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	laptop, phone, s := g.twoKeys()
	// Control: another key is deferred.
	if st, body := g.reqPost(s, "/account/remove", phone); st != http.StatusOK || !strings.Contains(body, `"pending":true`) {
		t.Fatalf("control: %d %s", st, body)
	}
	g.accountMuClear(phone)
	// The session's own key goes at once and ends the session.
	st, body := g.reqPost(s, "/account/remove", laptop)
	if st != http.StatusOK || !strings.Contains(body, `"signedOut":true`) || strings.Contains(body, "pending") {
		t.Fatalf("removing the key the session was made with: %d %s", st, body)
	}
	if _, ok, _ := g.s.passkeys.passkey(passkeyKey(laptop.ID)); ok {
		t.Error("the current key is still stored")
	}
}

// accountMuClear cancels a pending removal directly, so a test can go on from
// a clean account.
func (g *guarded) accountMuClear(a *webauthntest.Authenticator) {
	g.t.Helper()
	r, ok, err := g.s.passkeys.passkey(passkeyKey(a.ID))
	if err != nil || !ok {
		g.t.Fatal(err)
	}
	r.RemoveAt, r.RemoveRequested = time.Time{}, time.Time{}
	if err := g.s.passkeys.savePasskey(r); err != nil {
		g.t.Fatal(err)
	}
}

// A delay of 0 is the old behaviour: the other key goes at once too.
func TestADelayOfZeroRemovesAtOnce(t *testing.T) {
	g := newGuarded(t, 0)
	_, phone, s := g.twoKeys()
	st, body := g.reqPost(s, "/account/remove", phone)
	if st != http.StatusOK || strings.Contains(body, "pending") || g.keyCount("alice") != 1 {
		t.Fatalf("delay 0: %d %s", st, body)
	}
}

// The last key is never removed, and no removal may leave only keys that are
// themselves on their way out.
func TestNoRemovalLeavesNoStandingKey(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	laptop, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	// The laptop is the only key that stays: not removable, though it is the
	// session's own (which would be immediate).
	if st, _ := g.reqPost(s, "/account/remove", laptop); st != http.StatusConflict {
		t.Errorf("removing the only standing key: %d, want 409", st)
	}
	// The phone's own session cannot schedule the laptop's removal either:
	// the phone is on its way out, so nothing would stand.
	ps := g.signedIn(phone, "alice")
	if st, _ := g.reqPost(ps, "/account/remove", laptop); st != http.StatusConflict {
		t.Errorf("the pending key scheduling the other's removal: %d, want 409", st)
	}
	if g.pending(laptop) || g.keyCount("alice") != 2 {
		t.Fatal("a refused removal changed something")
	}
	// Control: with a third key the same request is accepted.
	third := mustAuth(t, webauthn.AlgES256)
	if st := g.addKey(s, third, webauthntest.Options{}); st != http.StatusOK {
		t.Fatal(st)
	}
	if st, _ := g.reqPost(ps, "/account/remove", laptop); st != http.StatusOK {
		t.Errorf("control, with a third key standing: %d", st)
	}
	// And a due removal never takes the last key even if one slipped through.
	g.advance(25 * time.Hour)
	if g.keyCount("alice") < 1 {
		t.Fatal("every key was removed")
	}
}

// (4) The notification fires with no secret in it, and is signed.
func TestTheNotificationCarriesNoSecretAndIsSigned(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	_, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.settle()
	g.hook.mu.Lock()
	defer g.hook.mu.Unlock()
	if len(g.hook.events) != 2 {
		t.Fatalf("%d events, want 2 (added, requested)", len(g.hook.events))
	}
	ev := g.hook.events[1]
	if ev.Event != "removal.requested" || ev.Login != "alice" || ev.Mail != "alice@mesocentre.example" || ev.Key != passkeyKey(phone.ID)[:16] ||
		ev.Link != g.s.cfg.Issuer+"/account" || ev.Issuer != g.s.cfg.Issuer || ev.Effective == "" || ev.Time == "" {
		t.Errorf("the event: %+v", ev)
	}
	for i, raw := range g.hook.raw {
		// The signature is the HMAC of exactly what was sent, under the secret;
		// the secret itself, a session, a CSRF token or a credential is not.
		if got, want := g.hook.heads[i].Get("X-Bridge-Signature"), sign([]byte(testNotifySecret), raw); got != want {
			t.Errorf("event %d: signature %q, want %q", i, got, want)
		}
		if sign([]byte("another secret, as long as the first one"), raw) == g.hook.heads[i].Get("X-Bridge-Signature") {
			t.Error("the signature does not depend on the secret")
		}
		all := string(raw) + fmt.Sprint(g.hook.heads[i])
		for _, secret := range []string{testNotifySecret, s.cookie, s.csrf, strings.TrimPrefix(s.cookie, accountCookieName+"="), b64(phone.ID), passkeyKey(phone.ID)} {
			if strings.Contains(all, secret) {
				t.Errorf("event %d carries %q", i, secret)
			}
		}
		// Not the client's whole address, only its family.
		// (The issuer and the link are the test server's, on 127.0.0.1: the
		// client field is what is checked.)
		var ev keyEvent
		json.Unmarshal(raw, &ev)
		if ev.Client != "ipv4" {
			t.Errorf("event %d: the client is not just a family: %s", i, raw)
		}
	}
	// The control: when the deployment asks for the address, it is there.
	g.s.cfg.Notify.IncludeAddress = true
	g.hook.mu.Unlock()
	g.resetThrottle()
	if st, _ := g.reqPost(s, "/account/removal/cancel", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.settle()
	g.hook.mu.Lock()
	var last keyEvent
	json.Unmarshal(g.hook.raw[len(g.hook.raw)-1], &last)
	if !strings.HasPrefix(last.Client, "127.0.0.1") || last.Event != "removal.cancelled" {
		t.Errorf("include_address: %+v", last)
	}
}

// Without a notify block the audit log and the banner are what there is, and
// nothing breaks; a webhook that fails is logged, without its URL.
func TestWithoutANotifyBlockTheLogIsTheFallback(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	g.s.cfg.Notify = nil
	_, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	out := g.log()
	for _, want := range []string{"account: audit: alice add ", "account: audit: alice remove-requested " + passkeyKey(phone.ID)[:16], "notify: removal.requested alice", "no notify block"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
	if len(g.hook.kinds()) != 0 {
		t.Error("the webhook was called without a notify block")
	}
	// A failing webhook: logged, the request still succeeds, the URL stays out of the log.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer bad.Close()
	g.s.cfg.Notify = &notifyBlock{URL: bad.URL + "/hook/token-in-the-path", secret: []byte(testNotifySecret)}
	if st, _ := g.reqPost(s, "/account/removal/cancel", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.settle()
	out = g.log()
	if !strings.Contains(out, "the webhook answered 500") || strings.Contains(out, "token-in-the-path") {
		t.Errorf("a failing webhook:\n%s", out)
	}
}

// The page says the removal is deferred before it is asked for, in each
// language, and the banner is translated.
func TestTheBannerAndTheQuestionAreInEveryLanguage(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	_, phone, s := g.twoKeys()
	_, page := g.accountPage(s.cookie)
	if !strings.Contains(page, "La suppression prendra effet dans 24 h") {
		t.Errorf("the remove question does not name the delay:\n%s", page)
	}
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	for _, l := range languages {
		res := g.accountReq("GET", "/account", s.cookie+"; lang="+l.Code, nil)
		body := html2text(readBody(res))
		for _, key := range []string{"rm.banner.title", "rm.cancel", "rm.pending"} {
			want, _ := lookup(l.Code, key)
			if !strings.Contains(body, want) {
				t.Errorf("%s: the page lacks %q (%s)", l.Code, want, key)
			}
		}
	}
}

func html2text(s string) string {
	return strings.NewReplacer("&#39;", "'", "&#34;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(s)
}

// The configuration: the default is 24h, "0" is immediate, nonsense is refused,
// and notify has its own rules.
func TestRemovalDelayAndNotifyConfiguration(t *testing.T) {
	f := newFixture(t, "")
	good := writeAccountsFile(t, localAccountsText())
	base, err := os.ReadFile(f.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte(testNotifySecret+"\n"), 0o600)
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("short"), 0o600)
	load := func(extra string) (*config, error) {
		p := filepath.Join(t.TempDir(), "bridge.hcl")
		os.WriteFile(p, append(append([]byte{}, base...), []byte(extra)...), 0o644)
		c, err := loadConfig([]string{p})
		if err == nil {
			t.Cleanup(func() { c.close() })
		}
		return c, err
	}
	local := func(delay string) string {
		d := ""
		if delay != "" {
			d = fmt.Sprintf("  passkey_removal_delay = %q\n", delay)
		}
		return fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n%s}\n", filepath.ToSlash(good), localScope, d) + stateExtra(t)
	}
	for in, want := range map[string]time.Duration{"": 24 * time.Hour, "0": 0, "0s": 0, "48h": 48 * time.Hour, "90m": 90 * time.Minute, "2160h": maxRemovalDelay} {
		c, err := load(local(in))
		if err != nil {
			t.Errorf("delay %q: %v", in, err)
			continue
		}
		if c.Local.removalDelay != want {
			t.Errorf("delay %q: %s, want %s", in, c.Local.removalDelay, want)
		}
	}
	for _, in := range []string{"forever", "-1h", "2161h", "24", "1 day"} {
		if _, err := load(local(in)); err == nil || !strings.Contains(err.Error(), "passkey_removal_delay") {
			t.Errorf("delay %q: %v", in, err)
		}
	}
	nb := func(url, file string) string {
		return fmt.Sprintf("notify {\n url = %q\n secret_file = %q\n}\n", url, filepath.ToSlash(file))
	}
	if c, err := load(local("") + nb("https://hooks.example.org/bridge", secret)); err != nil || string(c.Notify.secret) != testNotifySecret {
		t.Errorf("a good notify block: %v", err)
	}
	if _, err := load(local("") + nb("http://127.0.0.1:8025/hook", secret)); err != nil {
		t.Errorf("a loopback http url: %v", err)
	}
	for name, extra := range map[string]string{
		"http to a host":     local("") + nb("http://hooks.example.org/x", secret),
		"a short secret":     local("") + nb("https://hooks.example.org/x", short),
		"a missing secret":   local("") + nb("https://hooks.example.org/x", filepath.Join(dir, "none")),
		"credentials in url": local("") + nb("https://u:p@hooks.example.org/x", secret),
		"not a url":          local("") + nb("::", secret),
		"a file url":         local("") + nb("file:///etc/passwd", secret),
		"no local block":     nb("https://hooks.example.org/x", secret),
	} {
		if _, err := load(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
