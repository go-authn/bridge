// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

// The e-mail notice of a deferred removal (mailnotice.go, #122): the clock is the
// test's, the mail server a fake one speaking TLS.

// withMail points g at a fake mail server (a working one unless broken).
func withMail(t *testing.T, g *guarded, broken bool) *fakeSMTP {
	t.Helper()
	f := smtpOK("tls")
	tc := startSMTP(t, f, "127.0.0.1")
	m := f.block(t, "tls")
	m.window = defaultMailWindow
	if broken {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		m.Port = ln.Addr().(*net.TCPAddr).Port
		ln.Close() // nobody answers there
	}
	g.s.cfg.Mail, g.s.mailTLS = m, tc
	return f
}

func (f *fakeSMTP) mailCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.mails) }

func (f *fakeSMTP) lastMail() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mails) == 0 {
		return ""
	}
	return f.mails[len(f.mails)-1]
}

// lastBody is the last mail's body as the reader sees it, decoded.
func (f *fakeSMTP) lastBody(t *testing.T) string {
	t.Helper()
	m, err := netmail.ReadMessage(strings.NewReader(strings.ReplaceAll(f.lastMail(), "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// record reads the stored record of a key.
func (g *guarded) record(a *webauthntest.Authenticator) *passkeyRecord {
	g.t.Helper()
	r, ok, err := g.s.passkeys.passkey(passkeyKey(a.ID))
	if err != nil || !ok {
		g.t.Fatalf("the key is not stored: %v", err)
	}
	return r
}

// A removal request is carried out only after a notice was delivered; the
// control is the same request with a working server.
func TestARemovalWaitsForItsNoticeAndIsCarriedOutOnceDelivered(t *testing.T) {
	g := newGuarded(t, time.Hour)
	srv := withMail(t, g, false)
	_, phone, s := g.twoKeys()
	g.settle()
	if st, body := g.reqPost(s, "/account/remove", phone); st != http.StatusOK || !strings.Contains(body, `"pending":true`) {
		t.Fatalf("%d %s", st, body)
	}
	g.settle()
	if srv.mailCount() != 1 {
		t.Fatalf("%d mails, want 1:\n%s", srv.mailCount(), g.log())
	}
	body := srv.lastBody(t)
	for _, want := range []string{"removal REQUESTED", passkeyKey(phone.ID)[:16], "(added ", "unless somebody cancels", "If it was not you"} {
		if !strings.Contains(body, want) {
			t.Errorf("the mail lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "://") || strings.Contains(body, "www.") {
		t.Errorf("the mail carries a link:\n%s", body)
	}
	if !srv.saw("RCPT TO:<ALICE@MESOCENTRE.EXAMPLE>") {
		t.Errorf("the notice did not go to the account's address: %q", srv.cmds)
	}
	if g.record(phone).NoticePending {
		t.Error("delivered, and still waiting for a notice")
	}
	g.advance(2 * time.Hour)
	g.s.sweepRemovals()
	if g.keyCount("alice") != 1 {
		t.Error("the removal was not carried out after the notice was delivered")
	}
}

func TestARemovalWhoseNoticeCannotBeSentStaysPendingWithABoundedRetry(t *testing.T) {
	g := newGuarded(t, time.Hour)
	withMail(t, g, true)
	_, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.settle()
	if !g.record(phone).NoticePending {
		t.Fatal("the request does not wait for a notice")
	}
	// The delay ends with no notice delivered: the key stays.
	g.advance(2 * time.Hour)
	g.s.sweepRemovals()
	if g.keyCount("alice") != 2 || !g.pending(phone) {
		t.Fatal("a removal whose notice was never delivered was carried out")
	}
	// Retries: a pause between them (no storm), at most maxMailTries.
	for i := 0; i < 20; i++ {
		g.s.noticeFlushAll()
		g.settle()
		g.advance(40 * time.Minute)
	}
	g.s.noticeMu.Lock()
	a := g.s.notices["alice"]
	tries, gaveUp := a.tries, a.gaveUp
	g.s.noticeMu.Unlock()
	if tries != maxMailTries || !gaveUp {
		t.Errorf("tries %d, gave up %v: want %d and true", tries, gaveUp, maxMailTries)
	}
	if n := strings.Count(g.log(), "mailing alice failed"); n != maxMailTries-1 {
		t.Errorf("%d failure lines, want %d:\n%s", n, maxMailTries-1, g.log())
	}
	if !strings.Contains(g.log(), "GAVE UP") {
		t.Errorf("no loud line:\n%s", g.log())
	}
	g.advance(1000 * time.Hour)
	g.s.sweepRemovals()
	if g.keyCount("alice") != 2 {
		t.Error("the removal went through after the retries ended")
	}
}

// A cancellation cannot be blocked, whatever happens to its mail; the failure is
// logged and shown on the account page.
func TestACancellationAppliesWhenItsMailFails(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	withMail(t, g, true)
	laptop, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	s = g.signedIn(laptop, "alice")
	if st, body := g.reqPost(s, "/account/removal/cancel", phone); st != http.StatusOK || !strings.Contains(body, `"cancelled"`) {
		t.Fatalf("cancelling: %d %s", st, body)
	}
	g.settle()
	if g.pending(phone) {
		t.Fatal("the cancellation did not apply")
	}
	if !strings.Contains(g.log(), "mailing alice failed") {
		t.Errorf("the failure is not logged:\n%s", g.log())
	}
	_, page := g.accountPage(s.cookie)
	if !strings.Contains(page, `data-notice="failed"`) {
		t.Errorf("the page does not say the notice failed:\n%s", page)
	}
}

// An account with no address: the request proceeds, and the page and the log say
// that nobody was told.
func TestAnAccountWithoutAnAddressStillGetsItsRemovalAndSaysSo(t *testing.T) {
	g := newGuarded(t, time.Hour)
	srv := withMail(t, g, false)
	laptop := g.enrolled("bob", webauthn.AlgES256)
	s := g.signedIn(laptop, "bob")
	phone := mustAuth(g.t, webauthn.AlgEdDSA)
	if st := g.addKey(s, phone, webauthntest.Options{}); st != http.StatusOK {
		t.Fatalf("adding the phone: %d", st)
	}
	if st, body := g.reqPost(s, "/account/remove", phone); st != http.StatusOK || !strings.Contains(body, `"pending":true`) {
		t.Fatalf("%d %s", st, body)
	}
	g.settle()
	if g.record(phone).NoticePending || srv.mailCount() != 0 || len(srv.cmds) != 0 {
		t.Error("a notice is waiting for an address that does not exist")
	}
	if !strings.Contains(g.log(), "bob has no usable mail address") {
		t.Errorf("the log does not say nobody was told:\n%s", g.log())
	}
	if _, page := g.accountPage(s.cookie); !strings.Contains(page, `data-notice="none"`) {
		t.Errorf("the page does not say nobody was told:\n%s", page)
	}
	g.advance(2 * time.Hour)
	g.s.sweepRemovals()
	if g.keyCount("bob") != 1 {
		t.Error("the removal was held for want of an address")
	}
}

// A storm of requests and cancellations is one digest per window.
func TestAStormOfEventsIsOneDigestPerWindow(t *testing.T) {
	g := newGuarded(t, 24*time.Hour)
	srv := withMail(t, g, false)
	laptop, phone, s := g.twoKeys()
	g.settle()
	s = g.signedIn(laptop, "alice")
	for i := 0; i < 6; i++ {
		if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
			t.Fatal(st)
		}
		if st, _ := g.reqPost(s, "/account/removal/cancel", phone); st != http.StatusOK {
			t.Fatal(st)
		}
		g.advance(30 * time.Second)
		g.settle()
	}
	if n := srv.mailCount(); n != 1 {
		t.Fatalf("%d mails inside one window, want 1", n)
	}
	g.advance(11 * time.Minute)
	g.s.noticeFlushAll()
	g.settle()
	if n := srv.mailCount(); n != 2 {
		t.Fatalf("%d mails after the window, want 2", n)
	}
	digest := srv.lastBody(t)
	if n := strings.Count(digest, "\n- "); n < 10 {
		t.Errorf("the digest lists %d events, want the 11 that were collapsed:\n%s", n, digest)
	}
	g.advance(11 * time.Minute)
	g.s.noticeFlushAll()
	g.settle()
	if srv.mailCount() != 2 {
		t.Error("a mail with nothing in it")
	}
}

// A restart forgets the in-memory queue, not the fact that a removal awaits its
// notice: the sweep brings it back.
func TestARestartKeepsAPendingNotice(t *testing.T) {
	g := newGuarded(t, time.Hour)
	withMail(t, g, true)
	_, phone, s := g.twoKeys()
	if st, _ := g.reqPost(s, "/account/remove", phone); st != http.StatusOK {
		t.Fatal(st)
	}
	g.settle()
	srv := withMail(t, g, false)
	g.s.notices = nil // the restart
	g.s.sweepRemovals()
	g.settle()
	if srv.mailCount() != 1 || g.record(phone).NoticePending {
		t.Fatalf("mails %d, pending %v:\n%s", srv.mailCount(), g.record(phone).NoticePending, g.log())
	}
}
