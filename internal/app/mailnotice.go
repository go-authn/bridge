// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// The e-mail notice of a deferred passkey removal (#122).
//
//   - Recipient: the account's own address, the `mail` attribute of its record in
//     accounts_file (localMail), never anything from a request. An account with
//     none still gets its removal, and the account page and the log say that
//     nobody was told.
//   - A removal REQUEST is not carried out until a notice has been DELIVERED
//     (passkeyRecord.NoticePending, cleared by the delivery, persisted so a
//     restart keeps it). If the mail cannot be sent the bridge retries, at most
//     maxMailTries times with a growing pause, then logs loudly and leaves the
//     removal pending: the safe direction, since a thief's request for the
//     removal of the owner's key is the very thing the notice exists to expose.
//   - A CANCELLATION applies at once whatever happens to its mail, since it
//     cannot be blocked: a failure is logged and shown on the account page.
//   - Notices to one account are collapsed into one digest per
//     mail { window } (default 10 minutes), so a storm of requests and
//     cancellations is one mail, not hundreds.
const (
	maxMailTries = 5
	maxQueued    = 50
)

// A mailEvent is one line of a digest.
type mailEvent struct {
	Kind      string // "requested" or "cancelled"
	At        time.Time
	FullKey   string
	Key       string // the first sixteen characters, as the account page shows it
	Created   time.Time
	Effective time.Time
	Addr, UA  string
}

// acctNotices is what is waiting to be mailed to one account, and how the last
// attempts went.
type acctNotices struct {
	queue   []mailEvent
	dropped int // events beyond maxQueued, counted in the digest, not listed
	last    time.Time
	nextTry time.Time
	tries   int
	gaveUp  bool
	sending bool
	failed  bool
}

// noticeTo is the address a notice for login goes to, "" when none will be
// sent: no mail block, or the account has no usable address (logged).
func (s *server) noticeTo(login string) string {
	if s.cfg.Mail == nil {
		return ""
	}
	to := s.localMail(login)
	if _, err := mailAddr(to); err != nil {
		s.logf("account: notice: %s has no usable mail address in its record: the removal proceeds and nobody is told", login)
		return ""
	}
	return to
}

// noticeKey queues the notice of an event about a key. r is the request that
// caused it.
func (s *server) noticeKey(kind, login string, rec *passkeyRecord, effective time.Time, r *http.Request) {
	if s.noticeTo(login) == "" {
		return
	}
	ev := mailEvent{Kind: kind, At: s.now(), FullKey: rec.key(), Key: rec.key()[:16], Created: rec.Created, Effective: effective}
	if kind == "requested" {
		// The record's own instant: it is how the delivery finds the request again.
		ev.At = rec.RemoveRequested
	}
	if r != nil {
		ev.Addr, ev.UA = textField(s.clientAddr(r)), textField(r.UserAgent())
	}
	s.noticeEnqueue(login, ev)
}

func (s *server) noticeEnqueue(login string, ev mailEvent) {
	s.noticeMu.Lock()
	if s.notices == nil {
		s.notices = map[string]*acctNotices{}
	}
	a := s.notices[login]
	if a == nil {
		a = &acctNotices{}
		s.notices[login] = a
	}
	for _, q := range a.queue {
		if q.Kind == ev.Kind && q.FullKey == ev.FullKey && q.At.Equal(ev.At) {
			s.noticeMu.Unlock()
			return
		}
	}
	if len(a.queue) >= maxQueued {
		a.dropped++
	} else {
		a.queue = append(a.queue, ev)
	}
	a.tries, a.gaveUp = 0, false // news: try again
	s.noticeMu.Unlock()
	s.noticeLaunch(login)
}

// noticeLaunch sends in the background, bounded like the webhook's deliveries.
func (s *server) noticeLaunch(login string) {
	select {
	case s.notifySlots <- struct{}{}:
	default:
		return // the sweep will come back to it
	}
	s.notifyWG.Add(1)
	go func() {
		defer s.notifyWG.Done()
		defer func() { <-s.notifySlots }()
		s.noticeFlush(login)
	}()
}

// noticeFlushAll tries every account that has something waiting.
func (s *server) noticeFlushAll() {
	s.noticeMu.Lock()
	var logins []string
	for l, a := range s.notices {
		if len(a.queue) > 0 {
			logins = append(logins, l)
		}
	}
	s.noticeMu.Unlock()
	for _, l := range logins {
		s.noticeLaunch(l)
	}
}

// noticeFlush sends login's digest if the window, the pause after a failure and
// the bound on tries allow it.
func (s *server) noticeFlush(login string) {
	m := s.cfg.Mail
	if m == nil {
		return
	}
	s.noticeMu.Lock()
	a := s.notices[login]
	now := s.now()
	if a == nil || len(a.queue) == 0 || a.sending || a.gaveUp || now.Before(a.nextTry) ||
		(!a.last.IsZero() && now.Sub(a.last) < m.window) {
		s.noticeMu.Unlock()
		return
	}
	batch, dropped := slices.Clone(a.queue), a.dropped
	a.sending = true
	s.noticeMu.Unlock()

	err := s.noticeSend(login, batch, dropped)

	s.noticeMu.Lock()
	a.sending = false
	if err == nil {
		a.last, a.tries, a.failed = s.now(), 0, false
		a.queue = a.queue[len(batch):]
		a.dropped -= dropped
		s.noticeMu.Unlock()
		s.logf("account: notice: %d event(s) mailed to the holder of %s", len(batch), login)
		s.noticeDelivered(login, batch)
		return
	}
	a.tries++
	a.failed = true
	a.nextTry = now.Add(time.Minute << min(a.tries, 5))
	gave := a.tries >= maxMailTries
	a.gaveUp = gave
	s.noticeMu.Unlock()
	if gave {
		s.logf("account: notice: GAVE UP mailing %d event(s) for %s after %d tries (%v): a removal request stays pending until a notice is delivered; a new event tries again", len(batch), login, maxMailTries, err)
		return
	}
	s.logf("account: notice: mailing %s failed (try %d of %d): %v", login, a.tries, maxMailTries, err)
}

func (s *server) noticeSend(login string, batch []mailEvent, dropped int) error {
	m := s.cfg.Mail
	to := s.localMail(login)
	msg, err := buildMessage(m.From, to, "Passkey removal activity on your account", s.now(), digestBody(s.cfg.Issuer, login, batch, dropped))
	if err != nil {
		return err
	}
	var tc *tls.Config = s.mailTLS
	return m.send(context.Background(), tc, to, msg)
}

// noticeDelivered lets the removal requests in a delivered digest proceed.
func (s *server) noticeDelivered(login string, batch []mailEvent) {
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	for _, ev := range batch {
		if ev.Kind != "requested" {
			continue
		}
		rec, err := s.passkeys.findPasskey(login, ev.FullKey)
		if err != nil || !rec.pending() || !rec.NoticePending || !rec.RemoveRequested.Equal(ev.At) {
			continue
		}
		rec.NoticePending = false
		if err := s.passkeys.savePasskey(rec); err != nil {
			s.logf("account: notice: recording the delivery for %s: %v", login, err)
		}
	}
}

// noticeRelease lets removals that wait for a notice proceed when the mail block
// is no longer configured: there is nothing left to deliver it with, and holding
// them for ever would leave a key nobody can remove.
func (s *server) noticeRelease(recs []passkeyRecord) {
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	for i := range recs {
		rec, err := s.passkeys.findPasskey(recs[i].Login, recs[i].key())
		if err != nil || !rec.NoticePending {
			continue
		}
		rec.NoticePending = false
		if err := s.passkeys.savePasskey(rec); err != nil {
			s.logf("account: notice: releasing a removal of %s: %v", rec.Login, err)
		}
	}
}

// noticeFailed says whether the last notice to login could not be mailed.
func (s *server) noticeFailed(login string) bool {
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	a := s.notices[login]
	return a != nil && a.failed
}

// digestBody is the mail: plain text, what happened, when, which key, from where,
// and what to do. It carries no link that does anything.
func digestBody(issuer, login string, evs []mailEvent, dropped int) string {
	var b strings.Builder
	// The scheme is left off so that no mail client turns the name into a link.
	issuer = strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	fmt.Fprintf(&b, "This is a notice about the passkeys of your account %q at %s.\n\n", textField(login), textField(issuer))
	for _, ev := range evs {
		when := ev.At.UTC().Format("2006-01-02 15:04 MST")
		what := "removal CANCELLED for"
		if ev.Kind == "requested" {
			what = "removal REQUESTED for"
		}
		fmt.Fprintf(&b, "- %s: %s the passkey %s (added %s)", when, what, ev.Key, ev.Created.UTC().Format("2006-01-02"))
		if ev.Kind == "requested" && !ev.Effective.IsZero() {
			fmt.Fprintf(&b, "; it is removed on %s unless somebody cancels", ev.Effective.UTC().Format("2006-01-02 15:04 MST"))
		}
		if ev.Addr != "" {
			fmt.Fprintf(&b, ". From %s", ev.Addr)
			if ev.UA != "" {
				fmt.Fprintf(&b, " (%s)", ev.UA)
			}
		}
		b.WriteString(".\n")
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "- and %d more event(s) in the same period.\n", dropped)
	}
	b.WriteString("\nIf this was you, nothing more is needed.\n")
	b.WriteString("If it was not you, somebody may hold one of your passkeys: log in to your account page at your usual address, typed or bookmarked by you, and cancel any removal you did not ask for, then remove the passkey you no longer trust and tell your administrator.\n")
	b.WriteString("\nThis message contains no link on purpose. Do not act on any message that asks you to follow one.\n")
	return b.String()
}
