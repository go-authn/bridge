// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// Guardrails against somebody who holds ONE of a person's passkeys (a stolen,
// unlocked phone) removing the others from /account.
//
//   - Removing a key OTHER than the one the page was opened with is DEFERRED:
//     the key is "pending removal" for local { passkey_removal_delay } (24h by
//     default, "0" removes at once, as before). It keeps working, and any of the
//     account's keys can cancel the removal from /account, which says so in a
//     banner on every visit. Removing the key you are signed in with stays
//     immediate, and the last key is never removed.
//   - Every key added, and every removal requested, cancelled or done, is
//     reported: an audit line always, the banner, and, when the configuration
//     has a notify { url, secret_file } block, a signed webhook to whatever
//     sends the person their mail. The bridge has no mail facility of its own.
const (
	defaultRemovalDelay = 24 * time.Hour
	// maxRemovalDelay bounds the setting: a key that cannot be removed for a
	// year is a key that cannot be removed.
	maxRemovalDelay = 90 * 24 * time.Hour
)

// ---- the notify block ----

// notifyBlock is the `notify` block: where the events about an account's keys
// go. Optional; without it the audit log and the banner are all there is.
type notifyBlock struct {
	// URL receives a POST of one JSON object per event. https, or http to a
	// loopback address (a relay on the same host).
	URL string `hcl:"url"`
	// SecretFile holds the key the body is signed with (HMAC-SHA-256, header
	// X-Bridge-Signature: sha256=<hex>). The secret is never sent.
	SecretFile string `hcl:"secret_file"`
	// IncludeAddress puts the client's whole address in the event. By default
	// only its family ("ipv4" or "ipv6") is: the event ends up in a mail.
	IncludeAddress bool `hcl:"include_address,optional"`

	secret []byte
}

const minNotifySecret = 16

func (n *notifyBlock) check() error {
	u, err := url.Parse(n.URL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("url %q: an https URL without credentials", n.URL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip, err := netip.ParseAddr(u.Hostname())
		if u.Hostname() != "localhost" && (err != nil || !ip.IsLoopback()) {
			return fmt.Errorf("url %q: http is for a loopback address only; use https", n.URL)
		}
	default:
		return fmt.Errorf("url %q: an https URL", n.URL)
	}
	b, err := os.ReadFile(n.SecretFile)
	if err != nil {
		return fmt.Errorf("secret_file: %w", err)
	}
	n.secret = bytes.TrimSpace(b)
	if len(n.secret) < minNotifySecret {
		return fmt.Errorf("secret_file: a secret of %d characters is one somebody can guess; at least %d", len(n.secret), minNotifySecret)
	}
	return nil
}

// An event is what the webhook receives. No secret is in it: not the signing
// key, not a session, not a credential; the key is named by the first sixteen
// characters of its identifier, as the account page does.
type keyEvent struct {
	Event     string `json:"event"` // key.added, removal.requested, removal.cancelled, removal.done
	Time      string `json:"time"`  // RFC 3339, UTC
	Issuer    string `json:"issuer"`
	Login     string `json:"login"`
	Mail      string `json:"mail,omitempty"`
	Key       string `json:"key"`
	Effective string `json:"effective,omitempty"` // removal.requested: when the key goes
	Client    string `json:"client"`              // "ipv4", "ipv6", "unknown", or the address when configured
	Link      string `json:"link"`                // the account page
}

// addrFamily is "ipv4", "ipv6" or "unknown".
func addrFamily(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	ip, err := netip.ParseAddr(strings.Trim(addr, "[]"))
	switch {
	case err != nil:
		return "unknown"
	case ip.Is4() || ip.Is4In6():
		return "ipv4"
	}
	return "ipv6"
}

// localMail is the mail an account is known by, "" when it has none.
func (s *server) localMail(login string) string {
	if s.cfg.Local == nil || s.cfg.Local.store == nil {
		return ""
	}
	id, ok := s.cfg.Local.store.get(login)
	if !ok {
		return ""
	}
	if m := id.Attributes().Get("mail"); len(m) > 0 {
		return m[0]
	}
	return ""
}

// keyEvent reports an event about an account's keys. addr is the client's
// address, "" when no request caused it (a removal that came due).
func (s *server) keyEvent(kind, login string, rec *passkeyRecord, effective time.Time, addr string) {
	ev := keyEvent{
		Event: kind, Time: s.now().UTC().Format(time.RFC3339), Issuer: s.cfg.Issuer, Login: login,
		Mail: s.localMail(login), Key: rec.key()[:16], Client: addrFamily(addr), Link: s.cfg.Issuer + "/account",
	}
	if !effective.IsZero() {
		ev.Effective = effective.UTC().Format(time.RFC3339)
	}
	n := s.cfg.Notify
	if n != nil && n.IncludeAddress && addr != "" {
		ev.Client = addr
	}
	if n == nil {
		s.logf("account: notify: %s %s %s (no notify block: the audit log and the banner)", kind, login, ev.Key)
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		s.logf("account: notify: %v", err)
		return
	}
	select {
	case s.notifySlots <- struct{}{}:
	default:
		s.logf("account: notify: %s %s dropped: %d deliveries already in flight", kind, login, cap(s.notifySlots))
		return
	}
	s.notifyWG.Add(1)
	go func() {
		defer s.notifyWG.Done()
		defer func() { <-s.notifySlots }()
		if err := s.deliver(n, body); err != nil {
			s.logf("account: notify: %s %s: %v", kind, login, err)
		}
	}()
}

// sign is the signature of a body: HMAC-SHA-256 under the shared secret.
func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// deliver posts one event: five seconds, no redirect (a webhook that answers
// with one is misconfigured, and following it would send the body elsewhere),
// and a 2xx is a delivery.
func (s *server) deliver(n *notifyBlock, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "authn-bridge")
	req.Header.Set("X-Bridge-Signature", sign(n.secret, body))
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if s.notifyClient != nil {
		c = s.notifyClient
	}
	res, err := c.Do(req)
	if err != nil {
		return errors.New("the webhook could not be reached") // the URL is not repeated: it may carry a token
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("the webhook answered %d", res.StatusCode)
	}
	return nil
}

// ---- finding a key ----

// findPasskey is the credential of login whose row key starts with prefix (at
// least eight characters, and unique among the login's).
func (s *passkeyStore) findPasskey(login, prefix string) (*passkeyRecord, error) {
	if len(prefix) < 8 {
		return nil, errors.New("give at least the first 8 characters of the ID")
	}
	list, err := s.passkeys(login)
	if err != nil {
		return nil, err
	}
	var hit []*passkeyRecord
	for _, r := range list {
		if strings.HasPrefix(r.key(), prefix) {
			hit = append(hit, r)
		}
	}
	switch len(hit) {
	case 0:
		return nil, fmt.Errorf("%s has no passkey starting %q", login, prefix)
	case 1:
		return hit[0], nil
	}
	return nil, fmt.Errorf("%q starts %d of %s's passkeys: give more of it", prefix, len(hit), login)
}

// standing is how many of the keys would still be there, and not on their way
// out, without target.
func standing(list []*passkeyRecord, target *passkeyRecord) int {
	n := 0
	for _, r := range list {
		if r.key() != target.key() && !r.pending() {
			n++
		}
	}
	return n
}

// ---- the handlers ----

// accountRemove removes one passkey of the signed-in local account. It refuses
// a removal that would leave no key standing (the account would be locked out
// of its own page, and every grant bought without a passkey would end), counting
// as standing only keys with no removal pending. The key the session was made
// with goes at once, and ends the session: its credential is gone, and the
// grants it bought stop (localAccountGone, #87). Any other key is deferred for
// local { passkey_removal_delay } unless that is 0: it is marked, keeps working,
// and can be cancelled from the page by any of the account's keys.
func (s *server) accountRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
		Key  string `json:"key"`
	}
	k, sess, ok := s.localSession(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	login := sess.who.username
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	have, err := s.passkeys.passkeys(login)
	if err != nil {
		s.logf("local: reading passkeys: %v", err)
		http.Error(w, "the passkeys could not be read", http.StatusInternalServerError)
		return
	}
	if len(have) <= 1 {
		http.Error(w, "this is your last passkey: add another before removing it", http.StatusConflict)
		return
	}
	target, err := s.passkeys.findPasskey(login, req.Key)
	if err != nil {
		s.localLimit.failed(s.clientAddr(r), "")
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	if standing(have, target) < 1 {
		http.Error(w, "this would leave you with no passkey that stays: cancel a pending removal or add another passkey first", http.StatusConflict)
		return
	}
	addr := s.clientAddr(r)
	delay := s.cfg.Local.removalDelay
	if target.key() != sess.credential && delay > 0 {
		if target.pending() { // already asked: the time does not move
			writeJSONNoStore(w, http.StatusOK, map[string]any{"pending": true, "removeAt": target.RemoveAt.UTC().Format(time.RFC3339), "signedOut": false})
			return
		}
		target.RemoveRequested, target.RemoveAt = s.now(), s.now().Add(delay)
		// With a mail block the removal waits for a delivered notice (#122).
		target.NoticePending = s.noticeTo(login) != ""
		if err := s.passkeys.savePasskey(target); err != nil {
			s.logf("local: marking a passkey of %s for removal: %v", login, err)
			http.Error(w, "the removal could not be recorded", http.StatusInternalServerError)
			return
		}
		s.audit(sess, "remove-requested", target.key(), r)
		s.keyEvent("removal.requested", login, target, target.RemoveAt, addr)
		s.noticeKey("requested", login, target, target.RemoveAt, r)
		writeJSONNoStore(w, http.StatusOK, map[string]any{"pending": true, "removeAt": target.RemoveAt.UTC().Format(time.RFC3339), "signedOut": false})
		return
	}
	rec, err := s.passkeys.removePasskey(login, req.Key)
	if err != nil {
		s.localLimit.failed(addr, "")
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	ended := rec.key() == sess.credential
	if ended {
		s.accountSessions.take(k)
		http.SetCookie(w, s.accountCookie("", -1))
	}
	s.audit(sess, "remove", rec.key(), r)
	s.keyEvent("removal.done", login, rec, time.Time{}, addr)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"removed": rec.key()[:16], "signedOut": ended})
}

// accountRemovalCancel cancels a pending removal. Any key of the account may:
// that is the point, a person with one good key undoes what a stolen one asked.
func (s *server) accountRemovalCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
		Key  string `json:"key"`
	}
	_, sess, ok := s.localSession(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	login := sess.who.username
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	target, err := s.passkeys.findPasskey(login, req.Key)
	if err != nil || !target.pending() {
		s.localLimit.failed(s.clientAddr(r), "")
		http.Error(w, "no removal is pending for this passkey", http.StatusNotFound)
		return
	}
	target.RemoveAt, target.RemoveRequested, target.NoticePending = time.Time{}, time.Time{}, false
	if err := s.passkeys.savePasskey(target); err != nil {
		s.logf("local: cancelling the removal of a passkey of %s: %v", login, err)
		http.Error(w, "the cancellation could not be recorded", http.StatusInternalServerError)
		return
	}
	s.audit(sess, "remove-cancelled", target.key(), r)
	s.keyEvent("removal.cancelled", login, target, time.Time{}, s.clientAddr(r))
	// The cancellation is done whatever becomes of its mail: it cannot be blocked.
	s.noticeKey("cancelled", login, target, time.Time{}, r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"cancelled": target.key()[:16]})
}

// ---- carrying out the removals that come due ----

// sweepRemovals carries out the removals whose time has come for every
// account, once. The login and the account page do it for the keys they touch;
// this is what makes "done" happen, and be reported, when nobody looks.
func (s *server) sweepRemovals() {
	if s.passkeys == nil {
		return
	}
	logins := map[string]bool{}
	var unnoticed []passkeyRecord
	now := s.now()
	err := s.passkeys.each(kindPasskey, func(_ string, raw []byte) {
		var r passkeyRecord
		if json.Unmarshal(raw, &r) != nil {
			return
		}
		if r.due(now) {
			logins[r.Login] = true
		}
		if r.pending() && r.NoticePending {
			unnoticed = append(unnoticed, r)
		}
	})
	// A removal still waiting for its notice (a restart forgot the queue, or the
	// first try failed): queue it again, and try what is waiting.
	if s.cfg.Mail == nil {
		s.noticeRelease(unnoticed) // the block was taken out of the configuration
	}
	for i := range unnoticed {
		r := &unnoticed[i]
		if s.cfg.Mail == nil {
			break
		}
		s.noticeEnqueue(r.Login, mailEvent{Kind: "requested", At: r.RemoveRequested, FullKey: r.key(), Key: r.key()[:16], Created: r.Created, Effective: r.RemoveAt})
	}
	s.noticeFlushAll()
	if err != nil {
		s.logf("account: sweeping the pending removals: %v", err)
		return
	}
	for l := range logins {
		s.accountMu.Lock()
		_, err := s.passkeys.passkeys(l)
		s.accountMu.Unlock()
		if err != nil {
			s.logf("account: carrying out the removals of %s: %v", l, err)
		}
	}
}

// sweepLoop runs sweepRemovals every minute until ctx ends.
func (s *server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepRemovals()
		}
	}
}

// removalDone is the store's callback for a removal that came due.
func (s *server) removalDone(rec *passkeyRecord) {
	s.logf("account: audit: %s remove-done %s (the delay was over)", orUnnamed(rec.Login), rec.key()[:16])
	s.counters.inc("bridge_logins_total", "account_remove-done")
	s.keyEvent("removal.done", rec.Login, rec, time.Time{}, "")
}

// delayText is a delay as a person reads it in any language: "24 h", "90 min".
func delayText(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d h", int(d/time.Hour))
	}
	return fmt.Sprintf("%d min", int(d.Round(time.Minute)/time.Minute))
}
