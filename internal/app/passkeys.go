// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/webauthn"
)

// Passkeys: how a local account proves itself, and how it gets one.
//
// ⛔ The credentials and the invitations are in the provider's STATE DATABASE
// (state.go's bridge_state table), not in the accounts file: a signature
// counter changes at every login. They are read from the database at every
// use rather than held in memory, because `authn-bridge local-account` is
// another process: an invitation it issues must be usable at once, and a
// passkey it removes must stop working at once, not at the next restart.
//
// Enrolment is by a one-time invitation an administrator issues. The URL is
// <issuer>/local/enroll#<token>: the token is in the FRAGMENT, which a browser
// never sends, so it is in no access log and no Referer header. It is stored
// as its SHA-256, single-use, expiring, and revocable. Nothing is created by
// visiting a page: the page's script posts the token to /local/enroll/begin.

const (
	kindPasskey = "passkey"
	kindInvite  = "invite"
	// kindProfile is a local account's display name, when its owner changed it
	// (account.go): the one profile field that is theirs.
	kindProfile = "profile"

	// inviteDefaultTTL and inviteMaxTTL bound an invitation's life.
	inviteDefaultTTL = 24 * time.Hour
	inviteMaxTTL     = 72 * time.Hour

	// maxPasskeys is how many one account may have.
	maxPasskeys = 10

	// ceremonyTTL is how long a challenge may wait for its answer.
	ceremonyTTL = 5 * time.Minute

	// maxJSONBody bounds what the enrolment endpoints read; a registration is
	// about a kilobyte.
	maxJSONBody = 64 << 10
	// maxFormField bounds one field of the login's form post.
	maxFormField = 16 << 10
)

// passkeyForever is the expiry of a credential row: the state table expires
// rows, and a passkey does not.
var passkeyForever = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC)

var (
	errNoInvite = errors.New("no such invitation, or it has expired or been used")
)

// passkeyRecord is what is stored per credential.
type passkeyRecord struct {
	Login          string   `json:"login"`
	ID             []byte   `json:"id"`
	PublicKey      []byte   `json:"key"`
	SignCount      uint32   `json:"count"`
	BackupEligible bool     `json:"be"`
	BackupState    bool     `json:"bs"`
	Transports     []string `json:"transports,omitempty"`
	AAGUID         []byte   `json:"aaguid,omitempty"`
	// AttestedAAGUID is the model of the authenticator, in canonical UUID form,
	// ONLY when it was proved at registration by an attestation statement whose
	// certificate chain leads to a root the FIDO Metadata Service lists for that
	// AAGUID. attest.go sets it, for an administrator's registration only, and
	// only when the statement verified AND its chain led to such a root; AAGUID
	// above is the authenticator's own word, and a passkey that registered
	// before this, or under attestation "none", has it empty. The administrator
	// gate (admininvite.go) reads this field and never AAGUID.
	AttestedAAGUID string    `json:"attested_aaguid,omitempty"`
	Created        time.Time `json:"created"`
	LastUsed       time.Time `json:"last_used,omitzero"`
	// RemoveAt is when a removal the person asked for from /account takes
	// effect (zero: none is pending). Until then the key works like any other;
	// any of the account's keys may cancel it (account_removal.go).
	RemoveAt        time.Time `json:"remove_at,omitzero"`
	RemoveRequested time.Time `json:"remove_requested,omitzero"`
	// NoticePending is set when the request was made with a mail block and an
	// address to tell: the removal waits, however late, until a notice has been
	// delivered (mailnotice.go).
	NoticePending bool `json:"notice_pending,omitempty"`
}

func (r *passkeyRecord) key() string { return passkeyKey(r.ID) }

// pending says whether a removal is waiting on this key; due, whether its time
// has come.
func (r *passkeyRecord) pending() bool { return !r.RemoveAt.IsZero() }
func (r *passkeyRecord) due(now time.Time) bool {
	return !r.RemoveAt.IsZero() && !now.Before(r.RemoveAt) && !r.NoticePending
}

// passkeyKey is the row key of a credential: the SHA-256 of its ID in
// lowercase HEX, 64 characters whatever the ID's length (up to 1023 bytes), and
// what the CLI shows as the credential's ID.
//
// ⛔ Hex, not base64url like hashToken: base64url's alphabet has '-', so one key
// in 64 began with it, and `local-account remove-passkey alice -jvlq…` was read
// by the command line as a flag. An administrator could not remove that key,
// and removing a key is what the command exists for, typically a lost or
// compromised one. TestLocalAccountCLIAgainstARunningProvider caught it at
// random (7fd1ed1, coverage lane); TestPasskeyKeyIsNeverAFlag holds it now.
func passkeyKey(id []byte) string {
	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:])
}

func (r *passkeyRecord) credential() webauthn.Credential {
	c := webauthn.Credential{ID: r.ID, PublicKeyCOSE: r.PublicKey, SignCount: r.SignCount, BackupEligible: r.BackupEligible, Transports: r.Transports}
	copy(c.AAGUID[:], r.AAGUID)
	return c
}

// inviteRecord is an invitation, stored under the SHA-256 of its token.
type inviteRecord struct {
	Login   string    `json:"login"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by,omitempty"`
}

// passkeyStore is the credentials and invitations, over the state database.
type passkeyStore struct {
	b   *stateBlock
	now func() time.Time
	// onRemoved is called, once, for a key whose pending removal has come due
	// and was carried out (account_removal.go). May be nil.
	onRemoved func(*passkeyRecord)
}

func (s *passkeyStore) put(kind, k string, v any, expires time.Time) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return (&persister{b: s.b}).put(kind, k, raw, expires)
}

// get reads one row, not expired.
func (s *passkeyStore) get(kind, k string, v any) (bool, error) {
	var raw string
	var exp int64
	err := s.b.db.QueryRow(`SELECT v, expires FROM bridge_state WHERE kind = `+s.b.arg(1)+` AND k = `+s.b.arg(2), kind, k).Scan(&raw, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !s.now().Before(time.Unix(exp, 0)) {
		return false, nil
	}
	return true, json.Unmarshal([]byte(raw), v)
}

// del removes a row and says whether it was there.
func (s *passkeyStore) del(kind, k string) (bool, error) {
	res, err := s.b.db.Exec(`DELETE FROM bridge_state WHERE kind = `+s.b.arg(1)+` AND k = `+s.b.arg(2), kind, k)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// each calls f for every live row of kind.
func (s *passkeyStore) each(kind string, f func(k string, raw []byte)) error {
	rows, err := s.b.db.Query(`SELECT k, v FROM bridge_state WHERE kind = `+s.b.arg(1)+` AND expires > `+s.b.arg(2), kind, s.now().Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		f(k, []byte(v))
	}
	return rows.Err()
}

// passkeys are the credentials of one account, oldest first.
func (s *passkeyStore) passkeys(login string) ([]*passkeyRecord, error) {
	var out []*passkeyRecord
	var bad error
	err := s.each(kindPasskey, func(_ string, raw []byte) {
		var r passkeyRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			bad = err
			return
		}
		if r.Login == login {
			out = append(out, &r)
		}
	})
	if err == nil {
		err = bad
	}
	slices.SortFunc(out, func(a, b *passkeyRecord) int { return a.Created.Compare(b.Created) })
	if err == nil {
		out, err = s.reap(out)
	}
	return out, err
}

// reap carries out the removals whose delay is over, for the keys of ONE
// account (list), and returns the keys that remain. It is what makes a pending
// removal take effect at its time: every read of an account's keys, and the
// login's lookup of one, goes through here. A removal that would leave the
// account without a key is not carried out (it cannot be asked for: see
// requestRemoval) and is dropped instead.
func (s *passkeyStore) reap(list []*passkeyRecord) ([]*passkeyRecord, error) {
	now := s.now()
	var keep, gone []*passkeyRecord
	for _, r := range list {
		if r.due(now) {
			gone = append(gone, r)
		} else {
			keep = append(keep, r)
		}
	}
	if len(gone) == 0 {
		return list, nil
	}
	if len(keep) == 0 {
		for _, r := range gone {
			r.RemoveAt, r.RemoveRequested = time.Time{}, time.Time{}
			if err := s.savePasskey(r); err != nil {
				return list, err
			}
		}
		return gone, nil
	}
	for _, r := range gone {
		n, err := s.del(kindPasskey, r.key())
		if err != nil {
			return list, err
		}
		if n && s.onRemoved != nil {
			s.onRemoved(r)
		}
	}
	return keep, nil
}

// passkey is the credential with this row key. A key whose removal is due is
// not found: it stops working at its time, whether or not anybody has looked at
// the account since.
func (s *passkeyStore) passkey(k string) (*passkeyRecord, bool, error) {
	var r passkeyRecord
	ok, err := s.get(kindPasskey, k, &r)
	if !ok || err != nil {
		return nil, false, err
	}
	if r.due(s.now()) {
		if _, err := s.passkeys(r.Login); err != nil { // carries the removal out
			return nil, false, err
		}
		ok, err = s.get(kindPasskey, k, &r)
		if !ok || err != nil {
			return nil, false, err
		}
		if r.due(s.now()) { // the last key: its removal was dropped
			r.RemoveAt, r.RemoveRequested = time.Time{}, time.Time{}
		}
	}
	return &r, true, nil
}

func (s *passkeyStore) savePasskey(r *passkeyRecord) error {
	return s.put(kindPasskey, r.key(), r, passkeyForever)
}

// removePasskey deletes the credential of login whose row key starts with
// prefix (at least eight characters, and unique among the login's).
func (s *passkeyStore) removePasskey(login, prefix string) (*passkeyRecord, error) {
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
		if _, err := s.del(kindPasskey, hit[0].key()); err != nil {
			return nil, err
		}
		return hit[0], nil
	}
	return nil, fmt.Errorf("%q starts %d of %s's passkeys: give more of it", prefix, len(hit), login)
}

// removeAccount forgets everything held for a login: its passkeys, and its
// pending invitations.
func (s *passkeyStore) removeAccount(login string) error {
	list, err := s.passkeys(login)
	if err != nil {
		return err
	}
	for _, r := range list {
		if _, err := s.del(kindPasskey, r.key()); err != nil {
			return err
		}
	}
	_, err = s.revokeInvites(login)
	return err
}

// invite issues the one pending invitation of login, replacing any other, and
// returns its token. The token is shown once and stored as its hash.
func (s *passkeyStore) invite(login string, ttl time.Duration, by string) (string, time.Time, error) {
	if ttl <= 0 || ttl > inviteMaxTTL {
		return "", time.Time{}, fmt.Errorf("an invitation lives more than 0 and at most %s", inviteMaxTTL)
	}
	if _, err := s.revokeInvites(login); err != nil {
		return "", time.Time{}, err
	}
	tok := token()
	now := s.now()
	rec := inviteRecord{Login: login, Created: now, Expires: now.Add(ttl), By: by}
	if err := s.put(kindInvite, hashToken(tok), rec, rec.Expires); err != nil {
		return "", time.Time{}, err
	}
	return tok, rec.Expires, nil
}

// peekInvite reads an invitation without using it.
func (s *passkeyStore) peekInvite(tok string) (*inviteRecord, error) {
	var r inviteRecord
	ok, err := s.get(kindInvite, hashToken(tok), &r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNoInvite
	}
	return &r, nil
}

// burnInvite uses an invitation up. Of two requests with one token exactly one
// gets it: the row is deleted, and only the delete that found it succeeds.
func (s *passkeyStore) burnInvite(tok string) error {
	if _, err := s.peekInvite(tok); err != nil {
		return err
	}
	ok, err := s.del(kindInvite, hashToken(tok))
	if err != nil {
		return err
	}
	if !ok {
		return errNoInvite
	}
	return nil
}

// revokeInvites ends every pending invitation of login.
func (s *passkeyStore) revokeInvites(login string) (int, error) {
	var keys []string
	err := s.each(kindInvite, func(k string, raw []byte) {
		var r inviteRecord
		if json.Unmarshal(raw, &r) == nil && r.Login == login {
			keys = append(keys, k)
		}
	})
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if _, err := s.del(kindInvite, k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// ---- the ceremonies ----

// A ceremony is a challenge waiting for its answer: single-use, bound to what
// asked for it, and gone after ceremonyTTL.
type ceremony struct {
	enroll    bool
	challenge []byte
	// enrolment: the invitation's token, and whose it is.
	invite string
	login  string
	// login: the sealed login this belongs to. For the account page's ceremonies
	// (purpose set) it is the session's key, for an add and empty for a step-up.
	loginID string
	// purpose is "" for a login or an enrolment, purposeStepUp or purposeAddKey
	// for the account page. A ceremony is taken only by what asked for it: a
	// step-up assertion cannot end an OIDC login, nor the reverse.
	purpose string
}

func (s *server) startCeremony(c *ceremony) (string, error) {
	h := token()
	if err := s.ceremonies.put(hashToken(h), c, s.now().Add(ceremonyTTL)); err != nil {
		return "", err
	}
	return h, nil
}

func (s *server) takeCeremony(handle string, enroll bool) (*ceremony, bool) {
	c, ok := s.ceremonies.take(hashToken(handle))
	if !ok || c.enroll != enroll || c.purpose != "" {
		return nil, false
	}
	return c, true
}

// takeCeremonyFor is takeCeremony for the account page's two ceremonies.
func (s *server) takeCeremonyFor(handle, purpose string) (*ceremony, bool) {
	c, ok := s.ceremonies.take(hashToken(handle))
	if !ok || c.enroll || c.purpose != purpose {
		return nil, false
	}
	return c, true
}

func (s *server) relyingParty() webauthn.RelyingParty {
	return webauthn.RelyingParty{ID: s.cfg.rpID(), Origins: []string{s.cfg.origin()}}
}

// origin is the issuer's web origin, which is what a browser puts in
// clientDataJSON.
func (c *config) origin() string {
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// rpID is the RP ID: the issuer's host, without a port.
func (c *config) rpID() string {
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// userHandle is what an account's passkeys carry as user.id: 32 bytes of HMAC
// of the login under a key derived from the subject salt, so that it is stable
// and reveals nothing (the login is not in it).
func (s *server) userHandle(login string) []byte {
	key, err := hkdf.Key(sha256.New, s.cfg.salt, nil, "go-authn bridge local passkey user handle v1", 32)
	if err != nil {
		panic(err) // a fixed-length derivation does not fail
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(login))
	return m.Sum(nil)
}

var allowedTransports = []string{"usb", "nfc", "ble", "internal", "hybrid", "smart-card"}

// cleanTransports keeps the transports the browser may name, once each.
func cleanTransports(in []string) []string {
	var out []string
	for _, t := range in {
		if slices.Contains(allowedTransports, t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes unpadded base64url, strictly, and refuses an empty or
// oversized value.
func unb64(s string, max int) ([]byte, bool) {
	if s == "" || len(s) > max*2 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) <= max
}

// ---- enrolment ----

// pageHeadersScript is pageHeaders for the two pages that run the one script
// of this provider, from this origin. Nothing inline, nothing from elsewhere.
func pageHeadersScript(w http.ResponseWriter, formAction string) {
	pageHeaders(w, formAction)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action "+formAction+"; frame-ancestors 'none'")
}

// localEnrollPage is /local/enroll: static, and the same for everybody. The
// token is in the URL's fragment, which only the script reads.
func (s *server) localEnrollPage(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	pageHeadersScript(w, "'self'")
	w.WriteHeader(http.StatusOK)
	s.show(w, "localenroll", nil)
}

// uiJS is the one thing the header's script does: submit the language combo
// when it changes, and hide its button (which is for browsers without script).
// Static, the same for everybody, served from this origin.
const uiJS = `"use strict";
(function () {
  var sel = document.getElementById("lang-select");
  if (!sel || !sel.form) { return; }
  var go = document.getElementById("lang-go");
  if (go) { go.hidden = true; }
  sel.addEventListener("change", function () { sel.form.submit(); });
})();
`

// uiScript serves uiJS at /ui.js.
func (s *server) uiScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(uiJS))
}

// localScript is the script both pages run: the browser half of WebAuthn.
func (s *server) localScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(passkeyJS))
}

// jsonBody reads a JSON request, refusing anything a cross-site page could
// send: not application/json (a form cannot send it without a preflight, and
// this provider answers none), another origin, or an oversized body.
func (s *server) jsonBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		http.Error(w, "application/json expected", http.StatusUnsupportedMediaType)
		return false
	}
	if !s.sameOrigin(r) {
		s.logf("local: a passkey request did not come from this provider's page (from %s)", s.clientAddr(r))
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		http.Error(w, "the request could not be read", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSONNoStore(w http.ResponseWriter, status int, v any) { writeJSON(w, status, v) }

type credentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// localEnrollBegin checks an invitation and answers with the options for
// navigator.credentials.create(): the RP is the issuer's host, the key is
// discoverable and user-verified, attestation is "none", the algorithms are
// ES256, EdDSA and RS256, and the account's existing keys are excluded.
func (s *server) localEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !s.jsonBody(w, r, &req) {
		return
	}
	addr := s.clientAddr(r)
	if s.localLimit.blocked(addr, "") {
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	inv, err := s.passkeys.peekInvite(req.Token)
	if err != nil {
		if errors.Is(err, errNoInvite) {
			s.localLimit.failed(addr, "")
			s.counters.inc("bridge_logins_total", "local_enroll_refused")
			http.Error(w, errNoInvite.Error(), http.StatusForbidden)
			return
		}
		s.logf("local: reading an invitation: %v", err)
		http.Error(w, "the invitation could not be read", http.StatusInternalServerError)
		return
	}
	acct, ok := s.cfg.Local.store.get(inv.Login)
	if !ok {
		http.Error(w, errNoInvite.Error(), http.StatusForbidden)
		return
	}
	have, err := s.passkeys.passkeys(inv.Login)
	if err != nil {
		s.logf("local: reading passkeys: %v", err)
		http.Error(w, "the passkeys could not be read", http.StatusInternalServerError)
		return
	}
	if len(have) >= maxPasskeys {
		http.Error(w, fmt.Sprintf("an account has at most %d passkeys: remove one first", maxPasskeys), http.StatusConflict)
		return
	}
	ch, err := webauthn.NewChallenge()
	if err != nil {
		http.Error(w, "no challenge", http.StatusInternalServerError)
		return
	}
	handle, err := s.startCeremony(&ceremony{enroll: true, challenge: ch, invite: req.Token, login: inv.Login})
	if err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return
	}
	display := inv.Login
	if n := acct.Attributes().Get("displayName"); len(n) > 0 {
		display = n[0]
	}
	exclude := []credentialDescriptor{}
	for _, p := range have {
		exclude = append(exclude, credentialDescriptor{"public-key", b64(p.ID), p.Transports})
	}
	rp := s.relyingParty()
	writeJSONNoStore(w, http.StatusOK, map[string]any{
		"handle": handle,
		"publicKey": map[string]any{
			"challenge": b64(ch),
			"rp":        map[string]any{"id": rp.ID, "name": s.cfg.Issuer},
			"user":      map[string]any{"id": b64(s.userHandle(inv.Login)), "name": inv.Login, "displayName": display},
			"pubKeyCredParams": []map[string]any{
				{"type": "public-key", "alg": webauthn.AlgES256},
				{"type": "public-key", "alg": webauthn.AlgEdDSA},
				{"type": "public-key", "alg": webauthn.AlgRS256},
			},
			"authenticatorSelection": map[string]any{
				"residentKey":        "required",
				"requireResidentKey": true,
				"userVerification":   "required",
			},
			"attestation":        s.attestationFor(inv.Login),
			"excludeCredentials": exclude,
			"timeout":            int(ceremonyTTL / time.Millisecond),
		},
	})
}

// localEnrollFinish verifies the registration through go-authn/webauthn,
// stores the credential and burns the invitation.
func (s *server) localEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Handle            string   `json:"handle"`
		ID                string   `json:"id"`
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		Transports        []string `json:"transports"`
	}
	if !s.jsonBody(w, r, &req) {
		return
	}
	addr := s.clientAddr(r)
	if s.localLimit.blocked(addr, "") {
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	refuse := func(status int, msg string, why any) {
		s.localLimit.failed(addr, "")
		s.counters.inc("bridge_logins_total", "local_enroll_refused")
		s.logf("local: an enrolment was refused from %s: %v", addr, why)
		http.Error(w, msg, status)
	}
	cer, ok := s.takeCeremony(req.Handle, true)
	if !ok {
		refuse(http.StatusForbidden, "this enrolment has expired; start again from the invitation", "unknown or reused ceremony")
		return
	}
	cd, ok1 := unb64(req.ClientDataJSON, 16<<10)
	ao, ok2 := unb64(req.AttestationObject, 32<<10)
	id, ok3 := unb64(req.ID, webauthn.MaxCredentialIDLength)
	if !ok1 || !ok2 || !ok3 {
		refuse(http.StatusBadRequest, "the registration could not be read", "bad encoding")
		return
	}
	cred, attested, err := s.verifyEnrolment(cer.login, cer.challenge, cd, ao)
	if err != nil {
		refuse(http.StatusForbidden, "this passkey was refused", err)
		return
	}
	if !bytes.Equal(cred.ID, id) {
		refuse(http.StatusForbidden, "this passkey was refused", "the credential ID is not the one signed")
		return
	}
	// ⛔ The cap is rechecked here, under the lock the account page takes: the
	// count made when the ceremony began is stale by now, and a key added
	// meanwhile must not make an eleventh.
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	if _, taken, err := s.passkeys.passkey(passkeyKey(cred.ID)); err != nil || taken {
		refuse(http.StatusConflict, "this passkey is already registered", fmt.Sprintf("credential exists (%v)", err))
		return
	}
	if _, ok := s.cfg.Local.store.get(cer.login); !ok {
		refuse(http.StatusForbidden, errNoInvite.Error(), "the account was removed")
		return
	}
	if have, err := s.passkeys.passkeys(cer.login); err != nil || len(have) >= maxPasskeys {
		refuse(http.StatusConflict, fmt.Sprintf("an account has at most %d passkeys: remove one first", maxPasskeys), fmt.Sprintf("%d keys (%v)", len(have), err))
		return
	}
	// ⛔ The invitation is burnt BEFORE the credential is stored, and only the
	// request whose delete found it goes on: two enrolments with one token
	// cannot both succeed.
	if err := s.passkeys.burnInvite(cer.invite); err != nil {
		refuse(http.StatusForbidden, errNoInvite.Error(), err)
		return
	}
	rec := &passkeyRecord{
		Login: cer.login, ID: cred.ID, PublicKey: cred.PublicKeyCOSE, SignCount: cred.SignCount,
		BackupEligible: cred.BackupEligible, Transports: cleanTransports(req.Transports),
		AAGUID: cred.AAGUID[:], AttestedAAGUID: attested, Created: s.now(),
	}
	if err := s.passkeys.savePasskey(rec); err != nil {
		s.logf("local: storing a passkey for %s: %v", cer.login, err)
		http.Error(w, "the passkey could not be stored; ask for a new invitation", http.StatusInternalServerError)
		return
	}
	s.logf("local: %s enrolled a passkey (%s)", cer.login, rec.key()[:8])
	s.counters.inc("bridge_logins_total", "local_enrolled")
	writeJSONNoStore(w, http.StatusOK, map[string]any{"enrolled": true, "attested": attested != ""})
}

// ---- login ----

// localLoginBegin answers with the options for navigator.credentials.get():
// discoverable credentials, so allowCredentials is empty, and user
// verification is required.
func (s *server) localLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	id, _, ok := s.localLoginState(w, r)
	if !ok {
		return
	}
	var req struct {
		CSRF string `json:"csrf"`
	}
	if !s.jsonBody(w, r, &req) {
		return
	}
	want, err := s.localCSRF(id)
	if err != nil || subtle.ConstantTimeCompare([]byte(req.CSRF), []byte(want)) != 1 {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.localLimit.blocked(s.clientAddr(r), "") {
		s.counters.inc("bridge_logins_total", "local_throttled")
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	ch, err := webauthn.NewChallenge()
	if err != nil {
		http.Error(w, "no challenge", http.StatusInternalServerError)
		return
	}
	handle, err := s.startCeremony(&ceremony{challenge: ch, loginID: id})
	if err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return
	}
	writeJSONNoStore(w, http.StatusOK, map[string]any{
		"handle": handle,
		"publicKey": map[string]any{
			"challenge":        b64(ch),
			"rpId":             s.relyingParty().ID,
			"userVerification": "required",
			"allowCredentials": []credentialDescriptor{},
			"timeout":          int(ceremonyTTL / time.Millisecond),
		},
	})
}

// localLoginState is what the login endpoints share: a login in progress that
// has not gone to an institution and is not prompt=none.
func (s *server) localLoginState(w http.ResponseWriter, r *http.Request) (string, *login, bool) {
	id, l, err := s.current(r)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return "", nil, false
	}
	// One login, one way in: one that already went to an institution has an
	// AuthnRequest out, whose response could still arrive.
	if l.started || l.kind == "account" {
		s.page(w, http.StatusBadRequest, "This login has already gone to an institution; start again from the application.")
		return "", nil, false
	}
	if l.client != nil && !l.client.allowsLocal() {
		s.logf("login: a local sign-in was started for %s, which takes %s", l.client.ID, l.client.accountsLine())
		s.counters.inc("bridge_logins_total", "wrong_account_kind")
		s.finishError(w, r, l, "access_denied", "this application does not take local accounts")
		return "", nil, false
	}
	if l.options.IsPassive {
		// prompt=none: there is no session here to find.
		s.finishError(w, r, l, "login_required", "no session: a local account needs a passkey")
		return "", nil, false
	}
	return id, l, true
}

// localLoginFinish is the form post that ends a passkey login. It is a real
// form post, not a fetch, so that the redirect to the client is the browser's
// own and the page's form-action governs it, as it did the password form.
func (s *server) localLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	id, l, ok := s.localLoginState(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	want, err := s.localCSRF(id)
	if err != nil {
		s.page(w, http.StatusInternalServerError, "The login could not be checked.")
		return
	}
	if !s.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(want)) != 1 {
		s.logf("local: a login form did not come from this provider's page (from %s)", s.clientAddr(r))
		s.page(w, http.StatusForbidden, "The form did not come from this page; start again from the application.")
		return
	}
	addr := s.clientAddr(r)
	if s.localLimit.blocked(addr, "") {
		s.counters.inc("bridge_logins_total", "local_throttled")
		w.Header().Set("Retry-After", "900")
		s.renderLocal(w, http.StatusTooManyRequests, l, id, "Trop d'essais. Réessayez dans un quart d'heure. / Too many attempts: try again in fifteen minutes.")
		return
	}
	refuse := func(why any) {
		s.localLimit.failed(addr, "")
		s.logf("local: a passkey login was refused from %s: %v", addr, why)
		s.counters.inc("bridge_logins_total", "local_wrong")
		s.renderLocal(w, http.StatusUnauthorized, l, id, "Clé d'accès refusée. / Passkey refused.")
	}
	cer, ok := s.takeCeremony(r.PostForm.Get("handle"), false)
	if !ok || cer.loginID != id {
		// A challenge is this login's, once.
		refuse("unknown, reused or another login's ceremony")
		return
	}
	cd, ok1 := unb64(r.PostForm.Get("clientDataJSON"), maxFormField)
	ad, ok2 := unb64(r.PostForm.Get("authenticatorData"), maxFormField)
	sig, ok3 := unb64(r.PostForm.Get("signature"), maxFormField)
	credID, ok4 := unb64(r.PostForm.Get("id"), webauthn.MaxCredentialIDLength)
	handle, ok5 := unb64(r.PostForm.Get("userHandle"), 64)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) {
		refuse("bad encoding, or no user handle (a discoverable credential returns one)")
		return
	}
	rec, found, err := s.passkeys.passkey(passkeyKey(credID))
	if err != nil {
		s.logf("local: reading a passkey: %v", err)
		s.page(w, http.StatusInternalServerError, "The login could not be checked.")
		return
	}
	if !found {
		refuse("an unknown credential")
		return
	}
	acct, known := s.cfg.Local.store.get(rec.Login)
	if !known {
		refuse("the account was removed")
		return
	}
	// §7.2 step 6: the user handle is the account's.
	if subtle.ConstantTimeCompare(handle, s.userHandle(rec.Login)) != 1 {
		refuse("the user handle is not the credential's account")
		return
	}
	res, err := s.relyingParty().VerifyAssertion(cer.challenge, rec.credential(), cd, ad, sig, webauthn.Policy{RequireUV: true})
	if err != nil {
		refuse(fmt.Sprintf("%s: %v", rec.Login, err))
		return
	}
	rec.SignCount, rec.BackupState, rec.LastUsed = res.SignCount, res.BackupState, s.now()
	if err := s.passkeys.savePasskey(rec); err != nil {
		// The login is real; what is lost is the counter's advance.
		s.logf("local: storing the counter of a passkey of %s: %v", rec.Login, err)
	}
	s.localLimit.succeeded("")
	http.SetCookie(w, s.cookie(loginCookie, "", -1))
	if err := s.usedLogins.putNew(id, true, l.expires); err != nil {
		s.page(w, http.StatusBadRequest, "This login has already been answered; start again from the application.")
		return
	}
	who := s.localPerson(acct, rec)
	s.finishLogin(w, r, l, who)
}
