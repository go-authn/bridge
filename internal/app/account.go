// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/go-authn/webauthn"
)

// The account page: a signed-in local user manages their OWN passkeys, with no
// administrator. Passkey-only, like the rest: no password is asked, held or
// checked anywhere here.
//
//	GET  /local/account                    the page (step-up, or the key list)
//	POST /local/account/stepup/begin       challenge for a fresh assertion
//	POST /local/account/stepup/finish      verify it, set the session cookie
//	POST /local/account/add/begin          options for navigator.credentials.create
//	POST /local/account/add/finish         verify and store the new passkey
//	POST /local/account/remove             remove one of the account's passkeys
//	POST /local/account/signout            end the session
//
// ⛔ Getting in is a STEP-UP: a passkey assertion, user verification required,
// made for THIS page. Its challenge is a ceremony of its own purpose
// (purposeStepUp), so it cannot end an OIDC login and a login's assertion cannot
// open this page. The session it buys is a random token in a __Host- cookie
// (Secure, HttpOnly, SameSite=Strict, Path=/, no Domain), held in memory for
// five minutes and bound to the credential that was asserted: when that
// credential is removed -- from here or by the administrator -- the session ends
// with it. Nothing is kept in the browser's storage.
//
// ⛔ Every state change needs the session, a CSRF token derived from it (a label
// of its own: no token of the login page opens this one), a same-origin
// request, and room in the host's failure budget; and it leaves one audit line.

const (
	purposeStepUp = "stepup"
	purposeAddKey = "addkey"

	// accountCookieName carries the __Host- prefix, so a browser refuses it from
	// anything but a secure, host-only, Path=/ Set-Cookie.
	accountCookieName = "__Host-bridge-account"
	// accountTTL is how long a step-up lasts, and the age of the assertion that
	// may open the page.
	accountTTL = 5 * time.Minute

	accountCSRFLabel = "go-authn bridge local account csrf v1"
)

// accountSession is one step-up: whose, and the credential that was asserted.
type accountSession struct {
	login      string
	credential string
}

func (s *server) accountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/local/account", s.limited(s.localAccountPage))
	mux.HandleFunc("/local/account/stepup/begin", s.limited(s.accountStepUpBegin))
	mux.HandleFunc("/local/account/stepup/finish", s.limited(s.accountStepUpFinish))
	mux.HandleFunc("/local/account/add/begin", s.limited(s.accountAddBegin))
	mux.HandleFunc("/local/account/add/finish", s.limited(s.accountAddFinish))
	mux.HandleFunc("/local/account/remove", s.limited(s.accountRemove))
	mux.HandleFunc("/local/account/signout", s.limited(s.accountSignOut))
}

func (s *server) accountCookie(value string, life time.Duration) *http.Cookie {
	c := &http.Cookie{Name: accountCookieName, Value: value, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(life.Seconds())}
	if life < 0 {
		c.MaxAge = -1
	}
	return c
}

// sessionKey is the key a session is held under: the hash of the cookie's value.
func sessionKey(r *http.Request) (string, bool) {
	c, err := r.Cookie(accountCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return hashToken(c.Value), true
}

// session is the step-up this request carries, if it is still good: not
// expired, its credential still the account's, the account still in the file.
func (s *server) session(r *http.Request) (string, *accountSession, bool) {
	k, ok := sessionKey(r)
	if !ok {
		return "", nil, false
	}
	sess, ok := s.accountSessions.get(k)
	if !ok {
		return "", nil, false
	}
	rec, found, err := s.passkeys.passkey(sess.credential)
	if err != nil || !found || rec.Login != sess.login {
		s.accountSessions.take(k)
		return "", nil, false
	}
	if _, known := s.cfg.Local.store.get(sess.login); !known {
		s.accountSessions.take(k)
		return "", nil, false
	}
	return k, sess, true
}

func (s *server) accountCSRF(k string) string {
	t, err := s.csrfToken(accountCSRFLabel, k)
	if err != nil {
		return "" // accountPost refuses an empty token whatever the request carried
	}
	return t
}

type accountKey struct {
	Key, Prefix, Created, LastUsed string
	Backup, Current                bool
}

// localAccountPage is /local/account. The same URL answers a step-up page with
// no session and the list of keys with one; both are no-store.
func (s *server) localAccountPage(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	pageHeadersScript(w, "'self'")
	k, sess, ok := s.session(r)
	if !ok {
		w.WriteHeader(http.StatusOK)
		tmpl.ExecuteTemplate(w, "localaccount", map[string]any{"Signed": false})
		return
	}
	have, err := s.passkeys.passkeys(sess.login)
	if err != nil {
		s.logf("local: reading passkeys for the account page: %v", err)
		s.page(w, http.StatusInternalServerError, "Your passkeys could not be read.")
		return
	}
	const layout = "2006-01-02 15:04 MST"
	var keys []accountKey
	for _, p := range have {
		row := accountKey{Key: p.key(), Prefix: p.key()[:16], Created: p.Created.UTC().Format(layout), Backup: p.BackupEligible, Current: p.key() == sess.credential}
		if !p.LastUsed.IsZero() {
			row.LastUsed = p.LastUsed.UTC().Format(layout)
		}
		keys = append(keys, row)
	}
	w.WriteHeader(http.StatusOK)
	tmpl.ExecuteTemplate(w, "localaccount", map[string]any{
		"Signed": true, "Login": sess.login, "CSRF": s.accountCSRF(k), "Keys": keys, "Max": maxPasskeys, "Full": len(keys) >= maxPasskeys,
	})
}

// accountThrottled refuses, before anything is checked, a host that has
// failed too often.
func (s *server) accountThrottled(w http.ResponseWriter, addr string) bool {
	if s.localLimit.blocked(addr, "") {
		s.counters.inc("bridge_logins_total", "local_throttled")
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return true
	}
	return false
}

// accountPost is what the four state-changing endpoints share: a JSON request
// from this origin, a host not throttled, a live session, and its CSRF token.
// csrf says where v holds the token it carried.
func (s *server) accountPost(w http.ResponseWriter, r *http.Request, v any, csrf func() string) (string, *accountSession, bool) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return "", nil, false
	}
	if !s.jsonBody(w, r, v) {
		return "", nil, false
	}
	addr := s.clientAddr(r)
	if s.accountThrottled(w, addr) {
		return "", nil, false
	}
	k, sess, ok := s.session(r)
	if !ok {
		s.localLimit.failed(addr, "")
		http.Error(w, "the confirmation has expired: confirm with your passkey again", http.StatusUnauthorized)
		return "", nil, false
	}
	if want := s.accountCSRF(k); want == "" || subtle.ConstantTimeCompare([]byte(csrf()), []byte(want)) != 1 {
		s.localLimit.failed(addr, "")
		s.logf("local: an account request without its page's token (%s, from %s)", sess.login, addr)
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return "", nil, false
	}
	return k, sess, true
}

// audit is the one line every change leaves: who, what, which key, from where.
func (s *server) audit(sess *accountSession, action, key string, r *http.Request) {
	if len(key) > 16 {
		key = key[:16]
	}
	s.logf("local: audit: %s %s key=%s from %s", sess.login, action, key, s.clientAddr(r))
	s.counters.inc("bridge_logins_total", "local_account_"+action)
}

// ---- step-up ----

func (s *server) accountStepUpBegin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct{}
	if !s.jsonBody(w, r, &req) {
		return
	}
	if s.accountThrottled(w, s.clientAddr(r)) {
		return
	}
	ch, err := webauthn.NewChallenge()
	if err != nil {
		http.Error(w, "no challenge", http.StatusInternalServerError)
		return
	}
	// The handle is returned to this caller alone, in a same-origin JSON
	// response, and answers once: it is what binds the finish to this begin.
	handle, err := s.startCeremony(&ceremony{challenge: ch, purpose: purposeStepUp})
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

func (s *server) accountStepUpFinish(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Handle            string `json:"handle"`
		ID                string `json:"id"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	}
	if !s.jsonBody(w, r, &req) {
		return
	}
	addr := s.clientAddr(r)
	if s.accountThrottled(w, addr) {
		return
	}
	refuse := func(why any) {
		s.localLimit.failed(addr, "")
		s.logf("local: a step-up was refused from %s: %v", addr, why)
		s.counters.inc("bridge_logins_total", "local_stepup_refused")
		http.Error(w, "Clé d'accès refusée. / Passkey refused.", http.StatusUnauthorized)
	}
	cer, ok := s.takeCeremonyFor(req.Handle, purposeStepUp)
	if !ok {
		refuse("unknown, reused or another kind of ceremony")
		return
	}
	cd, ok1 := unb64(req.ClientDataJSON, maxFormField)
	ad, ok2 := unb64(req.AuthenticatorData, maxFormField)
	sig, ok3 := unb64(req.Signature, maxFormField)
	credID, ok4 := unb64(req.ID, webauthn.MaxCredentialIDLength)
	handle, ok5 := unb64(req.UserHandle, 64)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) {
		refuse("bad encoding, or no user handle")
		return
	}
	rec, found, err := s.passkeys.passkey(passkeyKey(credID))
	if err != nil {
		s.logf("local: reading a passkey: %v", err)
		http.Error(w, "the passkey could not be checked", http.StatusInternalServerError)
		return
	}
	if !found {
		refuse("an unknown credential")
		return
	}
	if _, known := s.cfg.Local.store.get(rec.Login); !known {
		refuse("the account was removed")
		return
	}
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
		s.logf("local: storing the counter of a passkey of %s: %v", rec.Login, err)
	}
	tok := token()
	sess := &accountSession{login: rec.Login, credential: rec.key()}
	if err := s.accountSessions.put(hashToken(tok), sess, s.now().Add(accountTTL)); err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return
	}
	if old, ok := sessionKey(r); ok {
		s.accountSessions.take(old)
	}
	http.SetCookie(w, s.accountCookie(tok, accountTTL))
	s.localLimit.succeeded("")
	s.audit(sess, "stepup", rec.key(), r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- add ----

func (s *server) accountAddBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
	}
	k, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	acct, ok := s.cfg.Local.store.get(sess.login)
	if !ok {
		http.Error(w, "the account was removed", http.StatusForbidden)
		return
	}
	have, err := s.passkeys.passkeys(sess.login)
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
	handle, err := s.startCeremony(&ceremony{challenge: ch, purpose: purposeAddKey, login: sess.login, loginID: k})
	if err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return
	}
	display := sess.login
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
			"user":      map[string]any{"id": b64(s.userHandle(sess.login)), "name": sess.login, "displayName": display},
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
			"attestation":        "none",
			"excludeCredentials": exclude,
			"timeout":            int(ceremonyTTL / time.Millisecond),
		},
	})
}

func (s *server) accountAddFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF              string   `json:"csrf"`
		Handle            string   `json:"handle"`
		ID                string   `json:"id"`
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		Transports        []string `json:"transports"`
	}
	k, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	addr := s.clientAddr(r)
	refuse := func(status int, msg string, why any) {
		s.localLimit.failed(addr, "")
		s.counters.inc("bridge_logins_total", "local_enroll_refused")
		s.logf("local: adding a passkey for %s was refused from %s: %v", sess.login, addr, why)
		http.Error(w, msg, status)
	}
	cer, ok := s.takeCeremonyFor(req.Handle, purposeAddKey)
	if !ok || cer.login != sess.login || cer.loginID != k {
		refuse(http.StatusForbidden, "this request has expired; start again", "unknown, reused or another session's ceremony")
		return
	}
	cd, ok1 := unb64(req.ClientDataJSON, 16<<10)
	ao, ok2 := unb64(req.AttestationObject, 32<<10)
	id, ok3 := unb64(req.ID, webauthn.MaxCredentialIDLength)
	if !ok1 || !ok2 || !ok3 {
		refuse(http.StatusBadRequest, "the registration could not be read", "bad encoding")
		return
	}
	cred, err := s.relyingParty().VerifyRegistration(cer.challenge, cd, ao, webauthn.Policy{RequireUV: true})
	if err != nil {
		refuse(http.StatusForbidden, "this passkey was refused", err)
		return
	}
	if !bytes.Equal(cred.ID, id) {
		refuse(http.StatusForbidden, "this passkey was refused", "the credential ID is not the one signed")
		return
	}
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	if _, taken, err := s.passkeys.passkey(passkeyKey(cred.ID)); err != nil || taken {
		refuse(http.StatusConflict, "this passkey is already registered", fmt.Sprintf("credential exists (%v)", err))
		return
	}
	have, err := s.passkeys.passkeys(sess.login)
	if err != nil || len(have) >= maxPasskeys {
		refuse(http.StatusConflict, fmt.Sprintf("an account has at most %d passkeys: remove one first", maxPasskeys), fmt.Sprintf("%d keys (%v)", len(have), err))
		return
	}
	rec := &passkeyRecord{
		Login: sess.login, ID: cred.ID, PublicKey: cred.PublicKeyCOSE, SignCount: cred.SignCount,
		BackupEligible: cred.BackupEligible, Transports: cleanTransports(req.Transports),
		AAGUID: cred.AAGUID[:], Created: s.now(),
	}
	if err := s.passkeys.savePasskey(rec); err != nil {
		s.logf("local: storing a passkey for %s: %v", sess.login, err)
		http.Error(w, "the passkey could not be stored", http.StatusInternalServerError)
		return
	}
	s.audit(sess, "add", rec.key(), r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"added": rec.key()[:16]})
}

// ---- remove, sign out ----

// accountRemove removes one passkey of the signed-in account. It refuses the
// last one (the account would be locked out of its own page, and every grant
// bought without a passkey would end). Removing the key the session was made
// with is allowed while another remains, and ends the session: its credential
// is gone. The grants the removed key bought stop at once (localAccountGone,
// #87): this path deletes the same row the administrator's command does.
func (s *server) accountRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
		Key  string `json:"key"`
	}
	k, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	have, err := s.passkeys.passkeys(sess.login)
	if err != nil {
		s.logf("local: reading passkeys: %v", err)
		http.Error(w, "the passkeys could not be read", http.StatusInternalServerError)
		return
	}
	if len(have) <= 1 {
		http.Error(w, "this is your last passkey: add another before removing it", http.StatusConflict)
		return
	}
	rec, err := s.passkeys.removePasskey(sess.login, req.Key)
	if err != nil {
		s.localLimit.failed(s.clientAddr(r), "")
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	ended := rec.key() == sess.credential
	if ended {
		s.accountSessions.take(k)
		http.SetCookie(w, s.accountCookie("", -1))
	}
	s.audit(sess, "remove", rec.key(), r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"removed": rec.key()[:16], "signedOut": ended})
}

func (s *server) accountSignOut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
	}
	k, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	s.accountSessions.take(k)
	http.SetCookie(w, s.accountCookie("", -1))
	s.audit(sess, "signout", sess.credential, r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}
