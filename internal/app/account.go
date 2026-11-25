// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/saml"
	"github.com/go-authn/webauthn"
)

// "Mon compte / My account": a space for EVERY signed-in person, federated or
// local. No password is asked, held or checked anywhere in it.
//
//	GET  /account                        the page: a confirmation, or the account
//	GET  /account/federation             confirm through the institution (SAML, ForceAuthn)
//	POST /account/open                   the end of that confirmation (its one-time handle)
//	POST /account/stepup/begin|finish    confirm with a passkey (local accounts)
//	POST /account/add/begin|finish       add a passkey (local accounts)
//	POST /account/remove                 remove one passkey (never the last; deferred unless it is the session's own)
//	POST /account/removal/cancel         cancel a pending removal (any of the account's keys)
//	POST /account/profile                the display name (local accounts); mail and groups are refused
//	POST /account/apps/revoke            end one application session, or all
//	POST /account/access/revoke          revoke an SSH certificate, WireGuard key
//	POST /account/signout                end the confirmation
//	GET  /account/passkey.js             the page's one script
//	GET  /local/account                  redirects to /account
//
// ⛔ Getting in is a STEP-UP: a fresh authentication made FOR this page and at
// most five minutes old -- for a local account a passkey assertion with user
// verification, for a federated person a SAML login with ForceAuthn whose
// AuthnInstant is checked (an IdP may ignore ForceAuthn). Its ceremony has a
// kind of its own (purposeStepUp, or an login of kind "account"), so it cannot
// end an OIDC login and an OIDC login's authentication does not open this page.
// What it buys is a random token in a __Host- cookie (Secure, HttpOnly,
// SameSite=Strict, Path=/, no Domain), held in memory for five minutes. The
// session holds the person as the authentication described them and is
// re-judged at every use (refused): a disabled person, a removed account, a
// removed passkey end it. Nothing is kept in the browser's storage.
//
// ⛔ Every change needs the session, a CSRF token derived from it (a label of
// its own), a same-origin request, and room in the host's failure budget, and
// leaves one audit line.

const (
	purposeStepUp = "stepup"
	purposeAddKey = "addkey"

	// accountCookieName carries the __Host- prefix, so a browser refuses it from
	// anything but a secure, host-only, Path=/ Set-Cookie.
	accountCookieName = "__Host-bridge-account"
	// accountTTL is how long a step-up lasts, and the age of the authentication
	// that may open the page.
	accountTTL = 5 * time.Minute
	// accountOpenTTL is how long the handle between the ACS and the cookie lives.
	accountOpenTTL = time.Minute

	accountCSRFLabel = "go-authn bridge account csrf v1"

	// maxNameLen bounds a display name.
	maxNameLen = 100
)

// accountSession is one step-up: who the authentication described, and for a
// local account the passkey that was asserted.
type accountSession struct {
	who        *person
	credential string
	// at is when the passkey was asserted: what an action that wants a FRESH
	// assertion (admininvite.go) measures.
	at time.Time
}

func (s *server) isLocal(p *person) bool {
	return s.cfg.Local != nil && p.idp == s.cfg.localEntityID()
}

func (s *server) accountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/account", s.limited(s.accountPage))
	mux.HandleFunc("/local/account", s.limited(s.accountMoved))
	mux.HandleFunc("/account/passkey.js", s.localScript)
	mux.HandleFunc("/account/federation", s.limited(s.accountFederation))
	mux.HandleFunc("/account/open", s.limited(s.accountOpen))
	mux.HandleFunc("/account/stepup/begin", s.limited(s.accountStepUpBegin))
	mux.HandleFunc("/account/stepup/finish", s.limited(s.accountStepUpFinish))
	mux.HandleFunc("/account/add/begin", s.limited(s.accountAddBegin))
	mux.HandleFunc("/account/add/finish", s.limited(s.accountAddFinish))
	mux.HandleFunc("/account/remove", s.limited(s.accountRemove))
	mux.HandleFunc("/account/removal/cancel", s.limited(s.accountRemovalCancel))
	mux.HandleFunc("/account/profile", s.limited(s.accountProfile))
	mux.HandleFunc("/account/apps/revoke", s.limited(s.accountAppsRevoke))
	mux.HandleFunc("/account/access/revoke", s.limited(s.accountAccessRevoke))
	mux.HandleFunc("/account/signout", s.limited(s.accountSignOut))
	mux.HandleFunc("/account/invite", s.limited(s.accountInvite))
}

func (s *server) accountMoved(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, s.cfg.Issuer+"/account", http.StatusFound)
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
// expired, and its person still not refused -- which, for a local account, is
// the account still in the file and the asserted passkey still its own.
func (s *server) session(r *http.Request) (string, *accountSession, bool) {
	k, ok := sessionKey(r)
	if !ok {
		return "", nil, false
	}
	sess, ok := s.accountSessions.get(k)
	if !ok {
		return "", nil, false
	}
	if why := s.refused(sess.who); why != "" || (!s.isLocal(sess.who) && !s.allowedIdP(sess.who.idp)) {
		s.accountSessions.take(k)
		return "", nil, false
	}
	return k, sess, true
}

// startSession holds a step-up and sets its cookie.
func (s *server) startSession(w http.ResponseWriter, r *http.Request, sess *accountSession) bool {
	tok := token()
	if err := s.accountSessions.put(hashToken(tok), sess, s.now().Add(accountTTL)); err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return false
	}
	if old, ok := sessionKey(r); ok {
		s.accountSessions.take(old)
	}
	http.SetCookie(w, s.accountCookie(tok, accountTTL))
	return true
}

func (s *server) accountCSRF(k string) string {
	t, err := s.csrfToken(accountCSRFLabel, k)
	if err != nil {
		return "" // accountPost refuses an empty token whatever the request carried
	}
	return t
}

// ---- the page ----

type accountKey struct {
	Key, Prefix, Created, LastUsed, Arg string
	Backup, Current                     bool
	// Pending is a removal waiting on this key; RemoveAt says when it takes effect.
	Pending  bool
	RemoveAt string
}

type accountApp struct {
	Client, Created, LastUsed, Arg string
}

type accountAccess struct {
	Kind, What, Detail, Expires, Arg string
}

const accountTimeLayout = "2006-01-02 15:04 MST"

func (s *server) accountPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	pageHeadersScript(w, "'self'")
	k, sess, ok := s.session(r)
	if !ok {
		w.WriteHeader(http.StatusOK)
		// ?done=1 is where the page's own sign-out button goes: the same
		// confirmation, under the words that say the session has ended.
		s.show(w, "account", map[string]any{"Signed": false, "Passkey": s.cfg.Local != nil, "Done": r.URL.Query().Get("done") == "1"})
		return
	}
	who := sess.who
	view := map[string]any{"Signed": true, "CSRF": s.accountCSRF(k), "Local": s.isLocal(who)}
	name, _ := who.profile["name"].(string)
	mail, _ := who.email["email"].(string)
	login := who.username
	if login == "" {
		login, _ = who.edu["eduperson_principal_name"].(string)
	}
	view["Login"], view["Name"], view["Mail"], view["Groups"] = login, name, mail, who.groups
	if s.isLocal(who) {
		// The words are the page's, in the person's language (i18n.go).
	} else {
		src := who.idp
		if idp, ok := s.fed.IdP(who.idp); ok {
			src = idp.Name("fr", "en") + " (" + who.idp + ")" // the page's own language is not known here
		}
		view["Source"] = src
	}

	if s.isLocal(who) {
		have, err := s.passkeys.passkeys(who.username)
		if err != nil {
			s.logf("local: reading passkeys for the account page: %v", err)
			s.page(w, http.StatusInternalServerError, "Your passkeys could not be read.")
			return
		}
		var keys []accountKey
		for _, p := range have {
			row := accountKey{Key: p.key(), Prefix: p.key()[:16], Created: p.Created.UTC().Format(accountTimeLayout), Backup: p.BackupEligible, Current: p.key() == sess.credential}
			row.Arg = jsonArg(map[string]string{"key": p.key()})
			if !p.LastUsed.IsZero() {
				row.LastUsed = p.LastUsed.UTC().Format(accountTimeLayout)
			}
			if p.pending() {
				row.Pending, row.RemoveAt = true, p.RemoveAt.UTC().Format(accountTimeLayout)
			}
			keys = append(keys, row)
		}
		// Deferred says the page's remove buttons for another key ask for a
		// delayed removal (the confirmation question tells the person so).
		view["CanInvite"] = s.isAdmin(who)
		view["Deferred"], view["Delay"] = s.cfg.Local.removalDelay > 0, delayText(s.cfg.Local.removalDelay)
		view["Keys"], view["Max"], view["Full"] = keys, maxPasskeys, len(keys) >= maxPasskeys
		// The e-mail notice (#122): say so when nobody can be told, and when the
		// last notice could not be mailed.
		if s.cfg.Mail != nil {
			if _, err := mailAddr(s.localMail(who.username)); err != nil {
				view["NoticeNone"] = true
			}
			view["NoticeFailed"] = s.noticeFailed(who.username)
		}
	}

	var apps []accountApp
	for _, g := range s.grantsOf(who) {
		row := accountApp{Client: g.client.ID, Arg: jsonArg(map[string]string{"id": familyID(g.family)})}
		if g.client.Name != "" {
			row.Client = g.client.Name + " (" + g.client.ID + ")"
		}
		if !g.created.IsZero() {
			row.Created = g.created.UTC().Format(accountTimeLayout)
		}
		if !g.lastUsed.IsZero() {
			row.LastUsed = g.lastUsed.UTC().Format(accountTimeLayout)
		}
		apps = append(apps, row)
	}
	view["Apps"] = apps

	access := s.accessOf(who)
	view["Access"], view["AccessOn"] = access, s.certs.path != ""
	w.WriteHeader(http.StatusOK)
	s.show(w, "account", view)
}

// jsonArg is a button's request body, as an HTML attribute carries it.
func jsonArg(m map[string]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// familyID is how a refresh-token family is named to its owner: a prefix of its
// hash, never the family's own handle.
func familyID(family string) string { return hashToken(family)[:16] }

func sameWho(a, b *person) bool { return a.idp == b.idp && a.subject == b.subject }

// grantsOf is the person's live refresh-token families, newest first.
func (s *server) grantsOf(who *person) []*refreshGrant {
	var out []*refreshGrant
	s.refresh.each(func(_ string, g *refreshGrant) {
		if sameWho(g.who, who) {
			out = append(out, g)
		}
	})
	slices.SortFunc(out, func(a, b *refreshGrant) int { return b.created.Compare(a.created) })
	return out
}

// accessOf is what the person holds that is not an OIDC session: the
// certificates and keys this provider issued.
func (s *server) accessOf(who *person) []accountAccess {
	var out []accountAccess
	now := s.now()
	for _, c := range s.certs.liveWhere(s.ownedBy(who), now) {
		what := map[string]string{"ssh": "access.kind.ssh", "x509": "access.kind.x509", "wireguard": "access.kind.wireguard"}[c.Kind]
		if what == "" {
			what = c.Kind
		}
		out = append(out, accountAccess{Kind: c.Kind, What: what, Detail: c.KeyID, Expires: c.NotAfter.UTC().Format(accountTimeLayout),
			Arg: jsonArg(map[string]string{"kind": c.Kind, "id": c.Serial})})
	}
	return out
}

// ownedBy says whether a certificate or key is the person's: by the username
// it was issued to, or by the stable identity -- as revokePerson finds them.
func (s *server) ownedBy(who *person) func(issuedCert) bool {
	return func(c issuedCert) bool {
		return (who.username != "" && oidc.EqualASCIIFold(c.Principal, who.username) && (c.IdP == "" || c.IdP == who.idp)) ||
			(c.Subject != "" && c.Subject == who.subject)
	}
}

// ---- the confirmation ----

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

// accountPost is what the state-changing endpoints share: a JSON request from
// this origin, a host not throttled, a live session, and its CSRF token. csrf
// says where v holds the token it carried.
func (s *server) accountPost(w http.ResponseWriter, r *http.Request, v any, csrf func() string) (string, *accountSession, bool) {
	if r.Method != http.MethodPost {
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
		http.Error(w, "the confirmation has expired: confirm again", http.StatusUnauthorized)
		return "", nil, false
	}
	if want := s.accountCSRF(k); want == "" || subtle.ConstantTimeCompare([]byte(csrf()), []byte(want)) != 1 {
		s.localLimit.failed(addr, "")
		s.logf("local: an account request without its page's token (%s, from %s)", orUnnamed(sess.who.username), addr)
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return "", nil, false
	}
	return k, sess, true
}

// audit is the one line every change leaves: who, what, which, from where.
func (s *server) audit(sess *accountSession, action, what string, r *http.Request) {
	if len(what) > 16 {
		what = what[:16]
	}
	s.logf("account: audit: %s %s %s from %s", orUnnamed(sess.who.username), action, what, s.clientAddr(r))
	s.counters.inc("bridge_logins_total", "account_"+action)
}

// accountFederation sends the person to their institution to confirm, with
// ForceAuthn. It is an authentication request of its own kind: no client, no
// redirect URI, and the ACS ends it at the account page.
func (s *server) accountFederation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if s.accountThrottled(w, s.clientAddr(r)) {
		return
	}
	id := token()
	l := &login{kind: "account", options: saml.Options{ForceAuthn: true}, maxAge: -1, expires: s.now().Add(loginLifetime)}
	s.logins.add(s.now(), 1, 0)
	if len(s.cfg.SAML.IdPs) == 1 {
		s.toIdP(w, r, id, l, s.cfg.SAML.IdPs[0])
		return
	}
	if !s.setLoginCookie(w, id, l) {
		return
	}
	if s.cfg.SAML.Discovery != "" {
		u, err := saml.DiscoveryURL(s.cfg.SAML.Discovery, s.sp.EntityID, s.cfg.Issuer+"/saml/disco")
		if err != nil {
			s.page(w, http.StatusInternalServerError, "The discovery service is misconfigured.")
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
	http.Redirect(w, r, s.cfg.Issuer+"/saml/choose", http.StatusFound)
}

// accountFromACS ends a confirmation through an institution, at the ACS. The
// response is a cross-site POST, and a SameSite=Strict cookie is not set from
// one reliably, so the session waits behind a one-time handle that the page
// returned here posts back, from this origin (accountOpen).
func (s *server) accountFromACS(w http.ResponseWriter, r *http.Request, a *saml.Assertion) {
	// An institution may ignore ForceAuthn: what it says about WHEN is what
	// counts.
	age := s.now().Sub(a.AuthnInstant)
	if age > accountTTL || -age > s.clockSkew() {
		s.logf("account: %s confirmed with an authentication %s old: refused", a.IdP.EntityID, age.Round(time.Second))
		s.page(w, http.StatusUnauthorized, "Votre établissement n'a pas demandé de vous authentifier à nouveau. Réessayez. / Your institution did not authenticate you again. Try again.")
		return
	}
	who, err := newPerson(a, s.cfg.Claims)
	if err != nil {
		s.logf("account: %s: %v", a.IdP.EntityID, err)
		s.page(w, http.StatusBadRequest, "Your institution did not say who you are.")
		return
	}
	if why := s.refused(who); why != "" {
		s.logf("account: %s via %s refused: %s", orUnnamed(who.username), who.idp, why)
		s.page(w, http.StatusForbidden, "Your access to this service has been disabled.")
		return
	}
	s.logf("account: %s confirmed through %s from %s", orUnnamed(who.username), who.idp, s.clientAddr(r))
	h := token()
	if err := s.accountOpens.put(hashToken(h), &accountSession{who: who}, s.now().Add(accountOpenTTL)); err != nil {
		s.page(w, http.StatusServiceUnavailable, "Too many in progress; try again in a minute.")
		return
	}
	pageHeadersScript(w, "'self'")
	w.WriteHeader(http.StatusOK)
	s.show(w, "accountopen", map[string]any{"Handle": h})
}

// accountOpen is the same-origin POST that turns the handle into the cookie.
func (s *server) accountOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !s.sameOrigin(r) {
		s.page(w, http.StatusForbidden, "The request did not come from this provider's page.")
		return
	}
	addr := s.clientAddr(r)
	if s.accountThrottled(w, addr) {
		return
	}
	sess, ok := s.accountOpens.take(hashToken(r.PostForm.Get("h")))
	if !ok {
		s.localLimit.failed(addr, "")
		s.page(w, http.StatusForbidden, "This confirmation has expired. Start again from your account page.")
		return
	}
	if why := s.refused(sess.who); why != "" {
		s.page(w, http.StatusForbidden, "Your access to this service has been disabled.")
		return
	}
	if !s.startSession(w, r, sess) {
		return
	}
	s.audit(sess, "confirm", "federation", r)
	http.Redirect(w, r, s.cfg.Issuer+"/account", http.StatusSeeOther)
}

// ---- step-up with a passkey ----

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
	acct, known := s.cfg.Local.store.get(rec.Login)
	if !known {
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
	who := s.localPerson(acct, rec)
	if why := s.refused(who); why != "" {
		refuse("refused: " + why)
		return
	}
	sess := &accountSession{who: who, credential: rec.key(), at: s.now()}
	if !s.startSession(w, r, sess) {
		return
	}
	s.localLimit.succeeded("")
	s.audit(sess, "stepup", rec.key(), r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- passkeys: add, remove ----

// localSession is accountPost for the passkey endpoints: a local account's.
func (s *server) localSession(w http.ResponseWriter, r *http.Request, v any, csrf func() string) (string, *accountSession, bool) {
	if s.cfg.Local == nil {
		http.NotFound(w, r)
		return "", nil, false
	}
	k, sess, ok := s.accountPost(w, r, v, csrf)
	if !ok {
		return "", nil, false
	}
	if !s.isLocal(sess.who) {
		http.Error(w, "passkeys are those of local accounts: your institution manages how you sign in", http.StatusForbidden)
		return "", nil, false
	}
	return k, sess, true
}

func (s *server) accountAddBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
	}
	k, sess, ok := s.localSession(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	login := sess.who.username
	acct, ok := s.cfg.Local.store.get(login)
	if !ok {
		http.Error(w, "the account was removed", http.StatusForbidden)
		return
	}
	have, err := s.passkeys.passkeys(login)
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
	handle, err := s.startCeremony(&ceremony{challenge: ch, purpose: purposeAddKey, login: login, loginID: k})
	if err != nil {
		http.Error(w, "too many in progress; try again in a minute", http.StatusServiceUnavailable)
		return
	}
	display := login
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
			"user":      map[string]any{"id": b64(s.userHandle(login)), "name": login, "displayName": display},
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
			"attestation":        s.attestationFor(login),
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
	k, sess, ok := s.localSession(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	login := sess.who.username
	addr := s.clientAddr(r)
	refuse := func(status int, msg string, why any) {
		s.localLimit.failed(addr, "")
		s.counters.inc("bridge_logins_total", "local_enroll_refused")
		s.logf("local: adding a passkey for %s was refused from %s: %v", login, addr, why)
		http.Error(w, msg, status)
	}
	cer, ok := s.takeCeremonyFor(req.Handle, purposeAddKey)
	if !ok || cer.login != login || cer.loginID != k {
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
	cred, attested, err := s.verifyEnrolment(login, cer.challenge, cd, ao)
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
	have, err := s.passkeys.passkeys(login)
	if err != nil || len(have) >= maxPasskeys {
		refuse(http.StatusConflict, fmt.Sprintf("an account has at most %d passkeys: remove one first", maxPasskeys), fmt.Sprintf("%d keys (%v)", len(have), err))
		return
	}
	rec := &passkeyRecord{
		Login: login, ID: cred.ID, PublicKey: cred.PublicKeyCOSE, SignCount: cred.SignCount,
		BackupEligible: cred.BackupEligible, Transports: cleanTransports(req.Transports),
		AAGUID: cred.AAGUID[:], AttestedAAGUID: attested, Created: s.now(),
	}
	if err := s.passkeys.savePasskey(rec); err != nil {
		s.logf("local: storing a passkey for %s: %v", login, err)
		http.Error(w, "the passkey could not be stored", http.StatusInternalServerError)
		return
	}
	s.audit(sess, "add", rec.key(), r)
	s.keyEvent("key.added", login, rec, time.Time{}, addr)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"added": rec.key()[:16], "attested": attested != ""})
}

// ---- profile ----

// accountProfile takes what a page could send for the identity section. Only a
// local account's display name is the person's to change; mail and groups are
// never, and are refused by name, with who does change them.
func (s *server) accountProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF   string    `json:"csrf"`
		Name   *string   `json:"name"`
		Mail   *string   `json:"mail"`
		Groups *[]string `json:"groups"`
	}
	_, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	who := sess.who
	by := "your institution"
	if s.isLocal(who) {
		by = "the service's administrator"
	}
	if req.Mail != nil || req.Groups != nil {
		s.localLimit.failed(s.clientAddr(r), "")
		s.audit(sess, "refused-profile", "mail-or-groups", r)
		http.Error(w, "Mail and groups cannot be changed here: "+by+" does. / L'adresse et les groupes ne se changent pas ici.", http.StatusForbidden)
		return
	}
	if req.Name == nil {
		http.Error(w, "nothing to change", http.StatusBadRequest)
		return
	}
	if !s.isLocal(who) {
		s.localLimit.failed(s.clientAddr(r), "")
		s.audit(sess, "refused-profile", "name", r)
		http.Error(w, "Your name comes from your institution, which changes it.", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(*req.Name)
	if name == "" || len(name) > maxNameLen || strings.IndexFunc(name, displayNameRuneBad) >= 0 {
		http.Error(w, fmt.Sprintf("a name is 1 to %d characters, without control, direction or invisible characters", maxNameLen), http.StatusBadRequest)
		return
	}
	if err := s.passkeys.put(kindProfile, loginKey(who.username), profileRecord{Name: name}, passkeyForever); err != nil {
		s.logf("local: storing a display name for %s: %v", who.username, err)
		http.Error(w, "the name could not be stored", http.StatusInternalServerError)
		return
	}
	who.profile["name"] = name
	s.audit(sess, "name", name, r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"name": name})
}

// ---- applications and sessions ----

// accountAppsRevoke ends one application session (a refresh-token family), or
// all of the person's: through revokeFamily and revokeMatching, which the
// administrator's RevokePerson uses.
func (s *server) accountAppsRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
		ID   string `json:"id"`
		All  bool   `json:"all"`
	}
	_, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	who := sess.who
	if req.All {
		rv := s.revokeMatching(func(_, idp, subject string) bool { return idp == who.idp && subject == who.subject })
		s.audit(sess, "revoke-apps", "all", r)
		writeJSONNoStore(w, http.StatusOK, map[string]any{"families": rv.families, "tokens": rv.tokens})
		return
	}
	var family string
	for _, g := range s.grantsOf(who) {
		if req.ID != "" && familyID(g.family) == req.ID {
			family = g.family
		}
	}
	if family == "" {
		s.localLimit.failed(s.clientAddr(r), "")
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	var rts []string
	s.refresh.each(func(rt string, g *refreshGrant) {
		if g.family == family {
			rts = append(rts, rt)
		}
	})
	for _, rt := range rts {
		s.refresh.take(rt)
	}
	n := s.revokeFamily(family)
	s.audit(sess, "revoke-app", req.ID, r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"tokens": n})
}

// ---- technical access ----

// accountAccessRevoke revokes one of the person's SSH certificate, X.509
// certificate or WireGuard key, in the stores they were issued into.
func (s *server) accountAccessRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRF string `json:"csrf"`
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	_, sess, ok := s.accountPost(w, r, &req, func() string { return req.CSRF })
	if !ok {
		return
	}
	who := sess.who
	notFound := func() {
		s.localLimit.failed(s.clientAddr(r), "")
		http.Error(w, "no such access", http.StatusNotFound)
	}
	mine := s.ownedBy(who)
	found := false
	for _, c := range s.certs.liveWhere(mine, s.now()) {
		if c.Kind == req.Kind && c.Serial == req.ID {
			found = true
		}
	}
	if !found {
		notFound()
		return
	}
	// By kind and serial, and only if it is still the person's: the predicate is
	// checked again under the store's lock.
	n, err := s.certs.revokeWhere(func(c issuedCert) bool { return c.Kind == req.Kind && c.Serial == req.ID && mine(c) }, s.now())
	if err != nil {
		s.logf("account: revoking %s %s of %s: %v", req.Kind, req.ID, who.username, err)
		http.Error(w, "it could not be revoked", http.StatusInternalServerError)
		return
	}
	s.audit(sess, "revoke-access", req.Kind+":"+req.ID, r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"revoked": n})
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
	s.audit(sess, "signout", "-", r)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}

// profileRecord is the one thing of a local account's profile its owner may
// change, kept in the state database beside its passkeys.
type profileRecord struct {
	Name string `json:"name"`
}

// displayNameOf is a local account's display name if its owner set one.
func (s *server) displayNameOf(login string) (string, bool) {
	var p profileRecord
	ok, err := s.passkeys.get(kindProfile, loginKey(login), &p)
	if err != nil || !ok || p.Name == "" {
		return "", false
	}
	return p.Name, true
}
