// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/oidc"
	"github.com/go-authn/saml"
)

// The local login: a page this provider serves itself, where a person signs in
// with a passkey (WebAuthn), for the accounts of a `local` block
// (localaccounts.go). There is no password anywhere: the page has no password
// field, no route reads one, and nothing checks one.
//
// What it refuses, each with a test:
//
//   - a request that does not carry the CSRF token of THIS login (the token is
//     an HMAC of the login's handle under a key derived from the subject salt),
//     or that a browser says is cross-site, or whose Origin is not the
//     issuer's;
//   - a challenge answered twice, or by another login, or after five minutes;
//   - a credential the account does not have, one whose user handle is
//     another account's, one that fails go-authn/webauthn's checks (origin,
//     rpIdHash, user verification, signature, a counter that did not advance);
//   - the eleventh failure from one host (a /64 for IPv6) in a quarter of an
//     hour: refused BEFORE any verification.
//
// And what it never does is take a destination from the request: the only
// place a successful login goes is the redirect URI the sealed login already
// holds, which authorize registered it against (redirectAllowed).

const (
	// localHostMax is the failures one host may have in localWindow; its
	// network gets coarseFactor times as many (limitKeys).
	localHostMax = 10
	// localLoginMax is the failures one key may have in localWindow.
	localLoginMax = 5
	localWindow   = 15 * time.Minute
	// localTracked bounds the keys counted at once. Anonymous people choose
	// the keys, so the table is capped, and past the cap a key nobody has
	// failed yet is refused rather than evicting one somebody has.
	localTracked = 20000
)

// localThrottle counts the failures, by key and by host.
type localThrottle struct {
	mu      sync.Mutex
	now     func() time.Time
	logins  map[string][]time.Time
	hosts   map[string][]time.Time
	swept   time.Time
	perHost int
}

func newLocalThrottle(now func() time.Time) *localThrottle {
	return &localThrottle{now: now, logins: map[string][]time.Time{}, hosts: map[string][]time.Time{}, perHost: localHostMax}
}

// recent is the failures under key that are still inside the window.
func (t *localThrottle) recent(m map[string][]time.Time, key string) []time.Time {
	now := t.now()
	var keep []time.Time
	for _, at := range m[key] {
		if d := now.Sub(at); d >= 0 && d < localWindow {
			keep = append(keep, at)
		}
	}
	if len(keep) == 0 {
		delete(m, key)
	} else {
		m[key] = keep
	}
	return keep
}

func (t *localThrottle) sweepLocked() {
	now := t.now()
	if d := now.Sub(t.swept); d >= 0 && d < localWindow/3 {
		return
	}
	t.swept = now
	for _, m := range []map[string][]time.Time{t.logins, t.hosts} {
		for k := range m {
			t.recent(m, k)
		}
	}
}

// loginKey is what a typed name is counted under: the whole of it, folded,
// bounded -- whether or not such an account exists.
func loginKey(login string) string {
	l := oidc.ASCIILower(login)
	if len(l) > 128 {
		l = l[:128]
	}
	return l
}

// blocked says whether this attempt is refused without being checked.
func (t *localThrottle) blocked(addr, login string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked()
	fine, coarse := limitKeys(addr)
	if len(t.recent(t.hosts, fine)) >= t.perHost || len(t.recent(t.hosts, coarse)) >= t.perHost*coarseFactor {
		return true
	}
	if login == "" {
		return false
	}
	k := loginKey(login)
	n := len(t.recent(t.logins, k))
	if n == 0 && len(t.logins) >= localTracked {
		return true
	}
	return n >= localLoginMax
}

// failed counts a refusal. An empty login counts the host alone.
func (t *localThrottle) failed(addr, login string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	fine, coarse := limitKeys(addr)
	t.hosts[fine] = append(t.recent(t.hosts, fine), now)
	t.hosts[coarse] = append(t.recent(t.hosts, coarse), now)
	if login == "" {
		return
	}
	k := loginKey(login)
	if _, tracked := t.logins[k]; tracked || len(t.logins) < localTracked {
		t.logins[k] = append(t.recent(t.logins, k), now)
	}
}

// succeeded forgets the key's failures: the person is in.
func (t *localThrottle) succeeded(login string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.logins, loginKey(login))
}

// ---- the pages ----

// localCSRF is the token a login's page carries: an HMAC of the login's handle
// under a key derived from the subject salt -- stateless, bound to this login,
// and not something another site can compute or read.
func (s *server) localCSRF(id string) (string, error) {
	return s.csrfToken("go-authn bridge local login csrf v1", id)
}

// csrfToken is the HMAC of id under a key derived from the salt and label: one
// label per kind of page, so that a token of one is no token of another.
func (s *server) csrfToken(label, id string) (string, error) {
	key, err := hkdf.Key(sha256.New, s.cfg.salt, nil, label, 32)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// sameOrigin says whether a POST came from a page of this provider, as far as
// the browser says. A request with neither header (curl, an old browser) is
// not refused here: the CSRF token, the single-use challenge and the login
// cookie are what hold.
func (s *server) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" && v != "same-origin" && v != "none" {
		return false
	}
	// ⛔ "null" from THIS origin is what a browser sends: this provider's pages
	// send Referrer-Policy: no-referrer, and under that policy a browser
	// serializes the Origin of a NAVIGATION (a form post) as "null" even from
	// the same origin (Fetch, "serialize a request origin"). Comparing it to the
	// issuer refused every passkey login in production (2026-11-18), the one
	// post the login page makes with form.submit(). So "null" passes ONLY when
	// the browser itself says same-origin; a "null" on its own (a sandboxed
	// iframe, a data: page, anywhere) is still refused, and every post still
	// needs the CSRF token.
	o := r.Header.Get("Origin")
	if o == "null" && r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	if o != "" {
		u, err := url.Parse(s.cfg.Issuer)
		if err != nil || o != u.Scheme+"://"+u.Host {
			return false
		}
	}
	return true
}

// localFormAction is the form-action source list of the login page. A browser
// applies the page's form-action to the redirects the POST ends in -- Chrome
// does -- so 'self' alone would stop the login's last step, the redirect to
// the client. The origin added is the one of the redirect URI the sealed login
// holds, which was matched against the registered ones; a device login ends on
// a page of this provider.
func localFormAction(l *login) string {
	u, err := url.Parse(l.redirectURI)
	if err != nil || l.redirectURI == "" || u.Scheme == "" {
		return "'self'"
	}
	src := u.Scheme + ":"
	if u.Host != "" {
		src = u.Scheme + "://" + u.Host
	}
	if strings.ContainsAny(src, " ;,'\"\\") {
		return "'self'"
	}
	return "'self' " + src
}

func (s *server) renderLocal(w http.ResponseWriter, status int, l *login, id, msg string) {
	csrf, err := s.localCSRF(id)
	if err != nil {
		s.logf("local: csrf: %v", err)
		s.page(w, http.StatusInternalServerError, "The login could not be shown.")
		return
	}
	pageHeadersScript(w, localFormAction(l))
	w.WriteHeader(status)
	s.show(w, "locallogin", map[string]any{"CSRF": csrf, "Error": msg})
}

// loginMethod is the page offered when people can log in through the
// federation and with a local account.
func (s *server) loginMethod(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil {
		http.NotFound(w, r)
		return
	}
	_, l, err := s.current(r)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	if l.started || l.kind == "account" {
		s.page(w, http.StatusBadRequest, "This login has already gone to an institution; start again from the application.")
		return
	}
	fed := s.cfg.Issuer + "/saml/choose"
	switch {
	case s.cfg.SAML.Discovery != "":
		u, err := saml.DiscoveryURL(s.cfg.SAML.Discovery, s.sp.EntityID, s.cfg.Issuer+"/saml/disco")
		if err != nil {
			s.page(w, http.StatusInternalServerError, "The discovery service is misconfigured.")
			return
		}
		fed = u
	case len(s.cfg.SAML.IdPs) == 1:
		fed = s.cfg.Issuer + "/saml/disco?entityID=" + url.QueryEscape(s.cfg.SAML.IdPs[0])
	}
	// Links, unlike forms, are not held by form-action: the page has none.
	headers(w)
	w.WriteHeader(http.StatusOK)
	s.show(w, "method", map[string]any{"Federation": fed})
}

// localLogin is the passkey page. It only answers GET: the sign-in itself is
// /local/login/begin and /local/login/finish, and nothing here reads a
// password, whatever is posted.
func (s *server) localLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed: local accounts sign in with a passkey, there is no password form", http.StatusMethodNotAllowed)
		return
	}
	id, l, ok := s.localLoginState(w, r)
	if !ok {
		return
	}
	s.renderLocal(w, http.StatusOK, l, id, "")
}

// localPerson is a local account as this provider describes a person: the
// subject, like a federated one, is HMACed under the salt (person.sub) from
// "local:" and the login, and never shown. credential is the passkey that
// signed in, which the grants it buys are held to.
func (s *server) localPerson(id *directory.Identity, rec *passkeyRecord) *person {
	login := id.Name()
	scope := s.cfg.Local.Scope
	p := &person{
		subject:    "local:" + login,
		idp:        s.cfg.localEntityID(),
		username:   login,
		credential: rec.key(),
		authTime:   s.now(),
		acr:        localACR,
		profile:    map[string]any{"preferred_username": login},
		email:      map[string]any{},
		edu:        map[string]any{"eduperson_principal_name": login + "@" + scope},
	}
	if n := id.Attributes().Get("displayName"); len(n) > 0 {
		p.profile["name"] = n[0]
	}
	// The name its owner chose on the account page wins over the file's.
	if n, ok := s.displayNameOf(login); ok {
		p.profile["name"] = n
	}
	if m := id.Attributes().Get("mail"); len(m) > 0 {
		p.email["email"] = m[0]
	}
	// ⛔ Held to the scope at every use, not only when the file was read: the
	// file parser refuses a group outside it, and this keeps one out if that
	// ever changes.
	for _, g := range id.Groups() {
		if localGroupAllowed(scope, s.cfg.Claims.TrustedGroups[p.idp], g) {
			p.groups = append(p.groups, g)
		}
	}
	return p
}

// localAccountGone says whether who is a local grant that its sources no
// longer stand behind: the account is gone from the file, or the passkey it
// was bought with is gone from the database (removed by the administrator, or
// not the account's). A grant whose record keeps no passkey (an application
// password, a certificate) is held to the account having one.
//
// ⛔ A database that cannot be read refuses: a revocation must not wait on it.
func (s *server) localAccountGone(who *person) bool {
	if s.cfg.Local == nil || who.idp != s.cfg.localEntityID() {
		return false
	}
	if _, ok := s.cfg.Local.store.get(who.username); !ok {
		return true
	}
	if s.passkeys == nil {
		return true
	}
	if who.credential == "" {
		// A certificate or a key: what the store keeps of
		// them is the login and the IdP, not the passkey. They are held to the
		// account having a passkey at all -- remove the last and they stop.
		have, err := s.passkeys.passkeys(who.username)
		if err != nil {
			s.logf("local: reading passkeys to check a grant: %v", err)
			return true
		}
		return len(have) == 0
	}
	rec, ok, err := s.passkeys.passkey(who.credential)
	if err != nil {
		s.logf("local: reading a passkey to check a grant: %v", err)
		return true
	}
	return !ok || rec.Login != who.username
}

// check is everything that can be said wrong about a local block.
func (l *localBlock) check(c *config) error {
	if !strings.HasPrefix(l.AccountsFile, "/") && !(len(l.AccountsFile) > 2 && l.AccountsFile[1] == ':') {
		return fmt.Errorf("accounts_file %q: an absolute path", l.AccountsFile)
	}
	if !scopeSyntax.MatchString(l.Scope) || len(l.Scope) > 253 {
		return fmt.Errorf("scope %q: a lowercase domain such as \"plateau-de-saclay.net\"", l.Scope)
	}
	if c.State == nil {
		return errors.New("a local block needs a state { } block: the passkeys, their signature counters and the invitations are kept in the state database")
	}
	l.removalDelay = defaultRemovalDelay
	if l.PasskeyRemovalDelay != "" {
		d, err := time.ParseDuration(l.PasskeyRemovalDelay)
		if err != nil || d < 0 || d > maxRemovalDelay {
			return fmt.Errorf("passkey_removal_delay %q: a duration from 0 to %s, such as \"24h\"", l.PasskeyRemovalDelay, maxRemovalDelay)
		}
		l.removalDelay = d
	}
	store, err := newLocalStore(l.AccountsFile, l.Scope, c.Claims.TrustedGroups[c.localEntityID()])
	if err != nil {
		return fmt.Errorf("accounts_file: %w", err)
	}
	l.store = store
	return l.checkAdmins(c)
}

// checkAdmins validates admins and admin_aaguids, and builds their sets.
func (l *localBlock) checkAdmins(c *config) error {
	l.adminSet, l.aaguidSet = nil, nil
	if len(l.Admins) == 0 {
		if len(l.AdminAAGUIDs) > 0 {
			return errors.New("admin_aaguids without admins")
		}
		return nil
	}
	if c.Mail == nil {
		return errors.New("admins needs a mail { } block: the invitation goes only by e-mail")
	}
	if len(l.AdminAAGUIDs) == 0 {
		return errors.New("admins needs admin_aaguids: the models of authenticator an administrator's passkey may be")
	}
	l.adminSet, l.aaguidSet = map[string]bool{}, map[string]bool{}
	for _, a := range l.Admins {
		if !loginSyntax.MatchString(a) {
			return fmt.Errorf("admins: %w", badLogin(a))
		}
		if _, ok := l.store.get(a); !ok {
			return fmt.Errorf("admins: %q is not an account of accounts_file", a)
		}
		if l.adminSet[a] {
			return fmt.Errorf("admins: %q twice", a)
		}
		l.adminSet[a] = true
	}
	for _, g := range l.AdminAAGUIDs {
		n, err := normAAGUID(g)
		if err != nil {
			return fmt.Errorf("admin_aaguids: %w", err)
		}
		l.aaguidSet[n] = true
	}
	return nil
}

// normAAGUID is an AAGUID in its canonical form, lowercase 8-4-4-4-12; the
// all-zero one (what an authenticator that does not say reports) is refused.
func normAAGUID(s string) (string, error) {
	n := strings.ToLower(s)
	if len(n) != 36 {
		return "", fmt.Errorf("%q: a UUID such as 9dd8d593-2213-438a-97f8-d6b813d51c27", s)
	}
	for i := 0; i < len(n); i++ {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if n[i] != '-' {
				return "", fmt.Errorf("%q: a UUID such as 9dd8d593-2213-438a-97f8-d6b813d51c27", s)
			}
		case !(n[i] >= '0' && n[i] <= '9' || n[i] >= 'a' && n[i] <= 'f'):
			return "", fmt.Errorf("%q: a UUID such as 9dd8d593-2213-438a-97f8-d6b813d51c27", s)
		}
	}
	if n == "00000000-0000-0000-0000-000000000000" {
		return "", fmt.Errorf("%q: the zero AAGUID names no model", s)
	}
	return n, nil
}
