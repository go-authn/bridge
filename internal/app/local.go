// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// The local login: a username and password form this provider serves itself,
// for the accounts of a `local` block (localaccounts.go).
//
// What it refuses, each with a test:
//
//   - a POST that does not carry the CSRF token of THIS login (the token is an
//     HMAC of the login's handle under a key derived from the subject salt), or
//     that a browser says is cross-site, or whose Origin is not the issuer's;
//   - a password it checks in different time for an unknown login (the same
//     argon2id runs against a dummy hash) -- so no user enumeration by timing;
//   - the sixth wrong password for one login in a quarter of an hour, and the
//     eleventh from one host (a /64 for IPv6), whatever the logins: both are
//     refused BEFORE any hashing, and both count unknown logins too, so a
//     refusal says nothing about whether the account exists;
//   - more than localHashers password checks at once: an argon2id costs 64 MiB,
//     and the form is anonymous.
//
// And what it never does is take a destination from the request: the only
// place a successful login goes is the redirect URI the sealed login already
// holds, which authorize registered it against (redirectAllowed).

const (
	// localLoginMax is the wrong passwords one login may have in localWindow.
	localLoginMax = 5
	// localHostMax is the wrong passwords one host may have in localWindow; its
	// network gets coarseFactor times as many (limitKeys).
	localHostMax = 10
	localWindow  = 15 * time.Minute
	// localTracked bounds the logins counted at once. Anonymous people choose
	// the keys, so the table is capped, and past the cap a login nobody has
	// failed yet is refused rather than evicting one somebody has.
	localTracked = 20000
	// localHashers is how many password checks run at once.
	localHashers = 4
	// localHashWait is how long a request waits for one of them.
	localHashWait = 2 * time.Second
)

// localThrottle counts the wrong passwords, by login and by host.
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

// loginKey is what a typed login is counted under: the whole of it, folded,
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
	k := loginKey(login)
	n := len(t.recent(t.logins, k))
	if n == 0 && len(t.logins) >= localTracked {
		return true
	}
	return n >= localLoginMax
}

// failed counts a wrong password.
func (t *localThrottle) failed(addr, login string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	fine, coarse := limitKeys(addr)
	t.hosts[fine] = append(t.recent(t.hosts, fine), now)
	t.hosts[coarse] = append(t.recent(t.hosts, coarse), now)
	k := loginKey(login)
	if _, tracked := t.logins[k]; tracked || len(t.logins) < localTracked {
		t.logins[k] = append(t.recent(t.logins, k), now)
	}
}

// succeeded forgets the login's failures: the person is in.
func (t *localThrottle) succeeded(login string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.logins, loginKey(login))
}

// ---- the pages ----

// localCSRF is the token a login's form carries: an HMAC of the login's handle
// under a key derived from the subject salt -- stateless, bound to this login,
// and not something another site can compute or read.
func (s *server) localCSRF(id string) (string, error) {
	key, err := hkdf.Key(sha256.New, s.cfg.salt, nil, "go-authn bridge local login csrf v1", 32)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// sameOrigin says whether a POST came from a page of this provider, as far as
// the browser says. A request with neither header (curl, an old browser) is
// not refused here: the CSRF token and the login cookie are what hold.
func (s *server) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" && v != "same-origin" && v != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
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

func (s *server) renderLocal(w http.ResponseWriter, status int, l *login, id, login, msg string) {
	csrf, err := s.localCSRF(id)
	if err != nil {
		s.logf("local: csrf: %v", err)
		s.page(w, http.StatusInternalServerError, "The login could not be shown.")
		return
	}
	pageHeaders(w, localFormAction(l))
	w.WriteHeader(status)
	tmpl.ExecuteTemplate(w, "locallogin", map[string]any{"CSRF": csrf, "Login": login, "Error": msg})
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
	if l.started {
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
	tmpl.ExecuteTemplate(w, "method", map[string]any{"Federation": fed})
}

// localLogin is the username and password form, and what it posts to.
func (s *server) localLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Local == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, l, err := s.current(r)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	// One login, one way in: one that already went to an institution has an
	// AuthnRequest out, whose response could still arrive.
	if l.started {
		s.page(w, http.StatusBadRequest, "This login has already gone to an institution; start again from the application.")
		return
	}
	if l.options.IsPassive {
		// prompt=none: there is no session here to find.
		s.finishError(w, r, l, "login_required", "no session: a local account needs a password")
		return
	}
	if r.Method == http.MethodGet {
		s.renderLocal(w, http.StatusOK, l, id, "", "")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
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
	typed := r.PostForm.Get("login")
	password := r.PostForm.Get("password")
	if s.localLimit.blocked(addr, typed) {
		s.counters.inc("bridge_logins_total", "local_throttled")
		w.Header().Set("Retry-After", "900")
		s.renderLocal(w, http.StatusTooManyRequests, l, id, "", "Trop d'essais. Réessayez dans un quart d'heure. / Too many attempts: try again in fifteen minutes.")
		return
	}

	acct, ok, busy := s.checkLocal(strings.TrimSpace(typed), password)
	switch {
	case busy:
		w.Header().Set("Retry-After", "5")
		s.renderLocal(w, http.StatusServiceUnavailable, l, id, "", "Le service est occupé. Réessayez dans un instant. / Busy: try again in a moment.")
		return
	case !ok:
		s.localLimit.failed(addr, typed)
		s.logf("local: a wrong login or password from %s", addr)
		s.counters.inc("bridge_logins_total", "local_wrong")
		// The same answer whether or not the account exists. The login is not
		// echoed back: it is what the person typed, and they can retype it.
		s.renderLocal(w, http.StatusUnauthorized, l, id, "", "Identifiant ou mot de passe incorrect. / Wrong login or password.")
		return
	}
	s.localLimit.succeeded(typed)
	http.SetCookie(w, s.cookie(loginCookie, "", -1))
	if err := s.usedLogins.putNew(id, true, l.expires); err != nil {
		s.page(w, http.StatusBadRequest, "This login has already been answered; start again from the application.")
		return
	}
	who := s.localPerson(acct)
	s.finishLogin(w, r, l, who)
}

// checkLocal verifies a login and password. The same argon2id runs for a login
// that does not exist, against a dummy hash. busy is true when no hasher
// became free in time: nothing was checked.
func (s *server) checkLocal(login, password string) (acct *directory.Identity, ok, busy bool) {
	select {
	case s.localHash <- struct{}{}:
		defer func() { <-s.localHash }()
	case <-time.After(localHashWait):
		return nil, false, true
	}
	id, known := s.cfg.Local.store.get(login)
	if !known || len(password) == 0 || len(password) > maxPasswordLen {
		// An unknown login, or a password no account's could be: the work is
		// still done, once.
		dummyHash().verify([]byte(password[:min(len(password), maxPasswordLen)]))
		return nil, false, false
	}
	if id.Verify(password) != nil {
		return nil, false, false
	}
	return id, true, false
}

// localPerson is a local account as this provider describes a person: the
// subject, like a federated one, is HMACed under the salt (person.sub) from
// "local:" and the login, and never shown.
func (s *server) localPerson(id *directory.Identity) *person {
	login := id.Name()
	scope := s.cfg.Local.Scope
	p := &person{
		subject:  "local:" + login,
		idp:      s.cfg.localEntityID(),
		username: login,
		authTime: s.now(),
		acr:      localACR,
		profile:  map[string]any{"preferred_username": login},
		email:    map[string]any{},
		edu:      map[string]any{"eduperson_principal_name": login + "@" + scope},
	}
	if n := id.Attributes().Get("displayName"); len(n) > 0 {
		p.profile["name"] = n[0]
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

// localAccountGone says whether who is a local account the file no longer has.
func (s *server) localAccountGone(who *person) bool {
	if s.cfg.Local == nil || who.idp != s.cfg.localEntityID() {
		return false
	}
	_, ok := s.cfg.Local.store.get(who.username)
	return !ok
}

// check is everything that can be said wrong about a local block.
func (l *localBlock) check(c *config) error {
	if !strings.HasPrefix(l.AccountsFile, "/") && !(len(l.AccountsFile) > 2 && l.AccountsFile[1] == ':') {
		return fmt.Errorf("accounts_file %q: an absolute path", l.AccountsFile)
	}
	if !scopeSyntax.MatchString(l.Scope) || len(l.Scope) > 253 {
		return fmt.Errorf("scope %q: a lowercase domain such as \"plateau-de-saclay.net\"", l.Scope)
	}
	store, err := newLocalStore(l.AccountsFile, l.Scope, c.Claims.TrustedGroups[c.localEntityID()])
	if err != nil {
		return fmt.Errorf("accounts_file: %w", err)
	}
	l.store = store
	return nil
}
