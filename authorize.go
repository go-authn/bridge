// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/saml"
)

// loginCookie carries the handle of a login in progress. The IdP carries
// the same handle back in RelayState, and the two must agree: without the
// cookie, somebody could start a login, stop at the IdP's response, and
// deliver THAT response into somebody else's browser -- who would then be
// logged into the relying party as the attacker.
const loginCookie = "bridge_login"

// loginLifetime bounds how long somebody may spend at their IdP.
const loginLifetime = 15 * time.Minute

var codeChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// authorize is the authorization endpoint (OIDC Core 3.1.2).
//
// Until the client and its redirect URI are known good, an error is shown
// here and NOT sent to the redirect URI: sending it would make this provider
// an open redirector for any URI anybody typed (RFC 6749 4.1.2.1).
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	q := r.Form
	for k, v := range q {
		if len(v) > 1 {
			// RFC 6749 3.1: parameters MUST NOT be included more than once.
			s.page(w, http.StatusBadRequest, "The parameter "+k+" appears more than once.")
			return
		}
	}
	client, ok := s.cfg.client(q.Get("client_id"))
	if !ok {
		s.page(w, http.StatusBadRequest, "This application is not known here.")
		return
	}
	redirect := q.Get("redirect_uri")
	if !redirectAllowed(client, redirect) {
		s.logf("authorize: %s asked to redirect to %q, which it did not register", client.ID, redirect)
		s.page(w, http.StatusBadRequest, "This application asked to be sent somewhere it did not register.")
		return
	}

	// From here on, the client is told.
	fail := func(code, desc string) { s.redirectError(w, r, redirect, q.Get("state"), code, desc) }
	if q.Get("request") != "" || q.Get("request_uri") != "" {
		fail("request_not_supported", "request objects are not supported")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only the authorization code flow is offered")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if !slices.Contains(scopes, "openid") {
		fail("invalid_scope", "the openid scope is required")
		return
	}
	if slices.Contains(scopes, "ssh") && !client.SSHCertificates {
		fail("invalid_scope", "this client may not ask for SSH certificates")
		return
	}
	if slices.Contains(scopes, "nfs") && !client.X509Certificates {
		fail("invalid_scope", "this client may not ask for NFS certificates")
		return
	}
	if slices.Contains(scopes, "ssf") {
		fail("invalid_scope", "the ssf scope is for client credentials, not for a login")
		return
	}
	if slices.Contains(scopes, "app_password") && !client.AppPasswords {
		fail("invalid_scope", "this client may not set application passwords")
		return
	}
	// ⛔ PKCE, S256, for every client. RFC 7636 4.3 makes "plain" the
	// DEFAULT when no method is given, so an absent method is refused
	// rather than read as S256: a provider that accepted it would be
	// comparing the verifier with itself.
	if q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if !codeChallenge.MatchString(q.Get("code_challenge")) {
		fail("invalid_request", "code_challenge is not a base64url SHA-256")
		return
	}

	var opts saml.Options
	prompts := strings.Fields(q.Get("prompt"))
	if slices.Contains(prompts, "none") && len(prompts) > 1 {
		fail("invalid_request", "prompt=none cannot be combined")
		return
	}
	opts.IsPassive = slices.Contains(prompts, "none")
	opts.ForceAuthn = slices.Contains(prompts, "login")
	// max_age: the IdP cannot be asked how old its session is, only to
	// make a new one. So any max_age asks for a fresh authentication, and
	// auth_time says when it happened.
	if q.Get("max_age") != "" {
		opts.ForceAuthn = true
	}
	opts.AuthnContext = strings.Fields(q.Get("acr_values"))

	l := &login{
		kind:        "authorize",
		client:      client,
		redirectURI: redirect,
		state:       q.Get("state"),
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		scopes:      scopes,
		options:     opts,
	}
	s.startLogin(w, r, l)
}

// redirectAllowed compares a redirect URI with the registered ones: exactly
// (RFC 9700 2.1), except that a loopback one may use any port, because a
// native application listens wherever the system lets it (RFC 8252 7.3).
func redirectAllowed(c *clientBlock, got string) bool {
	if got == "" {
		return false
	}
	if slices.Contains(c.RedirectURIs, got) {
		return true
	}
	g, err := url.Parse(got)
	if err != nil || g.Scheme != "http" || !loopbackHost(g.Hostname()) {
		return false
	}
	for _, r := range c.RedirectURIs {
		ru, err := url.Parse(r)
		if err != nil || ru.Scheme != "http" || !loopbackHost(ru.Hostname()) {
			continue
		}
		if ru.Hostname() == g.Hostname() && ru.Path == g.Path && ru.RawQuery == g.RawQuery && g.User == nil && g.Fragment == "" {
			return true
		}
	}
	return false
}

// redirectError sends an error to a redirect URI already checked, with the
// issuer (RFC 9207), so that a client talking to several providers can tell
// which one answered.
func (s *server) redirectError(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	u, _ := url.Parse(redirect)
	v := u.Query()
	v.Set("error", code)
	if desc != "" {
		v.Set("error_description", desc)
	}
	if state != "" {
		v.Set("state", state)
	}
	v.Set("iss", s.cfg.Issuer)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// startLogin remembers the login and sends the person to choose their IdP,
// or straight to it when there is only one.
func (s *server) startLogin(w http.ResponseWriter, r *http.Request, l *login) {
	id := token()
	if err := s.logins.put(id, l, s.now().Add(loginLifetime)); err != nil {
		s.page(w, http.StatusServiceUnavailable, "Too many logins are in progress; try again in a minute.")
		return
	}
	http.SetCookie(w, s.cookie(loginCookie, id, loginLifetime))
	if len(s.cfg.SAML.IdPs) == 1 {
		s.toIdP(w, r, id, l, s.cfg.SAML.IdPs[0])
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

// cookie is a login cookie. SameSite=None, because the IdP's response
// arrives as a cross-site POST, which a Lax cookie is not sent with; so it
// must also be Secure, which browsers require of SameSite=None. On a
// loopback http issuer -- a test -- it is Lax and not Secure.
func (s *server) cookie(name, value string, life time.Duration) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, MaxAge: int(life.Seconds())}
	if life < 0 {
		c.MaxAge = -1 // delete it now; 0 would make it a session cookie instead
	}
	if strings.HasPrefix(s.cfg.Issuer, "https://") {
		c.Secure = true
		c.SameSite = http.SameSiteNoneMode
	} else {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

// current is the login this browser has in progress.
func (s *server) current(r *http.Request) (string, *login, error) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		return "", nil, errors.New("this browser has no login in progress (was the cookie blocked?)")
	}
	l, ok := s.logins.get(c.Value)
	if !ok {
		return "", nil, errors.New("the login expired; start again from the application")
	}
	return c.Value, l, nil
}

// allowedIdP says whether people can log in through idp: the configuration
// lets them, and it is not disabled.
func (s *server) allowedIdP(entityID string) bool {
	return !s.disabled.idp(entityID, s.now()) && configuredIdP(s.cfg, entityID)
}

// configuredIdP says whether the configuration lists the IdP, or lists none.
func configuredIdP(cfg *config, entityID string) bool {
	return len(cfg.SAML.IdPs) == 0 || slices.Contains(cfg.SAML.IdPs, entityID)
}

// toIdP sends the person to their IdP with an AuthnRequest.
func (s *server) toIdP(w http.ResponseWriter, r *http.Request, id string, l *login, entityID string) {
	idp, ok := s.fed.IdP(entityID)
	if !ok || !s.allowedIdP(entityID) {
		s.page(w, http.StatusBadRequest, "That institution cannot be used to log in here.")
		return
	}
	// One login, one request: a second one would leave two responses
	// that could each answer it.
	already := false
	s.logins.update(id, func(p **login) {
		already = (*p).started
		(*p).started = true
	})
	if already {
		s.page(w, http.StatusBadRequest, "This login has already gone to an institution; start again from the application.")
		return
	}
	u, pending, err := s.sp.Request(idp, id, l.options)
	if err != nil {
		s.logf("saml request to %s: %v", entityID, err)
		s.page(w, http.StatusInternalServerError, "The request to your institution could not be made.")
		return
	}
	s.logins.update(id, func(p **login) { (*p).pending = pending })
	http.Redirect(w, r, u, http.StatusFound)
}

// disco is where a discovery service, or this provider's own list, sends
// the person back with the IdP they chose.
func (s *server) disco(w http.ResponseWriter, r *http.Request) {
	id, l, err := s.current(r)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	idp, err := saml.Chosen(r.URL.Query(), s.fed)
	if err != nil {
		s.page(w, http.StatusBadRequest, "No institution was chosen.")
		return
	}
	s.toIdP(w, r, id, l, idp.EntityID)
}
