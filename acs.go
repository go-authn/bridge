// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-authn/saml"
)

// acs is where the IdP POSTs its response.
func (s *server) acs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, "The response could not be read.")
		return
	}
	id, l, err := s.current(r)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	// ⛔ The response is for THIS browser's login: the handle the IdP
	// carried back must be the one in the cookie. See loginCookie.
	if r.PostForm.Get("RelayState") != id {
		s.logf("acs: a response for another login arrived in this browser")
		s.page(w, http.StatusBadRequest, "This response belongs to another login.")
		return
	}
	s.logins.add(s.now(), 0, 1)
	// The cookie goes whatever happens next. The login is spent once an IdP
	// has answered for it (below): only then, so that nobody anonymous can
	// fill usedLogins -- a sealed login is free to obtain, a signed response
	// is not.
	http.SetCookie(w, s.cookie(loginCookie, "", -1))
	if !l.started {
		s.page(w, http.StatusBadRequest, "This login never went to an institution.")
		return
	}

	// And the IdP is still one people may log in through: saml { idps } may
	// have changed since the login started, or the IdP been disabled.
	if !s.allowedIdP(l.pending.IdP) {
		s.page(w, http.StatusBadRequest, "That institution can no longer be used to log in here.")
		return
	}
	a, err := s.sp.Accept(r.PostForm.Get("SAMLResponse"), l.pending)
	if err != nil {
		var se *saml.StatusError
		if errors.As(err, &se) {
			s.logf("acs: %s said no: %v", l.pending.IdP, err)
			s.counters.inc("bridge_logins_total", "declined")
			code := "access_denied"
			if se.NoPassive() {
				// OIDC Core 3.1.2.6: prompt=none and a login was needed.
				code = "login_required"
			}
			s.finishError(w, r, l, code, "the institution did not authenticate you")
			return
		}
		s.logf("acs: a response from %s was refused: %v", l.pending.IdP, err)
		s.counters.inc("bridge_logins_total", "refused")
		s.page(w, http.StatusBadRequest, "Your institution's answer could not be accepted.")
		return
	}
	if err := s.usedLogins.putNew(id, true, l.expires); err != nil {
		s.logf("acs: a second response for a login already answered")
		s.page(w, http.StatusBadRequest, "This login has already been answered; start again from the application.")
		return
	}
	if l.maxAge > 0 && !l.options.ForceAuthn && s.now().Sub(a.AuthnInstant) > time.Duration(l.maxAge)*time.Second {
		s.reauthenticate(w, r, l, a.IdP.EntityID, s.now().Sub(a.AuthnInstant))
		return
	}
	who, err := newPerson(a, s.cfg.Claims)
	if err != nil {
		s.logf("acs: %s: %v", a.IdP.EntityID, err)
		s.counters.inc("bridge_logins_total", "no_identifier")
		s.finishError(w, r, l, "access_denied", "your institution did not say who you are")
		return
	}
	if why := s.refused(who); why != "" {
		s.logf("acs: %s via %s refused: %s", orUnnamed(who.username), who.idp, why)
		s.counters.inc("bridge_logins_total", "disabled")
		s.finishError(w, r, l, "access_denied", "your access to this service has been disabled")
		return
	}
	s.logf("login: %s via %s for %s", orUnnamed(who.username), who.idp, l.client.ID)
	s.counters.inc("bridge_logins_total", "ok")
	if l.kind == "device" {
		s.deviceDone(w, l, who, "")
		return
	}

	code := token()
	s.codes.put(code, &grant{
		client:      l.client,
		redirectURI: l.redirectURI,
		challenge:   l.challenge,
		nonce:       l.nonce,
		scopes:      l.scopes,
		who:         who,
	}, s.now().Add(s.cfg.codeTTL))
	u, _ := url.Parse(l.redirectURI)
	v := u.Query()
	v.Set("code", code)
	if l.state != "" {
		v.Set("state", l.state)
	}
	v.Set("iss", s.cfg.Issuer)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// finishError ends a login by telling the client why -- through its redirect
// URI, or, for a device, on the page the person is looking at (the device
// learns access_denied when it next polls).
func (s *server) finishError(w http.ResponseWriter, r *http.Request, l *login, code, desc string) {
	if l.kind == "device" {
		s.deviceDone(w, l, nil, "Refusé : "+desc+".")
		return
	}
	s.redirectError(w, r, l.redirectURI, l.state, code, desc)
}

func orUnnamed(s string) string {
	if s == "" {
		return "(no username)"
	}
	return s
}

// reauthenticate sends the person back to the IdP that just answered, with
// ForceAuthn, because its authentication is older than the client's
// max_age: OIDC Core 3.1.2.1 has the provider "actively re-authenticate"
// then, and only then. A new login, under a new handle: the one answered is
// spent.
func (s *server) reauthenticate(w http.ResponseWriter, r *http.Request, l *login, entityID string, age time.Duration) {
	s.logf("acs: %s authenticated the person %s ago, past max_age=%ds: asking again, with ForceAuthn", entityID, age.Round(time.Second), l.maxAge)
	l.options.ForceAuthn = true
	l.started = false
	l.expires = s.now().Add(loginLifetime)
	s.logins.add(s.now(), 1, 0)
	s.toIdP(w, r, token(), l, entityID)
}
