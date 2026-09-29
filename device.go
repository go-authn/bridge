// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// The device authorization grant (RFC 8628): a client with no browser --
// rclone mounting go-fileshare over WebDAV, a script -- shows a short code,
// and the person logs in at their institution on any other device.

const (
	deviceLifetime = 10 * time.Minute
	deviceInterval = 5 // seconds; RFC 8628 3.2's default, said explicitly
	// userCodeAlphabet is RFC 8628 6.1's: no vowels (no words), no digits,
	// one case -- typed on a phone without changing keyboards.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// codeAttempts is how many wrong codes one address may type per
	// deviceLifetime. 20^8 codes and ten tries in ten minutes is a chance
	// of about 4e-10 of guessing one (RFC 8628 5.1).
	codeAttempts = 10
)

// A deviceGrant is a device waiting for its person.
type deviceGrant struct {
	client   *clientBlock
	scopes   []string
	userCode string
	// nonce comes back in the ID token, as in the code flow. OpenPubkey
	// puts its commitment to the user's key there (the SHA3-256 of the
	// client instance claims), and sends it on THIS request in the device
	// flow: a nonce dropped here is a PK Token that never verifies.
	nonce string

	who      *person // set when the person has logged in
	denied   bool
	lastPoll time.Time
	interval time.Duration
}

// deviceAuthorization is the device authorization endpoint (RFC 8628 3.1).
func (s *server) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "the request could not be read")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !client.Device {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "this client may not use the device grant")
		return
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	if slices.Contains(scopes, "ssh") && !client.SSHCertificates {
		tokenError(w, http.StatusBadRequest, "invalid_scope", "this client may not ask for SSH certificates")
		return
	}
	if slices.Contains(scopes, "app_password") && !client.AppPasswords {
		tokenError(w, http.StatusBadRequest, "invalid_scope", "this client may not set application passwords")
		return
	}
	dc, uc := token(), userCode()
	exp := s.now().Add(deviceLifetime)
	s.devices.put(dc, &deviceGrant{client: client, scopes: scopes, userCode: uc, nonce: r.PostForm.Get("nonce"), interval: s.poll}, exp)
	s.userCodes.put(uc, dc, exp)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               dc,
		"user_code":                 uc[:4] + "-" + uc[4:],
		"verification_uri":          s.cfg.Issuer + "/device",
		"verification_uri_complete": s.cfg.Issuer + "/device?user_code=" + uc[:4] + "-" + uc[4:],
		"expires_in":                int(deviceLifetime.Seconds()),
		"interval":                  int(s.poll.Seconds()),
	})
}

// userCode is eight letters from the RFC 8628 alphabet, without the dash.
func userCode() string {
	b := make([]byte, 8)
	n := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range b {
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic(err)
		}
		b[i] = userCodeAlphabet[k.Int64()]
	}
	return string(b)
}

// normalise reads a user code the way people type one: any case, with or
// without the dash, with spaces.
func normalise(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(userCodeAlphabet, r) {
			return r
		}
		return -1
	}, s)
}

// attempts counts wrong user codes per client address.
type attempts struct {
	mu  sync.Mutex
	m   map[string][]time.Time
	now func() time.Time
}

// allow says whether addr may try another code, and counts this one.
func (a *attempts) allow(addr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	var recent []time.Time
	for _, t := range a.m[addr] {
		if now.Sub(t) < deviceLifetime {
			recent = append(recent, t)
		}
	}
	if len(recent) >= codeAttempts {
		a.m[addr] = recent
		return false
	}
	a.m[addr] = append(recent, now)
	return true
}

func clientAddr(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// device is the page where the person types the code, then confirms which
// application they are letting in, then logs in.
//
// ⛔ The confirmation step is not decoration. RFC 8628 5.4: somebody can
// start a device grant themselves and send the victim the code with a
// plausible story; the victim logs in, and the ATTACKER's device gets the
// token. The page says which application is asking, and that the code should
// only be entered if the person started this on their own device.
func (s *server) device(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	uc := normalise(r.Form.Get("user_code"))
	if uc == "" {
		s.render(w, http.StatusOK, "device", map[string]any{})
		return
	}
	if !s.tries.allow(clientAddr(r)) {
		s.render(w, http.StatusTooManyRequests, "device", map[string]any{"Error": "Trop d'essais. Réessayez dans quelques minutes."})
		return
	}
	dc, ok := s.userCodes.get(uc)
	var g *deviceGrant
	if ok {
		g, ok = s.devices.get(dc)
	}
	if !ok {
		s.render(w, http.StatusBadRequest, "device", map[string]any{"Error": "Ce code n'est pas valide, ou a expiré.", "Code": r.Form.Get("user_code")})
		return
	}
	if r.Method == http.MethodGet || r.Form.Get("confirm") == "" {
		// Ask. The form carries a token tied to this browser's cookie, so
		// that another site cannot post the confirmation for them.
		csrf := token()
		http.SetCookie(w, s.cookie(deviceCookie, csrf, deviceLifetime))
		s.render(w, http.StatusOK, "confirm", map[string]any{"Client": g.client.Name, "Code": uc[:4] + "-" + uc[4:], "CSRF": csrf})
		return
	}
	c, err := r.Cookie(deviceCookie)
	if r.Method != http.MethodPost || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		s.page(w, http.StatusBadRequest, "The confirmation did not come from this page.")
		return
	}
	http.SetCookie(w, s.cookie(deviceCookie, "", -1))
	if r.PostForm.Get("confirm") != "yes" {
		s.devices.update(dc, func(p **deviceGrant) { (*p).denied = true })
		s.userCodes.take(uc)
		s.page(w, http.StatusOK, "Refusé. L'appareil n'aura pas accès.")
		return
	}
	// A code opens one login: once confirmed, it cannot be typed again.
	s.userCodes.take(uc)
	s.startLogin(w, r, &login{kind: "device", client: g.client, deviceCode: dc})
}

const deviceCookie = "bridge_device"

// deviceDone ends a device login at the ACS.
func (s *server) deviceDone(w http.ResponseWriter, l *login, who *person, failure string) {
	ok := s.devices.update(l.deviceCode, func(p **deviceGrant) {
		if failure != "" {
			(*p).denied = true
		} else {
			(*p).who = who
		}
	})
	switch {
	case !ok:
		s.page(w, http.StatusBadRequest, "The device stopped waiting; start again on the device.")
	case failure != "":
		s.page(w, http.StatusForbidden, failure)
	default:
		s.page(w, http.StatusOK, "C'est fait : vous pouvez revenir à votre appareil. / Done: you can go back to your device.")
	}
}

// pollDevice is the token request with grant_type device_code (RFC 8628
// 3.4, 3.5).
func (s *server) pollDevice(w http.ResponseWriter, r *http.Request, client *clientBlock) {
	dc := r.PostForm.Get("device_code")
	g, ok := s.devices.get(dc)
	if !ok {
		tokenError(w, http.StatusBadRequest, "expired_token", "")
		return
	}
	if g.client.ID != client.ID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the device code was issued to another client")
		return
	}
	now := s.now()
	// Everything about the grant is read under its lock: the person may be
	// finishing their login at this very moment.
	var tooSoon, denied bool
	var who *person
	var scopes []string
	var nonce string
	s.devices.update(dc, func(p **deviceGrant) {
		// RFC 8628 3.5: polling faster than the interval earns slow_down,
		// and the interval grows by five seconds for good.
		if !(*p).lastPoll.IsZero() && now.Sub((*p).lastPoll) < (*p).interval {
			tooSoon = true
			(*p).interval += 5 * time.Second
		}
		(*p).lastPoll = now
		denied, who, scopes, nonce = (*p).denied, (*p).who, (*p).scopes, (*p).nonce
	})
	switch {
	case denied:
		s.devices.take(dc)
		tokenError(w, http.StatusBadRequest, "access_denied", "")
	case tooSoon:
		tokenError(w, http.StatusBadRequest, "slow_down", "")
	case who == nil:
		tokenError(w, http.StatusBadRequest, "authorization_pending", "")
	default:
		// Once: the grant is taken, so a second poll with the same device
		// code is expired_token, not a second set of tokens.
		if _, still := s.devices.take(dc); !still {
			tokenError(w, http.StatusBadRequest, "expired_token", "")
			return
		}
		resp, jti, err := s.issue(client, who, scopes, nonce)
		if err != nil {
			s.logf("token: %v", err)
			tokenError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		s.counters.inc("bridge_tokens_issued_total", "device_code")
		if rt := s.newRefresh(client, who, scopes, jti); rt != "" {
			resp["refresh_token"] = rt
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
