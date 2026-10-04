// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-authn/saml"
)

// A login in progress lives in the browser, sealed, and not here.
//
// Held in memory, it was what an anonymous flood filled: every /authorize
// cost this provider an entry for a quarter of an hour, and with a ceiling
// the flood locked everybody out (measured: one IPv6 /64, 134 ms), without
// one it was memory without end. Sealed into the login cookie -- the way
// SATOSA, the SAML-OIDC proxy of the R&E federations, carries its state --
// a login costs this provider nothing until the IdP answers, survives a
// restart, and any instance can finish what another started.
//
// The seal is AES-256-GCM under a key derived from the subject salt, which
// is secret, never changes, and is already what a restart must keep: the
// browser can neither read the login nor change it. The cookie's name is
// the additional data, so a value cut from one cookie does not open as
// another.

// maxSealedLogin is the most a sealed login may take: a browser keeps
// 4096 bytes per cookie, name and attributes included (RFC 6265 6.1).
const maxSealedLogin = 3600

// errLoginTooLarge is an authorization request too big to carry.
var errLoginTooLarge = errors.New("the authorization request is too large to carry through the login")

// sealedLogin is a login as it travels.
type sealedLogin struct {
	ID          string       `json:"i"` // the handle RelayState carries
	Expires     int64        `json:"x"`
	Kind        string       `json:"k"`
	DeviceCode  string       `json:"d,omitempty"`
	Client      string       `json:"c"`
	RedirectURI string       `json:"r,omitempty"`
	State       string       `json:"s,omitempty"`
	Nonce       string       `json:"n,omitempty"`
	Challenge   string       `json:"h,omitempty"`
	Scopes      []string     `json:"o,omitempty"`
	Options     saml.Options `json:"p"`
	Pending     saml.Pending `json:"q"`
	Started     bool         `json:"t,omitempty"`
	MaxAge      *int         `json:"m,omitempty"`
}

// loginAEAD is the cipher logins are sealed with.
func (s *server) loginAEAD() (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, s.cfg.salt, nil, "go-authn bridge login cookie v1", 32)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// sealLogin is l as the cookie carries it.
func (s *server) sealLogin(id string, l *login, expires time.Time) (string, error) {
	plain, err := json.Marshal(sealedLogin{
		ID: id, Expires: expires.Unix(), Kind: l.kind, DeviceCode: l.deviceCode,
		Client: l.client.ID, RedirectURI: l.redirectURI, State: l.state, Nonce: l.nonce,
		Challenge: l.challenge, Scopes: l.scopes, Options: l.options, Pending: l.pending,
		Started: l.started, MaxAge: maxAgePtr(l.maxAge),
	})
	if err != nil {
		return "", err
	}
	aead, err := s.loginAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	v := base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(loginCookie)))
	if len(v) > maxSealedLogin {
		return "", errLoginTooLarge
	}
	return v, nil
}

// openLogin is the login a cookie carries, if this provider sealed it,
// it has not expired, and its client still exists.
func (s *server) openLogin(v string) (string, *login, time.Time, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return "", nil, time.Time{}, errBadLogin
	}
	aead, err := s.loginAEAD()
	if err != nil {
		return "", nil, time.Time{}, err
	}
	if len(raw) < aead.NonceSize() {
		return "", nil, time.Time{}, errBadLogin
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(loginCookie))
	if err != nil {
		return "", nil, time.Time{}, errBadLogin
	}
	var sl sealedLogin
	if err := json.Unmarshal(plain, &sl); err != nil {
		return "", nil, time.Time{}, errBadLogin
	}
	expires := time.Unix(sl.Expires, 0)
	if !s.now().Before(expires) {
		return "", nil, time.Time{}, errLoginExpired
	}
	client, ok := s.cfg.client(sl.Client)
	if !ok {
		return "", nil, time.Time{}, errLoginExpired
	}
	// What the configuration allowed when the login started must still be
	// allowed when it ends -- a quarter of an hour later, or after a restart.
	if sl.RedirectURI != "" && !redirectAllowed(client, sl.RedirectURI) {
		return "", nil, time.Time{}, errLoginExpired
	}
	return sl.ID, &login{
		kind: sl.Kind, deviceCode: sl.DeviceCode, client: client, redirectURI: sl.RedirectURI,
		state: sl.State, nonce: sl.Nonce, challenge: sl.Challenge, scopes: sl.Scopes,
		options: sl.Options, pending: sl.Pending, started: sl.Started,
		maxAge: maxAgeOf(sl.MaxAge),
	}, expires, nil
}

var (
	errBadLogin     = errors.New("this browser's login could not be read; start again from the application")
	errLoginExpired = errors.New("the login expired; start again from the application")
	errLoginUsed    = errors.New("this login has already been answered; start again from the application")
)

// loginWindow estimates the logins in progress, which this provider no
// longer holds: started minus answered over the last loginLifetime, by the
// minute. An estimate -- a login abandoned at its IdP is counted until it
// would have expired, as it was when it was held.
type loginWindow struct {
	mu      sync.Mutex
	minutes [16]struct {
		at                int64 // unix minute
		started, answered int64
	}
}

func (lw *loginWindow) add(now time.Time, started, answered int64) {
	m := now.Unix() / 60
	lw.mu.Lock()
	defer lw.mu.Unlock()
	b := &lw.minutes[m%int64(len(lw.minutes))]
	if b.at != m {
		b.at, b.started, b.answered = m, 0, 0
	}
	b.started += started
	b.answered += answered
}

func (lw *loginWindow) inProgress(now time.Time) int64 {
	m := now.Unix() / 60
	span := int64(loginLifetime / time.Minute)
	lw.mu.Lock()
	defer lw.mu.Unlock()
	var n int64
	for _, b := range lw.minutes {
		if b.at > m-span && b.at <= m {
			n += b.started - b.answered
		}
	}
	return max(n, 0)
}

// maxAgePtr and maxAgeOf carry max_age through the cookie: absent is -1,
// which a zero value could not say (0 is a meaning of its own).
func maxAgePtr(n int) *int {
	if n < 0 {
		return nil
	}
	return &n
}

func maxAgeOf(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
