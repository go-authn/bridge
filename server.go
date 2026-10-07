// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/saml"
)

// server is the provider: the OpenID Connect side that relying parties
// talk to, and the SAML side that people log in through.
type server struct {
	cfg *config
	// disabled is who this provider refuses (disable.go).
	disabled *disabledList
	// certs is every certificate issued, and the revoked (certstore.go).
	certs *certStore
	// limiter is what an address may start a minute (limits.go).
	limiter *rateLimiter
	// state writes the long-lived stores through to a database (state.go).
	state *persister
	// ssfStreams and ssfEvents are the SSF transmitter's streams and its
	// undelivered events, by stream/jti (ssf.go).
	ssfStreams *ttl[storedStream]
	ssfEvents  *ttl[string]
	sp         *saml.SP
	fed        *saml.Federation
	log        io.Writer
	now        func() time.Time

	// usedLogins are the handles of logins an IdP has answered for: a login
	// lives in its cookie (loginseal.go), and this is what makes it single-use.
	// Written only after a signed response is accepted, so not by anybody
	// anonymous.
	usedLogins *ttl[bool]
	// assertions are the IDs of the SAML assertions accepted, until they
	// expire: go-authn/saml's replay cache, kept in the state database when
	// there is one, so that a restart or another instance does not accept the
	// same assertion again (saml-profiles 4.1.4.5).
	assertions *ttl[bool]
	logins     loginWindow
	// codes not yet exchanged.
	codes *ttl[*grant]
	// spent codes, remembered as long as the tokens they bought live, so
	// that a code used twice can take those tokens back (RFC 6749 4.1.2).
	spent *ttl[[]string]
	// issued access tokens, by jti: what /userinfo answers with, and what
	// revocation removes.
	issued *ttl[issuedToken]

	// devices waiting for their person, by device code; and the user codes
	// people type, pointing at them.
	devices *ttl[*deviceGrant]
	// poll is the interval devices are told to poll at (RFC 8628 3.2).
	poll      time.Duration
	userCodes *ttl[string]
	tries     *attempts

	// refresh tokens, by token; and the ones already rotated away, by
	// token, pointing at their family -- see rotate.
	refresh  *ttl[*refreshGrant]
	rotated  *ttl[string]
	families *ttl[[]string]

	logMu sync.Mutex

	fedState fedState
	counters counters
	started  time.Time
	// revLists is the revocation lists as last issued (revlists.go).
	revLists listCache
}

// A login is somebody on their way to their IdP and back.
type login struct {
	kind string // "authorize" or "device"

	// deviceCode is the device waiting for this login, for kind "device".
	deviceCode string

	// The authorization request, checked.
	client      *clientBlock
	redirectURI string
	state       string
	nonce       string
	challenge   string
	scopes      []string
	options     saml.Options

	pending saml.Pending
	started bool
	// maxAge is the request's max_age in seconds, -1 when none (authorize.go).
	maxAge int
	// expires is when the login, sealed in its cookie, stops opening.
	expires time.Time
}

// An issuedToken is an access token this provider still honours: what
// /userinfo answers with, and whose it is, so that one person's tokens can
// be found and ended.
type issuedToken struct {
	info     map[string]any
	username string
	idp      string
	// subject is the person's stable identity (person.subject), by which
	// disabling finds them when the username will not do.
	subject string
}

// A grant is what a code stands for.
type grant struct {
	client      *clientBlock
	redirectURI string
	challenge   string
	nonce       string
	scopes      []string
	who         *person
}

func newServer(cfg *config, log io.Writer) (*server, error) {
	key, cert, err := loadSPKey(cfg.SAML.KeyFile, cfg.SAML.CertFile)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	s := &server{cfg: cfg, log: log, now: time.Now, started: time.Now()}
	s.fed = &saml.Federation{URL: cfg.SAML.MetadataURL, Cert: cfg.metaCert, Now: func() time.Time { return s.now() }}
	s.sp = &saml.SP{
		EntityID:   cfg.SAML.EntityID,
		ACS:        cfg.Issuer + "/saml/acs",
		Key:        key,
		Cert:       cert,
		Federation: s.fed,
		Now:        func() time.Time { return s.now() },
	}
	now := func() time.Time { return s.now() }
	// What anonymous requests fill is capped (store.go).
	s.usedLogins = newTTL[bool](now).capped(maxPending).evicting()
	s.assertions = newTTL[bool](now)
	s.sp.Replay = ttlReplay{s.assertions}
	s.limiter = newRateLimiter(*cfg.RequestsPerMinute, now)
	s.codes = newTTL[*grant](now)
	s.spent = newTTL[[]string](now)
	s.issued = newTTL[issuedToken](now)
	s.devices = newTTL[*deviceGrant](now).capped(maxPending).evicting()
	s.poll = deviceInterval * time.Second
	s.userCodes = newTTL[string](now).capped(maxPending).evicting()
	s.tries = &attempts{m: map[string][]time.Time{}, now: now}
	s.refresh = newTTL[*refreshGrant](now)
	s.rotated = newTTL[string](now)
	s.families = newTTL[[]string](now)
	s.ssfStreams = newTTL[storedStream](now).capped(1000)
	s.ssfEvents = newTTL[string](now)
	if s.disabled, err = loadDisabled(cfg.DisabledFile); err != nil {
		return nil, fmt.Errorf("disabled_file: %w", err)
	}
	if s.certs, err = loadCertStore(cfg.CertificatesFile); err != nil {
		return nil, fmt.Errorf("certificates_file: %w", err)
	}
	if err := s.persistStores(); err != nil {
		return nil, err
	}
	return s, nil
}

// logf writes one line. ⛔ One: what an IdP or a client sent can be in it
// -- a StatusMessage, an error naming an attribute -- and a newline there
// forged whole log lines ("login: alice@... for web") for anybody who could
// post to the ACS. Control characters are escaped.
func (s *server) logf(format string, a ...any) {
	line := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return '\uFFFD'
		}
		return r
	}, fmt.Sprintf(format, a...))
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Fprintln(s.log, line)
}

// handler is every endpoint.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("/authorize", s.limited(s.authorize))
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("/userinfo", s.userinfo)
	mux.HandleFunc("GET /saml/metadata", s.samlMetadata)
	mux.HandleFunc("GET /saml/choose", s.choose)
	mux.HandleFunc("GET /saml/disco", s.disco)
	mux.HandleFunc("POST /saml/acs", s.limited(s.acs))
	mux.HandleFunc("POST /device_authorization", s.limited(s.deviceAuthorization))
	mux.HandleFunc("/device", s.device)
	mux.HandleFunc("POST /ssh/certificate", s.sshCertificate)
	mux.HandleFunc("GET /ssh/krl", s.sshKRL)
	mux.HandleFunc("GET /ssh/krl.sig", s.sshKRLSig)
	mux.HandleFunc("GET /ssh/config", s.sshConfig)
	s.ssfHandlers(mux)
	mux.HandleFunc("POST /x509/cert", s.x509Certificate)
	mux.HandleFunc("GET /x509/crl", s.x509CRL)
	mux.HandleFunc("/app-password", s.appPassword)
	mux.HandleFunc("/wireguard/key", s.limited(s.wireguardKey))
	mux.HandleFunc("GET /wireguard/peers", s.wireguardPeers)
	return mux
}

// loadSPKey reads the SP's RSA key and certificate.
func loadSPKey(keyFile, certFile string) (*rsa.PrivateKey, *x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	k, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("the SP key must be RSA: IdPs encrypt to it with RSA-OAEP")
	}
	b, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return k, c, nil
}

// httpServer is the public listener's server: every request bounded in size
// and in time (main.go says why).
func (s *server) httpServer(tc *tls.Config) *http.Server {
	return &http.Server{
		Handler:           http.MaxBytesHandler(s.handler(), maxBody),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         tc,
	}
}

// maxBody is the largest request body: four times the SAML size limit.
const maxBody = 1 << 20
