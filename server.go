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

	// logins in progress, keyed by the handle the browser carries in a
	// cookie and the IdP carries in RelayState.
	logins *ttl[*login]
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
}

// An issuedToken is an access token this provider still honours: what
// /userinfo answers with, and whose it is, so that one person's tokens can
// be found and ended.
type issuedToken struct {
	info     map[string]any
	username string
	idp      string
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
	s.logins = newTTL[*login](now)
	s.codes = newTTL[*grant](now)
	s.spent = newTTL[[]string](now)
	s.issued = newTTL[issuedToken](now)
	s.devices = newTTL[*deviceGrant](now)
	s.poll = deviceInterval * time.Second
	s.userCodes = newTTL[string](now)
	s.tries = &attempts{m: map[string][]time.Time{}, now: now}
	s.refresh = newTTL[*refreshGrant](now)
	s.rotated = newTTL[string](now)
	s.families = newTTL[[]string](now)
	s.ssfStreams = newTTL[storedStream](now)
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

func (s *server) logf(format string, a ...any) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Fprintf(s.log, format+"\n", a...)
}

// handler is every endpoint.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("/userinfo", s.userinfo)
	mux.HandleFunc("GET /saml/metadata", s.samlMetadata)
	mux.HandleFunc("GET /saml/choose", s.choose)
	mux.HandleFunc("GET /saml/disco", s.disco)
	mux.HandleFunc("POST /saml/acs", s.acs)
	mux.HandleFunc("POST /device_authorization", s.deviceAuthorization)
	mux.HandleFunc("/device", s.device)
	mux.HandleFunc("POST /ssh/certificate", s.sshCertificate)
	mux.HandleFunc("GET /ssh/krl", s.sshKRL)
	s.ssfHandlers(mux)
	mux.HandleFunc("POST /x509/cert", s.x509Certificate)
	mux.HandleFunc("GET /x509/crl", s.x509CRL)
	mux.HandleFunc("/app-password", s.appPassword)
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
