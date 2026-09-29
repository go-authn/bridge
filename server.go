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
	sp  *saml.SP
	fed *saml.Federation
	log io.Writer
	now func() time.Time

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
	issued *ttl[map[string]any]

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
	s := &server{cfg: cfg, log: log, now: time.Now}
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
	s.issued = newTTL[map[string]any](now)
	s.devices = newTTL[*deviceGrant](now)
	s.poll = deviceInterval * time.Second
	s.userCodes = newTTL[string](now)
	s.tries = &attempts{m: map[string][]time.Time{}, now: now}
	s.refresh = newTTL[*refreshGrant](now)
	s.rotated = newTTL[string](now)
	s.families = newTTL[[]string](now)
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
