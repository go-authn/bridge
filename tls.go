// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-authn/servercert"
)

// The public listener's certificate: from files, re-read when they change,
// or from an ACME CA -- go-authn/servercert's, shared with go-fileshare.
// What is here is the configuration's shape and what only this provider
// knows: the one host to certify is the issuer's.
//
// servercert, in short (its package documentation says more):
//
//   - Files are compared by content at most every 10 seconds during a
//     handshake; a changed pair that does not load keeps the one that did.
//   - ACME is x/crypto's autocert: Let's Encrypt by default (tls-alpn-01, or
//     http-01 on http_listen), or GÉANT TCS / HARICA with External Account
//     Binding, where an Enterprise account's domains are validated beforehand
//     and no challenge is asked.
//   - It works around golang/go#77704: x/crypto v0.57.0 polls a finalized
//     order at the finalize response's Location header, which RFC 8555 does
//     not require, and never fetched the certificate from CAs that omit it.
//
// ⛔ The SAML key (saml { key_file cert_file }) is NOT this certificate and
// never changes with it: it is published in the federation's metadata, and
// the IdPs encrypt to it. A web certificate renewed every 90 days would
// break every institution's login at every renewal.

// acmeBlock gets the public listener's certificate from an ACME CA.
type acmeBlock struct {
	// DirectoryURL is the CA's ACME directory: Let's Encrypt's by default;
	// for GÉANT TCS, the HARICA directory of the institution's ACME account.
	DirectoryURL string `hcl:"directory_url,optional"`

	// AcceptTermsOfService is the operator agreeing to the CA's terms, which
	// every CA asks for. Nobody else can agree on their behalf, so it is not
	// a default.
	AcceptTermsOfService bool `hcl:"accept_terms_of_service"`

	// Email is the account's contact: where the CA writes about expiry and
	// revocation. HARICA requires one.
	Email string `hcl:"email,optional"`

	// EABKeyID and EABHMACKeyFile are the External Account Binding a CA
	// such as HARICA hands out (RFC 8555 7.3.4); the file holds the MAC key,
	// base64url as CAs print it.
	EABKeyID       string `hcl:"eab_key_id,optional"`
	EABHMACKeyFile string `hcl:"eab_hmac_key_file,optional"`

	// CacheDir keeps the account key and the certificates, mode 0700.
	// Required: a certificate asked for again at every restart meets the
	// CA's rate limits within a day of restarts.
	CacheDir string `hcl:"cache_dir"`

	// HTTPListen, when set, answers http-01 challenges there (":80") and
	// redirects everything else to https.
	HTTPListen string `hcl:"http_listen,optional"`

	// DirectoryCAFile is a CA to trust for the directory's own TLS, for a
	// private ACME CA such as step-ca. The system's roots otherwise.
	DirectoryCAFile string `hcl:"directory_ca_file,optional"`

	host string
}

// check reads what acme needs that servercert does not check, without
// touching the network. issuer names the one host a certificate is asked
// for.
func (b *acmeBlock) check(issuer string) error {
	if !b.AcceptTermsOfService {
		return errors.New("accept_terms_of_service: the CA's terms must be accepted, by whoever runs this, in the configuration")
	}
	if b.CacheDir == "" {
		return errors.New("cache_dir is required: without it every restart asks the CA again, and meets its rate limits")
	}
	if b.HTTPListen != "" {
		if _, _, err := net.SplitHostPort(b.HTTPListen); err != nil {
			return fmt.Errorf("http_listen = %q: host:port", b.HTTPListen)
		}
	}
	if b.DirectoryCAFile != "" {
		if _, err := certPool(b.DirectoryCAFile); err != nil {
			return fmt.Errorf("directory_ca_file: %w", err)
		}
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("issuer %q: a certificate from a CA is for an https issuer", issuer)
	}
	b.host = u.Hostname()
	return nil
}

func certPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate in it")
	}
	return pool, nil
}

// absolute is p made absolute against the working directory, as the
// provider has always read it: servercert takes absolute paths only.
func absolute(p string) string {
	if p == "" {
		return ""
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// certConfig is the servercert configuration for c, or false when the
// public listener serves no TLS.
func (c *config) certConfig(logf func(string, ...any)) (servercert.Config, bool) {
	onError := func(err error) { logf("tls: %v", err) }
	switch {
	case c.ACME != nil:
		b := c.ACME
		a := &servercert.ACME{
			DirectoryURL:   b.DirectoryURL,
			Email:          b.Email,
			Domains:        []string{b.host},
			CacheDir:       absolute(b.CacheDir),
			EABKeyID:       b.EABKeyID,
			EABHMACKeyFile: absolute(b.EABHMACKeyFile),
			HTTPChallenge:  b.HTTPListen != "",
		}
		if b.DirectoryCAFile != "" {
			if pool, err := certPool(b.DirectoryCAFile); err == nil {
				a.HTTPClient = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
			}
		}
		return servercert.Config{ACME: a, OnError: onError}, true
	case c.CertFile != "":
		return servercert.Config{CertFile: absolute(c.CertFile), KeyFile: absolute(c.KeyFile), OnError: onError}, true
	}
	return servercert.Config{}, false
}

// publicTLS is the public listener's TLS: nil for none (a reverse proxy in
// front), and a function to run the http-01 listener when there is one. It
// opens that listener now, before anything is served.
//
// net/http's ServeTLS appends "http/1.1" and "h2" to the NextProtos
// servercert gives ("acme-tls/1" with ACME), which a Go server needs: one
// that advertises protocols refuses a client that shares none of them.
func (s *server) publicTLS() (*tls.Config, func(context.Context) error, error) {
	sc, ok := s.cfg.certConfig(s.logf)
	if !ok {
		return nil, nil, nil
	}
	src, err := servercert.New(sc)
	if err != nil {
		return nil, nil, err
	}
	var run func(context.Context) error
	if a := s.cfg.ACME; a != nil {
		s.logf("tls: certificates for %s from %s", a.host, orDefault(a.DirectoryURL, "Let's Encrypt"))
		if a.HTTPListen != "" {
			ln, err := net.Listen("tcp", a.HTTPListen)
			if err != nil {
				return nil, nil, fmt.Errorf("acme: http_listen: %w", err)
			}
			run = func(ctx context.Context) error {
				return serveHTTP(ctx, ln, src.HTTPHandler(nil), s.logf, "acme http-01")
			}
		}
	}
	return src.TLSConfig(), run, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// serveHTTP serves h on ln until ctx ends.
func serveHTTP(ctx context.Context, ln net.Listener, h http.Handler, logf func(string, ...any), what string) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	logf("%s on %s", what, ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
