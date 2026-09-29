// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// The public listener's certificate: from files, re-read when they change,
// or from an ACME CA.
//
// Files are what certbot, a Kubernetes secret or an institution's own
// tooling writes. They used to be read once, at start, so a renewed
// certificate went unused until somebody restarted the provider -- and the
// one being served expired in the meantime. They are looked at again at
// most every certCheckEvery, and a pair that does not load (certbot
// replaces the certificate before the key) keeps the one that did.
//
// ACME is golang.org/x/crypto/acme/autocert. What it had to do here, read
// in its source (x/crypto v0.57.0, autocert.go verifyRFC):
//
//   - Let's Encrypt: tls-alpn-01 on the public listener itself, or http-01
//     when http_listen is given (port 80, which also redirects to https).
//   - GÉANT TCS, which French institutions get through RENATER and which
//     HARICA issues since 2025: an ACME directory per account and External
//     Account Binding (RFC 8555 7.3.4). With an Enterprise Admin account
//     the domains are validated in HARICA's portal beforehand, so the order
//     comes back "ready" and autocert asks for no challenge at all: no
//     inbound connection is needed, which suits a provider behind a
//     firewall.
//
// ⛔ The SAML key (saml { key_file cert_file }) is NOT this certificate and
// never changes with it: it is published in the federation's metadata, and
// the IdPs encrypt to it. A web certificate renewed every 90 days would
// break every institution's login at every renewal.

// certCheckEvery is how often certificate files are looked at again.
const certCheckEvery = time.Minute

// fileCert serves cert_file and key_file, re-read when they change.
type fileCert struct {
	certFile, keyFile string
	logf              func(string, ...any)
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]time.Time // the files' modification times when cert was read
	checked time.Time
}

func newFileCert(certFile, keyFile string, logf func(string, ...any)) (*fileCert, error) {
	f := &fileCert{certFile: certFile, keyFile: keyFile, logf: logf, now: time.Now}
	// The first load has to work: a provider that starts with no
	// certificate answers nobody.
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fileCert) stamps() ([2]time.Time, error) {
	var s [2]time.Time
	for i, p := range []string{f.certFile, f.keyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			return s, err
		}
		s[i] = fi.ModTime()
	}
	return s, nil
}

// load reads the pair, and changes nothing unless it loads; f.mu is held,
// or f is not shared yet.
func (f *fileCert) load() error {
	s, err := f.stamps()
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return err
	}
	f.cert, f.stamp, f.checked = &c, s, f.now()
	return nil
}

// get is tls.Config.GetCertificate.
func (f *fileCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.now().Sub(f.checked) < certCheckEvery {
		return f.cert, nil
	}
	f.checked = f.now()
	s, err := f.stamps()
	if err != nil || s == f.stamp {
		return f.cert, nil
	}
	if err := f.load(); err != nil {
		// Half-written, or the key not yet replaced: load changed nothing,
		// so the pair that loaded is still served; look again later.
		f.logf("tls: %s: %v; still serving the certificate read before", f.certFile, err)
		return f.cert, nil
	}
	f.logf("tls: %s changed; serving it%s", f.certFile, notAfter(f.cert))
	return f.cert, nil
}

func notAfter(c *tls.Certificate) string {
	if c == nil || len(c.Certificate) == 0 {
		return ""
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return ""
	}
	return ", valid until " + x.NotAfter.UTC().Format(time.RFC3339)
}

// acmeBlock gets the public listener's certificate from an ACME CA.
type acmeBlock struct {
	// DirectoryURL is the CA's ACME directory: Let's Encrypt's by default;
	// for GÉANT TCS, the https://acme-v02.harica.gr/acme/<id>/directory of
	// the institution's ACME account.
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

	// CacheDir keeps the account key and the certificates. Required: a
	// certificate asked for again at every restart meets the CA's rate
	// limits within a day of restarts.
	CacheDir string `hcl:"cache_dir"`

	// HTTPListen, when set, answers http-01 challenges there (":80") and
	// redirects everything else to https.
	HTTPListen string `hcl:"http_listen,optional"`

	// DirectoryCAFile is a CA to trust for the directory's own TLS, for a
	// private ACME CA such as step-ca. The system's roots otherwise.
	DirectoryCAFile string `hcl:"directory_ca_file,optional"`

	// RenewBefore is how long before expiry to renew: 720h by default, as
	// autocert's.
	RenewBefore string `hcl:"renew_before,optional"`

	eab         *acme.ExternalAccountBinding
	renewBefore time.Duration
	host        string
}

// check reads what acme needs, without touching the network. issuer names
// the one host a certificate is asked for.
func (b *acmeBlock) check(issuer string) error {
	if !b.AcceptTermsOfService {
		return errors.New("accept_terms_of_service: the CA's terms must be accepted, by whoever runs this, in the configuration")
	}
	if b.DirectoryURL == "" {
		b.DirectoryURL = autocert.DefaultACMEDirectory
	}
	if u, err := url.Parse(b.DirectoryURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("directory_url = %q: an https URL", b.DirectoryURL)
	}
	if b.CacheDir == "" {
		return errors.New("cache_dir is required: without it every restart asks the CA again, and meets its rate limits")
	}
	if (b.EABKeyID == "") != (b.EABHMACKeyFile == "") {
		return errors.New("eab_key_id and eab_hmac_key_file go together")
	}
	if b.EABKeyID != "" {
		raw, err := os.ReadFile(b.EABHMACKeyFile)
		if err != nil {
			return err
		}
		key, err := decodeMACKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return fmt.Errorf("eab_hmac_key_file: %w", err)
		}
		b.eab = &acme.ExternalAccountBinding{KID: b.EABKeyID, Key: key}
	}
	if b.DirectoryCAFile != "" {
		if _, err := certPool(b.DirectoryCAFile); err != nil {
			return fmt.Errorf("directory_ca_file: %w", err)
		}
	}
	b.renewBefore = 720 * time.Hour
	if b.RenewBefore != "" {
		d, err := time.ParseDuration(b.RenewBefore)
		if err != nil || d <= 0 {
			return fmt.Errorf("renew_before = %q: a positive duration like \"720h\"", b.RenewBefore)
		}
		b.renewBefore = d
	}
	if b.HTTPListen != "" {
		if _, _, err := net.SplitHostPort(b.HTTPListen); err != nil {
			return fmt.Errorf("http_listen = %q: host:port", b.HTTPListen)
		}
	}
	// The certificate is for the issuer's host, and for nothing a client
	// could name in its ClientHello: autocert asks the CA for whatever
	// host it is told otherwise.
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("issuer %q: a certificate from a CA is for an https issuer", issuer)
	}
	b.host = u.Hostname()
	if net.ParseIP(b.host) != nil {
		return fmt.Errorf("issuer %q: a CA certifies a name, not an address", issuer)
	}
	return nil
}

// decodeMACKey reads an EAB MAC key as CAs print it: base64url, padded or
// not; standard base64 is accepted too, since some portals show that.
func decodeMACKey(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) > 0 {
			return k, nil
		}
	}
	return nil, errors.New("not base64url")
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

// manager is autocert's Manager for b.
func (b *acmeBlock) manager(logf func(string, ...any)) (*autocert.Manager, error) {
	if err := os.MkdirAll(b.CacheDir, 0o700); err != nil {
		return nil, err
	}
	var transport http.RoundTripper = http.DefaultTransport
	if b.DirectoryCAFile != "" {
		pool, err := certPool(b.DirectoryCAFile)
		if err != nil {
			return nil, err
		}
		transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	client := &acme.Client{
		DirectoryURL: b.DirectoryURL,
		UserAgent:    "go-authn-bridge/" + version(),
		HTTPClient:   &http.Client{Timeout: time.Minute, Transport: &orderLocation{next: transport}},
	}
	return &autocert.Manager{
		Prompt:                 autocert.AcceptTOS,
		Cache:                  autocert.DirCache(b.CacheDir),
		HostPolicy:             autocert.HostWhitelist(b.host),
		Client:                 client,
		Email:                  b.Email,
		ExternalAccountBinding: b.eab,
		RenewBefore:            b.renewBefore,
	}, nil
}

// publicTLS is the public listener's TLS: nil for none (a reverse proxy in
// front), and a function to run the http-01 listener when there is one. It
// opens that listener now, before anything is served.
func (s *server) publicTLS() (*tls.Config, func(context.Context) error, error) {
	switch {
	case s.cfg.ACME != nil:
		m, err := s.cfg.ACME.manager(s.logf)
		if err != nil {
			return nil, nil, fmt.Errorf("acme: %w", err)
		}
		tc := m.TLSConfig() // h2, http/1.1 and acme-tls/1, for tls-alpn-01
		tc.MinVersion = tls.VersionTLS12
		var run func(context.Context) error
		if l := s.cfg.ACME.HTTPListen; l != "" {
			ln, err := net.Listen("tcp", l)
			if err != nil {
				return nil, nil, fmt.Errorf("acme: http_listen: %w", err)
			}
			run = func(ctx context.Context) error {
				return serveHTTP(ctx, ln, m.HTTPHandler(nil), s.logf, "acme http-01")
			}
		}
		s.logf("tls: certificates for %s from %s", s.cfg.ACME.host, s.cfg.ACME.DirectoryURL)
		return tc, run, nil
	case s.cfg.CertFile != "":
		fc, err := newFileCert(s.cfg.CertFile, s.cfg.KeyFile, s.logf)
		if err != nil {
			return nil, nil, err
		}
		return &tls.Config{GetCertificate: fc.get, MinVersion: tls.VersionTLS12}, nil, nil
	}
	return nil, nil, nil
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

// orderLocation is under autocert's ACME client, for one defect of
// x/crypto's (v0.57.0, golang/go#77704): after finalizing an order that the
// CA is still processing, CreateOrderCert polls the URL in the finalize
// response's Location header. RFC 8555 7.4 puts no Location there, and
// Pebble and Buypass send none -- so the poll goes to "" and the
// certificate is never fetched. Let's Encrypt sends one, which is why this
// goes unnoticed; whether HARICA does is not known here.
//
// The order's URL is known before that: it is the Location of the
// new-order response (RFC 8555 7.4, which does require it), or the URL an
// order was fetched from. This remembers it by the order's finalize URL and
// supplies it when a finalize response lacks it. It changes nothing a CA
// that sends the header sees.
type orderLocation struct {
	next http.RoundTripper

	mu     sync.Mutex
	orders map[string]string // finalize URL -> order URL
}

func (o *orderLocation) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := o.next.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || res.StatusCode/100 != 2 ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	var order struct {
		Finalize string `json:"finalize"`
	}
	if json.Unmarshal(body, &order) != nil || order.Finalize == "" {
		return res, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.orders == nil {
		o.orders = map[string]string{}
	}
	here := req.URL.String()
	switch loc := res.Header.Get("Location"); {
	case loc != "":
		o.orders[order.Finalize] = loc // new-order, or a CA that sends it
	case here == order.Finalize:
		if u, ok := o.orders[here]; ok {
			res.Header.Set("Location", u) // the finalize response
		}
	default:
		o.orders[order.Finalize] = here // an order fetched from its URL
	}
	return res, nil
}
