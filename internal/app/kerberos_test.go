// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// stubKDC stands in for go-authn/kdc's MintHandler: TLS with client
// certificates REQUIRED, and a record of who asked for what.
type stubKDC struct {
	srv    *httptest.Server
	mu     sync.Mutex
	asked  []map[string]any
	caller []string
	status int
	during func() // runs while a request is being answered
}

func (k *stubKDC) handle(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	k.mu.Lock()
	k.asked = append(k.asked, req)
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		k.caller = append(k.caller, u.String())
	}
	st, during := k.status, k.during
	k.mu.Unlock()
	if during != nil {
		during()
	}
	if st != 0 {
		http.Error(w, "no", st)
		return
	}
	// 0x76 is [APPLICATION 22], the first byte of a KRB-CRED.
	_, _ = w.Write(append([]byte{0x76, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{0xaa}, 80)...))
}

func newStubKDC(t *testing.T, dir string) (*stubKDC, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kdc test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	leaf := func(name string, usage x509.ExtKeyUsage, uri string) (certPEM, keyPEM []byte, c tls.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}}
		if uri != "" {
			u, _ := url.Parse(uri)
			tmpl.URIs = []*url.URL{u}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}),
			tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	_, _, serverCert := leaf("kdc", x509.ExtKeyUsageServerAuth, "")
	bridgeCert, bridgeKey, _ := leaf("bridge", x509.ExtKeyUsageClientAuth, "https://bridge.test")

	k := &stubKDC{}
	k.srv = httptest.NewUnstartedServer(http.HandlerFunc(k.handle))
	k.srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	k.srv.StartTLS()
	t.Cleanup(k.srv.Close)

	for name, data := range map[string][]byte{
		"kdc-ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"bridge.pem": bridgeCert,
		"bridge.key": bridgeKey,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The stub's certificate is for "localhost"; the URL must say so.
	return k, strings.Replace(k.srv.URL, "127.0.0.1", "localhost", 1)
}

func kerberosFixture(t *testing.T) (*fixture, *stubKDC) {
	t.Helper()
	dir := t.TempDir()
	k, kdcURL := newStubKDC(t, dir)
	f := newFixture(t, `
kerberos {
  kdc_url   = "`+kdcURL+`"
  ca_file   = "`+filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem"))+`"
  cert_file = "`+filepath.ToSlash(filepath.Join(dir, "bridge.pem"))+`"
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "bridge.key"))+`"
  validity  = "8h"
}
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
client "kinit" {
  device           = true
  kerberos_tickets = true
}
client "plain" {
  device = true
}
`)
	return f, k
}

func postTGT(t *testing.T, f *fixture, token string) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/kerberos/tgt", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, res.Header
}

// The person's passkey login is a token; the token buys a TGT, for the
// scoped name, no longer than asked, over the KDC's mutual TLS.
func TestKerberosTGT(t *testing.T) {
	f, k := kerberosFixture(t)
	tok := f.deviceTokenAs("kinit", alice, "openid", "kerberos")
	status, body, h := postTGT(t, f, tok.AccessToken)
	if status != http.StatusOK || len(body) == 0 || body[0] != 0x76 {
		t.Fatalf("%d %.40q", status, body)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("headers %v", h)
	}
	if len(k.asked) != 1 {
		t.Fatalf("the KDC was asked %d times", len(k.asked))
	}
	if p := k.asked[0]["principal"]; p != "alice@"+idpScope {
		t.Errorf("principal %v, want the token's scoped name", p)
	}
	if secs, _ := k.asked[0]["lifetime_seconds"].(float64); secs <= 0 || secs > 8*3600 {
		t.Errorf("lifetime %v s, want at most the configured 8h", secs)
	}
	if len(k.caller) != 1 || k.caller[0] != "https://bridge.test" {
		t.Errorf("the KDC saw %v", k.caller)
	}
}

// The case the whole feature is for: a person with a passkey and no password.
// Their preferred_username is the bare login (local accounts never carry an
// "@"), and the principal is the login at the local scope.
func TestKerberosTGTForAPasskeyOnlyAccount(t *testing.T) {
	dir := t.TempDir()
	k, kdcURL := newStubKDC(t, dir)
	f := localFixture(t, `
kerberos {
  kdc_url   = "`+kdcURL+`"
  ca_file   = "`+filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem"))+`"
  cert_file = "`+filepath.ToSlash(filepath.Join(dir, "bridge.pem"))+`"
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "bridge.key"))+`"
}
client "kinit" {
  redirect_uris    = ["http://127.0.0.1/callback"]
  kerberos_tickets = true
}
`)
	a := f.enrolled("alice", webauthn.AlgES256)
	r := newRP(t, f, "kinit", "", "http://127.0.0.1/callback", "kerberos")
	b := newBrowser(t)
	csrf := f.openLocal(b, r.authURL())
	back := location(t, f.passkeyLogin(b, a, "alice", csrf, webauthntest.Options{}))
	tok, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if at := jwtClaims(t, tok.AccessToken); at["preferred_username"] != "alice" {
		t.Fatalf("preferred_username %v: the premise of this test", at["preferred_username"])
	}
	status, body, _ := postTGT(t, f, tok.AccessToken)
	if status != http.StatusOK || len(body) == 0 || body[0] != 0x76 {
		t.Fatalf("%d %.40q", status, body)
	}
	if len(k.asked) != 1 || k.asked[0]["principal"] != "alice@"+localScope {
		t.Errorf("the KDC was asked %v, want alice@%s", k.asked, localScope)
	}
}

func TestKerberosPrincipal(t *testing.T) {
	f := localFixture(t, "")
	s := f.s
	local := s.cfg.localEntityID()
	for name, c := range map[string]struct {
		claims map[string]any
		want   string
	}{
		"a federated eppn":            {map[string]any{"preferred_username": "alice@univ.example", "idp": "https://idp.univ.example"}, "alice@univ.example"},
		"a local login, scoped":       {map[string]any{"preferred_username": "alice", "idp": local}, "alice@" + localScope},
		"a federated bare name":       {map[string]any{"preferred_username": "alice", "idp": "https://idp.univ.example"}, ""},
		"no idp, bare":                {map[string]any{"preferred_username": "alice"}, ""},
		"nobody":                      {map[string]any{"idp": local}, ""},
		"a trailing @":                {map[string]any{"preferred_username": "alice@", "idp": "x"}, ""},
		"a leading @":                 {map[string]any{"preferred_username": "@univ.example", "idp": "x"}, ""},
		"a local login that has an @": {map[string]any{"preferred_username": "alice@evil.example", "idp": local}, ""},
	} {
		if got := s.kerberosPrincipal(c.claims); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestKerberosTGTRefusals(t *testing.T) {
	f, k := kerberosFixture(t)

	// No token, a token without the scope.
	if s, _, _ := postTGT(t, f, ""); s != http.StatusUnauthorized {
		t.Errorf("no token: %d", s)
	}
	tok := f.deviceTokenAs("kinit", alice, "openid")
	if s, _, _ := postTGT(t, f, tok.AccessToken); s != http.StatusForbidden {
		t.Errorf("no kerberos scope: %d", s)
	}
	// A client that may not ask for the scope never gets a device code for it.
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	if _, err := (&oauth2.Config{ClientID: "plain", Endpoint: ep, Scopes: []string{"openid", "kerberos"}}).DeviceAuth(t.Context()); err == nil {
		t.Error("a client without kerberos_tickets got a device code for kerberos")
	}
	if len(k.asked) != 0 {
		t.Errorf("the KDC was asked %d times for requests that were refused here", len(k.asked))
	}

	tok = f.deviceTokenAs("kinit", alice, "openid", "kerberos")

	// The realm refuses: the person has no business with it.
	k.status = http.StatusForbidden
	if s, _, _ := postTGT(t, f, tok.AccessToken); s != http.StatusForbidden {
		t.Errorf("KDC 403: %d", s)
	}
	// The realm is down.
	k.status = http.StatusServiceUnavailable
	if s, _, _ := postTGT(t, f, tok.AccessToken); s != http.StatusBadGateway {
		t.Errorf("KDC 503: %d", s)
	}
	k.status = 0

	// Disabled while the KDC was answering: the ticket is dropped.
	k.during = func() {
		if _, _, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{}); err != nil {
			t.Error(err)
		}
	}
	s, body, _ := postTGT(t, f, tok.AccessToken)
	if s != http.StatusUnauthorized || len(body) > 0 && body[0] == 0x76 {
		t.Errorf("a person disabled during the request: %d, %d bytes", s, len(body))
	}
	k.during = nil
	// And afterwards the token buys nothing.
	if s, _, _ := postTGT(t, f, tok.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("after disabling: %d", s)
	}
}

func TestNoKerberosBlockNoEndpoint(t *testing.T) {
	f := newFixture(t, `client "plain" {
  device = true
}
`)
	if s, _, _ := postTGT(t, f, "x"); s != http.StatusNotFound {
		t.Errorf("without a kerberos block: %d, want 404", s)
	}
}

func TestKerberosConfigRefusals(t *testing.T) {
	c := newConf(t)
	dir := c.dir
	_, kdcURL := newStubKDC(t, dir)
	block := func(extra string) string {
		return `kerberos {
  kdc_url   = "` + kdcURL + `"
  ca_file   = "` + filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem")) + `"
  cert_file = "` + filepath.ToSlash(filepath.Join(dir, "bridge.pem")) + `"
  key_file  = "` + filepath.ToSlash(filepath.Join(dir, "bridge.key")) + `"
` + extra + `}
`
	}
	for name, hcl := range map[string]string{
		"a client without the block": "client \"k\" {\n  device = true\n  kerberos_tickets = true\n}\n",
		"plain http":                 strings.Replace(block(""), "https://", "http://", 1),
		"eleven hours":               block("  validity = \"11h\"\n"),
		"thirty seconds":             block("  validity = \"30s\"\n"),
	} {
		if _, err := c.load(t, c.hcl(nil)+hcl); err == nil {
			t.Errorf("%s: the configuration was accepted", name)
		}
	}
	// The control: the same block, unaltered, with a client that may use it.
	ok := block("") + "client \"k\" {\n  device = true\n  kerberos_tickets = true\n}\n"
	if _, err := c.load(t, c.hcl(nil)+ok); err != nil {
		t.Errorf("the control: %v", err)
	}
}
