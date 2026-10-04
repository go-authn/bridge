// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The world these tests run in: a federation whose metadata xmlsec1 signs,
// an IdP whose responses xmlsec1 signs and encrypts, and this provider
// between them. Nothing on the SAML side is produced by go-authn/saml, which
// only reads.
//
// BRIDGE_REQUIRE_JUDGE=1 makes a missing xmlsec1 a failure rather than a
// skip, in the CI lanes that install it.

const (
	idpEntity = "https://idp.univ-example.fr/idp/shibboleth"
	idpScope  = "univ-example.fr"
)

type party struct {
	key      *rsa.PrivateKey
	cert     *x509.Certificate
	keyFile  string
	certFile string
}

func newParty(t *testing.T, dir, name string) *party {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := &party{key: k, cert: c, keyFile: filepath.Join(dir, name+".key"), certFile: filepath.Join(dir, name+".crt")}
	os.WriteFile(p.keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	os.WriteFile(p.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

func fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

type xmlsec struct {
	t    *testing.T
	path string
	lax  []string
	dir  string
}

func judge(t *testing.T, dir string) *xmlsec {
	t.Helper()
	p, err := exec.LookPath("xmlsec1")
	if err != nil {
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("xmlsec1 is required here and is not installed")
		}
		t.Skip("xmlsec1 is not installed")
	}
	x := &xmlsec{t: t, path: p, dir: dir}
	// 1.3 finds no key through a template's empty KeyInfo without this; 1.2,
	// which Ubuntu ships, does not know the flag.
	if out, _ := exec.Command(p, "--help-sign").CombinedOutput(); strings.Contains(string(out), "--lax-key-search") {
		x.lax = []string{"--lax-key-search"}
	}
	return x
}

func (x *xmlsec) run(cmd string, args ...string) string {
	x.t.Helper()
	all := append(append([]string{cmd}, x.lax...), args...)
	out, err := exec.Command(x.path, all...).CombinedOutput()
	if err != nil {
		x.t.Fatalf("xmlsec1 %s: %v\n%s", strings.Join(all, " "), err, out)
	}
	s := strings.TrimSpace(string(out))
	if strings.HasPrefix(s, "<?xml") {
		s = strings.TrimSpace(s[strings.Index(s, "?>")+2:])
	}
	return s
}

func (x *xmlsec) file(name, content string) string {
	p := filepath.Join(x.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		x.t.Fatal(err)
	}
	return p
}

const sigTemplate = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>`

// fixture is a whole deployment: files on disk, the federation, the IdP.
type fixture struct {
	t        *testing.T
	dir      string
	x        *xmlsec
	fedKey   *party // signs the federation's metadata
	idp      *party // the university's IdP
	sp       *party // this provider's SAML key
	metadata *httptest.Server
	srv      *httptest.Server
	s        *server
	cfgFile  string
	redirect string // the test client's redirect URI
	// setHandler puts another provider behind the same URL: a restart.
	setHandler func(http.Handler)
}

// newFixture writes a configuration and starts the provider. extra is HCL
// appended to the configuration; idps is how many other IdPs the federation
// lists besides the university's, so that a login has to choose.
func newFixture(t *testing.T, extra string) *fixture {
	dir, err := os.MkdirTemp("", "bridge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fixture{t: t, dir: dir}
	f.x = judge(t, dir)
	f.fedKey = newParty(t, dir, "federation")
	f.idp = newParty(t, dir, "idp")
	f.sp = newParty(t, dir, "sp")

	md := f.x.run("--sign", "--privkey-pem", f.fedKey.keyFile+","+f.fedKey.certFile,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor", "--output", "/dev/stdout",
		f.x.file("md.xml", f.federationMetadata()))
	f.metadata = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, md)
	}))
	t.Cleanup(f.metadata.Close)

	// The provider's own URL is only known once it listens, so it listens
	// first and is handed its handler after.
	var handler atomic.Value // http.Handler; a test may swap it for a restarted provider
	f.setHandler = func(h http.Handler) { handler.Store(&h) }
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*handler.Load().(*http.Handler)).ServeHTTP(w, r) })
	if fixtureOverTLS {
		// An https issuer, for what refuses any other (an SSF receiver):
		// this process's clients trust it until the test ends.
		f.srv = httptest.NewTLSServer(serve)
		pool := x509.NewCertPool()
		pool.AddCert(f.srv.Certificate())
		old := http.DefaultTransport
		http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
		t.Cleanup(func() { http.DefaultTransport = old })
	} else {
		f.srv = httptest.NewServer(serve)
	}
	t.Cleanup(f.srv.Close)
	f.redirect = "http://127.0.0.1:9/callback"

	if err := generateKey(filepath.Join(dir, "oidc.key"), 2048); err != nil {
		t.Fatal(err)
	}
	if err := generateSalt(filepath.Join(dir, "salt")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "web.secret"), []byte("a-secret-long-enough-to-pass"), 0o600)
	cfg := fmt.Sprintf(`
issuer            = %q
signing_key_file  = %q
subject_salt_file = %q

saml {
  key_file             = %q
  cert_file            = %q
  metadata_url         = %q
  metadata_cert_file   = %q
  metadata_fingerprint = %q
  names = { fr = "Passerelle", en = "Bridge" }
  technical_contact = "noc@example.org"
}

claims {
  username = "eppn"
  groups   = ["entitlement"]
}

client "web" {
  secret_file   = %q
  redirect_uris = [%q]
  audience      = ["fileshare"]
}

client "cli" {
  redirect_uris = ["http://127.0.0.1/callback"]
  subject       = "pairwise"
}
%s`, f.srv.URL, filepath.Join(dir, "oidc.key"), filepath.Join(dir, "salt"),
		f.sp.keyFile, f.sp.certFile, f.metadata.URL, f.fedKey.certFile, fingerprint(f.fedKey.cert),
		filepath.Join(dir, "web.secret"), f.redirect, extra)
	f.cfgFile = filepath.Join(dir, "bridge.hcl")
	os.WriteFile(f.cfgFile, []byte(cfg), 0o644)

	c, err := loadConfig([]string{f.cfgFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.close() })
	f.s, err = newServer(c, &testLog{t})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.fed.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.setHandler(f.s.handler())
	return f
}

type testLog struct{ t *testing.T }

func (l *testLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func (f *fixture) federationMetadata() string {
	idp := func(id, scope string, key *party) string {
		return `<md:EntityDescriptor entityID="` + id + `"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<md:Extensions><shibmd:Scope regexp="false">` + scope + `</shibmd:Scope><mdui:UIInfo><mdui:DisplayName xml:lang="fr">` + scope + `</mdui:DisplayName></mdui:UIInfo></md:Extensions>` +
			`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(key.cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://` + scope + `/SSO"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	}
	other := newParty(f.t, f.dir, "other-idp")
	return `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_fed" validUntil="` +
		time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `">` + fmt.Sprintf(sigTemplate, "_fed") +
		idp(idpEntity, idpScope, f.idp) + idp("https://idp.other-univ.fr/idp", "other-univ.fr", other) +
		`</md:EntitiesDescriptor>`
}

// browser is a person's browser: cookies, and redirects looked at one by
// one rather than followed.
type browser struct {
	t *testing.T
	c *http.Client
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (b *browser) get(u string) *http.Response {
	b.t.Helper()
	r, err := b.c.Get(u)
	if err != nil {
		b.t.Fatal(err)
	}
	return r
}

func (b *browser) post(u string, v url.Values) *http.Response {
	b.t.Helper()
	r, err := b.c.PostForm(u, v)
	if err != nil {
		b.t.Fatal(err)
	}
	return r
}

func location(t *testing.T, r *http.Response) *url.URL {
	t.Helper()
	if r.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(r.Body)
		t.Fatalf("status %d, want a redirect: %s", r.StatusCode, body)
	}
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// authnRequest reads the AuthnRequest out of a redirect to the IdP.
func authnRequest(t *testing.T, u *url.URL) (id, relayState string) {
	t.Helper()
	z, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, ` ID="`) + 5
	return s[i : i+strings.Index(s[i:], `"`)], u.Query().Get("RelayState")
}

// assertionOpts is what the IdP says.
type assertionOpts struct {
	eppn        string
	subjectID   string
	entitlement []string
	status      string // raw StatusCode, Success when empty
	acr         string
	// issuer and signer, when set, are another IdP of the federation
	// answering in place of the university's.
	issuer string
	signer *party
	// authnAt, when set, is the AuthnInstant: when the IdP says the person
	// authenticated (now by default).
	authnAt time.Time
}

// respond has the IdP (xmlsec1) answer a request: the assertion encrypted
// to the provider's key with AES-128-GCM, the Response signed -- a
// Shibboleth IdP v5's defaults.
func (f *fixture) respond(requestID string, o assertionOpts) string {
	f.t.Helper()
	issuer, signer := idpEntity, f.idp
	if o.issuer != "" {
		issuer, signer = o.issuer, o.signer
	}
	acs := f.s.cfg.Issuer + "/saml/acs"
	now := time.Now().UTC()
	ts, later := now.Add(-time.Second).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339)
	authnAt := ts
	if !o.authnAt.IsZero() {
		authnAt = o.authnAt.UTC().Format(time.RFC3339)
	}
	if o.acr == "" {
		o.acr = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	}
	attr := func(name string, vals ...string) string {
		if len(vals) == 0 || vals[0] == "" {
			return ""
		}
		s := `<saml:Attribute Name="` + name + `" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">`
		for _, v := range vals {
			s += `<saml:AttributeValue>` + v + `</saml:AttributeValue>`
		}
		return s + `</saml:Attribute>`
	}
	body := ""
	if o.status == "" {
		assertion := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a` + token()[:20] + `" Version="2.0" IssueInstant="` + ts + `">` +
			`<saml:Issuer>` + issuer + `</saml:Issuer>` +
			`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">t1</saml:NameID>` +
			`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="` + acs + `" InResponseTo="` + requestID + `" NotOnOrAfter="` + later + `"/></saml:SubjectConfirmation></saml:Subject>` +
			`<saml:Conditions NotBefore="` + ts + `" NotOnOrAfter="` + later + `"><saml:AudienceRestriction><saml:Audience>` + f.s.cfg.SAML.EntityID + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
			`<saml:AuthnStatement AuthnInstant="` + authnAt + `" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>` + o.acr + `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
			`<saml:AttributeStatement>` +
			attr("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", o.eppn) +
			attr("urn:oasis:names:tc:SAML:attribute:subject-id", o.subjectID) +
			attr("urn:oid:1.3.6.1.4.1.5923.1.1.1.7", o.entitlement...) +
			attr("urn:oid:2.16.840.1.113730.3.1.241", "Alice Martin") +
			attr("urn:oid:0.9.2342.19200300.100.1.3", "alice@"+idpScope) +
			`</saml:AttributeStatement></saml:Assertion>`
		tmpl := f.x.file("enc.xml", `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`)
		data := f.x.file("data.xml", `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`+assertion+`</saml:EncryptedAssertion>`)
		body = f.x.run("--encrypt", "--pubkey-cert-pem", f.sp.certFile, "--session-key", "aes-128",
			"--xml-data", data, "--node-name", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion", "--output", "/dev/stdout", tmpl)
		o.status = `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`
	}
	resp := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r` + token()[:20] + `" Version="2.0" IssueInstant="` + ts + `" Destination="` + acs + `" InResponseTo="` + requestID + `">` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` + fmt.Sprintf(sigTemplate, "_rID") + `<samlp:Status>` + o.status + `</samlp:Status>` + body + `</samlp:Response>`
	id := resp[strings.Index(resp, ` ID="`)+5:]
	id = id[:strings.Index(id, `"`)]
	resp = strings.Replace(resp, "#_rID", "#"+id, 1)
	signed := f.x.run("--sign", "--privkey-pem", signer.keyFile+","+signer.certFile,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", "--output", "/dev/stdout", f.x.file("resp.xml", resp))
	return base64.StdEncoding.EncodeToString([]byte(signed))
}

// fixtureOverTLS makes newFixture serve the provider over https.
var fixtureOverTLS bool

// newFixtureTLS is newFixture with an https issuer.
func newFixtureTLS(t *testing.T, extra string) *fixture {
	t.Helper()
	fixtureOverTLS = true
	defer func() { fixtureOverTLS = false }()
	return newFixture(t, extra)
}
