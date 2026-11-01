// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/saml"
	"github.com/go-authn/saml/samltest"
)

// The fuzzers hold one property each: whatever the input, nothing that was
// not signed (or sealed, or registered) comes out as if it had been. Each
// is seeded with the genuine article, so the property is tested at the
// boundary between accepted and refused, not only in the refused desert.

const (
	fuzzIdP = "https://idp.univ-ex.example/idp/shibboleth"
	fuzzSP  = "https://bridge.example/saml"
	fuzzACS = "https://bridge.example/saml/acs"
	fuzzReq = "_0123456789abcdef0123456789abcdef01234567"
)

type samlWorld struct {
	md      *saml.Metadata
	sp      *samltest.Party
	at      time.Time
	pending saml.Pending
	clear   []byte // a Response around an assertion signed in the clear
	sealed  []byte // a signed Response around an encrypted assertion
	mdXML   []byte
	fedCert *samltest.Party
}

func newSAMLWorld(tb testing.TB) *samlWorld {
	tb.Helper()
	party := func(name string) *samltest.Party {
		p, err := samltest.NewParty(name)
		if err != nil {
			tb.Fatal(err)
		}
		return p
	}
	w := &samlWorld{sp: party("sp"), fedCert: party("federation"), at: time.Now()}
	idp := &samltest.IdP{EntityID: fuzzIdP, Scope: idpScope, SSO: "https://" + idpScope + "/SSO", Signer: party("idp")}
	var err error
	fed := &samltest.Federation{Signer: w.fedCert, IdPs: []*samltest.IdP{idp}}
	if w.mdXML, err = fed.Metadata(24 * time.Hour); err != nil {
		tb.Fatal(err)
	}
	if w.md, err = saml.ParseMetadata(w.mdXML, w.fedCert.Cert, w.at); err != nil {
		tb.Fatal(err)
	}
	w.pending = saml.Pending{ID: fuzzReq, IdP: fuzzIdP, Issued: w.at}
	a := samltest.Assertion{InResponseTo: fuzzReq, SP: fuzzSP, ACS: fuzzACS, Now: w.at, Lifetime: time.Hour,
		Attributes: []samltest.Attribute{{Name: samltest.EPPN, Values: []string{mallory}}}}
	decode := func(s string, err error) []byte {
		if err != nil {
			tb.Fatal(err)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			tb.Fatal(err)
		}
		return b
	}
	w.clear = decode(idp.Response(a))
	a.EncryptTo = w.sp.Cert
	w.sealed = decode(idp.Response(a))
	return w
}

// accept is the SP the bridge builds (newServer), with a fresh replay cache
// so that the same input is judged the same way every time.
func (w *samlWorld) accept(doc []byte) (*saml.Assertion, error) {
	sp := &saml.SP{EntityID: fuzzSP, ACS: fuzzACS, Key: w.sp.Key, Cert: w.sp.Cert, Federation: w.md,
		Now: func() time.Time { return w.at.Add(time.Second) }}
	return sp.Accept(base64.StdEncoding.EncodeToString(doc), w.pending)
}

// FuzzACSAccept: a response the fuzzer rearranged is refused, or says
// exactly what the IdP signed -- mallory, from this IdP. Seeded with both
// shapes a Shibboleth IdP sends and with the signature-wrapping layouts.
func FuzzACSAccept(f *testing.F) {
	w := newSAMLWorld(f)
	for _, doc := range [][]byte{w.clear, w.sealed} {
		if _, err := w.accept(doc); err != nil {
			f.Fatalf("a genuine response is refused: %v", err)
		}
		f.Add(doc)
	}
	// Wrapping layouts around the genuine one, so mutation starts there.
	s := string(w.clear)
	i, j := strings.Index(s, "<saml:Assertion"), strings.LastIndex(s, "</saml:Assertion>")+len("</saml:Assertion>")
	evil := strings.Replace(s[i:j], mallory, victim, 1)
	f.Add([]byte(s[:i] + evil + s[i:]))
	f.Add([]byte(s[:i] + "<samlp:Extensions>" + s[i:j] + "</samlp:Extensions>" + evil + s[j:]))
	f.Add([]byte(strings.Replace(s, mallory, victim, 1)))
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "a">]>` + s))
	f.Fuzz(func(t *testing.T, doc []byte) {
		a, err := w.accept(doc)
		if err != nil {
			return
		}
		if a.IdP.EntityID != fuzzIdP {
			t.Fatalf("accepted from %q", a.IdP.EntityID)
		}
		if got := a.Attributes[saml.EduPersonPrincipalName]; !reflect.DeepEqual(got, []string{mallory}) {
			t.Fatalf("accepted, saying eppn=%q, which nobody signed", got)
		}
		for name, vals := range a.Attributes {
			if name != saml.EduPersonPrincipalName {
				t.Fatalf("accepted, with an attribute %q=%q nobody signed", name, vals)
			}
		}
	})
}

// FuzzFederationMetadata: metadata the fuzzer rearranged is refused, or
// names exactly the IdP the federation signed, with its key and scope.
func FuzzFederationMetadata(f *testing.F) {
	w := newSAMLWorld(f)
	want := w.md.IdPs[fuzzIdP]
	f.Add(w.mdXML)
	f.Add([]byte(strings.Replace(string(w.mdXML), idpScope+"<", "evil.example<", 1)))
	f.Fuzz(func(t *testing.T, doc []byte) {
		md, err := saml.ParseMetadata(doc, w.fedCert.Cert, w.at)
		if err != nil {
			return
		}
		if len(md.IdPs) != 1 {
			t.Fatalf("accepted with %d IdPs", len(md.IdPs))
		}
		got, ok := md.IdPs[fuzzIdP]
		if !ok {
			t.Fatalf("accepted, naming an IdP nobody signed: %v", md.IdPs)
		}
		if !slices.Equal(got.Scopes, want.Scopes) || len(got.Keys) != len(want.Keys) || !got.Keys[0].Equal(want.Keys[0]) || got.SSO != want.SSO {
			t.Fatalf("accepted, with scopes %q keys %d sso %q, not what was signed", got.Scopes, len(got.Keys), got.SSO)
		}
	})
}

// FuzzVerifyAccessToken: a bearer token is this provider's own, or nothing.
// Accepted, its header and claims are byte for byte the ones signed; only
// the encoding of the signature may differ (base64's unused trailing bits).
func FuzzVerifyAccessToken(f *testing.F) {
	keys := map[string]*signingKey{"RS256": fuzzKey(f, "RS256"), "ES256": fuzzKey(f, "ES256")}
	signed := map[string]string{}
	for alg, k := range keys {
		tok, err := k.sign("at+jwt", map[string]any{"iss": "https://bridge.example", "sub": "s1", "jti": "j1", "scope": "openid"})
		if err != nil {
			f.Fatal(err)
		}
		if _, err := k.verify("at+jwt", tok); err != nil {
			f.Fatalf("%s: its own token does not verify: %v", alg, err)
		}
		signed[alg] = tok
		f.Add(alg, tok)
		// The algorithm confusions: none, and HS256 keyed with the public key.
		parts := strings.Split(tok, ".")
		f.Add(alg, parts[0]+"."+parts[1]+".")
		f.Add(alg, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+k.kid+`","typ":"at+jwt"}`))+"."+parts[1]+".")
		f.Add(alg, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"`+k.kid+`","typ":"at+jwt"}`))+"."+parts[1]+"."+parts[2])
		f.Add(alg, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"`+k.alg()+`","kid":"`+k.kid+`","typ":"JWT"}`))+"."+parts[1]+"."+parts[2])
	}
	f.Fuzz(func(t *testing.T, alg, raw string) {
		k, ok := keys[alg]
		if !ok {
			return
		}
		claims, err := k.verify("at+jwt", raw)
		if err != nil {
			return
		}
		got, want := strings.Split(raw, "."), strings.Split(signed[alg], ".")
		if got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("verified a token this key never signed: %q", raw)
		}
		if claims["sub"] != "s1" || claims["jti"] != "j1" {
			t.Fatalf("claims %v", claims)
		}
	})
}

// fuzzKey is a signing key of the given algorithm, from a file as the
// provider loads it.
func fuzzKey(f *testing.F, alg string) *signingKey {
	f.Helper()
	file := filepath.Join(f.TempDir(), "k.pem")
	var err error
	if alg == "ES256" {
		err = generateECKey(file)
	} else {
		err = generateKey(file, 2048)
	}
	if err != nil {
		f.Fatal(err)
	}
	k, err := loadSigningKey(file)
	if err != nil {
		f.Fatal(err)
	}
	return k
}

// FuzzOpenLogin: the login cookie opens as what this provider sealed, or
// not at all.
func FuzzOpenLogin(f *testing.F) {
	s := &server{cfg: &config{salt: []byte("a salt of thirty-two bytes, ok!!"),
		Clients: []clientBlock{{ID: "web", RedirectURIs: []string{"https://rp.example/cb"}}}}, now: time.Now}
	l := &login{kind: "authorize", client: &s.cfg.Clients[0], redirectURI: "https://rp.example/cb", state: "st", nonce: "n", maxAge: -1}
	v, err := s.sealLogin("handle", l, time.Now().Add(time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v)
	f.Add(v[:len(v)/2])
	f.Add("")
	f.Fuzz(func(t *testing.T, c string) {
		id, got, _, err := s.openLogin(c)
		if err != nil {
			return
		}
		if id != "handle" || got.redirectURI != l.redirectURI || got.state != l.state || got.nonce != l.nonce {
			t.Fatalf("opened a login nobody sealed: %q %+v", id, got)
		}
	})
}

// FuzzRedirectAllowed: a redirect URI is accepted only when the browser
// would go to a registered one: the same string, or a loopback http one
// that differs from a registered loopback one by its port alone (RFC 8252
// 7.3). The judge reparses what was accepted, independently of the code.
func FuzzRedirectAllowed(f *testing.F) {
	c := &clientBlock{ID: "cli", RedirectURIs: []string{"http://127.0.0.1/callback", "https://rp.example/cb", "http://[::1]/cb"}}
	for _, s := range []string{
		"http://127.0.0.1/callback", "http://127.0.0.1:51004/callback", "https://rp.example/cb", "http://[::1]:8080/cb",
		"http://127.0.0.1:1@evil.example/callback", "http://127.0.0.1:99/callback#x", "http://127.0.0.1:99/callback?x=1",
		"https://rp.example/cb/../evil", "https://rp.example.evil.example/cb", "http://127.0.0.1.evil.example/callback",
		"http://127.0.0.1\\@evil.example/callback", "HTTP://127.0.0.1:5/callback", "http://127.0.0.1:5/%63allback",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, got string) {
		if !redirectAllowed(c, got) {
			return
		}
		if slices.Contains(c.RedirectURIs, got) {
			return
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("accepted %q, which does not parse: %v", got, err)
		}
		if u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			t.Fatalf("accepted %q: scheme %q user %v fragment %q opaque %q", got, u.Scheme, u.User, u.Fragment, u.Opaque)
		}
		if h := u.Hostname(); h != "127.0.0.1" && h != "::1" {
			t.Fatalf("accepted %q, which goes to %q", got, h)
		}
		if p := u.Port(); p != "" && strings.Trim(p, "0123456789") != "" {
			t.Fatalf("accepted %q with port %q", got, p)
		}
		// Rebuilt without its port, it is a registered URI: same path once
		// decoded (percent-encoding an unreserved character names the same
		// resource, RFC 3986 6.2.2.2), same query.
		base := "http://" + u.Hostname()
		if strings.Contains(u.Hostname(), ":") {
			base = "http://[" + u.Hostname() + "]"
		}
		if !slices.Contains(c.RedirectURIs, base+u.Path+queryOf(u)) {
			t.Fatalf("accepted %q, which is no registered URI with another port (path %q)", got, u.Path)
		}
	})
}

func queryOf(u *url.URL) string {
	if u.RawQuery == "" && !u.ForceQuery {
		return ""
	}
	return "?" + u.RawQuery
}
