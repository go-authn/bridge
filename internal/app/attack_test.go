// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The attacks on the ACS, end to end: a crafted SAMLResponse posted by a
// browser that holds a real login, as an attacker would.
//
// The attacker is mallory, a real member of the university: the IdP really
// signs what it says about her. Each attack takes that signed statement and
// rearranges the document so that a careless reader sees alice instead.
// The classes are Somorovsky et al., "On Breaking SAML: Be Whoever You Want
// to Be" (USENIX Security 2012), XSW1-XSW8, and the comment truncation of
// CVE-2017-11427. Signature rules: saml-core-2.0-os 5.4.2 (one Reference, to
// the ID of the signed element), 5.4.4 (transforms), saml-bindings 3.5.5.2
// (Destination of a signed POST).

const (
	mallory = "mallory@" + idpScope
	victim  = "alice@" + idpScope
)

// assertionXML is an assertion the IdP would write, unsigned: id is its ID,
// sig, when not empty, is placed after the Issuer (where an enveloped
// signature goes), body is appended before the closing tag.
func (f *fixture) assertionXML(requestID, id, eppn, sig, body string, o assertionOpts) string {
	acs := f.s.cfg.Issuer + "/saml/acs"
	if o.recipient != "" {
		acs = o.recipient
	}
	audienceName := f.s.cfg.SAML.EntityID
	if o.audience != "" {
		audienceName = o.audience
	}
	now := time.Now().UTC()
	ts, later := now.Add(-time.Second).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339)
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" IssueInstant="` + ts + `">` +
		`<saml:Issuer>` + idpEntity + `</saml:Issuer>` + sig +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">t1</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="` + acs + `" InResponseTo="` + requestID + `" NotOnOrAfter="` + later + `"/></saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + ts + `" NotOnOrAfter="` + later + `"><saml:AudienceRestriction><saml:Audience>` + audienceName + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + ts + `" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`<saml:AttributeStatement><saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>` + eppn + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
		body + `</saml:Assertion>`
}

// responseXML wraps assertions in an unsigned Response.
func (f *fixture) responseXML(requestID, id, inner string) string {
	ts := time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" IssueInstant="` + ts + `" Destination="` + f.s.cfg.Issuer + `/saml/acs" InResponseTo="` + requestID + `">` +
		`<saml:Issuer>` + idpEntity + `</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		inner + `</samlp:Response>`
}

// signedAssertion has the IdP (xmlsec1) sign an assertion about eppn in the
// clear, the response around it unsigned: the other shape saml-profiles
// 4.1.3.5 allows, and the one the assertion-level wrappings need. It returns
// the signed Assertion element, exactly as xmlsec1 wrote it.
func (f *fixture) signedAssertion(requestID, eppn string, o assertionOpts) string {
	f.t.Helper()
	id := "_a" + token()[:20]
	a := f.assertionXML(requestID, id, eppn, fmt.Sprintf(sigTemplate, id), "", o)
	signed := f.x.run("--sign", "--privkey-pem", f.idp.keyFile+","+f.idp.certFile,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion", "--output", "/dev/stdout",
		f.x.file("assertion.xml", f.responseXML(requestID, "_r"+token()[:20], a)))
	i := strings.Index(signed, "<saml:Assertion")
	j := strings.LastIndex(signed, "</saml:Assertion>")
	if i < 0 || j < 0 {
		f.t.Fatalf("no assertion in what xmlsec1 signed:\n%s", signed)
	}
	return signed[i : j+len("</saml:Assertion>")]
}

// signatureOf is the ds:Signature element inside a signed element.
func signatureOf(t *testing.T, signed string) string {
	t.Helper()
	i := strings.Index(signed, "<ds:Signature")
	j := strings.Index(signed, "</ds:Signature>")
	if i < 0 || j < 0 {
		t.Fatalf("no signature in:\n%s", signed)
	}
	return signed[i : j+len("</ds:Signature>")]
}

func idOf(t *testing.T, el string) string {
	t.Helper()
	i := strings.Index(el, ` ID="`)
	if i < 0 {
		t.Fatalf("no ID in %.80s", el)
	}
	i += len(` ID="`)
	return el[i : i+strings.Index(el[i:], `"`)]
}

// post delivers a raw SAMLResponse document for a login this browser has
// started, and says who, if anybody, the provider now believes logged in.
func (f *fixture) post(t *testing.T, b *browser, relay, doc string) (who string, status int) {
	t.Helper()
	r := b.post(f.s.cfg.Issuer+"/saml/acs", url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(doc))},
		"RelayState":   {relay},
	})
	defer r.Body.Close()
	io.Copy(io.Discard, r.Body)
	if r.StatusCode != http.StatusFound {
		return "", r.StatusCode
	}
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", r.StatusCode // an OAuth error sent to the client: nobody logged in
	}
	g, ok := f.s.codes.get(code)
	if !ok {
		t.Fatalf("a code %q the provider does not hold", code)
	}
	return g.who.username, r.StatusCode
}

// begin starts a login in a new browser and returns what the IdP is asked.
func (f *fixture) begin(t *testing.T) (b *browser, reqID, relay string) {
	t.Helper()
	b = newBrowser(t)
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	reqID, relay = f.startTo(t, b, r.authURL())
	return b, reqID, relay
}

// The planted positive: an unsigned response around an assertion signed in
// the clear is accepted, as mallory. Without it, every refusal below could be
// the shape being refused rather than the attack.
func TestSignedAssertionInTheClearIsAccepted(t *testing.T) {
	f := newFixture(t, "")
	b, reqID, relay := f.begin(t)
	a := f.signedAssertion(reqID, mallory, assertionOpts{})
	if who, st := f.post(t, b, relay, f.responseXML(reqID, "_r1", a)); who != mallory {
		t.Fatalf("a genuine response was not accepted as mallory: who=%q status=%d", who, st)
	}
	// And the detector sees the victim when the IdP really vouches for her:
	// `who == victim` below is a check that can fire.
	b, reqID, relay = f.begin(t)
	if who, st := f.post(t, b, relay, f.responseXML(reqID, "_r2", f.signedAssertion(reqID, victim, assertionOpts{}))); who != victim {
		t.Fatalf("a genuine response about the victim was not read as her: who=%q status=%d", who, st)
	}
}

// XSW3-XSW8 and their kin: the signed assertion about mallory is kept, an
// unsigned one about alice is added where a reader might pick it.
func TestAssertionWrappingAtTheACS(t *testing.T) {
	f := newFixture(t, "")
	for _, c := range []struct {
		name string
		// build gets the signed assertion (a), its signature (sig) and an
		// unsigned assertion about alice for the same request (evil, built
		// with any id and signature placement it needs).
		build func(a, sig string, evil func(id, sig, body string) string) string
	}{
		{"XSW3: evil assertion before the signed one", func(a, sig string, evil func(string, string, string) string) string {
			return evil("_evil", "", "") + a
		}},
		{"XSW3b: evil assertion after the signed one", func(a, sig string, evil func(string, string, string) string) string {
			return a + evil("_evil", "", "")
		}},
		{"XSW4: signed assertion nested inside the evil one", func(a, sig string, evil func(string, string, string) string) string {
			return evil("_evil", "", a)
		}},
		{"XSW5: signature copied onto the evil one, signed one in Extensions", func(a, sig string, evil func(string, string, string) string) string {
			return `<samlp:Extensions>` + a + `</samlp:Extensions>` + evil("_evil", sig, "")
		}},
		{"XSW6: signed one inside the copied signature's Object", func(a, sig string, evil func(string, string, string) string) string {
			s := strings.Replace(sig, "</ds:Signature>", "<ds:Object>"+a+"</ds:Object></ds:Signature>", 1)
			return evil("_evil", s, "")
		}},
		{"XSW7: evil assertion in Extensions, signed one in place", func(a, sig string, evil func(string, string, string) string) string {
			return `<samlp:Extensions>` + evil("_evil", "", "") + `</samlp:Extensions>` + a
		}},
		{"XSW8: signed one stripped of its signature, in the Object", func(a, sig string, evil func(string, string, string) string) string {
			stripped := strings.Replace(a, sig, "", 1)
			s := strings.Replace(sig, "</ds:Signature>", "<ds:Object>"+stripped+"</ds:Object></ds:Signature>", 1)
			return evil("_evil", s, "")
		}},
		{"same ID: evil assertion carries the signed one's ID and signature", func(a, sig string, evil func(string, string, string) string) string {
			return evil(idOf(t, a), sig, "")
		}},
		{"same ID twice: evil first, signed second", func(a, sig string, evil func(string, string, string) string) string {
			return evil(idOf(t, a), "", "") + a
		}},
		{"evil assertion only, signed one dropped", func(a, sig string, evil func(string, string, string) string) string {
			return evil("_evil", "", "")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, reqID, relay := f.begin(t)
			a := f.signedAssertion(reqID, mallory, assertionOpts{})
			evil := func(id, sig, body string) string {
				return f.assertionXML(reqID, id, victim, sig, body, assertionOpts{})
			}
			doc := f.responseXML(reqID, "_r"+token()[:20], c.build(a, signatureOf(t, a), evil))
			if who, st := f.post(t, b, relay, doc); who == victim {
				t.Fatalf("WRAPPED: logged in as %q (status %d)", who, st)
			} else if who != "" && who != mallory {
				t.Fatalf("logged in as %q, neither the signer's word nor the attacker's", who)
			}
		})
	}
}

// XSW1, XSW2 and kin at the Response level: the Response the IdP signed
// (encrypted assertion about mallory) is kept somewhere in the document, and
// the root is a new Response carrying an unsigned assertion about alice.
func TestResponseWrappingAtTheACS(t *testing.T) {
	f := newFixture(t, "")
	for _, c := range []struct {
		name  string
		build func(signed, sig, evilAssertion, reqID string) string
	}{
		{"XSW1: signed response inside the copied signature's Object", func(signed, sig, evilA, reqID string) string {
			s := strings.Replace(sig, "</ds:Signature>", "<ds:Object>"+signed+"</ds:Object></ds:Signature>", 1)
			return f.responseXML(reqID, "_evilr", s+evilA)
		}},
		{"XSW2: signed response as a detached sibling before the evil content", func(signed, sig, evilA, reqID string) string {
			return f.responseXML(reqID, "_evilr", sig+`<samlp:Extensions>`+signed+`</samlp:Extensions>`+evilA)
		}},
		{"same ID: evil root carries the signed response's ID and signature", func(signed, sig, evilA, reqID string) string {
			return f.responseXML(reqID, idOf(t, signed), sig+evilA)
		}},
		{"evil assertion appended to the signed response", func(signed, sig, evilA, reqID string) string {
			return strings.Replace(signed, "</samlp:Response>", evilA+"</samlp:Response>", 1)
		}},
		{"encrypted assertion swapped for the evil one", func(signed, sig, evilA, reqID string) string {
			i := strings.Index(signed, "<saml:EncryptedAssertion")
			j := strings.Index(signed, "</saml:EncryptedAssertion>")
			if i < 0 || j < 0 {
				t.Fatalf("no EncryptedAssertion in the signed response")
			}
			return signed[:i] + evilA + signed[j+len("</saml:EncryptedAssertion>"):]
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, reqID, relay := f.begin(t)
			raw, err := base64.StdEncoding.DecodeString(f.respond(reqID, assertionOpts{eppn: mallory}))
			if err != nil {
				t.Fatal(err)
			}
			signed := string(raw)
			evilA := f.assertionXML(reqID, "_evil", victim, "", "", assertionOpts{})
			doc := c.build(signed, signatureOf(t, signed), evilA, reqID)
			if who, st := f.post(t, b, relay, doc); who == victim {
				t.Fatalf("WRAPPED: logged in as %q (status %d)", who, st)
			} else if who != "" && who != mallory {
				t.Fatalf("logged in as %q", who)
			}
		})
	}
}

// CVE-2017-11427 and its family: a comment inserted into a signed text node
// is invisible to exclusive canonicalisation without comments, so the
// signature still verifies; a reader that takes only the first text node then
// reads a prefix of what was signed. The value read must be all of it.
func TestCommentInSignedTextIsNotATruncation(t *testing.T) {
	f := newFixture(t, "")
	// mallory's eppn, with a comment where a truncating reader would stop
	// at a name that is somebody else's.
	const signedAs = "alice.mallory@" + idpScope
	for _, at := range []string{"alice", "alice.mallory@univ-ex", "alice.mallory@"} {
		t.Run(at, func(t *testing.T) {
			b, reqID, relay := f.begin(t)
			a := f.signedAssertion(reqID, signedAs, assertionOpts{})
			tampered := strings.Replace(a, ">"+signedAs+"<", ">"+at+"<!---->"+strings.TrimPrefix(signedAs, at)+"<", 1)
			if tampered == a {
				t.Fatal("the comment was not inserted")
			}
			who, st := f.post(t, b, relay, f.responseXML(reqID, "_r"+token()[:20], tampered))
			// The signature still verifies (the comment is outside what
			// it covers), so the login goes through -- as all of it.
			if who != signedAs {
				t.Fatalf("read %q of a signed %q (status %d)", who, signedAs, st)
			}
		})
	}
}

// Validly signed, but for somebody else: another SP's audience, another
// ACS, another request. Each must be refused, or an assertion obtained at
// any SP of the federation would open this one.
func TestSignedForSomebodyElse(t *testing.T) {
	f := newFixture(t, "")
	for _, c := range []struct {
		name string
		o    assertionOpts
		req  func(reqID string) string
		dest string
	}{
		{"another SP's audience", assertionOpts{audience: "https://other-sp.example/shibboleth"}, nil, ""},
		{"another ACS as Recipient", assertionOpts{recipient: "https://other-sp.example/Shibboleth.sso/SAML2/POST"}, nil, ""},
		{"another request", assertionOpts{}, func(string) string { return "_" + strings.Repeat("0", 40) }, ""},
		{"another Destination", assertionOpts{}, nil, "https://other-sp.example/acs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, reqID, relay := f.begin(t)
			answers := reqID
			if c.req != nil {
				answers = c.req(reqID)
			}
			doc := f.responseXML(answers, "_r"+token()[:20], f.signedAssertion(answers, mallory, c.o))
			if c.dest != "" {
				doc = strings.Replace(doc, `Destination="`+f.s.cfg.Issuer+`/saml/acs"`, `Destination="`+c.dest+`"`, 1)
			}
			if who, st := f.post(t, b, relay, doc); who != "" {
				t.Fatalf("accepted as %q (status %d)", who, st)
			}
		})
	}
}

// The same signed response, delivered twice to two logins of the same
// browser session flow: the second must not log anybody in.
func TestResponseReplayedIntoANewLogin(t *testing.T) {
	f := newFixture(t, "")
	b, reqID, relay := f.begin(t)
	a := f.signedAssertion(reqID, mallory, assertionOpts{})
	doc := f.responseXML(reqID, "_r1", a)
	if who, _ := f.post(t, b, relay, doc); who != mallory {
		t.Fatalf("the first delivery was not accepted: %q", who)
	}
	b2, _, relay2 := f.begin(t)
	if who, st := f.post(t, b2, relay2, doc); who != "" {
		t.Fatalf("a replayed response logged %q in (status %d)", who, st)
	}
}

// XML that asks its reader to expand entities, or to fetch something: a
// DOCTYPE is refused before anything is read (billion laughs, XXE).
func TestEntityExpansionRefused(t *testing.T) {
	f := newFixture(t, "")
	for _, c := range []struct{ name, prolog, eppn string }{
		{"billion laughs", `<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>`, "&c;"},
		{"external entity", `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>`, "&x;"},
		{"internal entity naming alice", `<!DOCTYPE r [<!ENTITY who "` + victim + `">]>`, "&who;"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, reqID, relay := f.begin(t)
			a := f.signedAssertion(reqID, mallory, assertionOpts{})
			doc := c.prolog + f.responseXML(reqID, "_r1", strings.Replace(a, ">"+mallory+"<", ">"+c.eppn+"<", 1))
			if who, st := f.post(t, b, relay, doc); who != "" {
				t.Fatalf("a document with a DOCTYPE logged %q in (status %d)", who, st)
			}
		})
	}
}
