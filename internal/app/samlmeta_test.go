// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-authn/saml"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/sp-metadata-empty.golden.xml from the v0.34.0 mapping")

// metaServer is a server with what spMetadata reads: the configuration and a
// fixed SP certificate, so that the bytes can be compared with a file.
func metaServer(t *testing.T, cfg *config) *server {
	t.Helper()
	b, err := os.ReadFile("testdata/sp-golden-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return &server{cfg: cfg, sp: &saml.SP{EntityID: cfg.SAML.EntityID, ACS: cfg.Issuer + "/saml/acs", Cert: cert}}
}

// v034Metadata is spMetadata as it was before the organization, contact and
// ui blocks existed (v0.34.0), kept here as the reference the empty
// configuration must still equal, byte for byte.
func v034Metadata(s *server) ([]byte, error) {
	c := s.cfg.SAML
	d := saml.Description{
		Names:            c.Names,
		Descriptions:     c.Descriptions,
		InformationURL:   c.InformationURL,
		PrivacyStatement: c.PrivacyStatement,
		Technical:        c.Technical,
		Attributes: []string{saml.SubjectID, saml.EduPersonPrincipalName, saml.Mail,
			saml.DisplayName, saml.GivenName, saml.Surname},
	}
	if c.Discovery != "" {
		d.Discovery = s.cfg.Issuer + "/saml/disco"
	}
	for _, g := range s.cfg.Claims.Groups {
		d.Attributes = append(d.Attributes, groupAttributes[g])
	}
	return s.sp.Metadata(d)
}

const goldenFile = "testdata/sp-metadata-empty.golden.xml"

// With none of the new blocks configured the metadata is what it was.
func TestSPMetadataWithoutNewBlocksIsUnchanged(t *testing.T) {
	c := newConf(t)
	for name, extra := range map[string]string{
		"minimal": ``,
		"legacy fields": `saml {
  names = { fr = "Pont", en = "Bridge" }
}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := c.hcl(nil)
			if extra != "" {
				body = c.hcl(func(s string) string {
					return strings.Replace(s, "saml {", `saml {
  names                 = { fr = "Pont", en = "Bridge" }
  descriptions          = { en = "Sign in" }
  information_url       = "https://login.example.org/info"
  privacy_statement_url = "https://login.example.org/privacy"
  technical_contact     = "tech@example.org"
  discovery             = "https://discovery.renater.fr/renater"`, 1)
				})
			}
			cfg, err := c.load(t, body)
			if err != nil {
				t.Fatal(err)
			}
			s := metaServer(t, cfg)
			got, err := s.spMetadata()
			if err != nil {
				t.Fatal(err)
			}
			want, err := v034Metadata(s)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("the metadata changed with nothing configured:\n%s\n---\n%s", got, want)
			}
			if name != "minimal" {
				return
			}
			if *updateGolden {
				if err := os.WriteFile(goldenFile, want, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			golden, err := os.ReadFile(goldenFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, golden) {
				t.Fatalf("differs from %s:\n%s", goldenFile, got)
			}
		})
	}
}

const metaBlocks = `saml {
  names = { fr = "Pont", en = "Bridge" }
  technical_contact = "tech@example.org"
  organization {
    names         = { en = "Example Org" }
    display_names = { en = "Example Organisation", fr = "Organisation Exemple" }
    urls          = { en = "https://www.example.org/" }
  }
  contact {
    type       = "support"
    given_name = "Help desk"
    email      = "help@example.org"
  }
  contact {
    type     = "other"
    security = true
    email    = "security@example.org"
  }
  ui {
    logo {
      url    = "https://login.example.org/logo-en.png"
      width  = 200
      height = 80
      lang   = "en"
    }
    logo {
      url    = "https://login.example.org/logo.png"
      width  = 100
      height = 40
    }
    information_urls       = { en = "https://login.example.org/info/en", fr = "https://login.example.org/info/fr" }
    privacy_statement_urls = { en = "https://login.example.org/privacy/en" }
  }
`

func withBlocks(c *confFixture) string {
	return c.hcl(func(s string) string { return strings.Replace(s, "saml {", metaBlocks, 1) })
}

func TestSPMetadataBlocks(t *testing.T) {
	c := newConf(t)
	cfg, err := c.load(t, withBlocks(c))
	if err != nil {
		t.Fatal(err)
	}
	b, err := metaServer(t, cfg).spMetadata()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	// saml-metadata-2.0-os 2.3.2: role descriptors, Organization, then the
	// ContactPersons; technical_contact first, then the contacts as written.
	order := []string{
		"</md:SPSSODescriptor>",
		"<md:Organization>",
		"</md:Organization>",
		`contactType="technical"`,
		`contactType="support"`,
		`remd:contactType="http://refeds.org/metadata/contactType/security"`,
	}
	at := 0
	for _, w := range order {
		i := strings.Index(out[at:], w)
		if i < 0 {
			t.Fatalf("%q is missing or out of order after offset %d:\n%s", w, at, out)
		}
		at += i + len(w)
	}
	for _, w := range []string{
		`<mdui:Logo height="80" width="200" xml:lang="en">https://login.example.org/logo-en.png</mdui:Logo>`,
		`mdui:InformationURL xml:lang="fr">https://login.example.org/info/fr<`,
		`mdui:PrivacyStatementURL xml:lang="en">https://login.example.org/privacy/en<`,
		`xmlns:remd="http://refeds.org/metadata"`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("%q is missing:\n%s", w, out)
		}
	}
	dec := xml.NewDecoder(strings.NewReader(out))
	for {
		if _, err := dec.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("not well-formed XML: %v", err)
		}
	}
}

// One refusal per rule: the provider does not start.
func TestConfigMetadataRefusals(t *testing.T) {
	c := newConf(t)
	in := func(block string) func(string) string {
		// "|" stands for a newline: HCL wants one after every argument.
		return func(s string) string {
			return strings.Replace(s, "saml {", "saml {\n"+strings.ReplaceAll(block, "|", "\n"), 1)
		}
	}
	const logo = `ui {|logo {|url = "https://login.example.org/l.png"|width = 1|height = 1|`
	for name, tc := range map[string]struct{ block, want string }{
		"http logo":                     {`ui {|logo {|url = "http://login.example.org/l.png"|width = 1|height = 1|}|}`, "not an https URL"},
		"logo without size":             {`ui {|logo {|url = "https://login.example.org/l.png"|width = 0|height = 0|}|}`, "positive"},
		"logo language":                 {logo + `lang = "fr_FR"|}|}`, "language tag"},
		"http information URL":          {`ui {|information_urls = { fr = "http://login.example.org/" }|}`, "not an https URL"},
		"http privacy URL":              {`ui {|privacy_statement_urls = { fr = "http://login.example.org/" }|}`, "not an https URL"},
		"information URL twice":         {`information_url = "https://login.example.org/a"|ui {|information_urls = { en = "https://login.example.org/b" }|}`, "both give"},
		"organization without display":  {`organization {|names = { en = "x" }|display_names = {}|urls = { en = "https://www.example.org/" }|}`, "display name"},
		"organization with http URL":    {`organization {|names = { en = "x" }|display_names = { en = "x" }|urls = { en = "http://www.example.org/" }|}`, "not an https URL"},
		"unknown contact type":          {`contact {|type = "security"|email = "a@example.org"|}`, "unknown contact type"},
		"security contact not other":    {`contact {|type = "support"|security = true|email = "a@example.org"|}`, `of type "other"`},
		"contact e-mail with a name":    {`contact {|type = "support"|email = "Help <a@example.org>"|}`, "bare address"},
		"contact e-mail not an address": {`contact {|type = "support"|email = "help"|}`, "bare address"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.load(t, c.hcl(in(tc.block)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadConfig = %v, want an error holding %q", err, tc.want)
			}
		})
	}
	// A contact without an e-mail is an HCL error, not a published contact.
	if _, err := c.load(t, c.hcl(in(`contact {|type = "support"|}`))); err == nil {
		t.Error("a contact without an e-mail was accepted")
	}
	if _, err := c.load(t, withBlocks(c)); err != nil {
		t.Errorf("the full configuration is refused: %v", err)
	}
}

// Whatever the blocks hold, a configuration that loads yields metadata that is
// well-formed XML.
func FuzzConfigMetadataBlocks(f *testing.F) {
	f.Add("en", "https://a.example.org/l.png", "a@example.org", "support", 10, 10)
	f.Add("fr-CA", "http://a.example.org/", "<a@example.org>", "other", 0, -1)
	f.Add("", "", "", "", 0, 0)
	b, err := os.ReadFile("testdata/sp-golden-cert.pem")
	if err != nil {
		f.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, lang, u, email, typ string, w, h int) {
		s := &samlBlock{
			Names:        map[string]string{"en": "x"},
			Organization: &organizationBlock{Names: map[string]string{lang: u}, DisplayNames: map[string]string{lang: u}, URLs: map[string]string{lang: u}},
			Contacts:     []contactBlock{{Type: typ, Email: email, GivenName: u, Security: w > h}},
			UI: &uiBlock{
				Logos:           []logoBlock{{URL: u, Width: w, Height: h, Lang: lang}},
				InformationURLs: map[string]string{lang: u},
			},
		}
		d := s.description()
		if d.Validate() != nil {
			return
		}
		out, err := (&saml.SP{EntityID: "https://login.example.org/saml", ACS: "https://login.example.org/saml/acs", Cert: cert}).Metadata(d)
		if err != nil {
			t.Fatalf("Validate accepted what Metadata refuses: %v", err)
		}
		dec := xml.NewDecoder(bytes.NewReader(out))
		for {
			if _, err := dec.Token(); err == io.EOF {
				return
			} else if err != nil {
				t.Fatalf("ill-formed XML: %v\n%q", err, out)
			}
		}
	})
}
