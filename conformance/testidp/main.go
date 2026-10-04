// SPDX-License-Identifier: BSD-3-Clause

// Command testidp is the SAML IdP the conformance run logs in through:
// crewjam/saml's IdentityProvider with one person always logged in, and
// its metadata published the way a federation does -- scoped, wrapped in
// an EntitiesDescriptor and signed by a federation key the bridge pins.
//
// It is test infrastructure for the OpenID Foundation conformance suite
// (see ../README.md), and nothing else: it authenticates nobody.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/beevik/etree"
	cj "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	base := flag.String("base", "http://idp:8080", "this IdP's base URL, as browsers reach it")
	idpKey := flag.String("idp-key", "", "the IdP's signing key (PEM)")
	idpCert := flag.String("idp-cert", "", "the IdP's certificate (PEM)")
	fedKey := flag.String("fed-key", "", "the federation's metadata signing key (PEM)")
	fedCert := flag.String("fed-cert", "", "the federation's certificate (PEM)")
	spMetadata := flag.String("sp-metadata", "https://bridge:8443/saml/metadata", "where the bridge publishes its SP metadata")
	scope := flag.String("scope", "univ-example.fr", "the shibmd scope the federation grants")
	tlsCert := flag.String("tls-cert", "", "TLS certificate to serve with (PEM): the bridge reads metadata over https only")
	tlsKey := flag.String("tls-key", "", "its key (PEM)")
	flag.Parse()

	key, cert := loadPair(*idpKey, *idpCert)
	fk, fc := loadPair(*fedKey, *fedCert)
	b, err := url.Parse(*base)
	if err != nil {
		log.Fatal(err)
	}
	sps := &spFetcher{url: *spMetadata}
	idp := &cj.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *b.JoinPath("metadata"),
		SSOURL:                  *b.JoinPath("sso"),
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		ServiceProviderProvider: sps,
		SessionProvider: session{
			ID:                     "conformance",
			NameID:                 "alice",
			UserName:               "alice",
			UserEmail:              "alice@" + *scope,
			EduPersonPrincipalName: "alice@" + *scope,
			UserGivenName:          "Alice",
			UserSurname:            "Martin",
			UserCommonName:         "Alice Martin",
			SubjectID:              "a1b2c3@" + *scope,
		},
	}
	md, err := xml.Marshal(idp.Metadata())
	if err != nil {
		log.Fatal(err)
	}
	federation, err := federate(md, *scope, fk, fc)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sso", idp.ServeSSO)
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write(md)
	})
	mux.HandleFunc("/federation.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write(federation)
	})
	log.Printf("testidp: %s, entity %s", *listen, idp.MetadataURL.String())
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if *tlsCert != "" {
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Fatal(srv.ListenAndServe())
}

func loadPair(keyFile, certFile string) (*rsa.PrivateKey, *x509.Certificate) {
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	cb, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	kp, _ := pem.Decode(kb)
	cp, _ := pem.Decode(cb)
	if kp == nil || cp == nil {
		log.Fatalf("%s or %s is not PEM", keyFile, certFile)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(kp.Bytes); err == nil {
		key, _ = k.(*rsa.PrivateKey)
	} else if k, err := x509.ParsePKCS1PrivateKey(kp.Bytes); err == nil {
		key = k
	}
	if key == nil {
		log.Fatalf("%s is not an RSA key", keyFile)
	}
	cert, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return key, cert
}

// session is the one person, always logged in.
type session cj.Session

func (s session) GetSession(http.ResponseWriter, *http.Request, *cj.IdpAuthnRequest) *cj.Session {
	cs := cj.Session(s)
	cs.CreateTime = time.Now()
	cs.ExpireTime = time.Now().Add(time.Hour)
	return &cs
}

// spFetcher reads the bridge's SP metadata when a request first names it:
// the bridge starts after this IdP, since it reads this IdP's metadata.
type spFetcher struct {
	url string
	mu  sync.Mutex
	ed  *cj.EntityDescriptor
}

func (f *spFetcher) GetServiceProvider(_ *http.Request, id string) (*cj.EntityDescriptor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ed == nil {
		// The bridge's certificate here is a throwaway self-signed one.
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		res, err := c.Get(f.url)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		var ed cj.EntityDescriptor
		if err := xml.Unmarshal(b, &ed); err != nil {
			return nil, err
		}
		f.ed = &ed
	}
	if f.ed.EntityID != id {
		return nil, os.ErrNotExist
	}
	return f.ed, nil
}

// federate scopes the IdP's metadata, wraps it and signs it as a
// federation registry does.
func federate(entity []byte, scope string, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(entity); err != nil {
		return nil, err
	}
	ed := doc.Root()
	role := ed.FindElement("./IDPSSODescriptor")
	if role == nil {
		return nil, fmt.Errorf("no IDPSSODescriptor")
	}
	ext := etree.NewElement("Extensions")
	sc := ext.CreateElement("shibmd:Scope")
	sc.CreateAttr("xmlns:shibmd", "urn:mace:shibboleth:metadata:1.0")
	sc.CreateAttr("regexp", "false")
	sc.SetText(scope)
	role.InsertChildAt(0, ext)

	root := etree.NewElement("EntitiesDescriptor")
	root.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
	root.CreateAttr("ID", "_federation")
	root.CreateAttr("validUntil", time.Now().Add(7*24*time.Hour).UTC().Format(time.RFC3339))
	root.AddChild(ed)

	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}))
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, err
	}
	// The schema puts the Signature first; the enveloped transform removes
	// it wherever it is.
	last := len(signed.Child) - 1
	signed.Child = append([]etree.Token{signed.Child[last]}, signed.Child[:last]...)
	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToBytes()
}
