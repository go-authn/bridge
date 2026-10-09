// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confFixture is what a configuration refers to on disk, without the
// federation or xmlsec1: these tests stop at check().
type confFixture struct {
	dir, key, salt, spKey, spCert, fedCert, fp, secret string
}

func newConf(t *testing.T) *confFixture {
	dir := t.TempDir()
	c := &confFixture{dir: dir, key: filepath.Join(dir, "k"), salt: filepath.Join(dir, "s"), secret: filepath.Join(dir, "secret")}
	if err := generateKey(c.key, 2048); err != nil {
		t.Fatal(err)
	}
	if err := generateSalt(c.salt); err != nil {
		t.Fatal(err)
	}
	fed := newParty(t, dir, "fed")
	sp := newParty(t, dir, "sp")
	c.spKey, c.spCert, c.fedCert, c.fp = sp.keyFile, sp.certFile, fed.certFile, fingerprint(fed.cert)
	os.WriteFile(c.secret, []byte("0123456789abcdef-long"), 0o600)
	// Forward slashes: these paths are pasted into HCL strings, where a
	// Windows backslash is an escape. Go opens either spelling.
	for _, p := range []*string{&c.dir, &c.key, &c.salt, &c.spKey, &c.spCert, &c.fedCert, &c.secret} {
		*p = filepath.ToSlash(*p)
	}
	return c
}

func (c *confFixture) hcl(edit func(string) string) string {
	s := `
issuer            = "https://login.example.org/"
signing_key_file  = "` + c.key + `"
subject_salt_file = "` + c.salt + `"
saml {
  key_file             = "` + c.spKey + `"
  cert_file            = "` + c.spCert + `"
  metadata_url         = "https://pub.federation.renater.fr/metadata/fer/idps.xml"
  metadata_cert_file   = "` + c.fedCert + `"
  metadata_fingerprint = "` + c.fp + `"
}
client "web" {
  secret_file   = "` + c.secret + `"
  redirect_uris = ["https://app.example.org/cb"]
}
`
	if edit != nil {
		s = edit(s)
	}
	return s
}

func (c *confFixture) load(t *testing.T, body string) (*config, error) {
	t.Helper()
	p := filepath.Join(c.dir, "bridge.hcl")
	os.WriteFile(p, []byte(body), 0o644)
	cfg, err := loadConfig([]string{p})
	if cfg != nil {
		t.Cleanup(func() { cfg.close() })
	}
	return cfg, err
}

func TestConfigDefaults(t *testing.T) {
	c := newConf(t)
	cfg, err := c.load(t, c.hcl(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://login.example.org" {
		t.Errorf("issuer %q: the trailing slash was kept", cfg.Issuer)
	}
	web, _ := cfg.client("web")
	if cfg.SAML.EntityID != "https://login.example.org/saml" || cfg.Listen != "127.0.0.1:8080" ||
		cfg.Claims.Username != "eppn" || cfg.Claims.Groups[0] != "entitlement" ||
		web.Subject != "public" || web.Audience[0] != "web" || web.Name != "web" || web.public() {
		t.Errorf("defaults: %+v %+v %+v", cfg, cfg.SAML, web)
	}
	if cfg.codeTTL.Minutes() != 1 || cfg.tokenTTL.Hours() != 1 || cfg.idTokenTTL.Minutes() != 5 {
		t.Errorf("lifetimes: %s %s %s", cfg.codeTTL, cfg.tokenTTL, cfg.idTokenTTL)
	}
	if _, ok := cfg.client("nobody"); ok {
		t.Error("an unknown client was found")
	}
}

func TestConfigRefusals(t *testing.T) {
	c := newConf(t)
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("%q is not in the configuration", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	add := func(extra string) func(string) string { return func(s string) string { return s + extra } }
	short := filepath.ToSlash(filepath.Join(c.dir, "short"))
	os.WriteFile(short, []byte("tiny"), 0o600)
	smallKey := filepath.ToSlash(filepath.Join(c.dir, "small.key"))
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	os.WriteFile(smallKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)

	for name, c2 := range map[string]struct {
		edit func(string) string
		want string
	}{
		"http issuer":         {rep(`"https://login.example.org/"`, `"http://login.example.org"`), "https"},
		"issuer with a query": {rep(`"https://login.example.org/"`, `"https://login.example.org/?x=1"`), "no query"},
		"no saml block":       {func(s string) string { return s[:strings.Index(s, "saml {")] + s[strings.Index(s, "client"):] }, "saml block"},
		"a replaced cert":     {rep(c.fp, strings.Repeat("00", 32)), "not the certificate"},
		"no fingerprint":      {rep(`metadata_fingerprint = "`+c.fp+`"`, ``), "required"},
		"discovery and idps": {rep(`saml {`, `saml {
  discovery = "https://discovery.renater.fr/renater"
  idps = ["https://idp.example.org"]`), "discovery"},
		"a username attribute": {add(`claims { username = "cn" }`), "username"},
		"a groups attribute":   {add(`claims { groups = ["roles"] }`), "groups"},
		"no clients":           {func(s string) string { return s[:strings.Index(s, "client")] }, "no client"},
		"a client twice":       {add(`client "web" { redirect_uris = ["https://x.example/cb"] }`), "twice"},
		"a short secret":       {rep(c.secret, short), "guess"},
		"no redirect":          {add(`client "x" {}`), "no redirect_uris"},
		"an http redirect":     {add(`client "x" { redirect_uris = ["http://app.example.org/cb"] }`), "cleartext"},
		"a relative redirect":  {add(`client "x" { redirect_uris = ["/cb"] }`), "absolute"},
		"a fragment":           {add(`client "x" { redirect_uris = ["https://a.example/cb#f"] }`), "fragment"},
		"a refresh lifetime": {add(`client "x" {
  device = true
  refresh_lifetime = "long"
}`), "refresh_lifetime"},
		"a subject type": {add(`client "x" {
  redirect_uris = ["https://a.example/cb"]
  subject = "random"
}`), "public or pairwise"},
		"a ten-minute code":      {add(`code_lifetime = "11m"`), "ten minutes"},
		"a lifetime":             {add(`token_lifetime = "forever"`), "positive duration"},
		"a negative lifetime":    {add(`id_token_lifetime = "-5m"`), "positive duration"},
		"a short salt":           {rep(c.salt, short), "32 are required"},
		"no salt":                {rep(c.salt, c.dir+"/none"), "subject_salt_file"},
		"a 1024-bit signing key": {rep(c.key, smallKey), "2048"},
		"half of TLS":            {add(`cert_file = "x"`), "go together"},
		"not HCL":                {func(string) string { return "issuer = " }, ""},
		"an unknown attribute":   {add(`colour = "blue"`), ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.load(t, c2.edit(c.hcl(nil)))
			if err == nil {
				t.Fatal("ACCEPTED")
			}
			if c2.want != "" && !strings.Contains(err.Error(), c2.want) {
				t.Fatalf("refused, but: %v (want %q)", err, c2.want)
			}
		})
	}
	// ⛔ Not in the table above, because that table asserts on a SUBSTRING of
	// the refusal and an absent file has no portable one: Unix says "no such
	// file or directory", Windows says "The system cannot find the file
	// specified". Asserting the message there tested which operating system
	// ran the test, and failed on windows-latest. The KIND is portable.
	t.Run("a missing secret file", func(t *testing.T) {
		_, err := c.load(t, rep(c.secret, c.dir+"/none")(c.hcl(nil)))
		if err == nil {
			t.Fatal("ACCEPTED")
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("refused, but: %v (want it to wrap fs.ErrNotExist)", err)
		}
	})

	if _, err := loadConfig(nil); err == nil {
		t.Error("no configuration at all")
	}
	if _, err := loadConfig([]string{c.dir + "/missing"}); err == nil {
		t.Error("a missing file")
	}
}

// A directory of .hcl files is read as one, in name order.
func TestConfigDirectory(t *testing.T) {
	c := newConf(t)
	d := filepath.Join(c.dir, "conf.d")
	os.Mkdir(d, 0o755)
	body := c.hcl(nil)
	i := strings.Index(body, "client")
	os.WriteFile(filepath.Join(d, "10-provider.hcl"), []byte(body[:i]), 0o644)
	os.WriteFile(filepath.Join(d, "20-clients.hcl"), []byte(body[i:]), 0o644)
	os.WriteFile(filepath.Join(d, "README"), []byte("not configuration"), 0o644)
	if _, err := loadConfig([]string{d}); err != nil {
		t.Fatal(err)
	}
}

func TestKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	if err := generateKey(p, 2048); err != nil {
		t.Fatal(err)
	}
	if err := generateKey(p, 2048); err == nil {
		t.Error("a signing key was overwritten")
	}
	if err := generateSalt(filepath.Join(dir, "s")); err != nil || generateSalt(filepath.Join(dir, "s")) == nil {
		t.Error("the salt was overwritten, or not written")
	}
	k, err := loadSigningKey(p)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := k.sign("at+jwt", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.verify("at+jwt", tok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"another typ":       "",
		"two parts":         tok[:strings.LastIndex(tok, ".")],
		"a changed body":    tok[:strings.Index(tok, ".")+1] + "eyJhIjoyfQ" + tok[strings.LastIndex(tok, "."):],
		"a bad header":      "!!!" + tok[strings.Index(tok, "."):],
		"a bad signature":   tok[:strings.LastIndex(tok, ".")+1] + "!!!",
		"a header not JSON": "bm90IGpzb24" + tok[strings.Index(tok, "."):],
	} {
		typ := "at+jwt"
		if name == "another typ" {
			typ, bad = "JWT", tok
		}
		if _, err := k.verify(typ, bad); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Keys that are not keys, or not RSA.
	for name, content := range map[string][]byte{
		"not PEM":    []byte("hello"),
		"a cert":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"garbage":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"bad PKCS#1": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}),
	} {
		f := filepath.Join(dir, "bad")
		os.WriteFile(f, content, 0o600)
		if _, err := loadSigningKey(f); err == nil {
			t.Errorf("%s: loaded as a signing key", name)
		}
	}
	if _, err := loadSigningKey(filepath.Join(dir, "none")); err == nil {
		t.Error("a missing key file")
	}
	if !bytes.Contains(jwks(k), []byte(`"alg":"RS256"`)) {
		t.Error("the key set does not say RS256")
	}
}
