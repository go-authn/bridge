// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-authn/sshcert"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"golang.org/x/crypto/ssh"
)

// The per-client SSH profile (sshprofile.go), judged by OpenSSH's own
// ssh-keygen -L and -Q, jq, x/crypto's CertChecker and, where it runs, a
// real sshd.

// efpFixture is sshFixture with a second client in the EuroHPC Federation
// Platform's profile beside the default one, under the same CA.
func efpFixture(t *testing.T, extra string) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.ToSlash(filepath.Join(dir, "ca"))
	pub, err := generateSSHCA(ca)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, `
certificates_file = "`+filepath.ToSlash(filepath.Join(dir, "certs.json"))+`"
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
ssh_ca {
  key_file = "`+ca+`"
  validity = "8h"
}
client "sftp" {
  device           = true
  ssh_certificates = true
}
client "efp" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"
  ssh_extensions      = ["permit-pty", "permit-agent-forwarding"]
  ssh_source_address  = ["127.0.0.1", "10.0.0.0/8"]
  ssh_validity        = "1h"
  ssh_domain_grants   = ["login.example.org", "*.hpc.example.org"]
}
`+extra)
	f.s.poll = time.Second
	return f, pub
}

// testSSHKey is the same key at every run, so that two certificates for it
// can be compared whole.
func testSSHKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func parseCert(t *testing.T, line []byte) *ssh.Certificate {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatalf("%v: %s", err, line)
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %s", line)
	}
	return c
}

// keygenL is ssh-keygen -L on a certificate, or "" when OpenSSH is absent.
func keygenL(t *testing.T, line []byte) string {
	t.Helper()
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("ssh-keygen is required here")
		}
		return ""
	}
	p := filepath.Join(t.TempDir(), "id-cert.pub")
	os.WriteFile(p, line, 0o644)
	out, err := exec.Command(kg, "-L", "-f", p).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L: %v\n%s", err, out)
	}
	return string(out)
}

var keygenValid = regexp.MustCompile(`Valid: from (\S+) to (\S+)`)

// keygenValidity is how long ssh-keygen -L says the certificate is valid.
func keygenValidity(t *testing.T, out string) time.Duration {
	t.Helper()
	m := keygenValid.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no validity in:\n%s", out)
	}
	from, err1 := time.Parse("2006-01-02T15:04:05", m[1])
	to, err2 := time.Parse("2006-01-02T15:04:05", m[2])
	if err1 != nil || err2 != nil {
		t.Fatalf("validity %q: %v %v", m[0], err1, err2)
	}
	return to.Sub(from)
}

func TestSSHProfileEFP(t *testing.T) {
	f, caLine := efpFixture(t, "")
	pub, _ := testSSHKey()
	cuid := strings.ToLower(alice.subjectID)

	tok := f.deviceToken("efp", "openid", "ssh", "eduperson")
	status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	cert := parseCert(t, body)
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != cuid {
		t.Errorf("principals %q, want [%q]", cert.ValidPrincipals, cuid)
	}
	if got := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; got != time.Hour+sshSkew {
		t.Errorf("valid for %s, want 1h and the skew", got)
	}
	if v, ok := cert.Extensions["permit-pty"]; !ok || v != "" {
		t.Errorf("permit-pty %q %v", v, ok)
	}
	if _, ok := cert.Extensions["permit-agent-forwarding"]; !ok {
		t.Error("no permit-agent-forwarding")
	}
	for _, no := range []string{"permit-port-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if _, ok := cert.Extensions[no]; ok {
			t.Errorf("%s, which the client does not grant", no)
		}
	}
	if got := cert.CriticalOptions["source-address"]; got != "127.0.0.1,10.0.0.0/8" {
		t.Errorf("source-address %q", got)
	}
	// The domain grant, read back by the library sites use: the patterns
	// configured, for the hosting entity's hosts and no other.
	grants, present, err := sshcert.DomainGrant(cert)
	if err != nil || !present || !slices.Equal(grants, []string{"login.example.org", "*.hpc.example.org"}) {
		t.Errorf("domain grant %q present=%v: %v", grants, present, err)
	}
	for host, want := range map[string]bool{"login.example.org": true, "gpu1.hpc.example.org": true, "evil.example.net": false, "hpc.example.org": false} {
		if got := sshcert.Grants(grants, host); got != want {
			t.Errorf("granted on %s: %v, want %v", host, got, want)
		}
	}
	authorizeJudge(t, body, cuid)

	if out := keygenL(t, body); out != "" {
		for _, want := range []string{
			"Type: ssh-ed25519-cert-v01@openssh.com user certificate",
			"Principals: \n                " + cuid + "\n",
			"source-address 127.0.0.1,10.0.0.0/8",
			"permit-pty", "permit-agent-forwarding", GroupsExtension,
			// ssh-keygen does not know GÉANT's extension and prints its
			// data raw: a length, then the compact JSON array, as the
			// specification's test vectors are written -- computed here from
			// the JSON, not from the library that encoded it.
			DomainGrantExtension + " UNKNOWN OPTION: " + specGrantHex(`["login.example.org","*.hpc.example.org"]`),
		} {
			if !strings.Contains(out, want) {
				t.Errorf("ssh-keygen -L does not show %q:\n%s", want, out)
			}
		}
		for _, no := range []string{"permit-port-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
			if strings.Contains(out, no) {
				t.Errorf("ssh-keygen -L shows %s:\n%s", no, out)
			}
		}
		if d := keygenValidity(t, out); d != time.Hour+sshSkew {
			t.Errorf("ssh-keygen -L: valid for %s, want 1h05m", d)
		}
	}

	// The CertChecker go-fileshare uses: the CUID from 127.0.0.1, nobody
	// else, and not from an address outside source-address.
	caKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(caLine))
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return bytes.Equal(k.Marshal(), caKey.Marshal())
	}}
	if _, err := checker.Authenticate(connMeta(cuid), cert); err != nil {
		t.Errorf("CertChecker refused the CUID: %v", err)
	}
	if _, err := checker.Authenticate(connMeta("alice@"+idpScope), cert); err == nil {
		t.Error("the EFP certificate let in the username")
	}

	// Recorded with its principal, and with the username disabling knows.
	st, err := loadCertStore(f.s.cfg.CertificatesFile)
	if err != nil || len(st.Certs) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	if c := st.Certs[0]; c.Principal != "alice@"+idpScope || c.CertPrincipal != cuid || c.Subject == "" {
		t.Errorf("recorded %+v", c)
	}
}

// certStructure is a certificate with what changes at every issuance --
// serial, nonce, signature, CA key, the instant it starts and the token in
// its key ID -- set to fixed values, hashed: two certificates of one
// profile for one key and one person hash the same.
func certStructure(t *testing.T, c *ssh.Certificate) string {
	t.Helper()
	n := *c
	n.Serial, n.Nonce, n.Signature = 0, nil, nil
	n.ValidBefore -= n.ValidAfter
	n.ValidAfter = 0
	n.KeyId = regexp.MustCompile(`sub=\S+ jti=\S+$`).ReplaceAllString(n.KeyId, "sub=SUB jti=JTI")
	fixed, _ := testSSHKey()
	n.SignatureKey, _ = ssh.NewPublicKey(fixed)
	sum := sha256.Sum256(n.Marshal())
	return hex.EncodeToString(sum[:])
}

// defaultCertStructure is certStructure of alice's certificate from the
// default client (validity 8h), MEASURED on origin/main at 97f8361, before
// any profile existed, with this same function: not written by hand.
const defaultCertStructure = "6957b3f80121aaf9d7867457a300aab671b50ec011012ef74c934000273b7c7b"

// An EFP-profile client beside the default one leaves the default one's
// certificate as it was before profiles existed, byte for byte apart from
// serial, nonce, signature and times.
func TestSSHProfileLeavesTheDefaultAlone(t *testing.T) {
	f, _ := efpFixture(t, "")
	pub, _ := testSSHKey()
	efp := f.deviceToken("efp", "openid", "ssh", "eduperson")
	if s, b := certify(t, f, efp.AccessToken, authorizedKey(t, pub)); s != http.StatusOK {
		t.Fatalf("efp: %d %s", s, b)
	}
	tok := f.deviceToken("sftp", "openid", "ssh", "eduperson")
	status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	cert := parseCert(t, body)
	if got := certStructure(t, cert); got != defaultCertStructure {
		t.Errorf("the default client's certificate changed: structure %s, was %s\n%s", got, defaultCertStructure, keygenL(t, body))
	}
	// And the reasons it would have, spelled out.
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice@"+idpScope {
		t.Errorf("principals %q", cert.ValidPrincipals)
	}
	if len(cert.CriticalOptions) != 0 {
		t.Errorf("critical options %v", cert.CriticalOptions)
	}
	if len(cert.Extensions) != 1 || cert.Extensions[GroupsExtension] == "" {
		t.Errorf("extensions %v", cert.Extensions)
	}
	if got := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; got != 8*time.Hour+sshSkew {
		t.Errorf("valid for %s", got)
	}
	// Nor is its record any different.
	st, _ := loadCertStore(f.s.cfg.CertificatesFile)
	for _, c := range st.Certs {
		if c.Serial == "" || c.KeyID != cert.KeyId {
			continue
		}
		if c.CertPrincipal != "" || c.Subject != "" || c.Principal != "alice@"+idpScope {
			t.Errorf("the default client's record %+v", c)
		}
	}
}

func TestSSHProfileRefusals(t *testing.T) {
	f, _ := efpFixture(t, `
client "eppn" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "eduperson_principal_name"
}
client "sub" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "sub"
}
`)
	pub, _ := testSSHKey()
	key := authorizedKey(t, pub)

	// The scope that releases the claim was not granted.
	tok := f.deviceToken("efp", "openid", "ssh")
	if s, b := certify(t, f, tok.AccessToken, key); s != http.StatusForbidden || !strings.Contains(string(b), `the "eduperson" scope`) {
		t.Errorf("voperson_id without the eduperson scope: %d %s", s, b)
	}
	tok = f.deviceToken("eppn", "openid", "ssh")
	if s, b := certify(t, f, tok.AccessToken, key); s != http.StatusForbidden || !strings.Contains(string(b), `the "eduperson" scope`) {
		t.Errorf("eduperson_principal_name without the eduperson scope: %d %s", s, b)
	}

	// The scope was granted, and the IdP released no subject-id.
	noSubjectID := assertionOpts{eppn: "bob@" + idpScope}
	tok = f.deviceTokenAs("efp", noSubjectID, "openid", "ssh", "eduperson")
	if s, b := certify(t, f, tok.AccessToken, key); s != http.StatusForbidden || !strings.Contains(string(b), "released no voperson_id") {
		t.Errorf("no voperson_id: %d %s", s, b)
	}

	// A principal that would be two names to sshd.
	// A subject-id holding one never reaches here (go-authn/saml drops it:
	// measured, "released no voperson_id"), so the eppn, which may.
	comma := assertionOpts{eppn: "root,x@" + idpScope, subjectID: "C3@" + idpScope}
	tok = f.deviceTokenAs("eppn", comma, "openid", "ssh", "eduperson")
	if s, b := certify(t, f, tok.AccessToken, key); s != http.StatusForbidden || !strings.Contains(string(b), "cannot be put in a certificate") {
		t.Errorf("an eppn holding a comma: %d %s", s, b)
	}

	// eduperson_principal_name and sub, where they are released.
	tok = f.deviceToken("eppn", "openid", "ssh", "eduperson")
	if s, b := certify(t, f, tok.AccessToken, key); s != http.StatusOK || parseCert(t, b).ValidPrincipals[0] != alice.eppn {
		t.Errorf("eppn: %d %s", s, b)
	}
	tok = f.deviceToken("sub", "openid", "ssh")
	s, b := certify(t, f, tok.AccessToken, key)
	if s != http.StatusOK {
		t.Fatalf("sub: %d %s", s, b)
	}
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseCert(t, b).ValidPrincipals; len(got) != 1 || got[0] != claims["sub"] {
		t.Errorf("sub: principals %q, sub %v", got, claims["sub"])
	}
}

// GET /ssh/config is the CA key in EFP's shape: what a site's documented
// curl | jq -r '.PublicKey' turns into a TrustedUserCAKeys file.
func TestSSHConfigEndpoint(t *testing.T) {
	f, caLine := efpFixture(t, "")
	res, err := http.Get(f.s.cfg.Issuer + "/ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%s %v %s", res.Status, res.Header, body)
	}
	want := strings.TrimSuffix(caLine, " go-authn-bridge-ca")
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || len(doc) != 1 || doc["PublicKey"] != want {
		t.Errorf("%v %s, want {\"PublicKey\":%q}", err, body, want)
	}

	// jq, as EFP's documentation runs it.
	if jq, err := exec.LookPath("jq"); err == nil {
		cmd := exec.Command(jq, "-r", ".PublicKey")
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.Output()
		if err != nil || string(out) != want+"\n" {
			t.Errorf("jq -r .PublicKey: %v %q", err, out)
		}
		// ssh-keygen reads what jq wrote as a key.
		if kg, err := exec.LookPath("ssh-keygen"); err == nil {
			p := filepath.Join(t.TempDir(), "ca.pub")
			os.WriteFile(p, out, 0o644)
			if o, err := exec.Command(kg, "-l", "-f", p).CombinedOutput(); err != nil || !strings.Contains(string(o), "(ED25519)") {
				t.Errorf("ssh-keygen -l on jq's output: %v %s", err, o)
			}
		}
	} else if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
		t.Fatal("jq is required here")
	}

	// No CA, no endpoint.
	g := newFixture(t, "")
	if res, err := http.Get(g.s.cfg.Issuer + "/ssh/config"); err != nil || res.StatusCode != http.StatusNotFound {
		t.Errorf("without ssh_ca: %v %v", err, res.Status)
	}
}

// Disabling the person revokes their EFP-profile certificate into the KRL,
// by username -- and by their stable identity when they have none.
func TestSSHProfileDisableRevokesIntoTheKRL(t *testing.T) {
	f, _ := efpFixture(t, "")
	pub, _ := testSSHKey()
	key := authorizedKey(t, pub)

	issue := func(o assertionOpts) (*ssh.Certificate, []byte) {
		tok := f.deviceTokenAs("efp", o, "openid", "ssh", "eduperson")
		s, b := certify(t, f, tok.AccessToken, key)
		if s != http.StatusOK {
			t.Fatalf("%d %s", s, b)
		}
		return parseCert(t, b), b
	}
	aliceCert, aliceLine := issue(alice)
	// dave's IdP releases a subject-id and no eppn: no username at all.
	dave := assertionOpts{subjectID: "D4@" + idpScope}
	daveTok := f.deviceTokenAs("efp", dave, "openid", "ssh", "eduperson")
	s, daveLine := certify(t, f, daveTok.AccessToken, key)
	if s != http.StatusOK {
		t.Fatalf("dave: %d %s", s, daveLine)
	}
	daveCert := parseCert(t, daveLine)
	if daveCert.ValidPrincipals[0] != "d4@"+idpScope {
		t.Fatalf("dave's principals %q", daveCert.ValidPrincipals)
	}

	verdict := func(cert *ssh.Certificate, line []byte) string {
		res, err := http.Get(f.s.cfg.Issuer + "/ssh/krl")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		k, err := krl.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		v := "ok"
		if k.IsRevoked(cert) {
			v = "REVOKED"
		}
		if kg, err := exec.LookPath("ssh-keygen"); err == nil {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "krl"), data, 0o644)
			os.WriteFile(filepath.Join(dir, "c-cert.pub"), line, 0o644)
			out, _ := exec.Command(kg, "-Q", "-f", filepath.Join(dir, "krl"), filepath.Join(dir, "c-cert.pub")).CombinedOutput()
			if strings.Contains(string(out), "REVOKED") != (v == "REVOKED") {
				t.Errorf("ssh-keygen -Q says %q, go-authn/krl %s", out, v)
			}
		} else if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("ssh-keygen is required here")
		}
		return v
	}
	if verdict(aliceCert, aliceLine) != "ok" || verdict(daveCert, daveLine) != "ok" {
		t.Fatal("revoked before anybody was disabled")
	}
	// dave has no username: his certificate names nobody to SSF.
	if slices.Contains(f.s.peopleOf(idpEntity), "") {
		t.Errorf("peopleOf lists an empty username: %q", f.s.peopleOf(idpEntity))
	}

	_, r, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{})
	if err != nil || r.certificates != 1 {
		t.Fatalf("disabling alice: %v, %d certificates", err, r.certificates)
	}
	if v := verdict(aliceCert, aliceLine); v != "REVOKED" {
		t.Errorf("alice's EFP certificate after she was disabled: %s", v)
	}
	if v := verdict(daveCert, daveLine); v != "ok" {
		t.Errorf("dave's, when alice was disabled: %s", v)
	}

	// dave is disabled by the sub his client knows him by: the only name
	// he has here.
	claims, err := f.s.cfg.accessKey.verify("at+jwt", daveTok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	_, r, err = f.s.disablePerson(claims["sub"].(string), "test", "test", time.Time{})
	if err != nil || r.certificates != 1 {
		t.Fatalf("disabling dave by sub: %v, %d certificates", err, r.certificates)
	}
	if v := verdict(daveCert, daveLine); v != "REVOKED" {
		t.Errorf("dave's EFP certificate after he was disabled: %s", v)
	}
}

func TestSSHProfileConfig(t *testing.T) {
	c := newConf(t)
	ca := filepath.ToSlash(filepath.Join(c.dir, "ca"))
	if _, err := generateSSHCA(ca); err != nil {
		t.Fatal(err)
	}
	head := c.hcl(nil) + "certificates_file = \"" + c.dir + "/certs.json\"\n" +
		"ssh_ca {\nkey_file = \"" + ca + "\"\nvalidity = \"2h\"\n}\n"
	client := func(body string) string {
		return head + "client \"p\" {\ndevice = true\nssh_certificates = true\n" + body + "\n}\n"
	}
	for name, c2 := range map[string][2]string{
		"an unknown claim":                 {client(`ssh_principal_claim = "email"`), "ssh_principal_claim = \"email\""},
		"an unknown extension":             {client(`ssh_extensions = ["permit-everything"]`), "\"permit-everything\" is not one of"},
		"no-touch-required":                {client(`ssh_extensions = ["no-touch-required"]`), "\"no-touch-required\" is not one of"},
		"a critical option":                {client(`ssh_extensions = ["force-command"]`), "\"force-command\" is not one of"},
		"an extension twice":               {client(`ssh_extensions = ["permit-pty", "permit-pty"]`), "twice"},
		"a validity past the CA's":         {client(`ssh_validity = "3h"`), "longer than the ssh_ca validity"},
		"a validity":                       {client(`ssh_validity = "soon"`), "a positive duration"},
		"a zero validity":                  {client(`ssh_validity = "0s"`), "a positive duration"},
		"a host name":                      {client(`ssh_source_address = ["login.example.org"]`), "not an address or a CIDR prefix"},
		"bits under the mask":              {client(`ssh_source_address = ["10.1.2.3/8"]`), "bits set under its mask"},
		"two in one":                       {client(`ssh_source_address = ["10.0.0.1,10.0.0.2"]`), "not an address or a CIDR prefix"},
		"a zone":                           {client(`ssh_source_address = ["fe80::1%en0"]`), "not an address or a CIDR prefix"},
		"a domain with a comma":            {client(`ssh_domain_grants = ["a.example.org,b.example.org"]`), "contains ','"},
		"an upper-case domain":             {client(`ssh_domain_grants = ["Login.example.org"]`), "lower case"},
		"one label":                        {client(`ssh_domain_grants = ["localhost"]`), "at least two labels"},
		"a top-level wildcard":             {client(`ssh_domain_grants = ["*.eu"]`), "public suffix"},
		"an empty label":                   {client(`ssh_domain_grants = ["login..example.org"]`), "an empty label"},
		"a domain twice":                   {client(`ssh_domain_grants = ["login.example.org", "login.example.org"]`), "twice"},
		"more patterns than a grant holds": {client("ssh_domain_grants = [" + manyGrants(sshcert.MaxPatterns+1) + "]"), "sshcert"},
		"a profile with no ssh":            {head + "client \"p\" {\ndevice = true\nssh_principal_claim = \"voperson_id\"\n}\n", "need ssh_certificates"},
		"extensions with no ssh":           {head + "client \"p\" {\ndevice = true\nssh_extensions = [\"permit-pty\"]\n}\n", "need ssh_certificates"},
		"a validity with no ssh":           {head + "client \"p\" {\ndevice = true\nssh_validity = \"1h\"\n}\n", "need ssh_certificates"},
		"domain grants with no ssh":        {head + "client \"p\" {\ndevice = true\nssh_domain_grants = [\"login.example.org\"]\n}\n", "need ssh_certificates"},
		"a source address no ssh":          {head + "client \"p\" {\ndevice = true\nssh_source_address = [\"10.0.0.0/8\"]\n}\n", "need ssh_certificates"},
	} {
		if _, err := c.load(t, c2[0]); err == nil || !strings.Contains(err.Error(), c2[1]) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c2[1])
		}
	}
	// What is accepted, and what it becomes.
	got, err := c.load(t, client(`
ssh_principal_claim = "voperson_id"
ssh_extensions      = ["permit-pty", "permit-X11-forwarding", "permit-user-rc", "permit-port-forwarding", "permit-agent-forwarding"]
ssh_source_address  = ["192.0.2.7", "2001:DB8::/32"]
ssh_validity        = "2h"
`))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := got.client("p")
	if p.sshValidity != 2*time.Hour || p.SSHSourceAddress[1] != "2001:db8::/32" {
		t.Errorf("validity %s, source %q", p.sshValidity, p.SSHSourceAddress)
	}
	def, err := c.load(t, client(""))
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := def.client("p"); p.SSHPrincipalClaim != "preferred_username" || p.sshValidity != 2*time.Hour {
		t.Errorf("defaults: %q %s", p.SSHPrincipalClaim, p.sshValidity)
	}
	// The domain patterns GÉANT's specification gives as examples are
	// syntactically good: they wait only for the encoder.
	for _, g := range []string{"test.example.com", "*.example.com", "prod-*.example.com", "*.*.example.com", "login.my-hpc.eu"} {
		if err := domainPattern(g); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
}

// The live judge: OpenSSH's sshd, configured as EFP tells a site to be --
// TrustedUserCAKeys from /ssh/config through jq, the CUID in an
// AuthorizedPrincipalsFile -- plus the KRL as RevokedKeys, which EFP has
// none of. It lets the EFP-profile certificate in, and refuses it once the
// person is disabled. Run as whoever runs the tests, so it can only log
// that user in: sshd's own rule, not this test's.
func TestSSHProfileAgainstSSHD(t *testing.T) {
	// A lane that has OpenSSH installed (BRIDGE_REQUIRE_JUDGE, ubuntu in CI)
	// fails rather than skips: a judge that may stay silent proves nothing.
	skip := func(why string) {
		t.Helper()
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatalf("sshd is required here: %s", why)
		}
		t.Skip(why)
	}
	sshd := "/usr/sbin/sshd"
	if runtime.GOOS == "windows" {
		t.Skip("sshd is not run on Windows")
	}
	if _, err := os.Stat(sshd); err != nil {
		skip("no sshd here")
	}
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		skip("no ssh-keygen here")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	f, _ := efpFixture(t, "")
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run(kg, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "host"))

	// The CA key, as the site fetches it.
	res, err := http.Get(f.s.cfg.Issuer + "/ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ PublicKey string }
	json.NewDecoder(res.Body).Decode(&doc)
	res.Body.Close()
	os.WriteFile(filepath.Join(dir, "ca.pub"), []byte(doc.PublicKey+"\n"), 0o644)
	fetchKRL := func() {
		t.Helper()
		res, err := http.Get(f.s.cfg.Issuer + "/ssh/krl")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if err := os.WriteFile(filepath.Join(dir, "krl"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fetchKRL()

	cuid := strings.ToLower(alice.subjectID)
	os.MkdirAll(filepath.Join(dir, "principals"), 0o755)
	os.WriteFile(filepath.Join(dir, "principals", me.Username), []byte(cuid+"\n"), 0o644)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	conf := filepath.Join(dir, "sshd_config")
	os.WriteFile(conf, []byte(strings.Join([]string{
		"ListenAddress " + addr,
		"HostKey " + filepath.Join(dir, "host"),
		"PidFile none",
		"UsePAM no",
		"StrictModes no",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"AuthorizedKeysFile none",
		"TrustedUserCAKeys " + filepath.Join(dir, "ca.pub"),
		"AuthorizedPrincipalsFile " + filepath.Join(dir, "principals", "%u"),
		"RevokedKeys " + filepath.Join(dir, "krl"),
		"LogLevel VERBOSE",
		"",
	}, "\n")), 0o644)
	var log syncWriter
	cmd := exec.Command(sshd, "-D", "-e", "-f", conf)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-exited })

	pub, priv := testSSHKey()
	tok := f.deviceToken("efp", "openid", "ssh", "eduperson")
	status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	login := func() (string, error) {
		signer, _ := ssh.NewSignerFromKey(priv)
		cs, err := ssh.NewCertSigner(parseCert(t, body), signer)
		if err != nil {
			return "", err
		}
		var conn *ssh.Client
		for range 50 { // sshd takes a moment to listen
			conn, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User: me.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)},
				// The host key is made for this test: not what is judged.
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			})
			if err == nil || !strings.Contains(err.Error(), "connection refused") {
				break
			}
			select {
			case <-exited:
				// An sshd that will not run as this user (a missing privilege
				// separation directory, say) is not a verdict on the certificate.
				skip("sshd exited before it listened:\n" + log.String())
			default:
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			return "", err
		}
		defer conn.Close()
		sess, err := conn.NewSession()
		if err != nil {
			return "", err
		}
		defer sess.Close()
		out, err := sess.Output("echo efp-ok")
		return string(out), err
	}
	out, err := login()
	if err != nil || strings.TrimSpace(out) != "efp-ok" {
		t.Fatalf("sshd refused the EFP-profile certificate: %v %q\n%s", err, out, log.String())
	}

	// The principal is what admits: the username alone does not.
	os.WriteFile(filepath.Join(dir, "principals", me.Username), []byte("alice@"+idpScope+"\n"), 0o644)
	if _, err := login(); err == nil {
		t.Errorf("sshd let the certificate in under the username, not the CUID")
	}
	os.WriteFile(filepath.Join(dir, "principals", me.Username), []byte(cuid+"\n"), 0o644)

	// Disabled here; the site fetches the KRL again.
	if _, r, err := f.s.disablePerson("alice@"+idpScope, "test", "test", time.Time{}); err != nil || r.certificates != 1 {
		t.Fatalf("disabling: %v, %d certificates", err, r.certificates)
	}
	fetchKRL()
	if _, err := login(); err == nil {
		t.Errorf("sshd still lets alice in after she was disabled\n%s", log.String())
	} else if !strings.Contains(log.String(), "revoked") {
		t.Errorf("refused, but not for revocation: %v\n%s", err, log.String())
	}
}

// authorizeJudge runs the command a site runs, go-authn/sshcert's
// sshcert-authorize, built from the version this module requires, on the
// certificate the bridge issued: the CUID is let in on a host the grant
// names, and on no other.
func authorizeJudge(t *testing.T, certLine []byte, cuid string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	bin := filepath.Join(t.TempDir(), "sshcert-authorize")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/go-authn/sshcert/cmd/sshcert-authorize").CombinedOutput(); err != nil {
		t.Fatalf("building sshcert-authorize: %v\n%s", err, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte(cuid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(certLine))
	for host, want := range map[string]string{"login.example.org": cuid, "gpu1.hpc.example.org": cuid, "evil.example.net": ""} {
		out, _ := exec.Command(bin, "--syslog=false", "--domain", host, "--principals-dir", dir, "alice", fields[1]).Output()
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("sshcert-authorize on %s printed %q, want %q", host, got, want)
		}
	}
}

// specGrantHex is the domain-grant data as GÉANT's specification writes its
// test vectors: a big-endian uint32 length, then the JSON, in hex.
func specGrantHex(json string) string {
	return fmt.Sprintf("%08x", len(json)) + hex.EncodeToString([]byte(json))
}

// domainPattern applies the specification's syntax itself, not only through
// the encoder that runs after it at load: the two are separate layers, and a
// test that went through both could not tell which refused.
func TestDomainPatternAppliesTheSpecification(t *testing.T) {
	for _, p := range []string{"a.example.org,b.example.org", "a.example.org.", "*", "a b.example.org"} {
		if err := domainPattern(p); err == nil || !errors.Is(err, sshcert.ErrInvalidPattern) {
			t.Errorf("domainPattern(%q) = %v, want sshcert's refusal", p, err)
		}
	}
	for p, want := range map[string]string{
		"Login.example.org": "lower case", "example": "at least two labels",
		"login.*.org": "public suffix", "*.eu": "public suffix", "*.ac.uk": "public suffix",
		"*.gouv.fr": "public suffix", "*.github.io": "public suffix", "gpu-*.co.jp": "public suffix",
	} {
		if err := domainPattern(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("domainPattern(%q) = %v, want %q", p, err, want)
		}
	}
	// Under a registrable domain a wildcard is the hosting entity's own;
	// "a**" is two wildcards of one or more characters each, which the
	// specification allows.
	for _, p := range []string{"login.example.org", "*.hpc.example.org", "gpu-*.hpc.example.org", "*.example.ac.uk", "*.example.org", "a**.example.org"} {
		if err := domainPattern(p); err != nil {
			t.Errorf("domainPattern(%q): %v", p, err)
		}
	}
}

// manyGrants is n distinct valid patterns, as an HCL list body.
func manyGrants(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", fmt.Sprintf("h%d.example.org", i))
	}
	return b.String()
}
