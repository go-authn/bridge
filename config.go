// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"golang.org/x/crypto/ssh"
)

// A config is one HCL file, or a directory of them read as one.
type config struct {
	// Issuer is this provider's name, and the URL everything else hangs
	// from: /.well-known/openid-configuration, /authorize, /saml/acs. It is
	// compared WHOLE by every relying party, so it is written once here and
	// never derived from a request's Host header.
	Issuer string `hcl:"issuer"`

	// Listen is where to answer. Loopback by default: the usual shape is a
	// TLS reverse proxy in front, and a provider that appears on every
	// interface the moment it starts is a decision somebody should make on
	// purpose.
	Listen string `hcl:"listen,optional"`

	// CertFile and KeyFile serve TLS directly, re-read when they change
	// (tls.go).
	CertFile string `hcl:"cert_file,optional"`
	KeyFile  string `hcl:"key_file,optional"`

	// ACME serves TLS with a certificate from an ACME CA instead: Let's
	// Encrypt, or GÉANT TCS (HARICA) with External Account Binding.
	ACME *acmeBlock `hcl:"acme,block"`

	// SigningKeyFile is the RSA key that signs tokens (PEM). `bridge keygen`
	// writes one. It is a file, not generated at start: a key that changes
	// at every restart invalidates every token every relying party holds.
	SigningKeyFile string `hcl:"signing_key_file"`

	// RetiredSigningKeyFiles are keys that signed before the current one.
	// They sign nothing any more and stay PUBLISHED, because a verifier can
	// only check a signature whose key it can still fetch: an OpenPubkey PK
	// Token lives a day or a week, long after the ID token inside it
	// expired, and the openpubkey verifier never looks for old keys. Keep a
	// retired key here at least as long as the longest PK Token lifetime any
	// verifier allows.
	RetiredSigningKeyFiles []string `hcl:"retired_signing_key_files,optional"`

	// AccessTokenKeyFile signs access tokens instead of SigningKeyFile: a P-256
	// key, for ES256, whose signature is 86 characters where a 3072-bit RSA
	// one is 512 -- what brings a token under the 1023 characters OpenSSH
	// takes as a keyboard-interactive answer (ssh-oidc). ID tokens stay RS256.
	// `bridge keygen --access-token-key` writes one. A retired one goes in
	// retired_signing_key_files like any other.
	AccessTokenKeyFile string `hcl:"access_token_key_file,optional"`

	// SubjectSaltFile holds the secret that pairwise subjects are derived
	// with. ⛔ Required, and a file: SATOSA generates one at random when it
	// is not configured, and every "sub" then changes at every restart --
	// every relying party sees everybody as a new person.
	SubjectSaltFile string `hcl:"subject_salt_file"`

	// State keeps refresh tokens and the access tokens honoured at /userinfo
	// in a database, so that a restart logs nobody out (state.go). Absent,
	// they live in memory.
	State *stateBlock `hcl:"state,block"`

	// DisabledFile keeps the people and institutions an operator has
	// disabled through the admin API. Without it the API refuses to
	// disable anybody: a restart would forget them.
	DisabledFile string `hcl:"disabled_file,optional"`

	// CertificatesFile records every SSH and X.509 certificate issued, and
	// which are revoked (certstore.go). Required with ssh_ca or x509_ca.
	CertificatesFile string `hcl:"certificates_file,optional"`

	SAML    *samlBlock    `hcl:"saml,block"`
	Claims  *claimsBlock  `hcl:"claims,block"`
	Clients []clientBlock `hcl:"client,block"`

	// SSHCA certifies SSH keys for federated people.
	SSHCA *sshCABlock `hcl:"ssh_ca,block"`

	// X509CA issues X.509 client certificates for NFS over TLS (x509ca.go).
	X509CA *x509CABlock `hcl:"x509_ca,block"`

	// Admin serves the gRPC administration API (proto/bridge/admin/v1).
	// Absent, there is none.
	Admin *adminBlock `hcl:"admin,block"`

	// Metrics serves /healthz, /readyz and /metrics on a listener of its
	// own. Absent, there are none.
	Metrics *metricsBlock `hcl:"metrics,block"`

	// AppPasswords gives federated people a password for the protocols that
	// cannot carry a token: SMB and S3.
	AppPasswords *appPasswordsBlock `hcl:"app_passwords,block"`

	// Lifetimes. The defaults are short on purpose: a bearer token is
	// whoever holds it, and the federation says nothing when somebody
	// leaves.
	CodeLifetime    string `hcl:"code_lifetime,optional"`     // 1m
	TokenLifetime   string `hcl:"token_lifetime,optional"`    // 1h
	IDTokenLifetime string `hcl:"id_token_lifetime,optional"` // 5m

	files []string

	signingKey  *signingKey // ID tokens, and access tokens unless accessKey
	accessKey   *signingKey // access tokens: signingKey, or access_token_key_file
	retiredKeys []*signingKey
	salt        []byte
	metaCert    *x509.Certificate
	codeTTL     time.Duration
	tokenTTL    time.Duration
	idTokenTTL  time.Duration
}

// The SAML side: who this is in the federation, and which federation.
type samlBlock struct {
	// EntityID is this SP's name in the federation. The issuer + "/saml" by
	// default.
	EntityID string `hcl:"entity_id,optional"`

	// KeyFile and CertFile: the SP's key, which IdPs encrypt assertions to.
	KeyFile  string `hcl:"key_file"`
	CertFile string `hcl:"cert_file"`

	// MetadataURL is the federation's IdP metadata:
	// https://pub.federation.renater.fr/metadata/fer/idps.xml for RENATER.
	MetadataURL string `hcl:"metadata_url"`

	// MetadataCertFile is the federation's metadata signing certificate, and
	// MetadataFingerprint its SHA-256 fingerprint as the federation
	// publishes it. ⛔ Both are required: the certificate is checked against
	// the fingerprint at every start, so a file replaced on disk is noticed
	// rather than trusted.
	MetadataCertFile    string `hcl:"metadata_cert_file"`
	MetadataFingerprint string `hcl:"metadata_fingerprint"`

	// Discovery is an external discovery service to send people to, e.g.
	// https://discovery.renater.fr/renater. Without it, this provider shows
	// its own list of IdPs.
	Discovery string `hcl:"discovery,optional"`

	// IdPs restricts login to these entity IDs. Empty is every IdP of the
	// federation. RENATER's discovery service cannot be restricted, so a
	// list here and `discovery` together are refused.
	IdPs []string `hcl:"idps,optional"`

	// Names, Descriptions and the rest go in the SP's metadata, which is
	// what gets registered with the federation.
	Names            map[string]string `hcl:"names,optional"`
	Descriptions     map[string]string `hcl:"descriptions,optional"`
	InformationURL   string            `hcl:"information_url,optional"`
	PrivacyStatement string            `hcl:"privacy_statement_url,optional"`
	Technical        string            `hcl:"technical_contact,optional"`
}

// The administration API's listener.
type adminBlock struct {
	// Listen is unix:///path/to/socket (mode 0600) or host:port. TCP needs
	// the three TLS files -- mutual TLS -- loopback included: every local
	// user can reach 127.0.0.1.
	Listen       string `hcl:"listen"`
	TLSCertFile  string `hcl:"tls_cert_file,optional"`
	TLSKeyFile   string `hcl:"tls_key_file,optional"`
	ClientCAFile string `hcl:"client_ca_file,optional"`
	// Reflection lets grpcurl and friends list the services. Off by default.
	Reflection bool `hcl:"reflection,optional"`
}

// The health and metrics listener.
type metricsBlock struct {
	// Listen is host:port, e.g. 127.0.0.1:9101. Never the public listener.
	Listen string `hcl:"listen"`
}

// An SSH certificate authority.
type sshCABlock struct {
	// KeyFile is the CA's private key in OpenSSH format (`bridge keygen
	// --ssh-ca`). Its public half is what go-fileshare's
	// trusted_user_ca_file holds.
	KeyFile string `hcl:"key_file"`

	// Validity is how long a certificate lives: 12h by default, never
	// longer than the IdP's session when it said when that ends. Revoked
	// ones are listed in /ssh/krl until then, for servers that fetch it.
	Validity string `hcl:"validity,optional"`

	signer   ssh.Signer
	validity time.Duration
}

// How what the IdP said becomes claims.
type claimsBlock struct {
	// Username is the SAML attribute that becomes preferred_username: "eppn"
	// (the default), "subject_id", "uid" or "mail". It is what a relying
	// party such as go-fileshare calls the person.
	Username string `hcl:"username,optional"`

	// Groups are the attributes that become the "groups" claim:
	// "entitlement", "scoped_affiliation", "affiliation", "is_member_of".
	// Entitlements by default.
	Groups []string `hcl:"groups,optional"`
}

// One relying party.
type clientBlock struct {
	ID string `hcl:"id,label"`

	// SecretFile holds the client secret. Without one this is a PUBLIC
	// client -- a single-page app, a command-line tool -- which PKCE
	// protects in place of a secret.
	SecretFile string `hcl:"secret_file,optional"`

	// RedirectURIs are compared EXACTLY (RFC 9700 2.1), except that a
	// loopback redirect may use any port (RFC 8252 7.3), which is how a
	// command-line tool listens.
	RedirectURIs []string `hcl:"redirect_uris,optional"`

	// Audience is what the access token is addressed to, e.g. "fileshare".
	// The client ID when empty.
	Audience []string `hcl:"audience,optional"`

	// Subject is "public" (the same sub for every client, the default) or
	// "pairwise" (a different one per client, OIDC Core 8.1).
	Subject string `hcl:"subject,optional"`

	// Name is shown to people when they are asked to approve a device.
	Name string `hcl:"name,optional"`

	// Device lets this client use the device authorization grant (RFC 8628):
	// a command-line tool or a WebDAV client with no browser of its own shows
	// a code, and the person logs in on any other device. A client that only
	// does this needs no redirect URI.
	Device bool `hcl:"device,optional"`

	// RefreshLifetime turns on refresh tokens, and bounds them: a refresh
	// token lives this long from the LOGIN, however often it is rotated.
	// The federation is not asked again in that time, so this is how long
	// somebody who has left keeps access. Off by default.
	RefreshLifetime string `hcl:"refresh_lifetime,optional"`

	// SSHCertificates lets tokens of this client, with the "ssh" scope, have
	// an SSH public key certified by the ssh_ca block -- which is how a
	// federated person reaches go-fileshare over SFTP.
	SSHCertificates bool `hcl:"ssh_certificates,optional"`

	// X509Certificates lets tokens of this client, with the "nfs" scope,
	// have an X.509 client certificate issued by the x509_ca block -- which
	// is how NFS over TLS (RFC 9289) names a federated person.
	X509Certificates bool `hcl:"x509_certificates,optional"`

	// AppPasswords lets tokens of this client, with the "app_password"
	// scope, set the person's application password.
	AppPasswords bool `hcl:"app_passwords,optional"`

	secret     string
	refreshTTL time.Duration
}

func (c *clientBlock) public() bool { return c.secret == "" }

func loadConfig(paths []string) (*config, error) {
	files, err := hclFiles(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no configuration: give --config a file or a directory of .hcl files")
	}
	p := hclparse.NewParser()
	var bodies []*hcl.File
	for _, f := range files {
		hf, diags := p.ParseHCLFile(f)
		if diags.HasErrors() {
			return nil, diags
		}
		bodies = append(bodies, hf)
	}
	var c config
	body := hcl.MergeFiles(bodies)
	if diags := gohcl.DecodeBody(body, nil, &c); diags.HasErrors() {
		return nil, diags
	}
	c.files = files
	if err := c.check(); err != nil {
		// check may have opened the database before something after it was
		// refused.
		c.close()
		return nil, err
	}
	return &c, nil
}

func hclFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		m, err := filepath.Glob(filepath.Join(p, "*.hcl"))
		if err != nil {
			return nil, err
		}
		slices.Sort(m)
		out = append(out, m...)
	}
	return out, nil
}

// check is everything that can be said wrong about a configuration before
// anybody tries to log in through it.
func (c *config) check() error {
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	// OIDC Core 2: https, no query, no fragment. A trailing slash is
	// dropped, because relying parties compare the issuer whole and half of
	// them strip it.
	if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return fmt.Errorf("issuer %q: an issuer is https (http only on loopback, for testing)", c.Issuer)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return fmt.Errorf("issuer %q: no query, no fragment, and a host", c.Issuer)
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("cert_file and key_file go together")
	}
	if c.ACME != nil {
		if c.CertFile != "" {
			return errors.New("acme and cert_file: one or the other")
		}
		if err := c.ACME.check(c.Issuer); err != nil {
			return fmt.Errorf("acme: %w", err)
		}
	}
	if sc, ok := c.certConfig(func(string, ...any) {}); ok {
		if err := sc.Check(); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}

	if c.signingKey, err = loadSigningKey(c.SigningKeyFile); err != nil {
		return fmt.Errorf("signing_key_file: %w", err)
	}
	if c.signingKey.ec != nil {
		return errors.New("signing_key_file: ID tokens are RS256 (OpenID Connect requires it, OpenPubkey needs it): an RSA key; a P-256 key goes in access_token_key_file")
	}
	c.accessKey = c.signingKey
	if c.AccessTokenKeyFile != "" {
		if c.accessKey, err = loadSigningKey(c.AccessTokenKeyFile); err != nil {
			return fmt.Errorf("access_token_key_file: %w", err)
		}
		if c.accessKey.kid == c.signingKey.kid {
			return errors.New("access_token_key_file is signing_key_file: give it a key of its own, or leave it out")
		}
	}
	for _, f := range c.RetiredSigningKeyFiles {
		k, err := loadSigningKey(f)
		if err != nil {
			return fmt.Errorf("retired_signing_key_files: %w", err)
		}
		if k.kid == c.signingKey.kid || k.kid == c.accessKey.kid {
			return fmt.Errorf("retired_signing_key_files: %s is a current signing key", f)
		}
		c.retiredKeys = append(c.retiredKeys, k)
	}
	if c.salt, err = os.ReadFile(c.SubjectSaltFile); err != nil {
		return fmt.Errorf("subject_salt_file: %w", err)
	}
	if len(c.salt) < 32 {
		return fmt.Errorf("subject_salt_file: %d bytes, where 32 are required", len(c.salt))
	}

	for name, spec := range map[string]struct {
		in  string
		def time.Duration
		out *time.Duration
	}{
		"code_lifetime":     {c.CodeLifetime, time.Minute, &c.codeTTL},
		"token_lifetime":    {c.TokenLifetime, time.Hour, &c.tokenTTL},
		"id_token_lifetime": {c.IDTokenLifetime, 5 * time.Minute, &c.idTokenTTL},
	} {
		*spec.out = spec.def
		if spec.in != "" {
			d, err := time.ParseDuration(spec.in)
			if err != nil || d <= 0 {
				return fmt.Errorf("%s = %q: a positive duration like \"1h\"", name, spec.in)
			}
			*spec.out = d
		}
	}
	// RFC 6749 4.1.2: a code lives ten minutes at most.
	if c.codeTTL > 10*time.Minute {
		return fmt.Errorf("code_lifetime = %s: an authorization code lives ten minutes at most", c.codeTTL)
	}

	if c.SAML == nil {
		return errors.New("a saml block is required: it is where people log in")
	}
	s := c.SAML
	if s.EntityID == "" {
		s.EntityID = c.Issuer + "/saml"
	}
	if s.MetadataCertFile == "" || s.MetadataFingerprint == "" {
		return errors.New("saml: metadata_cert_file and metadata_fingerprint are both required")
	}
	if c.metaCert, err = pinnedCert(s.MetadataCertFile, s.MetadataFingerprint); err != nil {
		return fmt.Errorf("saml: %w", err)
	}
	if s.Discovery != "" && len(s.IdPs) > 0 {
		return errors.New("saml: an external discovery service lists every IdP; with `idps` restricted, leave `discovery` out and this provider lists them itself")
	}
	if len(s.Names) == 0 {
		s.Names = map[string]string{"en": u.Host}
	}

	if c.Claims == nil {
		c.Claims = &claimsBlock{}
	}
	if c.Claims.Username == "" {
		c.Claims.Username = "eppn"
	}
	if _, ok := usernameAttributes[c.Claims.Username]; !ok {
		return fmt.Errorf("claims: username %q: one of eppn, subject_id, uid, mail", c.Claims.Username)
	}
	if c.Claims.Groups == nil {
		c.Claims.Groups = []string{"entitlement"}
	}
	for _, g := range c.Claims.Groups {
		if _, ok := groupAttributes[g]; !ok {
			return fmt.Errorf("claims: groups %q: one of entitlement, scoped_affiliation, affiliation, is_member_of", g)
		}
	}

	if c.SSHCA != nil && c.CertificatesFile == "" {
		return fmt.Errorf("ssh_ca: %w", errNoCertStore)
	}
	if c.X509CA != nil {
		if c.CertificatesFile == "" {
			return fmt.Errorf("x509_ca: %w", errNoCertStore)
		}
		if err := c.X509CA.load(); err != nil {
			return fmt.Errorf("x509_ca: %w", err)
		}
	}
	if c.SSHCA != nil {
		if err := c.SSHCA.load(); err != nil {
			return fmt.Errorf("ssh_ca: %w", err)
		}
	}

	if a := c.Admin; a != nil {
		if !haveGRPC {
			return errors.New("admin: this binary was built with -tags nogrpc, and would start without the API the configuration asks for")
		}
		// TCP without all three TLS files -- loopback included, since every
		// local user can reach it -- unix with any of them, a relative socket
		// path, an unknown scheme: grpc-transports/control's rules.
		if err := checkAdmin(a); err != nil {
			return fmt.Errorf("admin: %w", err)
		}
	}
	if m := c.Metrics; m != nil {
		if _, _, err := net.SplitHostPort(m.Listen); err != nil {
			return fmt.Errorf("metrics: listen = %q: host:port", m.Listen)
		}
		if m.Listen == c.Listen {
			return errors.New("metrics: listen is the public listener; metrics have one of their own")
		}
	}
	if c.State != nil {
		if err := c.State.check(); err != nil {
			return fmt.Errorf("state: %w", err)
		}
	}
	if c.AppPasswords != nil {
		if err := c.AppPasswords.check(); err != nil {
			return fmt.Errorf("app_passwords: %w", err)
		}
	}

	if len(c.Clients) == 0 {
		return errors.New("no client block: nobody could ask this provider for anything")
	}
	seen := map[string]bool{}
	for i := range c.Clients {
		cl := &c.Clients[i]
		if seen[cl.ID] {
			return fmt.Errorf("client %q is declared twice", cl.ID)
		}
		seen[cl.ID] = true
		if cl.SecretFile != "" {
			b, err := os.ReadFile(cl.SecretFile)
			if err != nil {
				return fmt.Errorf("client %q: %w", cl.ID, err)
			}
			cl.secret = strings.TrimSpace(string(b))
			if len(cl.secret) < 16 {
				return fmt.Errorf("client %q: a secret of %d characters is a password somebody can guess", cl.ID, len(cl.secret))
			}
		}
		if len(cl.RedirectURIs) == 0 && !cl.Device {
			return fmt.Errorf("client %q: no redirect_uris, and not a device client", cl.ID)
		}
		if cl.RefreshLifetime != "" {
			d, err := time.ParseDuration(cl.RefreshLifetime)
			if err != nil || d <= 0 {
				return fmt.Errorf("client %q: refresh_lifetime = %q: a positive duration like \"720h\"", cl.ID, cl.RefreshLifetime)
			}
			cl.refreshTTL = d
		}
		for _, r := range cl.RedirectURIs {
			ru, err := url.Parse(r)
			if err != nil || !ru.IsAbs() || ru.Fragment != "" {
				return fmt.Errorf("client %q: redirect URI %q is not an absolute URI without a fragment", cl.ID, r)
			}
			if ru.Scheme == "http" && !loopbackHost(ru.Hostname()) {
				return fmt.Errorf("client %q: redirect URI %q: a code sent over cleartext http is a code anybody on the path has", cl.ID, r)
			}
		}
		if cl.AppPasswords && c.AppPasswords == nil {
			return fmt.Errorf("client %q: app_passwords needs an app_passwords block", cl.ID)
		}
		if cl.SSHCertificates && c.SSHCA == nil {
			return fmt.Errorf("client %q: ssh_certificates needs an ssh_ca block", cl.ID)
		}
		if cl.X509Certificates && c.X509CA == nil {
			return fmt.Errorf("client %q: x509_certificates needs an x509_ca block", cl.ID)
		}
		switch cl.Subject {
		case "":
			cl.Subject = "public"
		case "public", "pairwise":
		default:
			return fmt.Errorf("client %q: subject %q: public or pairwise", cl.ID, cl.Subject)
		}
		if len(cl.Audience) == 0 {
			cl.Audience = []string{cl.ID}
		}
		if cl.Name == "" {
			cl.Name = cl.ID
		}
	}
	return nil
}

func (c *config) client(id string) (*clientBlock, bool) {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i], true
		}
	}
	return nil, false
}

// pinnedCert reads a certificate and refuses it unless its SHA-256
// fingerprint is the one given, in any of the usual spellings.
func pinnedCert(file, fingerprint string) (*x509.Certificate, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a PEM certificate", file)
	}
	sum := sha256.Sum256(blk.Bytes)
	want := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(fingerprint))
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%s is not the certificate with fingerprint %s", file, fingerprint)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// close releases what the configuration opened: the application passwords'
// database. A *sql.DB left open is a file Windows will not delete and a
// connection pool a server never gives back.
func (c *config) close() error {
	var err error
	if c.AppPasswords != nil && c.AppPasswords.db != nil {
		err = c.AppPasswords.db.Close()
	}
	if c.State != nil && c.State.db != nil {
		err = errors.Join(err, c.State.db.Close())
	}
	return err
}
