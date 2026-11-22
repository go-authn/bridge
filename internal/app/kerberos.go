// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// A Kerberos TGT after a passkey login.
//
// A person whose account holds no password can get no ticket from a KDC by
// the usual means (an AS-REQ proves a long-term key). This endpoint asks the
// realm's KDC, over mutually authenticated TLS, to issue a TGT for the person
// the bearer token is about, and returns it as a KRB-CRED (RFC 4120 5.8) for
// the person's machine to load into its credential cache (Windows:
// KerberosSubmitTicket; go-authn/kinit does it).
//
// ⛔ What the TGT is worth is what the login was worth, so:
//   - the token must carry the "kerberos" scope, which only a client with
//     kerberos_tickets may ask for, and be addressed to this provider (its
//     access audience is the issuer, as for every bridge scope);
//   - the principal is the token's scoped username, user@domain, never a bare
//     name: a bare "alice" of one institution is not the "alice" of another
//     (the same rule x509_ca applies), and the KDC takes the string verbatim
//     and finds it, or not, in its directory;
//   - the lifetime never outlives the IdP's session (session_end) nor the
//     block's validity, at most ten hours: nothing renews a TGT here, a
//     longer-lived credential needs a new login. (The bound is on this
//     endpoint, per ticket: a refresh family is a separate matter, fixed at
//     the login and bounded by session_end for a SAML login, see refresh.go;)
//   - a person disabled, or a token revoked, while the KDC was being asked,
//     gets nothing: the ticket is dropped, as for an SSH or X.509 certificate.
//
// The KDC accepts the request only from this provider's client certificate
// (kerberos.cert_file, whose URI name is the issuer), never from the public.

// kerberosMaxValidity is the longest TGT this provider asks for. It matches
// go-authn/kdc's MaxMintLifetime, which caps it again on its side.
const kerberosMaxValidity = 10 * time.Hour

// kerberosBlock configures the TGT endpoint.
type kerberosBlock struct {
	// KDCURL is the KDC's mint endpoint, an https URL on its internal
	// listener (go-authn/kdc Server.MintHandler).
	KDCURL string `hcl:"kdc_url"`
	// CAFile is the PEM CA that signed the KDC's server certificate.
	CAFile string `hcl:"ca_file"`
	// CertFile and KeyFile are this provider's TLS client certificate for the
	// KDC. Its URI subjectAltName must be what the KDC lists in MintCallers
	// (conventionally the issuer URL).
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
	// Validity is the TGT's lifetime: ten hours by default, never more.
	Validity string `hcl:"validity,optional"`

	validity  time.Duration
	hc        *http.Client
	certName  string    // the client certificate's URI name, else its subject
	certUntil time.Time // its NotAfter
}

// certName is what the KDC lists in MintCallers: the URI subjectAltName, or
// the subject when there is none.
func certName(c *x509.Certificate) string {
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	return c.Subject.String()
}

// shortDuration prints 10h0m0s as 10h and 8h30m0s as 8h30m.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (b *kerberosBlock) load() error {
	u, err := url.Parse(b.KDCURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("kdc_url = %q: an https URL (the TGT's key travels in the answer)", b.KDCURL)
	}
	pemCA, err := os.ReadFile(b.CAFile)
	if err != nil {
		return fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		return fmt.Errorf("ca_file: %s holds no certificate", b.CAFile)
	}
	cert, err := tls.LoadX509KeyPair(b.CertFile, b.KeyFile)
	if err != nil {
		return fmt.Errorf("cert_file and key_file (the key must belong to the certificate): %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("cert_file: %w", err)
	}
	// Like kdcd's check on its mint certificate: a client certificate that
	// expired (or is not valid yet) is refused here, not at the first login.
	if now := time.Now(); now.After(leaf.NotAfter) {
		return fmt.Errorf("cert_file: the client certificate %s expired on %s", certName(leaf), leaf.NotAfter.Format(time.DateOnly))
	} else if now.Before(leaf.NotBefore) {
		return fmt.Errorf("cert_file: the client certificate %s is not valid before %s", certName(leaf), leaf.NotBefore.Format(time.DateOnly))
	}
	b.certName, b.certUntil = certName(leaf), leaf.NotAfter
	b.validity = kerberosMaxValidity
	if b.Validity != "" {
		d, err := time.ParseDuration(b.Validity)
		if err != nil || d < time.Minute {
			return fmt.Errorf("validity = %q: a duration of at least a minute, like \"8h\"", b.Validity)
		}
		if d > kerberosMaxValidity {
			return fmt.Errorf("validity = %s: more than %s", d, kerberosMaxValidity)
		}
		b.validity = d
	}
	b.hc = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert},
		}},
		// A KDC that redirects is not the KDC.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

var errKDCRefused = errors.New("the realm refused")

// mint asks the KDC for a TGT for principal, lasting seconds.
func (b *kerberosBlock) mint(ctx context.Context, principal string, seconds int64) ([]byte, error) {
	body, _ := json.Marshal(struct {
		Principal       string `json:"principal"`
		LifetimeSeconds int64  `json:"lifetime_seconds"`
	}{principal, seconds})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.KDCURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return nil, errKDCRefused
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the KDC answered %s", resp.Status)
	case len(out) < 64 || out[0] != 0x76: // [APPLICATION 22]: a KRB-CRED
		return nil, errors.New("the KDC's answer is not a KRB-CRED")
	}
	return out, nil
}

// kerberosPrincipal is the scoped name the person's TGT is for, "" when there
// is none to be had.
//
// A federated person's preferred_username is their eppn or subject-id, which
// the institution scoped (user@domain). A LOCAL account's is its bare login,
// deliberately never containing an "@" (localaccounts.go), so that no local
// login can be taken for a federated name; its scoped name is the login at the
// local block's scope, which is what eduperson_principal_name says for it. The
// two cannot meet: a federated name has an "@" and a local login never does.
func (s *server) kerberosPrincipal(claims map[string]any) string {
	if machine, ok := s.machineName(claims); ok {
		return machine
	}
	user, _ := claims["preferred_username"].(string)
	if idp, _ := claims["idp"].(string); s.cfg.Local != nil && idp == s.cfg.localEntityID() {
		if user == "" || strings.Contains(user, "@") {
			return "" // cannot happen: a local login never holds an "@"
		}
		user += "@" + s.cfg.Local.Scope
	} else if s.cfg.Local != nil && inLocalScope(s.cfg.Local.Scope, user) {
		// ⛔ A federated token (an old refresh grant, say) in the local scope
		// would be the local account's principal: no ticket.
		return ""
	}
	if at := strings.LastIndex(user, "@"); at < 1 || at == len(user)-1 {
		return ""
	}
	return user
}

// machineName is the principal of a machine identity's token: the client ID at
// the issuer's host (`winpc-17@login.example.org`), and true. A machine token
// (client_credentials with a registered key, ssf.go) has sub = the client ID
// and neither an idp nor a username; a person's sub is an HMAC and always
// comes with an idp. The name is DERIVED from the client the token was issued
// to, never from anything the machine sends, and an ID that holds an "@" or a
// character a principal cannot is refused, so a machine can never be taken for
// a person (people's names carry the "@" of their institution's scope, and a
// machine's carries the issuer's host).
func (s *server) machineName(claims map[string]any) (string, bool) {
	id, _ := claims["client_id"].(string)
	sub, _ := claims["sub"].(string)
	idp, _ := claims["idp"].(string)
	user, _ := claims["preferred_username"].(string)
	if id == "" || sub != id || idp != "" || user != "" {
		return "", false
	}
	if strings.ContainsAny(id, "@/") || certifiableName(id) != nil {
		return "", true // a machine, but with no name a principal can have
	}
	return id + "@" + s.cfg.rpID(), true
}

// kerberosTGT answers POST /kerberos/tgt with a KRB-CRED for the person the
// bearer token is about.
func (s *server) kerberosTGT(w http.ResponseWriter, r *http.Request) {
	kb := s.cfg.Kerberos
	if kb == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	claims, err := s.bearerClaims(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	clientID, _ := claims["client_id"].(string)
	client, ok := s.cfg.client(clientID)
	scope, _ := claims["scope"].(string)
	if !ok || !client.KerberosTickets || !slices.Contains(strings.Fields(scope), "kerberos") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="kerberos"`)
		http.Error(w, "this token may not have a Kerberos ticket issued", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	user := s.kerberosPrincipal(claims)
	if user == "" {
		// A bare name is not a person across institutions.
		http.Error(w, "the institution released no user@domain name to make a principal of", http.StatusForbidden)
		return
	}
	if err := certifiableName(user); err != nil || strings.Contains(user, "/") {
		http.Error(w, "the name cannot be a Kerberos principal", http.StatusForbidden)
		return
	}

	// ⛔ The token is held to the passkey it was bought with, as a refresh
	// grant is: the account having some other key left is not enough.
	jti, _ := claims["jti"].(string)
	_, machine := s.machineName(claims)
	if it, live := s.issued.get(jti); live && !machine && s.refused(it.who()) != "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}

	now := s.now()
	life := kb.validity
	if end, ok := claims["session_end"].(float64); ok && end > 0 {
		// The provider's clock, as everywhere else (s.now), never the host's.
		if d := time.Unix(int64(end), 0).Sub(now); d < life {
			life = d
		}
	}
	if life < time.Minute {
		http.Error(w, "the login ends too soon for a ticket: log in again", http.StatusForbidden)
		return
	}
	cred, err := kb.mint(r.Context(), user, int64(life/time.Second))
	switch {
	case errors.Is(err, errKDCRefused):
		s.logf("kerberos: the realm refused a TGT for %s", user)
		http.Error(w, "the realm does not issue a ticket to this person", http.StatusForbidden)
		return
	case err != nil:
		s.logf("kerberos: asking the KDC for %s: %v", user, err)
		http.Error(w, "the realm could not be reached", http.StatusBadGateway)
		return
	}
	// ⛔ The token was checked when the request started and the KDC took its
	// time: a person disabled or a token revoked since gets nothing. (A TGT
	// cannot be taken back once out; it is the same window every
	// certificate here closes with withdrawn.)
	if it, live := s.issued.get(jti); !live || (!machine && s.refused(it.who()) != "") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	s.counters.inc("bridge_kerberos_tgts_total", "")
	s.logf("kerberos: a TGT for %s, until %s", user, now.Add(life).UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(cred)
}
