// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido/mds"
	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

// The proof of an administrator's passkey model (attest.go): a signed FIDO
// metadata blob the test makes, an attestation authority it lists for the
// YubiKey Bio, and registrations signed under it.

func tKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func tCert(t testing.TB, tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type pkiCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t testing.TB, cn string, base time.Time, parent *pkiCA, crl string) pkiCA {
	t.Helper()
	k := tKey(t)
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: cn},
		NotBefore: base.AddDate(-1, 0, 0), NotAfter: base.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if crl != "" {
		tpl.CRLDistributionPoints = []string{crl}
	}
	if parent == nil {
		return pkiCA{tCert(t, tpl, tpl, &k.PublicKey, k), k}
	}
	return pkiCA{tCert(t, tpl, parent.cert, &k.PublicKey, parent.key), k}
}

func newAttCA(t testing.TB, base time.Time) pkiCA {
	return newTestCA(t, "Test Attestation Root", base, nil, "")
}

// leaf is an attestation certificate for model aaguid, as §8.2.1 asks.
func (ca pkiCA) leaf(t testing.TB, base time.Time, aaguid [16]byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return ca.leafExt(t, base, &aaguid)
}

// leafExt is leaf with the id-fido-gen-ce-aaguid extension carrying ext, or
// without the extension when ext is nil.
func (ca pkiCA) leafExt(t testing.TB, base time.Time, ext *[16]byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := tKey(t)
	var extra []pkix.Extension
	if ext != nil {
		v, _ := asn1.Marshal(ext[:])
		extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: v}}
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject: pkix.Name{Country: []string{"SE"}, Organization: []string{"Yubico AB"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Attestation"},
		NotBefore: base.AddDate(-1, 0, 0), NotAfter: base.AddDate(5, 0, 0),
		BasicConstraintsValid: true,
		ExtraExtensions:       extra,
	}
	return tCert(t, tpl, ca.cert, &k.PublicKey, ca.key), k
}

func aaguidBytes(t testing.TB, s string) [16]byte {
	t.Helper()
	var out [16]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		t.Fatalf("aaguid %q", s)
	}
	copy(out[:], raw)
	return out
}

// testMDS is the FIDO metadata service: a signed blob under a root, an
// intermediate and a leaf for mds.Hostname, each with a CRL.
type testMDS struct {
	t                          testing.TB
	now                        func() time.Time
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey *ecdsa.PrivateKey
	crls                       map[string][]byte

	mu       sync.Mutex
	entries  []string
	no       int
	nextDate string
	err      error
}

const (
	testRootCRL  = "http://crl.test/root.crl"
	testInterCRL = "http://crl.test/inter.crl"
)

func newTestMDS(t testing.TB, now func() time.Time) *testMDS {
	t.Helper()
	base := now()
	root := newTestCA(t, "Test MDS Root", base, nil, "")
	inter := newTestCA(t, "Test MDS Intermediate", base, &root, testRootCRL)
	lk := tKey(t)
	leaf := tCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: mds.Hostname}, DNSNames: []string{mds.Hostname},
		NotBefore: base.AddDate(-1, 0, 0), NotAfter: base.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{testInterCRL},
	}, inter.cert, &lk.PublicKey, inter.key)
	m := &testMDS{
		t: t, now: now, root: root.cert, inter: inter.cert, leaf: leaf,
		rootKey: root.key, interKey: inter.key, leafKey: lk, crls: map[string][]byte{},
		nextDate: base.AddDate(0, 0, 30).UTC().Format("2006-01-02"),
	}
	m.crls[testRootCRL] = m.crl(root, base)
	m.crls[testInterCRL] = m.crl(inter, base)
	return m
}

func (m *testMDS) crl(issuer pkiCA, base time.Time) []byte {
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: base.AddDate(0, 0, -1), NextUpdate: base.AddDate(0, 0, 400),
	}, issuer.cert, issuer.key)
	if err != nil {
		m.t.Fatal(err)
	}
	return der
}

// entry is the metadata of one model: its roots and one status report.
func (m *testMDS) entry(aaguid, status string, roots ...*x509.Certificate) string {
	var rs []string
	for _, r := range roots {
		rs = append(rs, base64.StdEncoding.EncodeToString(r.Raw))
	}
	b, err := json.Marshal(map[string]any{
		"aaguid":            aaguid,
		"metadataStatement": map[string]any{"description": "Test model", "attestationRootCertificates": rs},
		"statusReports":     []map[string]string{{"status": status, "effectiveDate": "2024-06-06"}},
	})
	if err != nil {
		m.t.Fatal(err)
	}
	return string(b)
}

// set replaces the entries of the blob, under the next serial number.
func (m *testMDS) set(entries ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = entries
	m.no++
}

func (m *testMDS) fail(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

func (m *testMDS) fetch(string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var es []json.RawMessage
	for _, e := range m.entries {
		es = append(es, json.RawMessage(e))
	}
	payload, err := json.Marshal(map[string]any{"legalHeader": "legal", "no": m.no, "nextUpdate": m.nextDate, "entries": es})
	if err != nil {
		return nil, err
	}
	x5c := []string{base64.StdEncoding.EncodeToString(m.leaf.Raw), base64.StdEncoding.EncodeToString(m.inter.Raw)}
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "x5c": x5c})
	signed := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, m.leafKey, sum[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return []byte(signed + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}

// verifier reads this service, with its root, its CRLs and the test's clock.
func (m *testMDS) verifier(t testing.TB, dir string, logf func(string, ...any)) *attestVerifier {
	pool := x509.NewCertPool()
	pool.AddCert(m.root)
	return &attestVerifier{
		client: &mds.Client{Dir: dir, Fetch: m.fetch, Options: mds.Options{
			Roots: pool, Now: m.now,
			CRL: func(u string) ([]byte, error) {
				if der, ok := m.crls[u]; ok {
					return der, nil
				}
				return nil, errors.New("no such CRL " + u)
			},
		}},
		now:  m.now,
		logf: logf,
	}
}

// load makes v read the blob as it now is.
func (m *testMDS) load(v *attestVerifier) {
	m.t.Helper()
	f := 0
	v.refresh(context.Background(), true, &f)
	if v.current() == nil {
		m.t.Fatal("the metadata did not load")
	}
}

// packedAO is the attestationObject of a registration by a, with model aaguid
// and a packed statement signed by key, carrying the chain x5c.
func packedAO(t testing.TB, a *webauthntest.Authenticator, rpID string, cd []byte, aaguid [16]byte, key *ecdsa.PrivateKey, x5c ...[]byte) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(rpID))
	ad := append([]byte(nil), h[:]...)
	ad = append(ad, 0x5d) // UP, UV, BE, BS, AT
	ad = binary.BigEndian.AppendUint32(ad, 0)
	ad = append(ad, aaguid[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.ID)))
	ad = append(ad, a.ID...)
	ad = append(ad, a.COSE...)
	ch := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte(nil), ad...), ch[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := em.Marshal(map[string]any{
		"fmt":      "packed",
		"attStmt":  map[string]any{"alg": -7, "sig": sig, "x5c": x5c},
		"authData": ad,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// makeAO builds the attestationObject of a registration, given the authenticator
// and the clientDataJSON the browser would have sent.
type makeAO func(a *webauthntest.Authenticator, cd []byte) []byte

// attestedBy is a packed statement by an attestation certificate of ca for
// model aaguid.
func (e *adminEnv) attestedBy(ca pkiCA, aaguid string) makeAO {
	return func(a *webauthntest.Authenticator, cd []byte) []byte {
		id := aaguidBytes(e.t, aaguid)
		leaf, key := ca.leaf(e.t, e.s.now(), id)
		return packedAO(e.t, a, e.s.cfg.rpID(), cd, id, key, leaf.Raw)
	}
}

// attestedByExt is attestedBy with a leaf whose id-fido-gen-ce-aaguid carries
// ext (nil: the leaf has no such extension).
func (e *adminEnv) attestedByExt(ca pkiCA, aaguid string, ext *[16]byte) makeAO {
	return func(a *webauthntest.Authenticator, cd []byte) []byte {
		id := aaguidBytes(e.t, aaguid)
		leaf, key := ca.leafExt(e.t, e.s.now(), ext)
		return packedAO(e.t, a, e.s.cfg.rpID(), cd, id, key, leaf.Raw)
	}
}

// noAttestation is what a browser asked for "none" sends.
func noAttestation(e *adminEnv) makeAO {
	return func(a *webauthntest.Authenticator, cd []byte) []byte {
		_, ao := a.Register(e.s.cfg.rpID(), e.s.cfg.origin(), challengeOf(e.t, cd), webauthntest.Options{})
		return ao
	}
}

// challengeOf is the challenge a clientDataJSON carries.
func challengeOf(t testing.TB, cd []byte) []byte {
	t.Helper()
	var c struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(cd, &c); err != nil {
		t.Fatal(err)
	}
	ch, err := base64.RawURLEncoding.DecodeString(c.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// enrolAs runs login's invitation to the end with the registration mk makes. It
// returns the finish's status, whether the answer says the model was proved,
// and the attestation conveyance the begin asked for.
func (e *adminEnv) enrolAs(login string, mk makeAO) (status int, attested bool, convey string, a *webauthntest.Authenticator) {
	e.t.Helper()
	a = mustAuth(e.t, webauthn.AlgES256)
	b := newBrowser(e.t)
	st, h, ch, pk := e.enrollBegin(b, e.invite(login))
	if st != http.StatusOK {
		e.t.Fatalf("begin: %d", st)
	}
	convey, _ = pk["attestation"].(string)
	cd, _ := a.Register(e.s.cfg.rpID(), e.s.cfg.origin(), ch, webauthntest.Options{})
	res := e.postJSON(b, "/local/enroll/finish", map[string]any{
		"handle": h, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(mk(a, cd)), "transports": []string{"usb"},
	})
	body := readBody(res)
	var ans struct {
		Attested bool `json:"attested"`
	}
	json.Unmarshal([]byte(body), &ans)
	return res.StatusCode, ans.Attested, convey, a
}

func (e *adminEnv) provenModel(a *webauthntest.Authenticator) string {
	e.t.Helper()
	rec, ok, err := e.s.passkeys.passkey(passkeyKey(a.ID))
	if err != nil || !ok {
		e.t.Fatalf("the key is not stored: %v", err)
	}
	return rec.AttestedAAGUID
}

// The whole path: an administrator registers a YubiKey Bio whose attestation
// leads to the root the metadata lists; the key is stored as PROVEN, and it
// opens the administrator page.
func TestAnAdministratorsAttestedKeyIsProvedAndOpensThePage(t *testing.T) {
	e := newAdminEnv(t)
	st, attested, convey, a := e.enrolAs("carol", e.attestedBy(e.attCA, yubikeyBio))
	if st != http.StatusOK || !attested || convey != "direct" {
		t.Fatalf("status %d, attested %v, attestation asked %q\n%s", st, attested, convey, e.log())
	}
	if got := e.provenModel(a); got != yubikeyBio {
		t.Fatalf("proven model %q, want %q", got, yubikeyBio)
	}
	rec, _, _ := e.s.passkeys.passkey(passkeyKey(a.ID))
	sess := e.forge("carol", rec.key())
	if st, body := e.invitePost(sess, "erin", "erin@elsewhere.example", "Erin"); st != http.StatusOK {
		t.Fatalf("the proven key does not open the page: %d %s", st, body)
	}
	// Everybody else is asked for "none": the browser asks them nothing.
	b := newBrowser(t)
	if _, _, _, pk := e.enrollBegin(b, e.invite("dave")); pk["attestation"] != "none" {
		t.Errorf("a non-administrator is asked for attestation %v", pk["attestation"])
	}
}

// Every statement that does not PROVE the model: the key is still enrolled
// (it signs in), but it is not marked as proven, and the log says why.
func TestAKeyThatDoesNotProveItsModelIsStoredUnproved(t *testing.T) {
	other := func(e *adminEnv) pkiCA { return newAttCA(e.t, e.s.now()) }
	for _, c := range []struct {
		name  string
		setup func(e *adminEnv) makeAO
		why   string
	}{
		{"no attestation", func(e *adminEnv) makeAO { return noAttestation(e) }, "prove no model"},
		{"a chain to a root the metadata does not list", func(e *adminEnv) makeAO {
			return e.attestedBy(other(e), yubikeyBio)
		}, "does not lead to a root"},
		{"a leaf without the id-fido-gen-ce-aaguid extension", func(e *adminEnv) makeAO {
			return e.attestedByExt(e.attCA, yubikeyBio, nil)
		}, "id-fido-gen-ce-aaguid"},
		{"a model the metadata does not know", func(e *adminEnv) makeAO {
			return e.attestedBy(e.attCA, someOtherAA)
		}, "is not in the FIDO metadata"},
		{"a model the metadata reports revoked", func(e *adminEnv) makeAO {
			e.mds.set(e.mds.entry(yubikeyBio, "REVOKED", e.attCA.cert))
			e.mds.load(e.s.attest)
			return e.attestedBy(e.attCA, yubikeyBio)
		}, "REVOKED"},
		{"a model whose attestation key is reported compromised", func(e *adminEnv) makeAO {
			e.mds.set(e.mds.entry(yubikeyBio, "ATTESTATION_KEY_COMPROMISE", e.attCA.cert))
			e.mds.load(e.s.attest)
			return e.attestedBy(e.attCA, yubikeyBio)
		}, "ATTESTATION_KEY_COMPROMISE"},
		{"no metadata loaded", func(e *adminEnv) makeAO {
			e.s.attest = e.mds.verifier(e.t, e.t.TempDir(), e.s.logf)
			return e.attestedBy(e.attCA, yubikeyBio)
		}, "not loaded"},
		{"metadata past its nextUpdate", func(e *adminEnv) makeAO {
			e.advance(40 * 24 * time.Hour)
			return e.attestedBy(e.attCA, yubikeyBio)
		}, "expired"},
		{"a root the metadata lists that is not a certificate", func(e *adminEnv) makeAO {
			bad, err := json.Marshal(map[string]any{
				"aaguid":            yubikeyBio,
				"metadataStatement": map[string]any{"description": "Test model", "attestationRootCertificates": []string{"AAAA"}},
				"statusReports":     []map[string]string{{"status": "FIDO_CERTIFIED", "effectiveDate": "2024-06-06"}},
			})
			if err != nil {
				e.t.Fatal(err)
			}
			e.mds.set(string(bad))
			e.mds.load(e.s.attest)
			return e.attestedBy(e.attCA, yubikeyBio)
		}, "the roots the FIDO metadata lists"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newAdminEnv(t)
			st, attested, _, a := e.enrolAs("carol", c.setup(e))
			if st != http.StatusOK || attested {
				t.Fatalf("status %d, attested %v", st, attested)
			}
			if got := e.provenModel(a); got != "" {
				t.Errorf("the key is marked proven: %q", got)
			}
			if !strings.Contains(e.log(), "WITHOUT a proven model") || !strings.Contains(e.log(), c.why) {
				t.Errorf("the log does not say why (%q):\n%s", c.why, e.log())
			}
		})
	}
}

// A registration that does not verify is refused for an administrator too: the
// failure is not swallowed into "stored without a proven model".
func TestAnAdministratorsBrokenRegistrationIsRefusedNotStored(t *testing.T) {
	e := newAdminEnv(t)
	st, attested, _, a := e.enrolAs("carol", func(*webauthntest.Authenticator, []byte) []byte { return []byte("not cbor") })
	if st == http.StatusOK || attested {
		t.Fatalf("a broken registration was accepted: %d %v", st, attested)
	}
	if _, ok, _ := e.s.passkeys.passkey(passkeyKey(a.ID)); ok {
		t.Fatal("a broken registration was stored")
	}
}

// verifyEnrolment itself answers a registration that does not verify with the
// error, for an administrator and for everybody else, and proves nothing.
func TestVerifyEnrolmentReturnsTheVerificationError(t *testing.T) {
	e := newAdminEnv(t)
	for _, login := range []string{"carol", "dave"} {
		cred, id, err := e.s.verifyEnrolment(login, []byte("challenge"), []byte("{}"), []byte("not cbor"))
		if err == nil || id != "" || len(cred.ID) != 0 {
			t.Errorf("%s: cred %v, proven %q, error %v", login, cred, id, err)
		}
	}
}

// A key that proved no model is refused by the administrator page with the
// reason for that, not the one for a model since revoked.
func TestAnUnprovedKeyIsRefusedForItsMissingProof(t *testing.T) {
	e := newAdminEnv(t)
	st, _, _, a := e.enrolAs("carol", noAttestation(e))
	if st != http.StatusOK {
		t.Fatalf("enrol: %d", st)
	}
	rec, _, _ := e.s.passkeys.passkey(passkeyKey(a.ID))
	sess := e.forge("carol", rec.key())
	st, body := e.invitePost(sess, "erin", "erin@elsewhere.example", "Erin")
	if st == http.StatusOK {
		t.Fatal("an unproved key opened the page")
	}
	if !strings.Contains(body+e.log(), "verified attestation") {
		t.Fatalf("the refusal does not name the missing proof: %d %s\n%s", st, body, e.log())
	}
}

// A key proved before its model was reported compromised stops opening the
// page, and opens it again when the report is gone; so does a blob that is no
// longer current.
func TestAProvedModelMustStillBeTrustedWhenTheKeyOpensThePage(t *testing.T) {
	e := newAdminEnv(t)
	rec, _, _ := e.s.passkeys.passkey(passkeyKey(e.alice.ID))
	logins := []string{"erin", "fred", "gina", "hugo", "ivan"}
	try := func() (int, string) {
		e.resetThrottle()
		login := logins[0] // each invitation creates an account
		logins = logins[1:]
		return e.invitePost(e.forge("alice", rec.key()), login, login+"@elsewhere.example", "")
	}
	if st, body := try(); st != http.StatusOK {
		t.Fatalf("before: %d %s", st, body)
	}
	e.mds.set(e.mds.entry(yubikeyBio, "USER_KEY_PHYSICAL_COMPROMISE", e.attCA.cert))
	e.mds.load(e.s.attest)
	if st, body := try(); st != http.StatusForbidden {
		t.Fatalf("a compromised model: %d %s", st, body)
	}
	if !strings.Contains(e.log(), "USER_KEY_PHYSICAL_COMPROMISE") {
		t.Errorf("the log does not say why:\n%s", e.log())
	}
	e.mds.set(e.mds.entry(yubikeyBio, "FIDO_CERTIFIED_L1", e.attCA.cert))
	e.mds.load(e.s.attest)
	if st, body := try(); st != http.StatusOK {
		t.Fatalf("after the report is gone: %d %s", st, body)
	}
	e.advance(40 * 24 * time.Hour) // past nextUpdate, nothing reloaded
	if st, body := try(); st != http.StatusForbidden {
		t.Fatalf("expired metadata: %d %s", st, body)
	}
	e.s.attest = nil
	if st, _ := try(); st != http.StatusForbidden {
		t.Fatalf("no metadata at all: %d", st)
	}
}

// An administrator adds a key from the account page: the same proof.
func TestAnAdministratorAddsAProvedKeyFromTheAccountPage(t *testing.T) {
	e := newAdminEnv(t)
	for _, c := range []struct {
		name string
		mk   makeAO
		want bool
	}{{"attested", e.attestedBy(e.attCA, yubikeyBio), true}, {"none", noAttestation(e), false}} {
		e.resetThrottle()
		res := e.accountReq("POST", "/account/add/begin", e.sess.cookie, map[string]string{"csrf": e.sess.csrf})
		var o struct {
			Handle    string         `json:"handle"`
			PublicKey map[string]any `json:"publicKey"`
		}
		if err := json.Unmarshal([]byte(readBody(res)), &o); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("%s: begin %d %v", c.name, res.StatusCode, err)
		}
		if o.PublicKey["attestation"] != "direct" {
			t.Errorf("%s: attestation asked %v", c.name, o.PublicKey["attestation"])
		}
		a := mustAuth(t, webauthn.AlgES256)
		cd, _ := a.Register(e.s.cfg.rpID(), e.s.cfg.origin(), decB64(t, o.PublicKey["challenge"].(string)), webauthntest.Options{})
		res = e.accountReq("POST", "/account/add/finish", e.sess.cookie, map[string]any{
			"csrf": e.sess.csrf, "handle": o.Handle, "id": b64(a.ID), "clientDataJSON": b64(cd), "attestationObject": b64(c.mk(a, cd)),
		})
		var ans struct {
			Attested bool `json:"attested"`
		}
		body := readBody(res)
		json.Unmarshal([]byte(body), &ans)
		if res.StatusCode != http.StatusOK || ans.Attested != c.want {
			t.Fatalf("%s: %d %s", c.name, res.StatusCode, body)
		}
		if got := e.provenModel(a); (got == yubikeyBio) != c.want {
			t.Errorf("%s: proven model %q", c.name, got)
		}
	}
}

// Self attestation proves nothing, whatever model it claims.
func TestSelfAttestationProvesNoModel(t *testing.T) {
	e := newAdminEnv(t)
	for _, att := range []webauthn.Attestation{
		{Format: "packed", Type: webauthn.AttestationSelf, AAGUID: aaguidBytes(t, yubikeyBio)},
		{Format: "none", Type: webauthn.AttestationNone},
	} {
		if id, err := e.s.attest.prove(att); err == nil || id != "" {
			t.Errorf("%v proved %q", att.Type, id)
		}
	}
	// A chain the roots cannot verify, though the metadata lists the model.
	if _, err := e.s.attest.prove(webauthn.Attestation{Type: webauthn.AttestationBasic, AAGUID: aaguidBytes(t, yubikeyBio)}); err == nil {
		t.Error("an empty trust path proved a model")
	}
}

func TestAAGUIDStringIsTheCanonicalForm(t *testing.T) {
	if got := aaguidString(aaguidBytes(t, yubikeyBio)); got != yubikeyBio {
		t.Errorf("%q", got)
	}
}

// A failing download keeps what is held and is retried after 15 minutes, then
// 30, then an hour at most; a success waits half of what the blob has left, but
// between an hour and a day.
func TestTheMetadataIsRefreshedWithBackoffAndKeptOnFailure(t *testing.T) {
	// 23:30 UTC of a day, with nextUpdate that same day: 30 minutes left.
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(23*time.Hour + 30*time.Minute)
	now := func() time.Time { return base }
	m := newTestMDS(t, now)
	m.set(m.entry(yubikeyBio, "FIDO_CERTIFIED_L1", m.root))
	var logs bytes.Buffer
	v := m.verifier(t, t.TempDir(), func(f string, a ...any) { logs.WriteString(f + "\n") })
	ctx := context.Background()
	fails := 0
	m.fail(errors.New("offline"))
	for i, want := range []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, time.Hour} {
		if got := v.refresh(ctx, true, &fails); got != want {
			t.Errorf("failure %d: wait %s, want %s", i+1, got, want)
		}
	}
	if v.current() != nil {
		t.Fatal("a blob without a download")
	}
	m.fail(nil)
	m.nextDate = base.Format("2006-01-02")
	if got := v.refresh(ctx, true, &fails); got != time.Hour || fails != 0 {
		t.Errorf("success with 30 minutes left: wait %s (failures %d), want the one-hour floor", got, fails)
	}
	m.nextDate = base.AddDate(0, 0, 30).Format("2006-01-02")
	m.set(m.entry(yubikeyBio, "FIDO_CERTIFIED_L1", m.root))
	if got := v.refresh(ctx, true, &fails); got != 24*time.Hour {
		t.Errorf("success with 30 days left: wait %s, want the one-day ceiling", got)
	}
	m.fail(errors.New("offline"))
	if got := v.refresh(ctx, true, &fails); got != 15*time.Minute {
		t.Errorf("a failure after a success: wait %s", got)
	}
	if v.current() == nil {
		t.Error("a failed download dropped the blob held")
	}
	if !strings.Contains(logs.String(), "could not be loaded") || !strings.Contains(logs.String(), "loaded, valid until") {
		t.Errorf("the log:\n%s", logs.String())
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if got := v.refresh(cancelled, true, &fails); got <= 0 {
		t.Errorf("a cancelled load waits %s", got)
	}
}

// run loads at once, and ends with its context. A second start, offline, takes
// the cache the first one wrote.
func TestTheMetadataLoopLoadsAndStops(t *testing.T) {
	now := time.Now
	m := newTestMDS(t, now)
	m.set(m.entry(yubikeyBio, "FIDO_CERTIFIED_L1", m.root))
	dir := t.TempDir()
	runUntilLoaded := func(v *attestVerifier) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { v.run(ctx); close(done) }()
		deadline := time.After(10 * time.Second)
		for v.current() == nil {
			select {
			case <-deadline:
				cancel()
				t.Fatal("the metadata was not loaded")
			case <-time.After(5 * time.Millisecond):
			}
		}
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("run did not stop with its context")
		}
	}
	runUntilLoaded(m.verifier(t, dir, t.Logf))
	m.fail(errors.New("offline"))
	second := m.verifier(t, dir, t.Logf)
	runUntilLoaded(second)
	if e, err := second.entry(yubikeyBio); err != nil || e == nil {
		t.Errorf("the cached metadata: %v", err)
	}
}

// stillTrusted on a verifier that does not exist says no: a service with
// administrators always has one.
func TestWithoutAVerifierNothingIsTrusted(t *testing.T) {
	var v *attestVerifier
	if err := v.stillTrusted(yubikeyBio); err == nil {
		t.Error("a nil verifier trusts a model")
	}
	s := &server{cfg: &config{Local: &localBlock{adminSet: map[string]bool{"alice": true}}}}
	if got := s.attestationFor("alice"); got != "none" {
		t.Errorf("without a verifier an administrator is asked for %q", got)
	}
}
