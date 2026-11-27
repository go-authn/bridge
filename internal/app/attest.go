// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-authn/fido/mds"
	"github.com/go-authn/webauthn"
)

// This file is what makes an administrator's passkey PROVEN to be of an
// allowed model, not merely said to be. The authenticator's own AAGUID is a
// claim (attestation "none" gives nothing else); here the claim is checked in
// three steps, and only a passkey that passes all of them gets
// passkeyRecord.AttestedAAGUID:
//
//  1. go-authn/webauthn verified the attestation statement: a packed statement
//     whose signature is made by the key of an attestation certificate that
//     carries the same AAGUID (WebAuthn L3 8.2), in its id-fido-gen-ce-aaguid
//     extension, which must be present (Policy.RequireAAGUIDExtension; 8.2.1). Self attestation and "none"
//     verify, but prove nothing and yield no AAGUID.
//  2. the FIDO Metadata Service (MDS3) knows that AAGUID, and reports nothing
//     that says the model is compromised or revoked (MDS3 3.1.3).
//  3. the certificate chain of the statement leads to one of the
//     attestationRootCertificates the metadata lists for that AAGUID.
//
// ⛔ The metadata is NEVER fetched on a request: refreshLoop-like, one
// goroutine (run) keeps a verified blob in memory, and a request only reads
// it. With no blob, or one past its nextUpdate, nothing is proven: the answer
// is a refusal, never a wait.

// mdsCompromised are the MDS3 statuses (3.1.3) that say an authenticator model
// is no longer to be trusted: its attestation key, its user verification or
// its keys are compromised, or the entry is revoked. Any such report, however
// old, refuses the model: a status that was meant to be lifted is lifted by
// the Alliance removing it, not by this list guessing which report is latest.
var mdsCompromised = map[string]bool{
	"REVOKED":                      true,
	"ATTESTATION_KEY_COMPROMISE":   true,
	"USER_VERIFICATION_BYPASS":     true,
	"USER_KEY_REMOTE_COMPROMISE":   true,
	"USER_KEY_PHYSICAL_COMPROMISE": true,
}

// defaultMDSDir is inside the systemd unit's StateDirectory
// (packaging/systemd/authn-bridge.service), the one place the service may write.
const defaultMDSDir = "/var/lib/authn-bridge/mds"

// How often the metadata is looked at again: at half of what its nextUpdate
// leaves, but between an hour and a day; and after a failure, a quarter of an
// hour, doubling up to an hour.
const (
	mdsRefreshMin = time.Hour
	mdsRefreshMax = 24 * time.Hour
	mdsRetryMin   = 15 * time.Minute
	mdsRetryMax   = time.Hour
)

// attestVerifier proves the model of a passkey from its attestation.
type attestVerifier struct {
	client *mds.Client
	now    func() time.Time
	logf   func(string, ...any)
	// minCert is local { admin_min_certification }: the least FIDO certification
	// level a model may have, LevelNone for no minimum. Checked in entry, so at
	// registration and again each time a key opens the administrator page.
	minCert mds.Level

	mu   sync.RWMutex
	blob *mds.Blob
}

// newAttestVerifier keeps the metadata in dir (created 0700, files 0600) and
// reads the real service: the pinned GlobalSign root, mds.fidoalliance.org.
func newAttestVerifier(dir string, now func() time.Time, logf func(string, ...any)) *attestVerifier {
	return &attestVerifier{
		client: &mds.Client{Dir: dir, Options: mds.Options{Now: now}},
		now:    now,
		logf:   logf,
	}
}

// aaguidString is an AAGUID in the canonical form the configuration and the
// metadata use: lowercase 8-4-4-4-12.
func aaguidString(a [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
}

// run keeps the metadata current until ctx ends. The first load takes the
// cache when it still verifies; every later one downloads.
func (v *attestVerifier) run(ctx context.Context) {
	force, failures := false, 0
	for {
		wait := v.refresh(ctx, force, &failures)
		force = true
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// refresh loads the metadata once and says how long to wait before the next
// time. A failure keeps the blob already held (it stays good until its own
// nextUpdate) and is retried sooner.
func (v *attestVerifier) refresh(ctx context.Context, force bool, failures *int) time.Duration {
	b, err := v.client.Load(ctx, force)
	if err != nil {
		*failures = min(*failures+1, 3)
		wait := min(mdsRetryMin<<(*failures-1), mdsRetryMax)
		v.logf("mds: the FIDO metadata could not be loaded (administrators' passkeys cannot be attested until it is): %v; again in %s", err, wait)
		return wait
	}
	*failures = 0
	v.mu.Lock()
	v.blob = b
	v.mu.Unlock()
	wait := min(max(b.StaleAfter(v.now())/2, mdsRefreshMin), mdsRefreshMax)
	v.logf("mds: FIDO metadata no. %d loaded, valid until %s; again in %s", b.No, b.NextUpdate().Format(time.RFC3339), wait.Round(time.Minute))
	return wait
}

// current is the blob held, nil when there is none or it is past nextUpdate.
func (v *attestVerifier) current() *mds.Blob {
	v.mu.RLock()
	b := v.blob
	v.mu.RUnlock()
	if b == nil || b.StaleAfter(v.now()) == 0 {
		return nil
	}
	return b
}

// entry is the metadata of a model that may still be trusted.
func (v *attestVerifier) entry(aaguid string) (*mds.Entry, error) {
	b := v.current()
	if b == nil {
		return nil, errors.New("the FIDO metadata is not loaded, or has expired")
	}
	e := b.Lookup(aaguid)
	if e == nil {
		return nil, fmt.Errorf("model %s is not in the FIDO metadata", aaguid)
	}
	for _, r := range e.StatusReports {
		if mdsCompromised[r.Status] {
			return nil, fmt.Errorf("the FIDO metadata reports %s for model %s", r.Status, aaguid)
		}
	}
	// admin_min_certification: the CURRENT level (MDS 3.1 3.1.3/3.1.4.1, see
	// mds.Entry.CertificationLevel), so a model certified L2 and later
	// re-certified lower no longer passes an L2 minimum.
	if v.minCert > mds.LevelNone {
		if got := e.CertificationLevel(v.now()); got < v.minCert {
			return nil, fmt.Errorf("the FIDO metadata gives model %s a certification level of %s, below admin_min_certification %s", aaguid, got, v.minCert)
		}
	}
	return e, nil
}

// prove is the AAGUID of att, in canonical form, when att proves it: a
// verified statement with a certificate chain that leads to a root the
// metadata lists for that model. Anything else is an error saying which step
// failed.
func (v *attestVerifier) prove(att webauthn.Attestation) (string, error) {
	if att.Type != webauthn.AttestationBasic {
		return "", errors.New("the passkey gave no attestation certificate (self attestation and \"none\" prove no model)")
	}
	id := aaguidString(att.AAGUID)
	e, err := v.entry(id)
	if err != nil {
		return "", err
	}
	roots, err := e.RootCertificates()
	if err != nil {
		return "", fmt.Errorf("the roots the FIDO metadata lists for %s: %w", id, err)
	}
	if err := att.VerifyTrustPath(roots, v.now()); err != nil {
		return "", fmt.Errorf("the attestation does not lead to a root the FIDO metadata lists for %s: %w", id, err)
	}
	return id, nil
}

// attestationFor is the attestation conveyance to ask the browser for when
// login registers a passkey: "direct" for an administrator, whose passkey must
// be proved, "none" for everybody else (the browser then asks the person
// nothing, and learns nothing of the key's make).
func (s *server) attestationFor(login string) string {
	if s.attest != nil && s.cfg.Local.adminSet[login] {
		return "direct"
	}
	return "none"
}

// verifyEnrolment verifies a registration, and for an administrator tries to
// prove the model. It returns the proven AAGUID, "" when none was proved: a
// passkey that is not proved is still stored and still signs in, it only does
// not open the administrator page. The reason is logged, never sent.
func (s *server) verifyEnrolment(login string, challenge, clientData, attestationObject []byte) (webauthn.Credential, string, error) {
	cred, att, err := s.relyingParty().VerifyRegistrationAttested(challenge, clientData, attestationObject, webauthn.Policy{RequireUV: true})
	if err != nil || s.attestationFor(login) != "direct" {
		return cred, "", err
	}
	// The registration is valid and will be stored. Proving the model asks for
	// more (the leaf's id-fido-gen-ce-aaguid extension, §8.2.1), and a key that
	// fails that is stored unproved like any other, never refused: so the
	// stricter policy is a second verification of the same registration.
	strict := webauthn.Policy{RequireUV: true, RequireAAGUIDExtension: true}
	_, att, err = s.relyingParty().VerifyRegistrationAttested(challenge, clientData, attestationObject, strict)
	if err != nil {
		s.logf("local: %s: the new passkey is stored WITHOUT a proven model: %v", login, err)
		return cred, "", nil
	}
	id, err := s.attest.prove(att)
	if err != nil {
		s.logf("local: %s: the new passkey is stored WITHOUT a proven model: %v", login, err)
		return cred, "", nil
	}
	return cred, id, nil
}

// stillTrusted says whether a model proved earlier is still one the metadata
// trusts: a key attested before its model was revoked stops opening the
// administrator page. Nil means yes.
func (v *attestVerifier) stillTrusted(aaguid string) error {
	if v == nil {
		return errors.New("no FIDO metadata is configured")
	}
	_, err := v.entry(aaguid)
	return err
}
