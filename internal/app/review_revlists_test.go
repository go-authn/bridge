// SPDX-License-Identifier: BSD-3-Clause

// Written by an adversarial review of v0.10.0, each proving a defect it found;
// kept as the regression tests of the fixes.

package app

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/go-authn/revocation"
)

// RFC 5280 5.2.3: "if the this update field (Section 5.1.2.4) in the two
// CRLs are not identical, the CRL numbers MUST be different."
func TestFoundCRLNumberReusedAcrossReissues(t *testing.T) {
	f, _ := x509Fixture(t)
	start := time.Now()
	at := start
	f.s.now = func() time.Time { return at }
	defer func() { f.s.now = time.Now }()
	_, a, _ := get(t, f.s.cfg.Issuer+"/x509/crl")
	at = start.Add(31 * time.Minute)
	_, b, _ := get(t, f.s.cfg.Issuer+"/x509/crl")
	ra, err := x509.ParseRevocationList(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := x509.ParseRevocationList(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ra.ThisUpdate.Equal(rb.ThisUpdate) && ra.Number.Cmp(rb.Number) == 0 {
		t.Errorf("two CRLs, thisUpdate %s and %s, share CRL number %v (RFC 5280 5.2.3 MUST NOT)",
			ra.ThisUpdate.Format(time.RFC3339), rb.ThisUpdate.Format(time.RFC3339), ra.Number)
	}
}

// The clock stepping back makes bridge re-issue the same version with an
// earlier generated_date: every distributor (PROTOCOL.md rule 2) refuses it.
func TestFoundClockBackReissuesARollback(t *testing.T) {
	f, _ := sshFixture(t)
	ca := f.s.cfg.SSHCA.signer.PublicKey()
	base := f.s.cfg.Issuer + "/ssh/krl"
	start := time.Now()
	at := start
	f.s.now = func() time.Time { return at }
	defer func() { f.s.now = time.Now }()
	_, raw1, h1 := get(t, base)
	_, sig1, _ := get(t, base+".sig", "If-Match", h1.Get("ETag"))
	l1, err := revocation.VerifyKRL(raw1, sig1, ca)
	if err != nil {
		t.Fatal(err)
	}
	at = start.Add(-10 * time.Minute) // NTP step back
	_, raw2, h2 := get(t, base)
	_, sig2, _ := get(t, base+".sig", "If-Match", h2.Get("ETag"))
	l2, err := revocation.VerifyKRL(raw2, sig2, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Follows(l1); errors.Is(err, revocation.ErrRollback) {
		t.Errorf("after a 10 min clock step back bridge serves a list distributors refuse: %v (and keeps serving it until %s)",
			err, l2.Issued.Add(listValidity/2).Format(time.RFC3339))
	}
}
