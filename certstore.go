// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"sync"
	"time"
)

// The certificates this provider issued, SSH and X.509, and which of them
// are revoked: what /ssh/krl and /x509/crl are made from.
//
// An SSH certificate used to be revocable by nobody: a server checks it
// against the CA at login and nothing else, so its lifetime was its
// revocation. Now every certificate is recorded BEFORE it is handed out --
// one that cannot be recorded is not issued, since it could never be
// revoked -- and disabling or revoking a person marks theirs.
//
// ⛔ Revocation is permanent. Enabling a person again does not bring their
// certificates back; they get new ones. A list a revocation could be taken
// out of is a list an attacker who can reach the admin API edits.
//
// Serials are random, 63 bits for SSH (PROTOCOL.certkeys: a uint64) and 127
// for X.509 (RFC 5280 4.1.2.2: positive, at most 20 octets), checked unique
// here. Not a counter: a counter tells every holder how many certificates
// were issued.

// issuedCert is one certificate.
type issuedCert struct {
	Kind      string    `json:"kind"`   // "ssh" or "x509"
	Serial    string    `json:"serial"` // decimal
	KeyID     string    `json:"key_id,omitempty"`
	Principal string    `json:"principal"`
	IdP       string    `json:"idp,omitempty"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   time.Time `json:"revoked,omitzero"`
}

// certStore is certificates_file.
type certStore struct {
	mu   sync.Mutex
	path string
	// Version is bumped by every revocation: the KRL's krl_version and the
	// CRL's number, the same value for both.
	Version uint64       `json:"version"`
	Certs   []issuedCert `json:"certificates"`
}

var errNoCertStore = errors.New("certificates_file is required with ssh_ca or x509_ca: a certificate that is not recorded can never be revoked")

func loadCertStore(path string) (*certStore, error) {
	s := &certStore{path: path}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// pruneLocked drops what has expired: an expired certificate is refused
// everywhere without being listed.
func (s *certStore) pruneLocked(now time.Time) {
	kept := s.Certs[:0]
	for _, c := range s.Certs {
		if now.Before(c.NotAfter) {
			kept = append(kept, c)
		}
	}
	s.Certs = kept
}

// newSerial is a random serial of bits bits not yet in the store.
func (s *certStore) newSerial(kind string, bits uint) (*big.Int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := new(big.Int).Lsh(big.NewInt(1), bits)
	for range 8 {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() == 0 {
			continue
		}
		taken := false
		for _, c := range s.Certs {
			if c.Kind == kind && c.Serial == n.String() {
				taken = true
				break
			}
		}
		if !taken {
			return n, nil
		}
	}
	return nil, errors.New("no free serial")
}

// add records c, and saves; a certificate that could not be recorded must
// not be handed out.
func (s *certStore) add(c issuedCert, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return errNoCertStore
	}
	old := slices.Clone(s.Certs) // prune filters in place
	s.pruneLocked(now)
	s.Certs = append(s.Certs, c)
	if err := writeJSONFile(s.path, s); err != nil {
		s.Certs = old
		return err
	}
	return nil
}

// revoke marks the unexpired certificates of whoever match says, and saves.
// It says how many it marked.
func (s *certStore) revoke(match func(principal, idp string) bool, now time.Time) (int, error) {
	return s.revokeWhere(func(c issuedCert) bool { return match(c.Principal, c.IdP) }, now)
}

// revokeOne marks one certificate, by its kind and serial.
func (s *certStore) revokeOne(kind, serial string, now time.Time) error {
	_, err := s.revokeWhere(func(c issuedCert) bool { return c.Kind == kind && c.Serial == serial }, now)
	return err
}

func (s *certStore) revokeWhere(match func(issuedCert) bool, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return 0, nil
	}
	s.pruneLocked(now)
	var marked []int
	for i, c := range s.Certs {
		if c.Revoked.IsZero() && match(c) {
			marked = append(marked, i)
		}
	}
	if len(marked) == 0 {
		return 0, nil
	}
	for _, i := range marked {
		s.Certs[i].Revoked = now
	}
	s.Version++
	if err := writeJSONFile(s.path, s); err != nil {
		for _, i := range marked {
			s.Certs[i].Revoked = time.Time{}
		}
		s.Version--
		return 0, err
	}
	return len(marked), nil
}

// revoked is the unexpired revoked certificates of one kind, and the
// version they are at.
func (s *certStore) revoked(kind string, now time.Time) ([]issuedCert, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []issuedCert
	for _, c := range s.Certs {
		if c.Kind == kind && !c.Revoked.IsZero() && now.Before(c.NotAfter) {
			out = append(out, c)
		}
	}
	return out, s.Version
}
