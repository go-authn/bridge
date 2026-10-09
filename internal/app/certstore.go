// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
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
	Kind      string    `json:"kind"`   // "ssh", "x509" or "wireguard"
	Serial    string    `json:"serial"` // decimal
	KeyID     string    `json:"key_id,omitempty"`
	Principal string    `json:"principal"`
	IdP       string    `json:"idp,omitempty"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   time.Time `json:"revoked,omitzero"`

	// A WireGuard key also records the client it was registered through,
	// and the person's sub as that client sees it: what a gateway is told.
	Client string `json:"client,omitempty"`
	Sub    string `json:"sub,omitempty"`

	// An SSH certificate whose client names the person by another claim
	// than the username (ssh_principal_claim) records the principal it
	// names, and the person's stable identity (person.subject), by which
	// disabling finds it when they have no username. Absent otherwise.
	CertPrincipal string `json:"cert_principal,omitempty"`
	Subject       string `json:"subject,omitempty"`
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

// The ways a WireGuard key is refused.
var (
	errKeyTaken   = errors.New("this key is registered to somebody else")
	errKeyRevoked = errors.New("this key was taken back; make a new one")
	errTooMany    = errors.New("too many keys")
)

// sameOwner is whether two records are one person's: the name as the IdP
// spelled it, compared without case as disabling compares it, and the IdP.
func sameOwner(a, b issuedCert) bool {
	return strings.EqualFold(a.Principal, b.Principal) && a.IdP == b.IdP
}

// registerKey records a WireGuard key for a person, or renews it when it is
// already theirs, and saves.
//
// ⛔ A public key is PUBLIC: anybody can read one off a configuration, a
// screenshot or a gateway. So a key is its first owner's until it expires
// or is taken back -- registering it again under another name is refused,
// not a transfer -- and a key taken back stays refused, since it may have
// been taken back because the device holding its private half was lost.
func (s *certStore) registerKey(c issuedCert, max int, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return errNoCertStore
	}
	old := slices.Clone(s.Certs)
	s.pruneLocked(now)
	held := 0
	for i, x := range s.Certs {
		if x.Kind != "wireguard" {
			continue
		}
		if x.Serial == c.Serial {
			switch {
			case !x.Revoked.IsZero():
				s.Certs = old
				return errKeyRevoked
			case !sameOwner(x, c):
				s.Certs = old
				return errKeyTaken
			}
			s.Certs[i].NotAfter, s.Certs[i].KeyID, s.Certs[i].Client, s.Certs[i].Sub = c.NotAfter, c.KeyID, c.Client, c.Sub
			if err := writeJSONFile(s.path, s); err != nil {
				s.Certs = old
				return err
			}
			return nil
		}
		if x.Revoked.IsZero() && sameOwner(x, c) {
			held++
		}
	}
	if held >= max {
		s.Certs = old
		return fmt.Errorf("%w: %d is the most one person may hold", errTooMany, max)
	}
	s.Certs = append(s.Certs, c)
	if err := writeJSONFile(s.path, s); err != nil {
		s.Certs = old
		return err
	}
	return nil
}

// ownsKey is whether key is a live WireGuard key of the person c names.
func (s *certStore) ownsKey(key string, c issuedCert, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.Certs {
		if x.Kind == "wireguard" && x.Serial == key && x.Revoked.IsZero() && now.Before(x.NotAfter) && sameOwner(x, c) {
			return true
		}
	}
	return false
}

// liveKeys is the WireGuard keys registered through the given clients, not
// taken back and not expired, and the store's version.
func (s *certStore) liveKeys(clients []string, now time.Time) ([]issuedCert, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []issuedCert
	for _, x := range s.Certs {
		if x.Kind == "wireguard" && x.Revoked.IsZero() && now.Before(x.NotAfter) && slices.Contains(clients, x.Client) {
			out = append(out, x)
		}
	}
	return out, s.Version
}
