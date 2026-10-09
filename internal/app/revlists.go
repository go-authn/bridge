// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// The revocation lists, issued as go-authn/revocation's PROTOCOL.md says: a
// list says when it stops being current, a KRL comes with a detached SSHSIG
// signature by the CA, and an issue is kept and served unchanged until it is
// half way to its expiry, or until something is revoked.
//
// ⛔ Issued per request, as they were, a list's bytes changed at every GET
// (a new date, a new signature) under an ETag that did not -- the version.
// A client polling with If-None-Match was answered 304 for as long as
// nothing was revoked and kept the copy it had, whose expiry then passed:
// a reader that enforces expiry fails closed for good against a healthy
// provider. The ETag is now the content's, and the content changes at least
// every listValidity/2.

// listValidity is how long an issued list stays current. Readers poll well
// within it; it is issued again at half of it.
const listValidity = time.Hour

type issuedList struct {
	raw, sig []byte // sig: a KRL's armored SSHSIG; nil for a CRL
	tag      string
	version  uint64
	number   uint64 // the CRL Number it was issued with
	issued   time.Time
}

type listCache struct {
	mu    sync.Mutex
	lists map[string]*issuedList // by kind: "ssh", "x509"
}

// issueList returns the list of this kind currently issued, making a new one
// when something was revoked since, or when the one held is half way to
// its expiry.
//
// Two rules a reader holds an issuer to (found by an adversarial review of
// v0.10.0):
//
//   - An issue is never dated before the one it replaces. A reader refuses
//     the same version issued earlier as a rollback, so a clock stepped back
//     re-issued lists the fleet would refuse until they lapsed. The issue
//     time is the later of now and the last issue's.
//   - Two CRLs with different thisUpdate have different numbers (RFC 5280
//     5.2.3: "if the this update field ... in the two CRLs are not
//     identical, the CRL numbers MUST be different"). The number was the
//     revocation counter, which a re-issue keeps. It is now the later of
//     the last number + 1 and the issue time in milliseconds: rising at
//     every issue, above every counter value published before, and above
//     what a restart left behind, with nothing stored.
func (s *server) issueList(kind string, make func(revoked []issuedCert, version, number uint64, now time.Time) (raw, sig []byte, err error)) (*issuedList, error) {
	now := s.now()
	revoked, version := s.certs.revoked(kind, now)
	s.revLists.mu.Lock()
	defer s.revLists.mu.Unlock()
	last := s.revLists.lists[kind]
	if last != nil && now.Before(last.issued) {
		now = last.issued
	}
	if last != nil && last.version == version && now.Before(last.issued.Add(listValidity/2)) {
		return last, nil
	}
	number := uint64(now.UnixMilli())
	if last != nil && number <= last.number {
		number = last.number + 1
	}
	raw, sig, err := make(revoked, version, number, now)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	l := &issuedList{raw: raw, sig: sig, tag: `"` + hex.EncodeToString(h[:16]) + `"`, version: version,
		number: number, issued: now}
	if s.revLists.lists == nil {
		s.revLists.lists = map[string]*issuedList{}
	}
	s.revLists.lists[kind] = l
	return l, nil
}

// serveList answers GET for an issued list, with its ETag and
// If-None-Match.
func serveList(w http.ResponseWriter, r *http.Request, l *issuedList, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("ETag", l.tag)
	h.Set("Cache-Control", "max-age=60")
	if r.Header.Get("If-None-Match") == l.tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(l.raw)
}
