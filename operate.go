// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// What an operator asks of a running provider, whichever way they ask it --
// the admin API, the metrics listener. Kept apart from both so that neither
// is the only way to reach it, and so that a binary built without gRPC still
// has it.

// fedState is what is known about the federation's metadata beyond the
// metadata itself: when it was last fetched, and how the last attempt went.
type fedState struct {
	mu          sync.Mutex
	lastRefresh time.Time
	lastErr     error
	refreshes   map[string]uint64 // "ok", "failed"
}

// refreshMetadata fetches the federation's metadata once and records how it went.
func (s *server) refreshMetadata(ctx context.Context) error {
	err := s.fed.Refresh(ctx)
	s.fedState.mu.Lock()
	defer s.fedState.mu.Unlock()
	if s.fedState.refreshes == nil {
		s.fedState.refreshes = map[string]uint64{}
	}
	if err != nil {
		s.fedState.lastErr = err
		s.fedState.refreshes["failed"]++
		return err
	}
	s.fedState.lastRefresh, s.fedState.lastErr = s.now(), nil
	s.fedState.refreshes["ok"]++
	return nil
}

// refreshLoop refreshes at three quarters of the metadata's cacheDuration,
// between five minutes and twelve hours -- go-authn/saml's Federation.Run,
// done here so that each attempt is recorded.
func (s *server) refreshLoop(ctx context.Context) {
	for {
		wait := 12 * time.Hour
		if md := s.fed.Metadata(); md != nil && md.CacheDuration > 0 {
			wait = md.CacheDuration * 3 / 4
		}
		wait = min(max(wait, 5*time.Minute), 12*time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := s.refreshMetadata(ctx); err != nil {
			s.logf("metadata refresh: %v", err)
		}
	}
}

// ready says whether the provider can log anybody in: it has federation
// metadata that is still vouched for. A provider past its metadata's
// validUntil knows no IdP at all.
func (s *server) ready() bool { return s.fed.Metadata() != nil }

// revoked is what revokePerson ended.
type revoked struct {
	families, tokens, logins int
	appPasswords             int64
	certificates             int
}

// revokePerson ends everything this provider still holds for somebody,
// by their preferred_username.
//
// ⛔ What it cannot end: an access token is a signed statement that a
// resource server checks on its own, and one already handed out stays valid
// there until it expires (an hour by default). What ends here is everything
// that comes back to THIS provider -- a refresh, /userinfo, an SSH
// certificate or an application password asked with that token -- so the
// person gets nothing new; and an SSH certificate already issued lasts its
// validity, which is why that is short.
func (s *server) revokePerson(username string, subjects ...string) (revoked, error) {
	username = s.normUsername(username)
	if username == "" && len(subjects) == 0 {
		return revoked{}, nil
	}
	// To whoever verifies this provider's tokens on their own (ssf.go)
	// FIRST: a step below failing -- the certificates file, the application
	// password table -- must not leave them uninformed, again at every retry.
	if username != "" {
		s.broadcast(accountSubject(username), s.now(), "", nil)
	}
	r := s.revokeMatching(func(u, _, subject string) bool {
		return (username != "" && strings.EqualFold(u, username)) || (subject != "" && slices.Contains(subjects, subject))
	})
	// Every step is tried, whatever an earlier one did.
	var errs []error
	if n, err := s.certs.revoke(func(p, _ string) bool { return username != "" && strings.EqualFold(p, username) }, s.now()); err != nil {
		errs = append(errs, fmt.Errorf("revoking certificates: %w", err))
	} else {
		r.certificates = n
	}
	if ap := s.cfg.AppPasswords; ap != nil && username != "" {
		if n, err := ap.removeCount(username); err != nil {
			errs = append(errs, fmt.Errorf("removing the application password: %w", err))
		} else {
			r.appPasswords = n
		}
	}
	s.logf("revoked %s: %d refresh families, %d access tokens, %d logins, %d app passwords, %d certificates",
		username, r.families, r.tokens, r.logins, r.appPasswords, r.certificates)
	return r, errors.Join(errs...)
}

// revokeIdP ends everything this provider still holds for the people one
// institution vouched for, application passwords included.
func (s *server) revokeIdP(entityID string) (revoked, error) {
	r := s.revokeMatching(func(_, idp, _ string) bool { return idp == entityID })
	// Every step is tried, whatever an earlier one did.
	var errs []error
	if n, err := s.certs.revoke(func(_, idp string) bool { return idp == entityID }, s.now()); err != nil {
		errs = append(errs, fmt.Errorf("revoking certificates: %w", err))
	} else {
		r.certificates = n
	}
	if ap := s.cfg.AppPasswords; ap != nil {
		var scopes []string
		if md := s.fed.Metadata(); md != nil && scopedUsername[s.cfg.Claims.Username] {
			if i, ok := md.IdPs[entityID]; ok {
				scopes = i.Scopes
			}
		}
		if n, err := ap.removeIdP(entityID, scopes); err != nil {
			errs = append(errs, fmt.Errorf("removing application passwords: %w", err))
		} else {
			r.appPasswords = n
		}
	}
	s.logf("revoked IdP %s: %d refresh families, %d access tokens, %d logins, %d app passwords, %d certificates",
		entityID, r.families, r.tokens, r.logins, r.appPasswords, r.certificates)
	return r, errors.Join(errs...)
}

// revokeMatching ends the grants, tokens and logins of whoever match says,
// by username and IdP.
func (s *server) revokeMatching(match func(username, idp, subject string) bool) revoked {
	var r revoked
	var families, rts []string
	s.refresh.each(func(rt string, g *refreshGrant) {
		if match(g.who.username, g.who.idp, g.who.subject) {
			families = append(families, g.family)
			rts = append(rts, rt)
		}
	})
	for _, rt := range rts {
		s.refresh.take(rt)
	}
	seen := map[string]bool{}
	for _, f := range families {
		if !seen[f] {
			seen[f] = true
			r.tokens += s.revokeFamily(f)
			r.families++
		}
	}
	var jtis []string
	s.issued.each(func(jti string, it issuedToken) {
		if match(it.username, it.idp, it.subject) {
			jtis = append(jtis, jti)
		}
	})
	for _, j := range jtis {
		if _, ok := s.issued.take(j); ok {
			r.tokens++
		}
	}
	var codes, devices []string
	s.codes.each(func(c string, g *grant) {
		if match(g.who.username, g.who.idp, g.who.subject) {
			codes = append(codes, c)
		}
	})
	s.devices.each(func(dc string, g *deviceGrant) {
		if g.who != nil && match(g.who.username, g.who.idp, g.who.subject) {
			devices = append(devices, dc)
		}
	})
	for _, c := range codes {
		s.codes.take(c)
		r.logins++
	}
	for _, dc := range devices {
		s.devices.take(dc)
		r.logins++
	}
	return r
}
