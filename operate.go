// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
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
	appPassword              bool
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
func (s *server) revokePerson(username string) (revoked, error) {
	var r revoked
	if username == "" {
		return r, nil
	}
	var families, rts []string
	s.refresh.each(func(rt string, g *refreshGrant) {
		if g.who.username == username {
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
		if it.username == username {
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
		if g.who.username == username {
			codes = append(codes, c)
		}
	})
	s.devices.each(func(dc string, g *deviceGrant) {
		if g.who != nil && g.who.username == username {
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
	if ap := s.cfg.AppPasswords; ap != nil {
		n, err := ap.removeCount(username)
		if err != nil {
			return r, err
		}
		r.appPassword = n > 0
	}
	s.logf("revoked %s: %d refresh families, %d access tokens, %d logins, app password %v",
		username, r.families, r.tokens, r.logins, r.appPassword)
	return r, nil
}
