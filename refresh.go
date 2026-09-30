// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"net/http"
	"time"
)

// A refreshGrant is what a refresh token stands for.
//
// Refresh tokens ROTATE (RFC 9700 4.14.2): each use returns a new one and
// retires the old. A retired token presented again means two parties hold
// the same family -- the client and whoever copied it -- and there is no
// telling which is which, so the whole family is revoked, including the
// access tokens it bought.
type refreshGrant struct {
	client *clientBlock
	who    *person
	scopes []string
	family string
	// until is the end of the family, fixed at the login: rotation does not
	// extend it. The federation is not asked again before it.
	until time.Time
}

// newRefresh starts a family, if the client has refresh tokens at all.
func (s *server) newRefresh(client *clientBlock, who *person, scopes []string, jti string) string {
	if client.refreshTTL == 0 {
		return ""
	}
	until := s.now().Add(client.refreshTTL)
	// An IdP that said when its session ends is believed: the family ends
	// then too, if that is sooner.
	if !who.sessionEnd.IsZero() && who.sessionEnd.Before(until) {
		until = who.sessionEnd
	}
	family := token()
	rt := token()
	s.refresh.put(hashToken(rt), &refreshGrant{client: client, who: who, scopes: scopes, family: family, until: until}, until)
	s.families.put(family, []string{jti}, until.Add(s.cfg.tokenTTL))
	return rt
}

// rotate is the token request with grant_type refresh_token.
func (s *server) rotate(w http.ResponseWriter, r *http.Request, client *clientBlock) {
	rt := r.PostForm.Get("refresh_token")
	// Kept under their hashes (state.go): what the store holds is no token.
	g, ok := s.refresh.take(hashToken(rt))
	if !ok {
		if family, reused := s.rotated.take(hashToken(rt)); reused {
			s.revokeFamily(family)
			s.logf("token: a rotated refresh token of %s was used again; its family is revoked", client.ID)
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return
	}
	if g.client.ID != client.ID {
		// Taken above, so it is spent: a refresh token shown to the wrong
		// client is one that has leaked.
		s.revokeFamily(g.family)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was issued to another client")
		return
	}
	if _, alive := s.families.get(g.family); !alive {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was revoked")
		return
	}
	resp, jti, err := s.issue(client, g.who, g.scopes, "")
	if err != nil {
		s.logf("token: %v", err)
		if errors.Is(err, errDisabled) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "access has been disabled")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// A rotation stays in its family, with the family's end.
	next := token()
	s.refresh.put(hashToken(next), g, g.until)
	s.rotated.put(hashToken(rt), g.family, g.until)
	s.families.update(g.family, func(j *[]string) { *j = append(*j, jti) })
	resp["refresh_token"] = next
	s.counters.inc("bridge_tokens_issued_total", "refresh_token")
	writeJSON(w, http.StatusOK, resp)
}

// revokeFamily ends a family: its refresh tokens stop rotating, and the
// access tokens it bought stop working at /userinfo. It says how many of
// those were still alive.
func (s *server) revokeFamily(family string) int {
	jtis, _ := s.families.take(family)
	n := 0
	for _, j := range jtis {
		if _, ok := s.issued.take(j); ok {
			n++
		}
	}
	return n
}
