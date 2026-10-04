// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Disabling: the people and the institutions this provider refuses.
//
// This provider has no users of its own to create or delete, and no groups:
// people exist because their institution vouches for them, and their groups
// are what it asserts (Dex, the closest provider to this one, is the same:
// its groups come from the connector and its API has no call to change
// them). What it CAN do is refuse -- one person, or everybody an
// institution vouches for -- which is what an operator needs when an
// account is compromised, or an institution's IdP is.
//
// Disabling is enforced where anything is handed out: at the end of a
// login (acs), and in issue(), which every grant goes through (code,
// refresh, device). What was handed out before is revoked at the same time,
// so the bearer paths (/userinfo, SSH certificates, application passwords),
// which all ask s.issued, refuse too.
//
// ⛔ Kept in a file, and not without one: a person disabled until the
// next restart is let back in at the next deployment, with the
// operator believing otherwise. A file that cannot be read stops the
// provider from starting, for the same reason.

// disabledEntry is one person or institution disabled.
type disabledEntry struct {
	Reason string    `json:"reason,omitempty"`
	By     string    `json:"by,omitempty"`
	Since  time.Time `json:"since"`
	// Until is when it lapses; zero is never.
	Until time.Time `json:"until,omitzero"`
	// Subjects are the stable identities (IdP!identifier) of the people a
	// person entry covers, found when it was made: an IdP may send another
	// eppn for the same person -- another case, a rename -- and the sub a
	// relying party knows them by stays the same.
	Subjects []string `json:"subjects,omitempty"`
}

func (e disabledEntry) inForce(now time.Time) bool {
	return e.Until.IsZero() || now.Before(e.Until)
}

// disabledList is the file's content: people by preferred_username, IdPs by
// entity ID.
type disabledList struct {
	mu     sync.Mutex
	path   string
	People map[string]disabledEntry `json:"people"`
	IdPs   map[string]disabledEntry `json:"idps"`
}

var errNoDisabledFile = errors.New("disabling needs disabled_file in the configuration: without it, a restart would forget who is disabled")

// loadDisabled reads path, which need not exist yet. An empty path is a
// provider that cannot disable anybody.
func loadDisabled(path string) (*disabledList, error) {
	s := &disabledList{path: path, People: map[string]disabledEntry{}, IdPs: map[string]disabledEntry{}}
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
	if s.People == nil {
		s.People = map[string]disabledEntry{}
	}
	if s.IdPs == nil {
		s.IdPs = map[string]disabledEntry{}
	}
	// Usernames compare without case (normUsername); a file written before
	// that kept them as typed.
	people := map[string]disabledEntry{}
	for k, e := range s.People {
		k = strings.ToLower(k)
		if o, ok := people[k]; ok {
			// One person twice: never-ending wins, else the later end.
			e.Subjects = append(e.Subjects, o.Subjects...)
			if o.Until.IsZero() || (!e.Until.IsZero() && o.Until.After(e.Until)) {
				e.Until = o.Until
			}
		}
		people[k] = e
	}
	s.People = people
	return s, nil
}

// saveLocked writes the file whole, through a temporary file in the same
// directory, synced and renamed: a crash leaves the old list or the new one,
// never half of either. Lapsed entries are dropped on the way.
func (s *disabledList) saveLocked(now time.Time) error {
	if s.path == "" {
		return errNoDisabledFile
	}
	for k, e := range s.People {
		if !e.inForce(now) {
			delete(s.People, k)
		}
	}
	for k, e := range s.IdPs {
		if !e.inForce(now) {
			delete(s.IdPs, k)
		}
	}
	return writeJSONFile(s.path, s)
}

// writeJSONFile writes v to path whole, through a temporary file in the same
// directory, synced and renamed, mode 0600: a crash leaves the old content
// or the new, never half of either.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// set records (or replaces) an entry, and saves. On a failed save the
// list in memory is left as it was: what is in force is what is on disk.
func (s *disabledList) set(idp bool, key string, e disabledEntry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.People
	if idp {
		m = s.IdPs
	}
	old, had := m[key]
	m[key] = e
	if err := s.saveLocked(now); err != nil {
		if had {
			m[key] = old
		} else {
			delete(m, key)
		}
		return err
	}
	return nil
}

// lift removes an entry and saves; it says whether one was in force.
func (s *disabledList) lift(idp bool, key string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.People
	if idp {
		m = s.IdPs
	}
	old, had := m[key]
	if !had {
		return false, nil
	}
	delete(m, key)
	if err := s.saveLocked(now); err != nil {
		m[key] = old
		return false, err
	}
	return old.inForce(now), nil
}

// person and idp say whether an entry is in force.
func (s *disabledList) person(username, subject string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if username != "" {
		if e, ok := s.People[strings.ToLower(username)]; ok && e.inForce(now) {
			return true
		}
	}
	if subject != "" {
		for _, e := range s.People {
			if e.inForce(now) && slices.Contains(e.Subjects, subject) {
				return true
			}
		}
	}
	return false
}

func (s *disabledList) idp(entityID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.IdPs[entityID]
	return ok && e.inForce(now)
}

// namedDisabled is an entry with its key, for listing.
type namedDisabled struct {
	key string
	disabledEntry
}

// list is what is in force, sorted by key.
func (s *disabledList) list(now time.Time) (people, idps []namedDisabled) {
	s.mu.Lock()
	defer s.mu.Unlock()
	collect := func(m map[string]disabledEntry) []namedDisabled {
		var out []namedDisabled
		for k, e := range m {
			if e.inForce(now) {
				out = append(out, namedDisabled{k, e})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
		return out
	}
	return collect(s.People), collect(s.IdPs)
}

// errBadDisable is a request that names nobody, or ends in the past.
var errBadDisable = errors.New("nothing to disable")

// errDisabled is issue() refusing: the person, or their institution, is
// disabled here.
var errDisabled = errors.New("disabled")

// refused says why who may not have anything from this provider, or "".
func (s *server) refused(who *person) string {
	now := s.now()
	switch {
	case s.disabled.idp(who.idp, now):
		return "institution disabled"
	case s.disabled.person(who.username, who.subject, now):
		return "person disabled"
	}
	return ""
}

// disablePerson records the entry, then revokes. In that order: a
// grant racing the revocation meets the entry in issue().
func (s *server) disablePerson(username, reason, by string, until time.Time) (disabledEntry, revoked, error) {
	name := username // as typed: a sub is case-sensitive
	username = s.normUsername(username)
	now := s.now()
	if username == "" {
		return disabledEntry{}, revoked{}, fmt.Errorf("%w: a username is required", errBadDisable)
	}
	if !until.IsZero() && !until.After(now) {
		return disabledEntry{}, revoked{}, fmt.Errorf("%w: it would already have ended", errBadDisable)
	}
	e := disabledEntry{Reason: reason, By: by, Since: now, Until: until, Subjects: s.subjectsOf(name)}
	if err := s.disabled.set(false, username, e, now); err != nil {
		return disabledEntry{}, revoked{}, err
	}
	s.logf("disabled %s (%d known identities) by %s until %s: %s", username, len(e.Subjects), by, untilText(until), reason)
	r, err := s.revokePerson(username, e.Subjects...)
	return e, r, err
}

func (s *server) enablePerson(username, by string) (bool, error) {
	username = s.normUsername(username)
	was, err := s.disabled.lift(false, username, s.now())
	if err == nil && was {
		s.logf("enabled %s by %s", username, by)
	}
	return was, err
}

func (s *server) disableIdP(entityID, reason, by string, until time.Time) (disabledEntry, revoked, error) {
	// Who this provider knows of there, before revoking erases the traces.
	people := s.peopleOf(entityID)
	now := s.now()
	if entityID == "" {
		return disabledEntry{}, revoked{}, fmt.Errorf("%w: an entity ID is required", errBadDisable)
	}
	if !until.IsZero() && !until.After(now) {
		return disabledEntry{}, revoked{}, fmt.Errorf("%w: it would already have ended", errBadDisable)
	}
	e := disabledEntry{Reason: reason, By: by, Since: now, Until: until}
	if err := s.disabled.set(true, entityID, e, now); err != nil {
		return disabledEntry{}, revoked{}, err
	}
	s.logf("disabled IdP %s by %s until %s: %s", entityID, by, untilText(until), reason)
	r, err := s.revokeIdP(entityID)
	for _, u := range people {
		s.broadcast(s.personSubjects(u, s.subjectsOf(u)), now, reason, nil)
	}
	// And everybody in its scopes, whom this provider has no trace of.
	var scopes []string
	if md := s.fed.Metadata(); md != nil {
		if i, ok := md.IdPs[entityID]; ok {
			scopes = i.Scopes
		}
	}
	if len(scopes) > 0 {
		s.broadcast(only(map[string]any{"tenant": map[string]any{"format": "opaque", "id": entityID}}), now, reason, map[string]any{"scopes": scopes})
	}
	return e, r, err
}

func (s *server) enableIdP(entityID, by string) (bool, error) {
	was, err := s.disabled.lift(true, entityID, s.now())
	if err == nil && was {
		s.logf("enabled IdP %s by %s", entityID, by)
	}
	return was, err
}

// normUsername is a username as disabling compares it: without case. Every
// attribute a username comes from compares so -- subject-id (SAML V2.0
// Subject Identifier Attributes 3.3.1), and eduPersonPrincipalName, uid and
// mail, whose schemas declare caseIgnoreMatch -- so "Alice@univ.fr" is the
// person disabled as "alice@univ.fr", whatever case her IdP sends today.
func (s *server) normUsername(u string) string { return strings.ToLower(u) }

// subjectsOf are the stable identities of the people known here by name:
// their username, without case, or the sub a relying party knows them by
// (public or pairwise, for any client) -- which is how a person whose IdP
// releases no username can be named at all.
func (s *server) subjectsOf(name string) []string {
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	s.refresh.each(func(_ string, g *refreshGrant) {
		if g.who.subject == "" || seen[g.who.subject] {
			return
		}
		if g.who.username != "" && strings.EqualFold(g.who.username, name) {
			seen[g.who.subject] = true
			return
		}
		for i := range s.cfg.Clients {
			if g.who.sub(s.cfg.salt, &s.cfg.Clients[i]) == name {
				seen[g.who.subject] = true
				return
			}
		}
	})
	// And from the access tokens still live: a client without refresh tokens
	// leaves nothing else, and the token's sub is the one its client knows.
	s.issued.each(func(_ string, it issuedToken) {
		if it.subject == "" {
			return
		}
		if (it.username != "" && strings.EqualFold(it.username, name)) || it.info["sub"] == name {
			seen[it.subject] = true
		}
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func untilText(t time.Time) string {
	if t.IsZero() {
		return "enabled again"
	}
	return t.UTC().Format(time.RFC3339)
}
