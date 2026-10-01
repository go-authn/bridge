// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ttl is a map whose entries expire.
//
// Everything this provider remembers -- a login in progress, a code not yet
// exchanged, a device waiting for its person -- lives minutes, and lives in
// memory. A restart forgets it, which costs people one login and costs the
// deployment no database; it is said here because it also means ONE process:
// two behind a load balancer would each know half the codes.
type ttl[V any] struct {
	mu  sync.Mutex
	m   map[string]entry[V]
	now func() time.Time
	// store, when set, is where it is written through (state.go).
	store *persistent[V]
	// max, when set, is how many entries it holds: a put past it is
	// refused. What anonymous requests fill -- logins, device grants --
	// has one, or a flood of them is memory without end (measured: 100,000
	// logins, 63 MB, from as many unauthenticated /authorize).
	max int
	// swept is when expired entries were last removed: at most once a
	// second, not at every put -- sweeping a map of 100,000 under the lock
	// at every insert made the 100th thousand 80 times slower than the first.
	swept time.Time
}

// errFull is a put past max.
var errFull = errors.New("too many in progress; try again in a minute")

// capped sets max, and returns t.
func (t *ttl[V]) capped(n int) *ttl[V] {
	t.max = n
	return t
}

type entry[V any] struct {
	v       V
	expires time.Time
}

func newTTL[V any](now func() time.Time) *ttl[V] {
	return &ttl[V]{m: map[string]entry[V]{}, now: now}
}

// put stores v under k until expires. It refuses (errFull) a new key past
// max; replacing a key is always allowed.
func (t *ttl[V]) put(k string, v V, expires time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.putLocked(k, v, expires)
}

func (t *ttl[V]) putLocked(k string, v V, expires time.Time) error {
	t.sweep()
	if _, there := t.m[k]; !there && t.max > 0 && len(t.m) >= t.max {
		t.sweepNow()
		if len(t.m) >= t.max {
			return errFull
		}
	}
	t.m[k] = entry[V]{v, expires}
	t.write(k, v, expires)
	return nil
}

// get returns the value under k if it has not expired.
func (t *ttl[V]) get(k string) (V, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[k]
	if !ok || !t.now().Before(e.expires) {
		var zero V
		return zero, false
	}
	return e.v, true
}

// take returns the value under k and removes it, atomically: of two
// requests with the same one-time code, exactly one gets it.
func (t *ttl[V]) take(k string) (V, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[k]
	delete(t.m, k)
	if ok {
		t.forget(k)
	}
	if !ok || !t.now().Before(e.expires) {
		var zero V
		return zero, false
	}
	return e.v, true
}

// update changes the value under k in place, if it is there and alive.
func (t *ttl[V]) update(k string, f func(*V)) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[k]
	if !ok || !t.now().Before(e.expires) {
		return false
	}
	f(&e.v)
	t.m[k] = e
	t.write(k, e.v, e.expires)
	return true
}

// sweep removes expired entries, at most once a second.
func (t *ttl[V]) sweep() {
	if now := t.now(); now.Sub(t.swept) >= time.Second || now.Before(t.swept) {
		t.sweepNow()
	}
}

func (t *ttl[V]) sweepNow() {
	now := t.now()
	t.swept = now
	for k, e := range t.m {
		if !now.Before(e.expires) {
			delete(t.m, k)
		}
	}
}

// token is 32 random bytes, URL-safe: a code, a state handle, a device code.
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on any platform Go supports
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// each calls f for every live entry, under the lock: f must not call back
// into t.
func (t *ttl[V]) each(f func(k string, v V)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	now := t.now()
	for k, e := range t.m {
		if now.Before(e.expires) {
			f(k, e.v)
		}
	}
}

// count is how many live entries there are.
func (t *ttl[V]) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	now, n := t.now(), 0
	for _, e := range t.m {
		if now.Before(e.expires) {
			n++
		}
	}
	return n
}

// maxPending is how many logins, and how many device grants, may be in
// progress at once: far past any real crowd, and a ceiling for a flood.
const maxPending = 20000

// errTaken is putNew on a key that is there.
var errTaken = errors.New("taken")

// putNew is put, but only if k is not there (or expired): a user code must
// not be handed out twice while both are alive -- the second would send
// the first person's approval to another device.
func (t *ttl[V]) putNew(k string, v V, expires time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, there := t.m[k]; there && t.now().Before(e.expires) {
		return errTaken
	}
	return t.putLocked(k, v, expires)
}
