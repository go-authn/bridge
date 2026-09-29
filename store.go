// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/base64"
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
}

type entry[V any] struct {
	v       V
	expires time.Time
}

func newTTL[V any](now func() time.Time) *ttl[V] {
	return &ttl[V]{m: map[string]entry[V]{}, now: now}
}

// put stores v under k until expires.
func (t *ttl[V]) put(k string, v V, expires time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	t.m[k] = entry[V]{v, expires}
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
	return true
}

func (t *ttl[V]) sweep() {
	now := t.now()
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
