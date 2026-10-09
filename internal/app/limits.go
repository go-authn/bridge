// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// What an anonymous client may cost. Starting a login (/authorize), a device
// grant (/device_authorization) and posting to the ACS cost memory or an RSA
// operation before anybody is authenticated, so each address gets so many a
// minute; the stores they fill are capped as well (store.go), so that many
// addresses together still meet a ceiling.
//
// The address is the TCP peer's -- or, behind a reverse proxy named in
// trusted_proxies, the client the proxy reports in X-Forwarded-For. Without
// that, every request behind a proxy is the proxy's, and one person typing
// wrong device codes locks everybody out.

// defaultPerMinute is how many anonymous requests an address may make a
// minute: past what a campus NAT sends at nine in the morning for one
// address, and far below what a flood needs.
const defaultPerMinute = 120

// rateLimiter is a token bucket per address.
type rateLimiter struct {
	perMinute int
	now       func() time.Time

	mu    sync.Mutex
	m     map[string]bucket
	swept time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
	size   float64 // tokens when full
	rate   float64 // tokens a second
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	return &rateLimiter{perMinute: perMinute, now: now, m: map[string]bucket{}}
}

// coarseFactor is how many times an address's allowance its wider
// network gets (limitKeys).
const coarseFactor = 10

// allow takes one token for addr, and one for its wider network, if both
// have one.
func (l *rateLimiter) allow(addr string) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	// A full bucket is the same as no bucket: forget those every minute,
	// or the map keeps every address that ever asked.
	if now.Sub(l.swept) >= time.Minute {
		for a, b := range l.m {
			if b.tokens+now.Sub(b.at).Seconds()*b.rate >= b.size {
				delete(l.m, a)
			}
		}
		l.swept = now
	}
	fine, coarse := limitKeys(addr)
	size := float64(l.perMinute)
	f := l.refill(fine, size, now)
	c := l.refill(coarse, size*coarseFactor, now)
	if f.tokens < 1 || c.tokens < 1 {
		l.m[fine], l.m[coarse] = f, c
		return false
	}
	f.tokens--
	c.tokens--
	l.m[fine], l.m[coarse] = f, c
	return true
}

// refill is the bucket under key, brought up to now.
func (l *rateLimiter) refill(key string, size float64, now time.Time) bucket {
	b, ok := l.m[key]
	if !ok {
		b = bucket{tokens: size, at: now, size: size, rate: size / 60}
	}
	b.tokens = min(b.size, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
	return b
}

// limitKeys are the buckets an address draws on. One host holds a whole
// IPv6 /64 (RFC 6177, RFC 8981 privacy addresses rotate inside it), so
// an address-per-bucket limit is no limit at all there: the /64 is the
// host. And one site holds a /48, or an IPv4 /24, so those share a wider
// bucket, coarseFactor times larger: a campus behind one /24 still logs
// in by the thousand a minute, and flooding needs many networks rather
// than many addresses -- measured before this, one /64 filled the login
// store in 134 ms.
func limitKeys(addr string) (fine, coarse string) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr, "?" + addr
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String(), netip.PrefixFrom(a, 24).Masked().String()
	}
	return netip.PrefixFrom(a, 64).Masked().String(), netip.PrefixFrom(a, 48).Masked().String()
}

// limited wraps h: an address past its allowance is told so, 429.
func (s *server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(s.clientAddr(r)) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests from this address; try again in a minute", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}

// clientAddr is who is asking: the TCP peer, or behind a trusted proxy the
// last address in X-Forwarded-For that is not one of the proxies -- the one
// the nearest untrusted hop connected from. Earlier entries are whatever the
// client wrote, and not believed.
func (s *server) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.cfg.trusted(peer) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return host // a header that does not parse names nobody
		}
		if !s.cfg.trusted(a) {
			return a.String()
		}
	}
	return host
}

// trusted says whether a is one of trusted_proxies.
func (c *config) trusted(a netip.Addr) bool {
	for _, p := range c.trustedProxies {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

func (c *config) checkLimits() error {
	for _, s := range c.TrustedProxies {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return fmt.Errorf("trusted_proxies: %q is neither an address nor a prefix", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.trustedProxies = append(c.trustedProxies, p.Masked())
	}
	if c.RequestsPerMinute == nil {
		n := defaultPerMinute
		c.RequestsPerMinute = &n
	}
	if *c.RequestsPerMinute < 0 {
		return fmt.Errorf("requests_per_minute = %d: 0 turns the limit off, and nothing below", *c.RequestsPerMinute)
	}
	return nil
}
