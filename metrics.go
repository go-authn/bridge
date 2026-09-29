// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-net-health/endpoint"
)

// /healthz, /readyz and /metrics, on a listener of their own (the metrics
// block), never on the public one: a scraper needs no route to the login
// pages, and the internet needs none to these.
//
// The endpoints and the exposition are go-net-health/endpoint's, shared with
// go-fileshare; what is here is what this provider has to say.
//
// ⛔ No label names a person or an institution. A per-IdP counter would
// say which universities' people use this service and when, which is not
// this provider's to publish; the audit log is where individual events go.

// counters are the monotonic counts, by name and label value.
type counters struct {
	mu sync.Mutex
	m  map[string]map[string]uint64
}

func (c *counters) inc(metric, label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]map[string]uint64{}
	}
	if c.m[metric] == nil {
		c.m[metric] = map[string]uint64{}
	}
	c.m[metric][label]++
}

func (c *counters) get(metric string) map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]uint64{}
	for l, v := range c.m[metric] {
		out[l] = v
	}
	return out
}

// counterHelp is every counter this provider keeps: its help text and the
// name of its one label ("" for none).
var counterHelp = map[string][2]string{
	"bridge_logins_total":           {"Federated logins that reached the ACS, by outcome.", "result"},
	"bridge_tokens_issued_total":    {"Token responses, by grant type.", "grant"},
	"bridge_ssh_certificates_total": {"SSH certificates signed.", ""},
	"bridge_app_passwords_total":    {"Application passwords set or removed.", "op"},
}

// errNotReady is /readyz's answer while no metadata is vouched for.
var errNotReady = errors.New("no federation metadata that is still valid")

func (s *server) readiness() error {
	if !s.ready() {
		return errNotReady
	}
	return nil
}

func (s *server) metricsHandler() http.Handler {
	return endpoint.Handler(endpoint.Options{
		Ready:      s.readiness,
		Collectors: []endpoint.Collector{endpoint.BuildInfo("bridge"), endpoint.GoRuntime, s.collect},
	})
}

// collect is this provider's families.
func (s *server) collect(w *endpoint.Writer) {
	up := 0.0
	if s.ready() {
		up = 1
	}
	w.Gauge("bridge_start_time_seconds", "When this process started, in Unix seconds.", endpoint.S(float64(s.started.Unix())))
	w.Gauge("bridge_ready", "1 while the federation's metadata is loaded and still valid.", endpoint.S(up))
	if md := s.fed.Metadata(); md != nil {
		w.Gauge("bridge_metadata_valid_until_timestamp_seconds", "When the federation stops vouching for the metadata in use.", endpoint.S(float64(md.ValidUntil.Unix())))
		w.Gauge("bridge_metadata_idps", "SAML 2.0 identity providers in the metadata in use.", endpoint.S(float64(len(md.IdPs))))
	}
	s.fedState.mu.Lock()
	last := s.fedState.lastRefresh
	ok, failed := s.fedState.refreshes["ok"], s.fedState.refreshes["failed"]
	s.fedState.mu.Unlock()
	if !last.IsZero() {
		w.Gauge("bridge_metadata_last_refresh_timestamp_seconds", "When the metadata was last fetched successfully.", endpoint.S(float64(last.Unix())))
	}
	w.Counter("bridge_metadata_refreshes_total", "Metadata fetches, by outcome.",
		endpoint.S(float64(failed), endpoint.L("result", "failed")), endpoint.S(float64(ok), endpoint.L("result", "ok")))
	w.Gauge("bridge_logins_in_progress", "Logins gone to an IdP and not yet back.", endpoint.S(float64(s.logins.count())))
	w.Gauge("bridge_devices_waiting", "Device grants waiting for their person.", endpoint.S(float64(s.devices.count())))
	w.Gauge("bridge_refresh_families", "Refresh token families alive.", endpoint.S(float64(s.families.count())))
	w.Gauge("bridge_access_tokens", "Access tokens this provider still honours at /userinfo.", endpoint.S(float64(s.issued.count())))

	names := make([]string, 0, len(counterHelp))
	for n := range counterHelp {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		help, label := counterHelp[n][0], counterHelp[n][1]
		vals := s.counters.get(n)
		if label == "" {
			w.Counter(n, help, endpoint.S(float64(vals[""])))
			continue
		}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		samples := make([]endpoint.Sample, 0, len(keys))
		for _, k := range keys {
			samples = append(samples, endpoint.S(float64(vals[k]), endpoint.L(label, k)))
		}
		w.Counter(n, help, samples...)
	}
}

// openMetrics opens the metrics listener before anything is served: a
// configuration that asks for it and cannot have it does not start. It
// returns nil when there is no metrics block.
func (s *server) openMetrics() (func(context.Context) error, error) {
	b := s.cfg.Metrics
	if b == nil {
		return nil, nil
	}
	ln, err := net.Listen("tcp", b.Listen)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return s.serveMetrics(ctx, ln) }, nil
}

func (s *server) serveMetrics(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.metricsHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	s.logf("metrics on %s", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
