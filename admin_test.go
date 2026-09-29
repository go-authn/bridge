// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	adminv1 "github.com/go-authn/bridge/proto/bridge/admin/v1"
	"github.com/grpc-transports/control"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// adminFixture is a provider with an admin socket and a metrics listener,
// serving; and a gRPC client on the socket.
func adminFixture(t *testing.T, extra string) (*fixture, adminv1.AdminServiceClient, *grpc.ClientConn, string) {
	t.Helper()
	// A short path: a unix socket's is limited to about a hundred bytes.
	dir, err := os.MkdirTemp("", "ba")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	f := newFixture(t, extra+`
admin { listen = "unix://`+filepath.ToSlash(sock)+`" }
metrics { listen = "127.0.0.1:0" }
`)
	f.s.poll = time.Second
	admin, err := f.s.openAdmin()
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := f.s.openMetricsFor(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go admin(ctx)
	go metrics.run(ctx)
	cc, err := control.Dial(control.ClientConfig{Target: "unix://" + sock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return f, adminv1.NewAdminServiceClient(cc), cc, "http://" + metrics.addr
}

func TestAdminStatusAndLists(t *testing.T) {
	f, c, cc, _ := adminFixture(t, "")
	ctx := t.Context()
	st, err := c.Status(ctx, &adminv1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Issuer != f.s.cfg.Issuer || st.Federation.Idps != 2 || st.Federation.Usable != 2 || st.Federation.ValidUntil == nil {
		t.Errorf("status %+v", st)
	}
	// A refresh now: recorded, with its time.
	rm, err := c.RefreshMetadata(ctx, &adminv1.RefreshMetadataRequest{})
	st = rm.GetStatus()
	if err != nil || st.Federation.LastRefresh == nil || st.Federation.LastError != "" {
		t.Fatalf("refresh: %v %+v", err, st.GetFederation())
	}
	idps, err := c.ListIdPs(ctx, &adminv1.ListIdPsRequest{Query: "other"})
	if err != nil || idps.Total != 1 || idps.Idps[0].EntityId != "https://idp.other-univ.fr/idp" {
		t.Errorf("ListIdPs: %v %+v", err, idps)
	}
	if all, _ := c.ListIdPs(ctx, &adminv1.ListIdPsRequest{Limit: 1}); all.Total != 2 || len(all.Idps) != 1 {
		t.Errorf("ListIdPs limit: %+v", all)
	}
	cl, err := c.ListClients(ctx, &adminv1.ListClientsRequest{})
	if err != nil || len(cl.Clients) != 2 || cl.Clients[0].Id != "web" || cl.Clients[0].Public || !cl.Clients[1].Public {
		t.Errorf("ListClients: %v %+v", err, cl)
	}
	// grpc.health.v1, overall and by service.
	h := healthpb.NewHealthClient(cc)
	for _, svc := range []string{"", adminv1.AdminService_ServiceDesc.ServiceName} {
		r, err := h.Check(ctx, &healthpb.HealthCheckRequest{Service: svc})
		if err != nil || r.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("health %q: %v %v", svc, err, r.GetStatus())
		}
	}
	// With the metadata expired, there is nothing to list, and Status says
	// none is in use.
	now := f.s.now
	f.s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := c.ListIdPs(ctx, &adminv1.ListIdPsRequest{}); err == nil {
		t.Error("IdPs listed from expired metadata")
	}
	if st, _ := c.Status(ctx, &adminv1.StatusRequest{}); st.Federation.ValidUntil != nil {
		t.Error("expired metadata reported as in use")
	}
	f.s.now = now
	// A refresh that fails is an answer, not an RPC error, and the metadata
	// in use stays.
	f.s.fed.URL = "https://127.0.0.1:1/gone.xml"
	rm, err = c.RefreshMetadata(ctx, &adminv1.RefreshMetadataRequest{})
	st = rm.GetStatus()
	if err != nil || st.Federation.LastError == "" || st.Federation.Idps != 2 {
		t.Errorf("a failed refresh: %v %+v", err, st.GetFederation())
	}
}

// RevokePerson ends what comes back to this provider: the refresh token no
// longer refreshes, the access token no longer answers at /userinfo, and
// the application password is gone.
func TestAdminRevokePerson(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.ToSlash(filepath.Join(dir, "dsn"))
	db := "file:" + filepath.ToSlash(filepath.Join(dir, "app.db"))
	os.WriteFile(dsn, []byte(db), 0o600)
	f, c, _, _ := adminFixture(t, `
app_passwords {
  driver   = "sqlite"
  dsn_file = "`+dsn+`"
}
client "files" {
  device           = true
  app_passwords    = true
  refresh_lifetime = "720h"
}
`)
	tok := f.deviceToken("files", "openid", "app_password")
	if s, _ := setPassword(t, f, tok.AccessToken, http.MethodPost); s != http.StatusOK {
		t.Fatalf("setting a password: %d", s)
	}
	if _, ok := people(t, db)["alice@"+idpScope]; !ok {
		t.Fatal("no password was set")
	}

	r, err := c.RevokePerson(t.Context(), &adminv1.RevokePersonRequest{Username: "alice@" + idpScope})
	if err != nil {
		t.Fatal(err)
	}
	if v := r.Revoked; v.RefreshFamilies != 1 || v.AccessTokens < 1 || v.AppPasswords != 1 {
		t.Errorf("revoked %+v", r)
	}
	ep, _ := endpoints(t.Context(), f.s.cfg.Issuer)
	cfg := &oauth2.Config{ClientID: "files", Endpoint: ep}
	if _, err := cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
		t.Error("a revoked person's refresh token still works")
	}
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != http.StatusUnauthorized {
		t.Error("a revoked person's access token still answers at /userinfo")
	}
	if _, ok := people(t, db)["alice@"+idpScope]; ok {
		t.Error("a revoked person's application password is still there")
	}
	// Nobody to revoke is not an error; no name is.
	if r, err := c.RevokePerson(t.Context(), &adminv1.RevokePersonRequest{Username: "nobody@x"}); err != nil || r.Revoked.RefreshFamilies != 0 {
		t.Errorf("revoking nobody: %v %+v", err, r)
	}
	if _, err := c.RevokePerson(t.Context(), &adminv1.RevokePersonRequest{}); err == nil {
		t.Error("revoking an empty name")
	}
}

// The metrics listener: health, readiness, and an exposition Prometheus's
// own parser reads.
func TestMetricsEndpoints(t *testing.T) {
	f, _, _, base := adminFixture(t, "")
	r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect)
	f.login(newBrowser(t), r.authURL(), alice)

	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200} {
		res, err := http.Get(base + path)
		if err != nil || res.StatusCode != want {
			t.Errorf("%s: %v %v", path, err, res.StatusCode)
		}
	}
	res, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type %q: Prometheus 3 refuses a scrape without it", ct)
	}
	body, _ := io.ReadAll(res.Body)
	p := expfmt.NewTextParser(model.LegacyValidation)
	families, err := p.TextToMetricFamilies(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("Prometheus's parser refused the exposition: %v\n%s", err, body)
	}
	want := map[string]float64{"bridge_ready": 1, "bridge_metadata_idps": 2}
	for n, v := range want {
		mf := families[n]
		if mf == nil || mf.Metric[0].GetGauge().GetValue() != v {
			t.Errorf("%s = %v, want %v", n, mf, v)
		}
	}
	logins := families["bridge_logins_total"]
	if logins == nil {
		t.Fatal("no bridge_logins_total")
	}
	found := false
	for _, m := range logins.Metric {
		for _, l := range m.Label {
			if l.GetName() == "result" && l.GetValue() == "ok" && m.GetCounter().GetValue() == 1 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the login is not counted:\n%s", body)
	}
	// ⛔ No label names a person or an institution.
	for _, mf := range families {
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if strings.Contains(l.GetValue(), "alice") || strings.Contains(l.GetValue(), idpScope) {
					t.Errorf("%s carries %s=%q", mf.GetName(), l.GetName(), l.GetValue())
				}
			}
		}
	}
	for n := range families {
		if !model.LegacyValidation.IsValidMetricName(n) {
			t.Errorf("metric name %q", n)
		}
	}

	// Past the metadata's validUntil: not ready, and health says so too.
	f.s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if res, _ := http.Get(base + "/readyz"); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/readyz with expired metadata: %d", res.StatusCode)
	} else if b, _ := io.ReadAll(res.Body); !strings.Contains(string(b), "no federation metadata") {
		t.Errorf("/readyz does not say why: %q", b)
	}
	if res, _ := http.Get(base + "/healthz"); res.StatusCode != http.StatusOK {
		t.Errorf("/healthz must stay up: a restart would not fix expired metadata")
	}
}

func TestAdminConfigRefusals(t *testing.T) {
	c := newConf(t)
	for name, extra := range map[string]string{
		"TCP without mTLS":           `admin { listen = "127.0.0.1:9000" }`,
		"TCP with half of mTLS":      "admin {\nlisten = \"127.0.0.1:9000\"\ntls_cert_file = \"x\"\ntls_key_file = \"y\"\n}",
		"a unix socket with no path": `admin { listen = "unix://" }`,
		"metrics without a port":     `metrics { listen = "127.0.0.1" }`,
		"metrics on the public port": "listen = \"127.0.0.1:8080\"\nmetrics { listen = \"127.0.0.1:8080\" }",
	} {
		if _, err := c.load(t, c.hcl(nil)+extra); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
}

// metricsRun is the metrics listener on a port the system chose.
type metricsRun struct {
	run  func(context.Context) error
	addr string
}

func (s *server) openMetricsFor(t *testing.T) (metricsRun, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return metricsRun{}, err
	}
	return metricsRun{func(ctx context.Context) error { return s.serveMetrics(ctx, ln) }, ln.Addr().String()}, nil
}

// Over TCP, mutual TLS: a client with a certificate from the pinned CA is
// served and named in the audit line by its CN; one without is refused.
func TestAdminOverMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := testCA(t)
	writeCert := func(name string, isClient bool) (string, string) {
		cert, key := testLeaf(t, ca, caKey, name, isClient)
		c, k := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		os.WriteFile(c, cert, 0o644)
		os.WriteFile(k, key, 0o600)
		return filepath.ToSlash(c), filepath.ToSlash(k)
	}
	srvCert, srvKey := writeCert("localhost", false)
	cliCert, cliKey := writeCert("operator", true)
	caFile := filepath.ToSlash(filepath.Join(dir, "ca.crt"))
	os.WriteFile(caFile, pemCert(ca.Raw), 0o644)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	var log strings.Builder
	f := newFixture(t, `
admin {
  listen         = "`+addr+`"
  tls_cert_file  = "`+srvCert+`"
  tls_key_file   = "`+srvKey+`"
  client_ca_file = "`+caFile+`"
}
`)
	f.s.log = &syncLog{b: &log}
	run, err := f.s.openAdmin()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go run(ctx)

	cc, err := control.Dial(control.ClientConfig{Target: addr, CertFile: cliCert, KeyFile: cliKey, ServerCAFile: caFile, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if _, err := adminv1.NewAdminServiceClient(cc).RevokePerson(t.Context(), &adminv1.RevokePersonRequest{Username: "nobody@x"}); err != nil {
		t.Fatalf("a client with a certificate: %v", err)
	}
	if !strings.Contains(log.String(), "cn=operator revokes nobody@x") {
		t.Errorf("the audit line does not name the client certificate:\n%s", log.String())
	}
	// Without a client certificate: refused at the handshake.
	bare, err := control.Dial(control.ClientConfig{Target: addr, ServerCAFile: caFile, ServerName: "localhost"})
	if err == nil {
		defer bare.Close()
		ctx2, c2 := context.WithTimeout(t.Context(), 5*time.Second)
		defer c2()
		if _, err := adminv1.NewAdminServiceClient(bare).Status(ctx2, &adminv1.StatusRequest{}); err == nil {
			t.Error("a client without a certificate was served")
		}
	}
}

type syncLog struct {
	mu sync.Mutex
	b  *strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
