// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned writes a certificate for names and its key, and returns them.
func selfSigned(t *testing.T, dir, name string, names ...string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	cert, _ = x509.ParseCertificate(der)
	return certFile, keyFile, cert
}

func TestACMEConfigRefusals(t *testing.T) {
	c := newConf(t)
	mac := filepath.ToSlash(filepath.Join(c.dir, "mac"))
	os.WriteFile(mac, []byte("HjudV5qnbreN-n9WyFSH-t4HXuEx_XFen45zuxY-G1h6fr74V3cUM_dVlwQZBWmc\n"), 0o600)
	bad := filepath.ToSlash(filepath.Join(c.dir, "bad"))
	os.WriteFile(bad, []byte("%%%"), 0o600)
	cache := filepath.ToSlash(filepath.Join(c.dir, "acme"))
	block := func(body string) func(string) string {
		return func(s string) string { return s + "acme {\n" + body + "\n}\n" }
	}
	for _, tc := range []struct {
		name, want string
		edit       func(string) string
	}{
		{"terms", "accept_terms_of_service", block(`accept_terms_of_service = false
cache_dir = "` + cache + `"`)},
		{"cache", "cache_dir", block(`accept_terms_of_service = true
cache_dir = ""`)},
		{"eab half", "go together", block(`accept_terms_of_service = true
cache_dir = "` + cache + `"
eab_key_id = "kid-1"`)},
		{"http directory", "https URL", block(`accept_terms_of_service = true
cache_dir = "` + cache + `"
directory_url = "http://ca.example/dir"`)},
		{"http listen", "http_listen", block(`accept_terms_of_service = true
cache_dir = "` + cache + `"
http_listen = "80"`)},
		{"both", "one or the other", func(s string) string {
			return block(`accept_terms_of_service = true
cache_dir = "`+cache+`"`)(s) + "cert_file = \"" + c.spCert + "\"\nkey_file = \"" + c.spKey + "\"\n"
		}},
		{"ip issuer", "IP address", func(s string) string {
			return strings.Replace(block(`accept_terms_of_service = true
cache_dir = "`+cache+`"`)(s), "https://login.example.org/", "https://192.0.2.1/", 1)
		}},
	} {
		if _, err := c.load(t, c.hcl(tc.edit)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// And one that loads, with EAB: the issuer's host is the one domain, and
	// the paths go to servercert absolute.
	cfg, err := c.load(t, c.hcl(block(`accept_terms_of_service = true
cache_dir = "`+cache+`"
email = "noc@example.org"
eab_key_id = "kid-1"
eab_hmac_key_file = "`+mac+`"`)))
	if err != nil {
		t.Fatal(err)
	}
	// A MAC key that is not base64 loads -- servercert reads the file in New,
	// not in Check -- and the provider does not start: publicTLS runs before
	// anything is served.
	badCfg, err := c.load(t, c.hcl(block(`accept_terms_of_service = true
cache_dir = "`+cache+`"
eab_key_id = "kid-1"
eab_hmac_key_file = "`+bad+`"`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&server{cfg: badCfg, log: io.Discard}).publicTLS(); err == nil {
		t.Error("started with an EAB MAC key that is not base64")
	}
	sc, ok := cfg.certConfig(t.Logf)
	if !ok || sc.ACME == nil || len(sc.ACME.Domains) != 1 || sc.ACME.Domains[0] != "login.example.org" || sc.ACME.EABKeyID != "kid-1" || !filepath.IsAbs(sc.ACME.CacheDir) || !filepath.IsAbs(sc.ACME.EABHMACKeyFile) {
		t.Errorf("servercert config %+v %+v", sc, sc.ACME)
	}
}

// pebble is Let's Encrypt's test CA, the judge here: this repository asks,
// something it did not write issues. It requires External Account Binding,
// as HARICA does, and validates tls-alpn-01 against the listener for real.
type pebble struct {
	dir, caFile string
	mgmt        string
}

func startPebble(t *testing.T, tlsPort string, macKey string) *pebble {
	t.Helper()
	bin, err := exec.LookPath("pebble")
	if err != nil {
		if gp, _ := exec.Command("go", "env", "GOPATH").Output(); len(gp) > 0 {
			for _, name := range []string{"pebble", "pebble.exe"} {
				if p := filepath.Join(strings.TrimSpace(string(gp)), "bin", name); fileExists(p) {
					bin, err = p, nil
				}
			}
		}
	}
	if err != nil {
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatal("pebble is required here and is not installed (go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1)")
		}
		t.Skip("pebble is not installed")
	}
	dir := t.TempDir()
	caFile, keyFile, _ := selfSigned(t, dir, "pebble", "127.0.0.1", "localhost")
	listen, mgmt := freePort(t), freePort(t)
	conf := map[string]any{"pebble": map[string]any{
		"listenAddress":                  "127.0.0.1:" + listen,
		"managementListenAddress":        "127.0.0.1:" + mgmt,
		"certificate":                    caFile,
		"privateKey":                     keyFile,
		"httpPort":                       5002,
		"tlsPort":                        mustAtoi(tlsPort),
		"externalAccountBindingRequired": true,
		"externalAccountMACKeys":         map[string]string{"kid-1": macKey},
	}}
	b, _ := json.Marshal(conf)
	confFile := filepath.Join(dir, "pebble.json")
	os.WriteFile(confFile, b, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "-config", confFile, "-dnsserver", dnsStub(t))
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Logf("pebble:\n%s", out.String())
		}
	})
	p := &pebble{dir: "https://127.0.0.1:" + listen + "/dir", caFile: caFile, mgmt: "https://127.0.0.1:" + mgmt}
	for i := 0; ; i++ {
		if _, err := p.get(p.dir); err == nil {
			break
		}
		if i == 100 {
			t.Fatalf("pebble did not start:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return p
}

func (p *pebble) get(u string) ([]byte, error) {
	pool, err := certPool(p.caFile)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	res, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, res.Status)
	}
	return io.ReadAll(res.Body)
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func mustAtoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// A certificate from an ACME CA with External Account Binding, validated
// over tls-alpn-01 on the listener itself; the same with a wrong MAC key
// gets nothing.
func TestACMEAgainstPebble(t *testing.T) {
	const macKey = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := startPebble(t, port, macKey)

	serve := func(key string) (*server, func()) {
		dir := t.TempDir()
		mac := filepath.Join(dir, "mac")
		os.WriteFile(mac, []byte(key), 0o600)
		b := &acmeBlock{
			DirectoryURL: p.dir, AcceptTermsOfService: true, Email: "noc@example.org",
			EABKeyID: "kid-1", EABHMACKeyFile: mac, CacheDir: filepath.Join(dir, "cache"),
			DirectoryCAFile: p.caFile,
		}
		if err := b.check("https://bridge.test:" + port); err != nil {
			t.Fatal(err)
		}
		s := &server{cfg: &config{ACME: b, Issuer: "https://bridge.test:" + port}, log: io.Discard}
		tc, run, err := s.publicTLS()
		if err != nil || run != nil {
			t.Fatalf("publicTLS: %v %v", err, run != nil)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), TLSConfig: tc}
		go srv.ServeTLS(ln, "", "")
		return s, func() { srv.Close() }
	}

	// The wrong MAC key first, on the same listener: no account, no
	// certificate, the handshake fails.
	_, stop := serve("b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH")
	if _, err := tls.Dial("tcp", "127.0.0.1:"+port, &tls.Config{ServerName: "bridge.test", InsecureSkipVerify: true}); err == nil {
		t.Error("a certificate with the wrong EAB MAC key")
	}
	stop()

	// The right key: a listener again on the same port, which Pebble dials.
	ln, err = net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	_, stop = serve(macKey)
	defer stop()
	conn, err := tls.Dial("tcp", "127.0.0.1:"+port, &tls.Config{ServerName: "bridge.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	chain := conn.ConnectionState().PeerCertificates
	conn.Close()

	// Verified against Pebble's root, fetched from Pebble: the certificate
	// is Pebble's, for the issuer's host.
	root, err := p.get(p.mgmt + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: "bridge.test", Roots: roots, Intermediates: inter}); err != nil {
		t.Errorf("the served certificate does not chain to Pebble's root: %v", err)
	}
	// A browser's ALPN (h2, http/1.1) is served: with ACME, servercert's
	// NextProtos is acme-tls/1 alone, and a Go server refuses a client that
	// shares none of them unless ServeTLS has appended its own.
	for _, protos := range [][]string{{"h2", "http/1.1"}, {"http/1.1"}} {
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			ForceAttemptHTTP2: protos[0] == "h2",
			TLSClientConfig:   &tls.Config{RootCAs: withInter(roots, chain[1:]), NextProtos: protos},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
			},
		}}
		res, err := hc.Get("https://bridge.test:" + port + "/")
		if err != nil {
			t.Errorf("ALPN %v: %v", protos, err)
			continue
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("ALPN %v: %s", protos, res.Status)
		}
	}
	// And a name other than the issuer's is not asked for.
	if _, err := tls.Dial("tcp", "127.0.0.1:"+port, &tls.Config{ServerName: "elsewhere.example", InsecureSkipVerify: true}); err == nil {
		t.Error("a certificate for a host that is not the issuer's")
	}
}

// dnsStub answers every A question with 127.0.0.1 and every other one
// (AAAA, CAA) with no records: what Pebble's validation asks before it dials
// the listener. Over TCP, which is how Pebble asks a -dnsserver (va.go:142).
// autocert refuses a name without a dot, so the test cannot use "localhost".
func dnsStub(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, int(l[0])<<8|int(l[1]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					a := dnsAnswer(q)
					if a == nil {
						return
					}
					c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func dnsAnswer(q []byte) []byte {
	n := len(q)
	if n < 12 {
		return nil
	}
	// The question: labels to a zero byte, then type and class.
	i := 12
	for i < n && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > n {
		return nil
	}
	qtype := int(q[i+1])<<8 | int(q[i+2])
	resp := append([]byte{}, q[:i+5]...)
	resp[2] = 0x84 | q[2]&0x01 // QR, AA, and RD as asked
	resp[3] = 0x00
	resp[6], resp[7] = 0, 0 // ANCOUNT
	resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
	if qtype == 1 {
		resp[7] = 1
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	return resp
}

// http_listen: challenges there, and everything else sent to https.
func TestACMEHTTPListener(t *testing.T) {
	dir := t.TempDir()
	b := &acmeBlock{AcceptTermsOfService: true, CacheDir: filepath.Join(dir, "c"), HTTPListen: "127.0.0.1:0"}
	if err := b.check("https://bridge.example.org"); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: &config{ACME: b}, log: io.Discard}
	tc, run, err := s.publicTLS()
	if err != nil || run == nil || tc == nil {
		t.Fatalf("publicTLS: %v", err)
	}
	if !strings.Contains(strings.Join(tc.NextProtos, ","), "acme-tls/1") {
		t.Errorf("NextProtos %v: tls-alpn-01 cannot be answered", tc.NextProtos)
	}
	if fi, err := os.Stat(b.CacheDir); err != nil || os.PathSeparator == '/' && fi.Mode().Perm() != 0o700 {
		t.Errorf("cache_dir: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got := make(chan string, 1)
	s.log = logTo(func(line string) {
		if i := strings.LastIndex(line, " on "); i >= 0 {
			select {
			case got <- strings.TrimSpace(line[i+4:]):
			default:
			}
		}
	})
	go run(ctx)
	var addr string
	select {
	case addr = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the http-01 listener never said where it was")
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Get("http://" + addr + "/authorize?x=1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "https://") {
		t.Errorf("not sent to https: %d %q", res.StatusCode, loc)
	}
	// Taken already: the provider does not start.
	b.HTTPListen = addr
	if _, _, err := s.publicTLS(); err == nil {
		t.Error("http_listen on an address in use")
	}
}

type logTo func(string)

func (l logTo) Write(p []byte) (int, error) { l(string(p)); return len(p), nil }

// serve over TLS from files: discovery answers, over HTTP/2 as before.
func TestServeTLSFromFiles(t *testing.T) {
	f := newFixture(t, "")
	cfg := f.s.cfg
	port := freePort(t)
	cfg.Listen = "127.0.0.1:" + port
	cfg.CertFile, cfg.KeyFile, _ = selfSigned(t, t.TempDir(), "web", "127.0.0.1")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, io.Discard) }()
	pool, _ := certPool(cfg.CertFile)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}}
	var res *http.Response
	var err error
	for i := 0; i < 100; i++ {
		if res, err = c.Get("https://127.0.0.1:" + port + "/.well-known/openid-configuration"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		t.Errorf("%d over %s", res.StatusCode, res.Proto)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cfg.CertFile = filepath.Join(t.TempDir(), "gone.crt")
	if err := serve(t.Context(), cfg, io.Discard); err == nil {
		t.Error("served TLS with no certificate")
	}
}

// withInter is roots with the served intermediates added as roots too:
// Pebble's chain is leaf, intermediate, and its root is fetched apart.
func withInter(roots *x509.CertPool, inter []*x509.Certificate) *x509.CertPool {
	p := roots.Clone()
	for _, c := range inter {
		p.AddCert(c)
	}
	return p
}

// `bridge check` reads the certificate pair, as the provider would at start:
// servercert's Check alone does not.
func TestCheckReadsTheCertificate(t *testing.T) {
	f := newFixture(t, "")
	dir := t.TempDir()
	good, goodKey, _ := selfSigned(t, dir, "a", "127.0.0.1")
	_, otherKey, _ := selfSigned(t, dir, "b", "127.0.0.1")
	base, _ := os.ReadFile(f.cfgFile)
	write := func(cert, key string) string {
		p := filepath.Join(dir, cert[len(cert)-5:]+filepath.Base(key)+".hcl")
		os.WriteFile(p, append(append([]byte{}, base...), []byte("cert_file = \""+filepath.ToSlash(cert)+"\"\nkey_file = \""+filepath.ToSlash(key)+"\"\n")...), 0o600)
		return p
	}
	out, err := runCmd(t, "check", "--config", write(good, goodKey))
	if err != nil || !strings.Contains(out, "tls           from ") {
		t.Errorf("a good pair: %v\n%s", err, out)
	}
	if _, err := runCmd(t, "check", "--config", write(good, otherKey)); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Errorf("a key that is not the certificate's passed check: %v", err)
	}
}
