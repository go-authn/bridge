// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	netmail "net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is an in-process SMTP server. It records every command line, whether
// an AUTH was seen in the clear, and the messages it accepted.
type fakeSMTP struct {
	t         *testing.T
	ln        net.Listener
	cfg       *tls.Config
	implicit  bool   // TLS from the first byte
	starttls  bool   // offers STARTTLS
	auth      string // the AUTH line to advertise after TLS ("" none)
	clearAuth bool   // also advertises AUTH before TLS: a trap for a client that sends credentials anyway
	user, pw  string

	mu        sync.Mutex
	cmds      []string
	authClear bool
	mech      string
	mails     []string
}

func (f *fakeSMTP) record(c string) { f.mu.Lock(); f.cmds = append(f.cmds, c); f.mu.Unlock() }

func (f *fakeSMTP) saw(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.HasPrefix(strings.ToUpper(c), prefix) {
			return true
		}
	}
	return false
}

func smtpCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake smtp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

// startSMTP serves one fake server whose certificate names certNames.
func startSMTP(t *testing.T, f *fakeSMTP, certNames ...string) *tls.Config {
	t.Helper()
	cert, pool := smtpCert(t, certNames...)
	f.t = t
	f.cfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return &tls.Config{RootCAs: pool}
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	secure := false
	if f.implicit {
		tc := tls.Server(c, f.cfg)
		if tc.Handshake() != nil {
			return
		}
		c, secure = tc, true
	}
	r := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	line := func() (string, bool) {
		l, err := r.ReadString('\n')
		return strings.TrimRight(l, "\r\n"), err == nil
	}
	say("220 fake ESMTP")
	for {
		l, ok := line()
		if !ok {
			return
		}
		f.record(l)
		up := strings.ToUpper(l)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250-fake")
			if f.starttls && !secure {
				say("250-STARTTLS")
			}
			if f.auth != "" && (secure || f.clearAuth) {
				say("250-AUTH " + f.auth)
			}
			say("250 8BITMIME")
		case up == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.cfg)
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
			r = bufio.NewReader(c)
		case strings.HasPrefix(up, "AUTH "):
			if !secure {
				f.mu.Lock()
				f.authClear = true
				f.mu.Unlock()
			}
			parts := strings.Fields(l)
			f.mu.Lock()
			f.mech = strings.ToUpper(parts[1])
			f.mu.Unlock()
			var user, pw string
			switch strings.ToUpper(parts[1]) {
			case "PLAIN":
				ir := ""
				if len(parts) > 2 {
					ir = parts[2]
				} else {
					say("334 ")
					ir, _ = line()
				}
				b, _ := base64.StdEncoding.DecodeString(ir)
				f := strings.Split(string(b), "\x00")
				if len(f) == 3 {
					user, pw = f[1], f[2]
				}
			case "LOGIN":
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := line()
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := line()
				ub, _ := base64.StdEncoding.DecodeString(u)
				pb, _ := base64.StdEncoding.DecodeString(p)
				user, pw = string(ub), string(pb)
			default:
				say("504 no such mechanism")
				continue
			}
			if user == f.user && pw == f.pw {
				say("235 ok")
			} else {
				say("535 no")
			}
		case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				d, ok := line()
				if !ok || d == "." {
					break
				}
				b.WriteString(d + "\n")
			}
			f.mu.Lock()
			f.mails = append(f.mails, b.String())
			f.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeSMTP) block(t *testing.T, security string) *mailBlock {
	t.Helper()
	port := f.ln.Addr().(*net.TCPAddr).Port
	return &mailBlock{Host: "127.0.0.1", Port: port, Security: security, Username: "bridge", From: "bridge@example.org", password: "s3cret-pw"}
}

func smtpOK(security string) *fakeSMTP {
	return &fakeSMTP{implicit: security == "tls", starttls: security == "starttls", auth: "PLAIN LOGIN", user: "bridge", pw: "s3cret-pw"}
}

func sendTest(m *mailBlock, tc *tls.Config) error {
	return m.send(context.Background(), tc, "alice@example.org", []byte("Subject: t\r\n\r\nhello\r\n.dot line\r\n"))
}

func TestMailDeliversOverImplicitTLSAndSTARTTLS(t *testing.T) {
	for _, sec := range []string{"tls", "starttls"} {
		f := smtpOK(sec)
		tc := startSMTP(t, f, "127.0.0.1")
		if err := sendTest(f.block(t, sec), tc); err != nil {
			t.Fatalf("%s: %v", sec, err)
		}
		if len(f.mails) != 1 || !strings.Contains(f.mails[0], "hello") {
			t.Fatalf("%s: mails %q", sec, f.mails)
		}
		if f.authClear {
			t.Fatalf("%s: AUTH in clear", sec)
		}
		if f.mech != "PLAIN" {
			t.Errorf("%s: mechanism %s, want the strongest supported (PLAIN)", sec, f.mech)
		}
	}
}

func TestMailUsesLOGINWhenOnlyThatIsOffered(t *testing.T) {
	f := smtpOK("tls")
	f.auth = "CRAM-MD5 LOGIN"
	tc := startSMTP(t, f, "127.0.0.1")
	if err := sendTest(f.block(t, "tls"), tc); err != nil {
		t.Fatal(err)
	}
	if f.mech != "LOGIN" || len(f.mails) != 1 {
		t.Fatalf("mech %q, mails %d", f.mech, len(f.mails))
	}
}

func TestMailRefusesAServerWithoutASupportedMechanism(t *testing.T) {
	for name, auth := range map[string]string{"none advertised": "", "only CRAM-MD5": "CRAM-MD5 XOAUTH2"} {
		f := smtpOK("tls")
		f.auth = auth
		tc := startSMTP(t, f, "127.0.0.1")
		err := sendTest(f.block(t, "tls"), tc)
		if !errors.Is(err, errMailNoAuth) {
			t.Errorf("%s: %v, want errMailNoAuth", name, err)
		}
		if f.saw("MAIL") || f.saw("AUTH") {
			t.Errorf("%s: the client went on after refusing: %q", name, f.cmds)
		}
	}
}

func TestMailNeverSendsCredentialsInClear(t *testing.T) {
	// starttls mode, a server that does not offer STARTTLS but advertises AUTH
	// in clear on 127.0.0.1: net/smtp.PlainAuth would send the password.
	f := smtpOK("starttls")
	f.starttls, f.clearAuth = false, true
	tc := startSMTP(t, f, "127.0.0.1")
	err := sendTest(f.block(t, "starttls"), tc)
	if !errors.Is(err, errMailNoSTARTTLS) {
		t.Fatalf("%v, want errMailNoSTARTTLS", err)
	}
	if f.authClear || f.saw("AUTH") || f.saw("MAIL") {
		t.Fatalf("something was said in clear: %q", f.cmds)
	}
}

func TestMailAuthRefusesWithoutTLSEvenToLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		for _, mech := range []string{"PLAIN", "LOGIN"} {
			a := &mailAuth{mech: mech, user: "u", pass: "p"}
			if _, ir, err := a.Start(&smtp.ServerInfo{Name: host, TLS: false, Auth: []string{mech}}); !errors.Is(err, errMailClear) || ir != nil {
				t.Errorf("%s %s: %v %q", host, mech, err, ir)
			}
			if _, ir, err := a.Start(&smtp.ServerInfo{Name: host, TLS: true, Auth: []string{mech}}); err != nil || (mech == "PLAIN") != (ir != nil) {
				t.Errorf("%s %s over TLS: %v %q", host, mech, err, ir)
			}
		}
	}
}

func TestMailRefusesAMismatchedCertificate(t *testing.T) {
	for _, sec := range []string{"tls", "starttls"} {
		f := smtpOK(sec)
		tc := startSMTP(t, f, "other.example") // not 127.0.0.1
		err := sendTest(f.block(t, sec), tc)
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("%s: %v, want a certificate error", sec, err)
		}
		if f.authClear || f.saw("AUTH") || f.saw("MAIL") {
			t.Fatalf("%s: the client went on: %q", sec, f.cmds)
		}
	}
	// And an unknown CA: no roots given, the system's are used.
	f := smtpOK("tls")
	startSMTP(t, f, "127.0.0.1")
	if err := sendTest(f.block(t, "tls"), nil); err == nil {
		t.Fatal("a self-signed certificate was accepted")
	}
}

func TestMailCannotBeToldToSkipVerification(t *testing.T) {
	f := smtpOK("tls")
	startSMTP(t, f, "other.example")
	err := sendTest(f.block(t, "tls"), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("InsecureSkipVerify was honoured")
	}
}

func TestMailAuthenticationFailure(t *testing.T) {
	f := smtpOK("tls")
	f.pw = "another"
	tc := startSMTP(t, f, "127.0.0.1")
	err := sendTest(f.block(t, "tls"), tc)
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "s3cret-pw") || f.saw("MAIL") {
		t.Fatalf("leak or went on: %v %q", err, f.cmds)
	}
}

func TestMailHeaderInjectionIsRefused(t *testing.T) {
	f := smtpOK("tls")
	tc := startSMTP(t, f, "127.0.0.1")
	m := f.block(t, "tls")
	for _, to := range []string{"a@b.org\r\nRCPT TO:<x@y.org>", "a@b.org\nBcc: x@y.org", "a@b.org>\r\n", "Bob <a@b.org>", "a b@c.org", ""} {
		if err := m.send(context.Background(), tc, to, []byte("x")); err == nil {
			t.Errorf("recipient %q accepted", to)
		}
	}
	m.From = "bridge@example.org\r\nBcc: x@y.org"
	if err := m.send(context.Background(), tc, "a@b.org", []byte("x")); err == nil {
		t.Error("sender with CRLF accepted")
	}
	if f.saw("RCPT") || f.saw("MAIL") || len(f.cmds) > 0 {
		t.Errorf("the server heard %q", f.cmds)
	}
	for _, bad := range []struct{ from, to, subject string }{
		{"a@b.org", "c@d.org", "hi\r\nBcc: x@y.org"},
		{"a@b.org", "c@d.org", "hi\nBcc: x@y.org"},
		{"a@b.org", "c@d.org", "hi Bcc: x"},
		{"a@b.org\r\nX: y", "c@d.org", "s"},
		{"a@b.org", "c@d.org\r\nX: y", "s"},
	} {
		if _, err := buildMessage(bad.from, bad.to, bad.subject, time.Now(), "body"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMailBodyCannotForgeHeadersOrEndTheMessage(t *testing.T) {
	body := "line\r\n.\r\nQUIT\r\nBcc: x@y.org\r\n\r\n..\r\n"
	msg, err := buildMessage("a@b.org", "c@d.org", "subject é", time.Unix(0, 0), body)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := netmail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Bcc") != "" {
		t.Fatal("a Bcc header came out of the body")
	}
	if got := parsed.Header.Get("To"); got != "c@d.org" {
		t.Fatalf("To %q", got)
	}
	f := smtpOK("tls")
	tc := startSMTP(t, f, "127.0.0.1")
	if err := f.block(t, "tls").send(context.Background(), tc, "c@d.org", msg); err != nil {
		t.Fatal(err)
	}
	if f.saw("QUIT") && len(f.mails) != 1 {
		t.Fatal("the body ended the message early")
	}
}

func TestMailBlockCheck(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte("hunter2-hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := func() *mailBlock {
		return &mailBlock{Host: "smtp.example.org", Username: "u", PasswordFile: pw, From: "bridge@example.org"}
	}
	m := good()
	if err := m.check(); err != nil {
		t.Fatal(err)
	}
	if m.password != "hunter2-hunter2" || m.Port != 465 || m.Security != "tls" || m.window != defaultMailWindow {
		t.Fatalf("%+v", m)
	}
	m = good()
	m.Security = "starttls"
	if m.check(); m.Port != 587 {
		t.Fatalf("starttls port %d", m.Port)
	}
	cases := map[string]func(*mailBlock){
		"no TLS":                          func(m *mailBlock) { m.Security = "none" },
		"plain":                           func(m *mailBlock) { m.Security = "plain" },
		"no credentials":                  func(m *mailBlock) { m.Username, m.PasswordFile = "", "" },
		"no username":                     func(m *mailBlock) { m.Username = "" },
		"no password file":                func(m *mailBlock) { m.PasswordFile = "" },
		"missing file":                    func(m *mailBlock) { m.PasswordFile = filepath.Join(dir, "nope") },
		"a directory":                     func(m *mailBlock) { m.PasswordFile = dir },
		"host with a slash":               func(m *mailBlock) { m.Host = "smtp/x" },
		"no host":                         func(m *mailBlock) { m.Host = "" },
		"port 0 is default, 70000 is not": func(m *mailBlock) { m.Port = 70000 },
		"from with a name":                func(m *mailBlock) { m.From = "Bridge <bridge@example.org>" },
		"from with CRLF":                  func(m *mailBlock) { m.From = "bridge@example.org\r\nBcc: x@y" },
		"window too short":                func(m *mailBlock) { m.Window = "1s" },
		"window too long":                 func(m *mailBlock) { m.Window = "400h" },
		"window not a time":               func(m *mailBlock) { m.Window = "soon" },
		"username with NUL":               func(m *mailBlock) { m.Username = "u\x00v" },
	}
	for name, mut := range cases {
		m := good()
		mut(m)
		if err := m.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	multi := filepath.Join(dir, "multi")
	os.WriteFile(multi, []byte("a\nb\n"), 0o600)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, make([]byte, maxMailPassword+1), 0o600)
	for _, f := range []string{empty, multi, big} {
		m := good()
		m.PasswordFile = f
		if err := m.check(); err == nil {
			t.Errorf("%s accepted", filepath.Base(f))
		}
	}
}

func TestMailPasswordFileMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits")
	}
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("hunter2-hunter2"), 0o600)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
		os.Chmod(pw, mode)
		m := &mailBlock{Host: "h", Username: "u", PasswordFile: pw, From: "a@b.org"}
		err := m.check()
		if err == nil || !strings.Contains(err.Error(), "group or others") {
			t.Errorf("mode %04o: %v", mode, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error shows the secret: %v", err)
		}
	}
	os.Chmod(pw, 0o400)
	m := &mailBlock{Host: "h", Username: "u", PasswordFile: pw, From: "a@b.org"}
	if err := m.check(); err != nil {
		t.Errorf("0400: %v", err)
	}
}

func TestPickAuth(t *testing.T) {
	for in, want := range map[string]string{
		"PLAIN LOGIN": "PLAIN", "LOGIN PLAIN": "PLAIN", "login": "LOGIN", "CRAM-MD5 LOGIN": "LOGIN",
		"CRAM-MD5": "", "": "", "XPLAIN": "",
	} {
		if got := pickAuth(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestTextFieldIsBoundedAndPlain(t *testing.T) {
	if got := textField("a\r\nb\x00c d"); got != "a  b c d" {
		t.Errorf("%q", got)
	}
	long := textField(strings.Repeat("é", 500))
	if r := []rune(long); len(r) != 203 || !strings.HasSuffix(long, "...") {
		t.Errorf("%d runes", len(r))
	}
	if got := textField(strings.Repeat("x", 200)); strings.HasSuffix(got, "...") {
		t.Errorf("200 characters were cut")
	}
}

func FuzzBuildMessage(f *testing.F) {
	f.Add("a@b.org", "c@d.org", "subject", "body")
	f.Add("a@b.org", "c@d.org", "hi\r\nBcc: x@y.org", "x")
	f.Add("a@b.org\r\nX: y", "c@d.org", "s", ".\r\n")
	f.Add("a@b.org", "c@d.org\nBcc: z", "s t", "\r\n\r\nBcc: q")
	f.Fuzz(func(t *testing.T, from, to, subject, body string) {
		msg, err := buildMessage(from, to, subject, time.Unix(0, 0), body)
		if err != nil {
			return
		}
		head, _, ok := strings.Cut(string(msg), "\r\n\r\n")
		if !ok {
			t.Fatalf("no header end: %q", msg)
		}
		known := map[string]bool{"From": true, "To": true, "Subject": true, "Date": true, "Message-Id": true, "Mime-Version": true, "Auto-Submitted": true, "Content-Type": true, "Content-Transfer-Encoding": true}
		lines := strings.Split(head, "\r\n")
		if len(lines) != len(known) {
			t.Fatalf("%d header lines, want %d: %q", len(lines), len(known), head)
		}
		for _, l := range lines {
			k, _, ok := strings.Cut(l, ": ")
			if !ok || !known[textproto.CanonicalMIMEHeaderKey(k)] {
				t.Fatalf("unexpected header line %q in %q", l, head)
			}
			if strings.ContainsAny(l, "\r\n") {
				t.Fatalf("line break inside %q", l)
			}
		}
		p, err := netmail.ReadMessage(strings.NewReader(string(msg)))
		if err != nil {
			t.Fatalf("unparseable: %v", err)
		}
		if p.Header.Get("To") != to || p.Header.Get("From") != from || p.Header.Get("Bcc") != "" {
			t.Fatalf("headers changed: %v", p.Header)
		}
	})
}
