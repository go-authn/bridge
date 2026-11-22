// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/go-authn/secretsource"
)

// The mail block: how the bridge tells a person, through a channel that holds
// none of their passkeys, that the removal of one was requested or cancelled
// (#122). A key can always cancel a pending removal, so a thief holding one key
// can cancel the removal the owner asked for with another; only a notice the
// thief cannot reach lets the owner see it.
//
//	mail {
//	  host          = "smtp.example.org"
//	  security      = "tls"                              # "tls" (465) or "starttls" (587)
//	  username      = "authn-bridge"
//	  password_from = "systemd-creds:smtp"               # a secretsource reference; password_file = PATH is the deprecated alias of "file:PATH"
//	  from          = "authn-bridge@example.org"
//	}
//
// The rules are not options. TLS is always on, before anything is said that
// matters: implicit TLS, or STARTTLS that the server offers and completes (a
// server that does not is refused, never talked to in clear). The server's
// certificate is verified against the system roots. Credentials are required,
// and are sent only once TLS is up, never to localhost over cleartext either.
type mailBlock struct {
	Host     string `hcl:"host"`
	Port     int    `hcl:"port,optional"`
	Security string `hcl:"security,optional"`
	Username string `hcl:"username"`
	// PasswordFrom is a secretsource reference to the SMTP password, such as
	// "systemd-creds:smtp" or "file:/etc/authn-bridge/smtp.password". The
	// configuration never holds the secret itself (never the environment or a
	// command line either).
	PasswordFrom string `hcl:"password_from,optional"`
	// PasswordFile is the deprecated spelling of password_from = "file:PATH".
	PasswordFile string `hcl:"password_file,optional"`
	From         string `hcl:"from"`
	// Window is the least time between two mails to one account: notices that
	// arrive within it are collapsed into one digest. Default 10m, 1m to 24h.
	Window string `hcl:"window,optional"`

	password string
	window   time.Duration
}

const (
	defaultMailWindow = 10 * time.Minute
	maxMailPassword   = 4 << 10
	mailTimeout       = 30 * time.Second
)

func (m *mailBlock) check() error {
	if m.Host == "" || strings.ContainsAny(m.Host, " /\\@\t\r\n") {
		return fmt.Errorf("host %q: a host name", m.Host)
	}
	switch m.Security {
	case "":
		m.Security = "tls"
	case "tls", "starttls":
	default:
		return fmt.Errorf("security %q: \"tls\" (implicit TLS) or \"starttls\"; mail without TLS is not an option", m.Security)
	}
	if m.Port == 0 {
		m.Port = 465
		if m.Security == "starttls" {
			m.Port = 587
		}
	}
	if m.Port < 1 || m.Port > 65535 {
		return fmt.Errorf("port %d is not a port", m.Port)
	}
	if m.PasswordFrom != "" && m.PasswordFile != "" {
		return errors.New("password_from and password_file are both set: keep password_from (password_file is its deprecated alias)")
	}
	ref := m.PasswordFrom
	if m.PasswordFile != "" {
		ref = "file:" + m.PasswordFile
	}
	if m.Username == "" || ref == "" {
		return errors.New("username and password_from are required: the bridge sends mail through an authenticated server only")
	}
	if strings.ContainsAny(m.Username, "\x00\r\n") {
		return errors.New("username: no NUL, CR or LF")
	}
	if _, err := mailAddr(m.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	m.window = defaultMailWindow
	if m.Window != "" {
		d, err := time.ParseDuration(m.Window)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return fmt.Errorf("window %q: a duration from 1m to 24h", m.Window)
		}
		m.window = d
	}
	ctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
	defer cancel()
	sec, err := secretsource.Open(ctx, ref)
	if err != nil {
		return fmt.Errorf("password_from: %w", err)
	}
	defer sec.Close()
	// systemd-creds: returns the bytes exactly; a lone trailing newline from
	// `echo` is not part of a password, any other control character is refused.
	p := strings.TrimRight(string(sec.Bytes()), "\r\n")
	if p == "" || len(p) > maxMailPassword || strings.ContainsAny(p, "\x00\r\n") {
		return errors.New("password_from: one non-empty line without NUL")
	}
	m.password = p
	return nil
}

// mailAddr is an address the bridge will put in an envelope or a header: a bare
// ASCII addr-spec, no display name, no control character. It is the one
// validator for the sender, the recipient and every header value built from them.
func mailAddr(s string) (string, error) {
	if s == "" || len(s) > 254 {
		return "", errors.New("an e-mail address")
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return "", fmt.Errorf("%q: an address of printable ASCII", s)
		}
	}
	a, err := netmail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" || strings.ContainsAny(s, "<>,;\"") {
		return "", fmt.Errorf("%q: a bare address such as alice@example.org", s)
	}
	return s, nil
}

// ---- the authentication, after TLS only ----

var (
	errMailNoSTARTTLS = errors.New("the server does not offer STARTTLS: nothing is sent in clear")
	errMailNoAuth     = errors.New("the server offers no AUTH mechanism the bridge supports (PLAIN, LOGIN) after TLS")
	errMailClear      = errors.New("refusing to send credentials over a connection that is not TLS")
)

// mailAuth is PLAIN or LOGIN. Unlike smtp.PlainAuth it has no exception for
// localhost: Start refuses whenever the connection is not TLS.
type mailAuth struct {
	mech, user, pass string
}

func (a *mailAuth) Start(si *smtp.ServerInfo) (string, []byte, error) {
	if !si.TLS {
		return "", nil, errMailClear
	}
	switch a.mech {
	case "PLAIN":
		return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
	case "LOGIN":
		return "LOGIN", nil, nil
	}
	return "", nil, errMailNoAuth
}

func (a *mailAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if a.mech != "LOGIN" {
		return nil, errors.New("unexpected challenge")
	}
	switch strings.ToLower(strings.TrimRight(string(from), ": ")) {
	case "username":
		return []byte(a.user), nil
	case "password":
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected LOGIN challenge")
}

// pickAuth is the strongest mechanism the server lists among the ones supported:
// PLAIN, then LOGIN. "" when none.
func pickAuth(advertised string) string {
	have := map[string]bool{}
	for _, f := range strings.Fields(strings.ToUpper(advertised)) {
		have[f] = true
	}
	for _, m := range []string{"PLAIN", "LOGIN"} {
		if have[m] {
			return m
		}
	}
	return ""
}

// ---- sending ----

// send delivers msg from the configured sender to one recipient. tc is the TLS
// configuration (nil: the system roots; tests pass their own roots). Everything,
// the dial included, ends within mailTimeout.
func (m *mailBlock) send(ctx context.Context, tc *tls.Config, to string, msg []byte) error {
	from, err := mailAddr(m.From)
	if err != nil {
		return err
	}
	if to, err = mailAddr(to); err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, mailTimeout)
	defer cancel()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tc != nil {
		cfg = tc.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		cfg.InsecureSkipVerify = false
	}
	cfg.ServerName = m.Host

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(m.Port)))
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	var c *smtp.Client
	if m.Security == "tls" {
		t := tls.Client(conn, cfg)
		if err := t.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		c, err = smtp.NewClient(t, m.Host)
	} else {
		c, err = smtp.NewClient(conn, m.Host)
		if err == nil {
			if ok, _ := c.Extension("STARTTLS"); !ok {
				c.Close()
				return errMailNoSTARTTLS
			}
			err = c.StartTLS(cfg)
		}
	}
	if err != nil {
		return fmt.Errorf("SMTP: %w", err)
	}
	defer c.Close()
	// Both paths above end with TLS up (implicit: the handshake is done;
	// STARTTLS: c.StartTLS succeeded), and mailAuth.Start refuses to send the
	// credentials on a connection that is not TLS, whatever got us here.
	mech := ""
	if ok, params := c.Extension("AUTH"); ok {
		mech = pickAuth(params)
	}
	if mech == "" {
		return errMailNoAuth
	}
	if err := c.Auth(&mailAuth{mech: mech, user: m.Username, pass: m.password}); err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	_, werr := w.Write(msg)
	if err := errors.Join(werr, w.Close()); err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	c.Quit()
	return nil
}

// ---- the message ----

// headerValue refuses what would end a header line or forge another: any
// control character, and so CR and LF, and the Unicode line separators.
func headerValue(name, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("header %s: a control or line-break character is refused", name)
		}
	}
	return nil
}

// buildMessage is a plain-text mail, headers built from validated parts only.
func buildMessage(from, to, subject string, date time.Time, body string) ([]byte, error) {
	for name, v := range map[string]string{"From": from, "To": to, "Subject": subject} {
		if err := headerValue(name, v); err != nil {
			return nil, err
		}
	}
	if _, err := mailAddr(from); err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	if _, err := mailAddr(to); err != nil {
		return nil, fmt.Errorf("to: %w", err)
	}
	var id [12]byte
	rand.Read(id[:]) // crypto/rand.Read does not fail (it aborts the program if it must)
	domain := from[strings.LastIndexByte(from, '@')+1:]
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", to)
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", date.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")
	q := quotedprintable.NewWriter(&b)
	q.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
	q.Close()
	return b.Bytes(), nil
}

// textField makes something a client sent safe to print in a mail body: no
// control characters, bounded.
func textField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "..."
	}
	return s
}
