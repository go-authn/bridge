// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"bytes"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
	netmail "net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

// The administrator's web invitation (admininvite.go): who may, what it does,
// and every way it says no.

const (
	yubikeyBio  = "9dd8d593-2213-438a-97f8-d6b813d51c27"
	someOtherAA = "ee882879-721c-4913-9775-3dfcce97072a"
)

func adminAccountsText() string {
	return `account "alice" {
  name = "Alice Martin"
  mail = "alice@mesocentre.example"
}

account "bob" {
  name = "Bob Durand"
  mail = "bob@mesocentre.example"
}

account "carol" {
  name = "Carol Petit"
}

account "dave" {
  name = "Dave Roux"
  mail = "dave@mesocentre.example"
}
`
}

// adminEnv is a provider with three administrators (alice and bob with an
// address, carol without), dave who is not one, a clock in the test's hands and
// a working mail server.
type adminEnv struct {
	*fixture
	clock   time.Time
	clockMu sync.Mutex
	logs    *bytes.Buffer
	smtp    *fakeSMTP
	alice   *webauthntest.Authenticator
	sess    *accountSess
}

func (e *adminEnv) advance(d time.Duration) {
	e.clockMu.Lock()
	e.clock = e.clock.Add(d)
	e.clockMu.Unlock()
	e.resetThrottle()
}

func (e *adminEnv) log() string { return e.fixture.logs(e.logs) }

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	local := fmt.Sprintf("local {\n  accounts_file = %q\n  scope = %q\n  passkey_removal_delay = \"0\"\n}\n",
		filepath.ToSlash(writeAccountsFile(t, adminAccountsText())), localScope) + stateExtra(t)
	e := &adminEnv{fixture: newFixture(t, local), clock: time.Now(), logs: &bytes.Buffer{}}
	e.s.now = func() time.Time { e.clockMu.Lock(); defer e.clockMu.Unlock(); return e.clock }
	t.Cleanup(func() { e.s.notifyWG.Wait(); e.s.now = time.Now })
	e.s.log = e.logs
	f := smtpOK("tls")
	tc := startSMTP(t, f, "127.0.0.1")
	m := f.block(t, "tls")
	m.window = defaultMailWindow
	e.s.cfg.Mail, e.s.mailTLS, e.smtp = m, tc, f
	l := e.s.cfg.Local
	l.adminSet = map[string]bool{"alice": true, "bob": true, "carol": true}
	l.aaguidSet = map[string]bool{yubikeyBio: true}
	e.alice = e.keyOf("alice", yubikeyBio)
	e.sess = e.signedIn(e.alice, "alice")
	return e
}

// keyOf enrols login with a key whose model was PROVED to be aaguid.
func (e *adminEnv) keyOf(login, aaguid string) *webauthntest.Authenticator {
	e.t.Helper()
	a := e.enrolled(login, webauthn.AlgES256)
	rec, ok, err := e.s.passkeys.passkey(passkeyKey(a.ID))
	if err != nil || !ok {
		e.t.Fatalf("the key is not stored: %v", err)
	}
	rec.AttestedAAGUID = aaguid
	if err := e.s.passkeys.savePasskey(rec); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *adminEnv) do(method, cookie string, v url.Values) (int, string) {
	e.t.Helper()
	var body io.Reader
	if v != nil {
		body = strings.NewReader(v.Encode())
	}
	req, err := http.NewRequest(method, e.s.cfg.Issuer+"/account/invite", body)
	if err != nil {
		e.t.Fatal(err)
	}
	if v != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	res, err := newBrowser(e.t).c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.StatusCode, readBody(res)
}

func (e *adminEnv) invitePost(s *accountSess, login, mail, name string) (int, string) {
	return e.do("POST", s.cookie, url.Values{"csrf": {s.csrf}, "login": {login}, "mail": {mail}, "name": {name}})
}

func (e *adminEnv) exists(login string) bool {
	e.t.Helper()
	ok, err := accountExists(e.s.cfg.Local, login)
	if err != nil {
		e.t.Fatal(err)
	}
	return ok
}

type sentMail struct{ to, subject, body string }

func (e *adminEnv) sent() []sentMail {
	e.t.Helper()
	e.s.notifyWG.Wait()
	e.smtp.mu.Lock()
	defer e.smtp.mu.Unlock()
	var out []sentMail
	for _, raw := range e.smtp.mails {
		m, err := netmail.ReadMessage(strings.NewReader(strings.ReplaceAll(raw, "\n", "\r\n")))
		if err != nil {
			e.t.Fatal(err)
		}
		b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, sentMail{to: m.Header.Get("To"), subject: m.Header.Get("Subject"), body: strings.ReplaceAll(string(b), "\r\n", "\n")})
	}
	return out
}

var enrollLink = regexp.MustCompile(`/local/enroll#([A-Za-z0-9_-]+)`)

// An administrator invites a new account: it is created, the link goes to the
// invitee ALONE and works once, the admin's page does not show it, and every
// administrator with an address gets one message of their own without it.
func TestAnAdministratorInvitesAnAccountByMail(t *testing.T) {
	e := newAdminEnv(t)
	if st, body := e.accountPage(e.sess.cookie); st != http.StatusOK || !strings.Contains(body, `id="invite-link"`) {
		t.Fatalf("the administrator's account page has no invitation link: %d", st)
	}
	st, body := e.do("GET", e.sess.cookie, nil)
	if st != http.StatusOK || !strings.Contains(body, `name="csrf" value="`+e.sess.csrf+`"`) {
		t.Fatalf("the form: %d\n%s", st, body)
	}
	st, body = e.invitePost(e.sess, "erin", "erin@elsewhere.example", "Erin Blanc")
	if st != http.StatusOK || !strings.Contains(body, `id="invite-sent"`) {
		t.Fatalf("%d\n%s", st, body)
	}
	if strings.Contains(body, "enroll") || strings.Contains(body, "/local/") {
		t.Errorf("the administrator's page shows a link or a token:\n%s", body)
	}
	if !e.exists("erin") {
		t.Fatal("the account was not created")
	}
	mails := e.sent()
	if len(mails) != 3 {
		t.Fatalf("%d mails, want the invitee's and one per administrator with an address (alice, bob):\n%s", len(mails), e.log())
	}
	var tok string
	to := map[string]sentMail{}
	for _, m := range mails {
		if strings.ContainsAny(m.to, ", ;") {
			t.Errorf("a recipient list in To: %q", m.to)
		}
		if _, err := netmail.ParseAddress(m.to); err != nil {
			t.Errorf("To %q: %v", m.to, err)
		}
		to[m.to] = m
	}
	inv, ok := to["erin@elsewhere.example"]
	if !ok {
		t.Fatalf("the invitee got nothing: %v", to)
	}
	mm := enrollLink.FindStringSubmatch(inv.body)
	if mm == nil {
		t.Fatalf("the invitee's mail has no link:\n%s", inv.body)
	}
	tok = mm[1]
	for _, a := range []string{"alice@mesocentre.example", "bob@mesocentre.example"} {
		n, ok := to[a]
		if !ok {
			t.Fatalf("%s was not told: %v", a, to)
		}
		for _, want := range []string{"alice", "erin", "erin@elsewhere.example", "UTC"} {
			if !strings.Contains(n.body, want) {
				t.Errorf("the notice to %s lacks %q:\n%s", a, want, n.body)
			}
		}
		if strings.Contains(n.body, tok) || strings.Contains(n.body, "enroll") || strings.Contains(n.body, "/local/") {
			t.Errorf("the notice to %s carries the link or the token:\n%s", a, n.body)
		}
	}
	for _, m := range mails {
		if m.to != "erin@elsewhere.example" && strings.Contains(m.body, tok) {
			t.Errorf("the token is in a mail to %s", m.to)
		}
	}
	if !strings.Contains(e.log(), "UNREACHABLE") || !strings.Contains(e.log(), "carol") {
		t.Errorf("carol has no address and the log does not say so:\n%s", e.log())
	}
	if !strings.Contains(e.log(), "alice invited erin (erin@elsewhere.example)") {
		t.Errorf("no line says who invited whom:\n%s", e.log())
	}
	// The link is the same invitation as the CLI's: it enrols, once.
	// The store re-reads the accounts file at most once a second, on the real clock.
	time.Sleep(1100 * time.Millisecond)
	if _, ok := e.s.cfg.Local.store.get("erin"); !ok {
		t.Fatal("the account is not in the store")
	}
	if st, _, _, _ := e.enrollBegin(newBrowser(t), tok); st != http.StatusOK {
		t.Fatalf("the mailed link does not start an enrolment: %d", st)
	}
}

// A notice that cannot be delivered to one administrator is logged and the
// invitation stands.
func TestAFailedNoticeToOneAdministratorDoesNotUndoTheInvitation(t *testing.T) {
	e := newAdminEnv(t)
	e.smtp.rejectRcpt = "bob@mesocentre"
	if st, body := e.invitePost(e.sess, "erin", "erin@elsewhere.example", ""); st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	mails := e.sent()
	if len(mails) != 2 || !e.exists("erin") {
		t.Fatalf("%d mails, account %v:\n%s", len(mails), e.exists("erin"), e.log())
	}
	if !strings.Contains(e.log(), "notice to administrator bob failed") {
		t.Errorf("the failure is not logged:\n%s", e.log())
	}
}

// An invitation whose mail cannot be sent creates nothing, so it can be tried
// again.
func TestAnInvitationThatCannotBeMailedCreatesNothing(t *testing.T) {
	e := newAdminEnv(t)
	e.smtp.reject = "RCPT TO"
	st, body := e.invitePost(e.sess, "erin", "erin@elsewhere.example", "")
	if st != http.StatusBadGateway {
		t.Fatalf("%d %s", st, body)
	}
	if e.exists("erin") {
		t.Error("the account stayed")
	}
	e.smtp.reject = ""
	if st, body := e.invitePost(e.sess, "erin", "erin@elsewhere.example", ""); st != http.StatusOK {
		t.Fatalf("the retry: %d %s", st, body)
	}
}

// Every way to be refused: nothing is created, nothing is mailed.
func TestTheInvitationIsRefusedUnlessEveryConditionHolds(t *testing.T) {
	type tc struct {
		name   string
		status int
		setup  func(e *adminEnv) *accountSess
	}
	sessOf := func(e *adminEnv, login string, aaguid string) *accountSess {
		a := e.keyOf(login, aaguid)
		return e.signedIn(a, login)
	}
	cases := []tc{
		{"a user who is not an administrator", 403, func(e *adminEnv) *accountSess { return sessOf(e, "dave", yubikeyBio) }},
		{"a federated person of an administrator's name", 403, func(e *adminEnv) *accountSess {
			rec, _, _ := e.s.passkeys.passkey(passkeyKey(e.alice.ID))
			who := &person{idp: idpEntity, subject: idpEntity + "!alice", username: "alice", credential: rec.key()}
			tok := token()
			if err := e.s.accountSessions.put(hashToken(tok), &accountSession{who: who, credential: rec.key(), at: e.s.now()}, e.s.now().Add(accountTTL)); err != nil {
				e.t.Fatal(err)
			}
			s := &accountSess{cookie: accountCookieName + "=" + tok}
			s.csrf = e.s.accountCSRF(hashToken(tok))
			return s
		}},
		{"an assertion older than the step-up allows", 403, func(e *adminEnv) *accountSess {
			e.advance(adminStepUpMax + time.Minute)
			return e.sess
		}},
		{"a key of another model", 403, func(e *adminEnv) *accountSess { return sessOf(e, "bob", someOtherAA) }},
		{"a key whose model is only SELF-REPORTED", 403, func(e *adminEnv) *accountSess {
			a := e.enrolled("bob", webauthn.AlgES256)
			rec, _, _ := e.s.passkeys.passkey(passkeyKey(a.ID))
			rec.AAGUID = []byte{0x9d, 0xd8, 0xd5, 0x93, 0x22, 0x13, 0x43, 0x8a, 0x97, 0xf8, 0xd6, 0xb8, 0x13, 0xd5, 0x1c, 0x27}
			if err := e.s.passkeys.savePasskey(rec); err != nil {
				e.t.Fatal(err)
			}
			return e.signedIn(a, "bob")
		}},
		{"a bad token", 403, func(e *adminEnv) *accountSess { return &accountSess{cookie: e.sess.cookie, csrf: "x" + e.sess.csrf} }},
		{"no session", 401, func(e *adminEnv) *accountSess { return &accountSess{csrf: e.sess.csrf} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newAdminEnv(t)
			s := c.setup(e)
			st, body := e.invitePost(s, "erin", "erin@elsewhere.example", "")
			if st != c.status {
				t.Fatalf("status %d, want %d: %s", st, c.status, body)
			}
			if e.exists("erin") || len(e.sent()) != 0 {
				t.Errorf("the refused request still created the account or sent mail (%d mails)", len(e.sent()))
			}
		})
	}
}

// A GET shows the form only to who may use it.
func TestTheFormIsNotServedToWhoMayNotUseIt(t *testing.T) {
	e := newAdminEnv(t)
	dave := e.signedIn(e.keyOf("dave", yubikeyBio), "dave")
	if st, _ := e.do("GET", dave.cookie, nil); st != http.StatusForbidden {
		t.Errorf("a user who is not an administrator: %d", st)
	}
	if _, body := e.accountPage(dave.cookie); strings.Contains(body, "invite-link") {
		t.Error("dave's account page offers the invitation")
	}
	e.advance(adminStepUpMax + time.Second)
	if st, _ := e.do("GET", e.sess.cookie, nil); st != http.StatusForbidden {
		t.Errorf("a stale assertion: %d", st)
	}
}

// Without a mail block the page does not exist.
func TestTheInvitationPageNeedsAMailBlock(t *testing.T) {
	e := newAdminEnv(t)
	e.s.cfg.Mail = nil
	if st, _ := e.do("GET", e.sess.cookie, nil); st != http.StatusNotFound {
		t.Errorf("GET: %d", st)
	}
	if st, _ := e.invitePost(e.sess, "erin", "erin@elsewhere.example", ""); st != http.StatusNotFound {
		t.Errorf("POST: %d", st)
	}
	if e.exists("erin") {
		t.Error("an account was created without a mail block")
	}
}

// Nothing in the form reaches a header.
func TestTheFormCannotInjectAHeader(t *testing.T) {
	e := newAdminEnv(t)
	for _, c := range []struct{ login, mail, name string }{
		{"erin", "erin@elsewhere.example\r\nBcc: evil@example.org", ""},
		{"erin", "erin@elsewhere.example\nBcc: evil@example.org", ""},
		{"erin", "erin@elsewhere.example,evil@example.org", ""},
		{"erin", "<erin@elsewhere.example>", ""},
		{"erin", "Erin <erin@elsewhere.example>", ""},
		{"erin", "erin@elsewhere.example", "Erin\r\nBcc: evil@example.org"},
		{"erin\r\nBcc: evil@example.org", "erin@elsewhere.example", ""},
		{"erin@elsewhere.example", "erin@elsewhere.example", ""},
		{"Erin", "erin@elsewhere.example", ""},
		{"", "erin@elsewhere.example", ""},
		{"erin", "", ""},
	} {
		if st, _ := e.invitePost(e.sess, c.login, c.mail, c.name); st != http.StatusBadRequest {
			t.Errorf("%q %q %q: status %d, want 400", c.login, c.mail, c.name, st)
		}
	}
	if len(e.sent()) != 0 || e.exists("erin") {
		t.Errorf("a refused form created something (%d mails):\n%s", len(e.sent()), e.log())
	}
}

func TestAnExistingLoginIsNotInvitedAgain(t *testing.T) {
	e := newAdminEnv(t)
	if st, _ := e.invitePost(e.sess, "dave", "dave@elsewhere.example", ""); st != http.StatusConflict {
		t.Errorf("status %d", st)
	}
	if len(e.sent()) != 0 {
		t.Error("mail was sent")
	}
}

func TestInvitationsAreLimitedPerAdministrator(t *testing.T) {
	e := newAdminEnv(t)
	for i := 0; i < adminInviteMax; i++ {
		if !e.s.inviteAllowed("alice") {
			t.Fatalf("refused the %dth", i+1)
		}
	}
	if e.s.inviteAllowed("alice") {
		t.Error("the limit was not enforced")
	}
	if !e.s.inviteAllowed("bob") {
		t.Error("another administrator was counted with alice")
	}
	if st, _ := e.invitePost(e.sess, "erin", "erin@elsewhere.example", ""); st != http.StatusTooManyRequests {
		t.Errorf("through the page: %d", st)
	}
	e.advance(adminInviteWindow + time.Second)
	if !e.s.inviteAllowed("alice") {
		t.Error("the window did not end")
	}
}

// The configuration: what makes admins and admin_aaguids acceptable.
func TestTheAdminSettingsAreChecked(t *testing.T) {
	path := writeAccountsFile(t, adminAccountsText())
	st, err := newLocalStore(path, localScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	withMail := &config{Mail: &mailBlock{}}
	for _, c := range []struct {
		name    string
		l       localBlock
		c       *config
		wantErr string
	}{
		{"none", localBlock{}, withMail, ""},
		{"ok", localBlock{Admins: []string{"alice"}, AdminAAGUIDs: []string{strings.ToUpper(yubikeyBio)}}, withMail, ""},
		{"no mail block", localBlock{Admins: []string{"alice"}, AdminAAGUIDs: []string{yubikeyBio}}, &config{}, "mail"},
		{"no models", localBlock{Admins: []string{"alice"}}, withMail, "admin_aaguids"},
		{"models alone", localBlock{AdminAAGUIDs: []string{yubikeyBio}}, withMail, "without admins"},
		{"unknown admin", localBlock{Admins: []string{"zoe"}, AdminAAGUIDs: []string{yubikeyBio}}, withMail, "not an account"},
		{"twice", localBlock{Admins: []string{"alice", "alice"}, AdminAAGUIDs: []string{yubikeyBio}}, withMail, "twice"},
		{"bad login", localBlock{Admins: []string{"Alice"}, AdminAAGUIDs: []string{yubikeyBio}}, withMail, "login"},
		{"bad model", localBlock{Admins: []string{"alice"}, AdminAAGUIDs: []string{"yubikey"}}, withMail, "UUID"},
		{"zero model", localBlock{Admins: []string{"alice"}, AdminAAGUIDs: []string{"00000000-0000-0000-0000-000000000000"}}, withMail, "zero"},
	} {
		l := c.l
		l.store = st
		err := l.checkAdmins(c.c)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: %v, want it to say %q", c.name, err, c.wantErr)
		}
		if c.name == "ok" && !l.aaguidSet[yubikeyBio] {
			t.Errorf("the model was not normalised to lower case: %v", l.aaguidSet)
		}
	}
}

// `check` outside the unit reports a systemd credential it cannot read; the
// service refuses to start without it.
func TestAMissingSystemdCredentialIsReportedByCheckAndRefusedByTheService(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	mk := func(outside bool) *mailBlock {
		return &mailBlock{Host: "smtp.example.org", Username: "bridge", From: "bridge@example.org", PasswordFrom: "systemd-creds:smtp-password-absent-for-the-test", outside: outside}
	}
	m := mk(true)
	if err := m.check(); err != nil || m.unresolved != "smtp-password-absent-for-the-test" {
		t.Errorf("check outside the service: %v, unresolved %q", err, m.unresolved)
	}
	err := mk(false).check()
	if err == nil || !strings.Contains(err.Error(), "LoadCredentialEncrypted=smtp-password-absent-for-the-test") {
		t.Errorf("the service accepted a missing credential, or said nothing useful: %v", err)
	}
	// Inside a unit (CREDENTIALS_DIRECTORY set) a missing credential is an error
	// for `check` too: it is the unit's drop-in that is wrong.
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	if err := mk(true).check(); err == nil {
		t.Error("check inside a unit without the credential passed")
	}
}

func TestASystemdCredentialIsReadFromTheCredentialsDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd credentials are Linux's")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smtp-password"), []byte("s3cret-pw\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	m := &mailBlock{Host: "smtp.example.org", Username: "bridge", From: "bridge@example.org", PasswordFrom: "systemd-creds:smtp-password", outside: true}
	if err := m.check(); err != nil || m.password != "s3cret-pw" || m.unresolved != "" {
		t.Errorf("%v %q %q", err, m.password, m.unresolved)
	}
}

// The form parser: whatever it accepts is safe to put in an envelope, a header,
// an HCL string and a log line.
func FuzzParseInviteForm(f *testing.F) {
	for _, s := range []string{
		"login=erin&mail=erin%40example.org&name=Erin",
		"login=erin&mail=erin%40example.org%0d%0aBcc%3a+x%40example.org",
		"login=er%0ain&mail=a%40b.example",
		"login=erin&mail=a%40b.example&name=%e2%80%a8",
		"login=erin&mail=%22a%40b%22%40example.org",
		"login=erin&login=bob&mail=a%40b.example",
		"login=" + strings.Repeat("a", 70) + "&mail=a%40b.example",
		"login=erin&mail=a%40b.example&name=" + strings.Repeat("x", 300),
		"%zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		req, err := parseInviteForm(v)
		if err != nil {
			return
		}
		if !loginSyntax.MatchString(req.Login) {
			t.Fatalf("login %q", req.Login)
		}
		if _, err := mailAddr(req.Mail); err != nil {
			t.Fatalf("mail %q: %v", req.Mail, err)
		}
		if req.Name == "" || plainText(req.Name, inviteNameMax) != nil {
			t.Fatalf("name %q", req.Name)
		}
		for _, s := range []string{req.Login, req.Mail, req.Name} {
			if strings.ContainsAny(s, "\r\n\x00") {
				t.Fatalf("a control character in %q", s)
			}
		}
		if _, err := buildMessage("bridge@example.org", req.Mail, "s", time.Unix(0, 0), "b"); err != nil {
			t.Fatalf("accepted %q but cannot mail it: %v", req.Mail, err)
		}
	})
}
