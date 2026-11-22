// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each step of the SMTP dialogue that can be refused is a refusal of the send,
// named by its step.
func TestMailSendNamesTheStepThatWasRefused(t *testing.T) {
	for _, step := range []string{"MAIL FROM", "RCPT TO", "DATA", "END"} {
		f := smtpOK("tls")
		f.reject = step
		tc := startSMTP(t, f, "127.0.0.1")
		err := sendTest(f.block(t, "tls"), tc)
		if err == nil {
			t.Errorf("%s refused, and the send succeeded", step)
			continue
		}
		want := step + ":"
		if step == "END" {
			want = "DATA:"
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want it to name %q", step, err, want)
		}
		if f.mailCount() != 0 {
			t.Errorf("%s: a mail was recorded", step)
		}
	}
}

func TestNoticeWithoutAMailBlockOrAnAddressDoesNothing(t *testing.T) {
	g := newGuarded(t, time.Hour)
	if g.s.cfg.Mail != nil {
		t.Fatal("fixture has a mail block")
	}
	if to := g.s.noticeTo("alice"); to != "" {
		t.Errorf("no mail block, and a notice goes to %q", to)
	}
	// Queued events stay queued: with no mail block nothing is sent or dropped.
	g.s.noticeEnqueue("alice", mailEvent{Kind: "requested", FullKey: "k", At: g.s.now()})
	g.s.noticeFlush("alice")
	g.s.noticeFlushAll()
	g.settle()
	g.s.noticeMu.Lock()
	n := len(g.s.notices["alice"].queue)
	g.s.noticeMu.Unlock()
	if n != 1 {
		t.Errorf("%d queued events, want the 1 left alone", n)
	}

	srv := withMail(t, g, false)
	g.s.noticeKey("requested", "bob", &passkeyRecord{}, time.Time{}, nil)
	g.s.noticeMu.Lock()
	b := g.s.notices["bob"]
	g.s.noticeMu.Unlock()
	if b != nil {
		t.Error("an account with no address got a queue")
	}
	if !strings.Contains(g.log(), "bob has no usable mail address") {
		t.Errorf("the missing address is not logged:\n%s", g.log())
	}
	err := g.s.noticeSend("bob", nil, 0)
	if err == nil || !strings.HasPrefix(err.Error(), "to:") {
		t.Errorf("noticeSend for bob: %v, want a refusal of the recipient", err)
	}
	if srv.mailCount() != 0 {
		t.Error("a mail was sent to nobody")
	}
}

func TestMailConfiguration(t *testing.T) {
	f := newFixture(t, "")
	good := writeAccountsFile(t, localAccountsText())
	base, err := os.ReadFile(f.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(t.TempDir(), "smtp.password")
	if err := os.WriteFile(pw, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(extra string) (*config, error) {
		p := filepath.Join(t.TempDir(), "bridge.hcl")
		os.WriteFile(p, append(append([]byte{}, base...), []byte(extra)...), 0o644)
		c, err := loadConfig([]string{p})
		if err == nil {
			t.Cleanup(func() { c.close() })
		}
		return c, err
	}
	local := fmt.Sprintf("local {\n accounts_file = %q\n scope = %q\n}\n", filepath.ToSlash(good), localScope) + stateExtra(t)
	mail := func(extra string) string {
		return fmt.Sprintf("mail {\n host = \"smtp.example.org\"\n username = \"bridge\"\n password_file = %q\n from = \"bridge@example.org\"\n%s}\n", filepath.ToSlash(pw), extra)
	}
	c, err := load(local + mail(""))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mail == nil || c.Mail.password != "s3cret" || c.Mail.Port != 465 || c.Mail.Security != "tls" {
		t.Errorf("the good block loaded as %+v", c.Mail)
	}
	if _, err := load(mail("")); err == nil || !strings.Contains(err.Error(), "no local block") {
		t.Errorf("mail without a local block: %v", err)
	}
	if _, err := load(local + mail(" security = \"plain\"\n")); err == nil || !strings.Contains(err.Error(), "mail:") || !strings.Contains(err.Error(), "security") {
		t.Errorf("security plain: %v", err)
	}
}
