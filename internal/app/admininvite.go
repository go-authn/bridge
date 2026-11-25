// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/spf13/cobra"
	"github.com/zclconf/go-cty/cty"
)

// An administrator invites a new LOCAL account from /account/invite.
//
// Who may: a local account named in local { admins }, signed in with a passkey
// asserted at most adminStepUpMax ago (a step-up, user verification required),
// whose credential is of a model in local { admin_aaguids } PROVED by a verified
// attestation (passkeyRecord.AttestedAAGUID). A federated session is never an
// administrator, whatever its name. Every condition is checked again on the
// POST that does the work, and the page does not exist without a mail block.
//
// What it does: the account is created in accounts_file as `authn-bridge local
// invite --name` does, an invitation (one-time token, inviteDefaultTTL) is made,
// and its link is mailed to the invitee's address and shown to nobody. Every
// administrator with an address is told who invited whom, from where and when,
// never the link.
const (
	// adminStepUpMax is how old the assertion of an administrator may be.
	adminStepUpMax = 3 * time.Minute
	// adminInviteMax invitations per administrator in adminInviteWindow.
	adminInviteMax    = 10
	adminInviteWindow = time.Hour
	// inviteFormMax bounds the form: it holds a login, an address, a name.
	inviteFormMax = 4 << 10
	// inviteNameMax is a display name's length, as the account page bounds it.
	inviteNameMax = 200
)

// inviteRequest is what the form says, validated.
type inviteRequest struct {
	Login, Mail, Name string
}

// parseInviteForm validates the form's fields as the CLI does: the login by
// loginSyntax (so it is in the local scope), the address by mailAddr (a bare
// ASCII addr-spec: no CR, LF, comma, angle bracket), the display name as plain
// text. An empty name is the login.
func parseInviteForm(v url.Values) (inviteRequest, error) {
	req := inviteRequest{Login: v.Get("login"), Mail: v.Get("mail"), Name: strings.TrimSpace(v.Get("name"))}
	if !loginSyntax.MatchString(req.Login) {
		return inviteRequest{}, badLogin(req.Login)
	}
	if _, err := mailAddr(req.Mail); err != nil {
		return inviteRequest{}, fmt.Errorf("mail: %w", err)
	}
	if req.Name == "" {
		req.Name = req.Login
	}
	if err := plainText(req.Name, inviteNameMax); err != nil {
		return inviteRequest{}, fmt.Errorf("name: %w", err)
	}
	return req, nil
}

// isAdmin says whether p is a local administrator: a local account, in admins,
// with the page available (a mail block). A federated person of the same name
// has another idp, and is not.
func (s *server) isAdmin(p *person) bool {
	l := s.cfg.Local
	return l != nil && s.cfg.Mail != nil && s.isLocal(p) && l.adminSet[p.username]
}

// adminRefusal says why sess may not invite, "" when it may.
func (s *server) adminRefusal(sess *accountSession) string {
	if !s.isAdmin(sess.who) {
		return "not an administrator of local accounts"
	}
	if age := s.now().Sub(sess.at); sess.at.IsZero() || age < 0 || age > adminStepUpMax {
		return "the passkey assertion is older than " + adminStepUpMax.String()
	}
	rec, ok, err := s.passkeys.passkey(sess.credential)
	if err != nil || !ok || rec.Login != sess.who.username {
		return "the asserted passkey is not the administrator's own"
	}
	// AttestedAAGUID, never AAGUID: the latter is the authenticator's own word.
	if rec.AttestedAAGUID == "" || !s.cfg.Local.aaguidSet[rec.AttestedAAGUID] {
		return "the passkey is not of an allowed model by a verified attestation"
	}
	return ""
}

// inviteAllowed counts one more invitation of admin, false when too many.
func (s *server) inviteAllowed(admin string) bool {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	now := s.now()
	if s.adminInvites == nil {
		s.adminInvites = map[string][]time.Time{}
	}
	recent := slices.DeleteFunc(s.adminInvites[admin], func(t time.Time) bool { return now.Sub(t) >= adminInviteWindow })
	if len(recent) >= adminInviteMax {
		s.adminInvites[admin] = recent
		return false
	}
	s.adminInvites[admin] = append(recent, now)
	return true
}

func (s *server) accountInvite(w http.ResponseWriter, r *http.Request) {
	l := s.cfg.Local
	if l == nil || s.cfg.Mail == nil || len(l.adminSet) == 0 || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
		http.NotFound(w, r)
		return
	}
	addr := s.clientAddr(r)
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, inviteFormMax)
		if err := r.ParseForm(); err != nil || !s.sameOrigin(r) {
			s.page(w, http.StatusForbidden, "The request did not come from this provider's page.")
			return
		}
	}
	if s.accountThrottled(w, addr) {
		return
	}
	k, sess, ok := s.session(r)
	if !ok {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, s.cfg.Issuer+"/account", http.StatusFound)
			return
		}
		s.localLimit.failed(addr, "")
		s.page(w, http.StatusUnauthorized, "The confirmation has expired: confirm again from your account page.")
		return
	}
	csrf := s.accountCSRF(k)
	if r.Method == http.MethodPost {
		if csrf == "" || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(csrf)) != 1 {
			s.localLimit.failed(addr, "")
			s.logf("account: audit: invite: a request without its page's token (%s, from %s)", orUnnamed(sess.who.username), addr)
			s.page(w, http.StatusForbidden, "The request did not come from this page.")
			return
		}
	}
	if why := s.adminRefusal(sess); why != "" {
		s.logf("account: audit: invite refused for %s from %s: %s", orUnnamed(sess.who.username), addr, why)
		s.counters.inc("bridge_logins_total", "account_invite_refused")
		msg := "You may not invite accounts."
		if sess.credential != "" && s.isAdmin(sess.who) && strings.Contains(why, "older") {
			msg = "Confirm again with your key, then open this page within three minutes."
		}
		s.page(w, http.StatusForbidden, msg)
		return
	}
	if r.Method == http.MethodGet {
		s.render(w, http.StatusOK, "invite", map[string]any{"CSRF": csrf})
		return
	}
	req, err := parseInviteForm(r.PostForm)
	if err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := sess.who.username
	if !s.inviteAllowed(admin) {
		s.logf("account: audit: invite refused for %s from %s: more than %d in %s", admin, addr, adminInviteMax, adminInviteWindow)
		s.page(w, http.StatusTooManyRequests, "Too many invitations: try again later.")
		return
	}
	if status, msg := s.inviteLocal(req, admin, addr); status != http.StatusOK {
		s.page(w, status, msg)
		return
	}
	s.render(w, http.StatusOK, "invite", map[string]any{"CSRF": csrf, "Sent": true})
}

// inviteLocal creates the account and its invitation, mails the link to the
// invitee, and tells the administrators. A failed mail takes the account back,
// so the same invitation can be tried again.
func (s *server) inviteLocal(req inviteRequest, admin, addr string) (int, string) {
	lb := s.cfg.Local
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	exists, err := accountExists(lb, req.Login)
	if err != nil {
		s.logf("account: invite: reading accounts_file: %v", err)
		return http.StatusInternalServerError, "The accounts could not be read."
	}
	if exists {
		return http.StatusConflict, "That login already exists."
	}
	var trusted []string
	if s.cfg.Claims != nil {
		trusted = s.cfg.Claims.TrustedGroups[s.cfg.localEntityID()]
	}
	cmd := &cobra.Command{Use: "web-invite"}
	cmd.SetErr(io.Discard)
	if err := editAccounts(cmd, lb, trusted, false, req.Login, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
		// accountExists, above and under the same lock, answered no; editAccounts
		// parses what it wrote and refuses a duplicate block.
		if len(b.Blocks()) > 0 {
			b.AppendNewline()
		}
		body := b.AppendNewBlock("account", []string{req.Login}).Body()
		body.SetAttributeValue("name", cty.StringVal(req.Name))
		body.SetAttributeValue("mail", cty.StringVal(req.Mail))
		return nil
	}); err != nil {
		s.logf("account: invite: creating %s: %v", req.Login, err)
		return http.StatusInternalServerError, "The account could not be created."
	}
	undo := func() {
		if _, err := s.passkeys.revokeInvites(req.Login); err != nil {
			s.logf("account: invite: revoking the invitation of %s: %v", req.Login, err)
		}
		if err := editAccounts(cmd, lb, trusted, false, req.Login, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
			if blk := find(); blk != nil {
				b.RemoveBlock(blk)
			}
			return nil
		}); err != nil {
			s.logf("account: invite: taking %s back: %v", req.Login, err)
		}
	}
	tok, exp, err := s.passkeys.invite(req.Login, inviteDefaultTTL, "web:"+admin)
	if err != nil {
		s.logf("account: invite: %v", err)
		undo()
		return http.StatusInternalServerError, "The invitation could not be created."
	}
	m := s.cfg.Mail
	body := fmt.Sprintf("%s invited you to create the account %q at %s.\n\nOpen this link, once, to register your passkey (valid until %s):\n\n%s/local/enroll#%s\n\nIf you did not expect this message, ignore it: nothing is created until the link is used.\n",
		textField(admin), textField(req.Login), textField(s.cfg.Issuer), exp.UTC().Format("2006-01-02 15:04 MST"), s.cfg.Issuer, tok)
	msg, err := buildMessage(m.From, req.Mail, "Invitation to "+textField(s.cfg.Issuer), s.now(), body)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = m.send(ctx, s.mailTLS, req.Mail, msg)
		cancel()
	}
	if err != nil {
		s.logf("account: audit: invite: %s's invitation of %s (%s) could not be mailed: %v", admin, req.Login, req.Mail, err)
		undo()
		return http.StatusBadGateway, "The invitation could not be mailed: nothing was created. Try again later."
	}
	s.logf("account: audit: invite: %s invited %s (%s) from %s, valid until %s", admin, req.Login, req.Mail, addr, exp.UTC().Format(time.RFC3339))
	s.counters.inc("bridge_logins_total", "account_invite")
	s.notifyAdmins(admin, req, addr)
	return http.StatusOK, ""
}

// notifyAdmins mails every administrator with an address one message of its own
// (no recipient list): who invited whom, when, from where. No link, no token.
// A failure is logged and changes nothing; an administrator with no usable
// address is logged as unreachable.
func (s *server) notifyAdmins(admin string, req inviteRequest, addr string) {
	m := s.cfg.Mail
	now := s.now()
	body := fmt.Sprintf("Administrator %s invited the account %q (%s) at %s on %s, from %s.\n\nThis message contains no link on purpose. If this was not expected, tell the other administrators.\n",
		textField(admin), textField(req.Login), textField(req.Mail), textField(s.cfg.Issuer), now.UTC().Format("2006-01-02 15:04 MST"), textField(addr))
	for _, a := range slices.Sorted(func(yield func(string) bool) {
		for k := range s.cfg.Local.adminSet {
			if !yield(k) {
				return
			}
		}
	}) {
		to := s.localMail(a)
		if _, err := mailAddr(to); err != nil {
			s.logf("account: invite: administrator %s is UNREACHABLE: no usable mail address, not told that %s invited %s", a, admin, req.Login)
			continue
		}
		msg, err := buildMessage(m.From, to, "New account invited at "+textField(s.cfg.Issuer), now, body)
		if err != nil {
			s.logf("account: invite: notice to administrator %s: %v", a, err)
			continue
		}
		s.notifyWG.Add(1)
		go func() {
			defer s.notifyWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.send(ctx, s.mailTLS, to, msg); err != nil {
				s.logf("account: invite: notice to administrator %s failed: %v", a, err)
			}
		}()
	}
}
