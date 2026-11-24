package app

import (
	"errors"
	"fmt"
	"slices"
)

// Which kind of account may sign in to a client: accounts = ["local"],
// ["federated"], or absent for both.
//
// ⛔ One rule, asked at every place a grant is made or used, never only where
// a login is OFFERED: the UI hides a path, it does not close it. The places
// are the authorization endpoint (which routes only to the allowed path), the
// federation and local login steps (a login in progress for a client of the
// other kind is refused), the end of a login (finishLogin, whatever source
// vouched), and issue(), which every token goes through -- code exchange,
// refresh and device alike -- so a grant bought before the restriction was
// written stops with it, as a removed IdP stops what it bought.

const (
	accountsLocal     = "local"
	accountsFederated = "federated"
)

// errKindRefused is issue() refusing: this client does not take that kind of
// account.
var errKindRefused = errors.New("account kind not accepted by this client")

// checkAccounts validates the accounts attribute; hasLocal says whether the
// configuration has a `local` block.
func (c *clientBlock) checkAccounts(hasLocal bool) error {
	if c.Accounts == nil {
		return nil
	}
	if len(c.Accounts) == 0 {
		return errors.New(`accounts = []: nobody could sign in; "local", "federated", or leave it out for both`)
	}
	seen := map[string]bool{}
	for _, a := range c.Accounts {
		if a != accountsLocal && a != accountsFederated {
			return fmt.Errorf("accounts: %q is not %q or %q", a, accountsLocal, accountsFederated)
		}
		if seen[a] {
			return fmt.Errorf("accounts: %q twice", a)
		}
		seen[a] = true
	}
	if seen[accountsLocal] && !hasLocal {
		return errors.New(`accounts names "local", and there is no local block`)
	}
	return nil
}

func (c *clientBlock) allowsLocal() bool {
	return c.Accounts == nil || slices.Contains(c.Accounts, accountsLocal)
}

func (c *clientBlock) allowsFederated() bool {
	return c.Accounts == nil || slices.Contains(c.Accounts, accountsFederated)
}

// accountsLine is what `check` prints for the restriction.
func (c *clientBlock) accountsLine() string {
	switch {
	case c.allowsLocal() && c.allowsFederated():
		return "local and federated accounts"
	case c.allowsLocal():
		return "local accounts only"
	default:
		return "federated accounts only"
	}
}

// accountsRefused says why client does not take who, or "". A person whose
// source is the local accounts is local, whether or not the block is still
// there (refused() deals with that); anybody else is federated.
func (s *server) accountsRefused(client *clientBlock, who *person) string {
	if client == nil || who == nil {
		return ""
	}
	if who.idp == s.cfg.localEntityID() {
		if !client.allowsLocal() {
			return "this client does not take local accounts"
		}
		return ""
	}
	if !client.allowsFederated() {
		return "this client takes " + client.accountsLine()
	}
	return ""
}

// logKindRefused writes the refusal without anything of the person but the
// name the login line already carries.
func (s *server) logKindRefused(where string, client *clientBlock, who *person, why string) {
	s.logf("%s: %s via %s refused for %s: %s", where, orUnnamed(who.username), who.idp, client.ID, why)
}
