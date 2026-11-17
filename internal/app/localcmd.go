// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/spf13/cobra"
	"github.com/zclconf/go-cty/cty"
)

// `authn-bridge local-account invite|revoke-invite|passkeys|remove-passkey|
// remove <login>` manages the accounts of the `local` block. Local accounts
// are passkey-only: there is no password to set, and no command that reads one.
//
// An account is made by an invitation, a one-time URL the person opens on the
// device that will hold their passkey. The program writes the accounts file
// the provider reads, and checks what it wrote with the provider's own parser
// before replacing anything: it never leaves a file the provider would refuse.
// The invitations and passkeys are in the state database, which the provider
// reads at every use, so none of this needs a restart.
func newLocalAccountCmd(configs func() []string) *cobra.Command {
	root := &cobra.Command{
		Use:   "local-account",
		Short: "invite people to, and remove them from, the local accounts (passkeys only)",
		Long: `Manage the accounts of the configuration's local { } block. Local accounts have
no password: a person enrols a passkey with a one-time invitation.

    authn-bridge local-account invite  --config /etc/authn-bridge --name "Alice Martin" alice
    authn-bridge local-account invite  --config /etc/authn-bridge alice          # another key
    authn-bridge local-account revoke-invite --config /etc/authn-bridge alice
    authn-bridge local-account passkeys      --config /etc/authn-bridge alice
    authn-bridge local-account remove-passkey --config /etc/authn-bridge alice <id>
    authn-bridge local-account remove  --config /etc/authn-bridge alice

invite prints https://<issuer>/local/enroll#<token> and nothing else on
standard output. The token is in the fragment, so it reaches no log, and it is
stored only as a hash: it is shown once, works once, and expires (--ttl 24h by
default, 72h at most). Send it over a channel only the person reads.`,
		// A word that is no subcommand ("passwd") is an error, not a help page
		// with a success status.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}

	var name, mail string
	var groups []string
	var ttl time.Duration
	invite := &cobra.Command{
		Use:   "invite <login>",
		Short: "create an account, or add a key to one, and print a one-time enrolment URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login := args[0]
			lb, st, issuer, trusted, err := localSettings(configs())
			if err != nil {
				return err
			}
			defer st.db.Close()
			if !loginSyntax.MatchString(login) {
				return badLogin(login)
			}
			if ttl <= 0 || ttl > inviteMaxTTL {
				return fmt.Errorf("--ttl %s: an invitation lives more than 0 and at most %s", ttl, inviteMaxTTL)
			}
			exists, err := accountExists(lb, login)
			if err != nil {
				return err
			}
			switch {
			case !exists && name == "":
				return fmt.Errorf("no account %q: give --name, the display name, to create it", login)
			case exists && (name != "" || mail != "" || len(groups) > 0):
				return fmt.Errorf("account %q exists: --name, --mail and --group describe a new account; edit the accounts file to change one", login)
			}
			if !exists {
				if err := editAccounts(cmd, lb, trusted, true, login, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
					if find() != nil {
						return fmt.Errorf("account %q exists", login)
					}
					if len(b.Blocks()) > 0 {
						b.AppendNewline()
					}
					body := b.AppendNewBlock("account", []string{login}).Body()
					body.SetAttributeValue("name", cty.StringVal(name))
					if mail != "" {
						body.SetAttributeValue("mail", cty.StringVal(mail))
					}
					if len(groups) > 0 {
						var vs []cty.Value
						for _, g := range groups {
							vs = append(vs, cty.StringVal(g))
						}
						body.SetAttributeValue("groups", cty.ListVal(vs))
					}
					return nil
				}); err != nil {
					return err
				}
			}
			tok, exp, err := (&passkeyStore{b: st, now: time.Now}).invite(login, ttl, "local-account")
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "invitation for %s, valid until %s (single use; replaces any other pending one)\n", login, exp.Format(time.RFC3339))
			fmt.Fprintf(cmd.OutOrStdout(), "%s/local/enroll#%s\n", issuer, tok)
			return nil
		},
	}
	invite.Flags().StringVar(&name, "name", "", "the display name (the `name` claim): creates the account")
	invite.Flags().StringVar(&mail, "mail", "", "the mail address (the `email` claim), optional, with --name")
	invite.Flags().StringArrayVar(&groups, "group", nil, "a group, in the local scope; repeatable, with --name")
	invite.Flags().DurationVar(&ttl, "ttl", inviteDefaultTTL, "how long the invitation works (at most 72h)")

	revoke := &cobra.Command{
		Use:   "revoke-invite <login>",
		Short: "end the pending invitation of an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, st, _, _, err := localSettings(configs())
			if err != nil {
				return err
			}
			defer st.db.Close()
			n, err := (&passkeyStore{b: st, now: time.Now}).revokeInvites(args[0])
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("%s has no pending invitation", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoke-invite %s: %d\n", args[0], n)
			return nil
		},
	}

	list := &cobra.Command{
		Use:   "passkeys <login>",
		Short: "list an account's passkeys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, st, _, _, err := localSettings(configs())
			if err != nil {
				return err
			}
			defer st.db.Close()
			recs, err := (&passkeyStore{b: st, now: time.Now}).passkeys(args[0])
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tCREATED\tLAST USED\tBACKUP-ELIGIBLE")
			for _, r := range recs {
				used := "never"
				if !r.LastUsed.IsZero() {
					used = r.LastUsed.UTC().Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%t\n", r.key(), r.Created.UTC().Format(time.RFC3339), used, r.BackupEligible)
			}
			return tw.Flush()
		},
	}

	rmkey := &cobra.Command{
		Use:   "remove-passkey <login> <id>",
		Short: "delete one passkey, and with it the grants it bought",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, st, _, _, err := localSettings(configs())
			if err != nil {
				return err
			}
			defer st.db.Close()
			r, err := (&passkeyStore{b: st, now: time.Now}).removePasskey(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "remove-passkey %s: %s\n", args[0], r.key())
			return nil
		},
	}

	remove := &cobra.Command{
		Use:   "remove <login>",
		Short: "delete an account, its passkeys and invitations, and with them everything it was given (refresh tokens, certificates)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lb, st, _, trusted, err := localSettings(configs())
			if err != nil {
				return err
			}
			defer st.db.Close()
			if err := editAccounts(cmd, lb, trusted, false, args[0], func(b *hclwrite.Body, find func() *hclwrite.Block) error {
				blk := find()
				if blk == nil {
					return fmt.Errorf("no account %q", args[0])
				}
				b.RemoveBlock(blk)
				return nil
			}); err != nil {
				return err
			}
			return (&passkeyStore{b: st, now: time.Now}).removeAccount(args[0])
		},
	}
	root.AddCommand(invite, revoke, list, rmkey, remove)
	return root
}

func badLogin(login string) error {
	return fmt.Errorf("login %q: 1-%d characters of a-z, 0-9, \".\", \"_\" and \"-\", starting with a letter or digit, and never an \"@\"", login, maxLoginLen)
}

// accountExists says whether the accounts file already has the login.
func accountExists(lb *localBlock, login string) (bool, error) {
	b, _, err := readAccountsFile(lb.AccountsFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	f, diags := hclwrite.ParseConfig(b, lb.AccountsFile, hcl.InitialPos)
	if diags.HasErrors() {
		return false, diags
	}
	for _, blk := range f.Body().Blocks() {
		if blk.Type() == "account" && slices.Equal(blk.Labels(), []string{login}) {
			return true, nil
		}
	}
	return false, nil
}

// localSettings reads the local and state blocks of the configuration, and
// only those: the command works on a configuration whose other parts are not
// finished. It opens the state database (the caller closes it).
func localSettings(paths []string) (*localBlock, *stateBlock, string, []string, error) {
	files, err := hclFiles(paths)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if len(files) == 0 {
		return nil, nil, "", nil, errors.New("no configuration: give --config a file or a directory of .hcl files")
	}
	p := hclparse.NewParser()
	var bodies []*hcl.File
	for _, f := range files {
		hf, diags := p.ParseHCLFile(f)
		if diags.HasErrors() {
			return nil, nil, "", nil, diags
		}
		bodies = append(bodies, hf)
	}
	var c struct {
		Issuer string       `hcl:"issuer"`
		Local  *localBlock  `hcl:"local,block"`
		State  *stateBlock  `hcl:"state,block"`
		Claims *claimsBlock `hcl:"claims,block"`
		Remain hcl.Body     `hcl:",remain"`
	}
	if diags := gohcl.DecodeBody(hcl.MergeFiles(bodies), nil, &c); diags.HasErrors() {
		return nil, nil, "", nil, diags
	}
	if c.Local == nil {
		return nil, nil, "", nil, errors.New("the configuration has no local block")
	}
	if c.State == nil {
		return nil, nil, "", nil, errors.New("the configuration has no state block: the passkeys and invitations are kept there")
	}
	issuer := strings.TrimRight(c.Issuer, "/")
	var trusted []string
	if c.Claims != nil {
		trusted = c.Claims.TrustedGroups[(&config{Issuer: issuer}).localEntityID()]
	}
	if err := c.State.check(); err != nil {
		return nil, nil, "", nil, fmt.Errorf("state: %w", err)
	}
	return c.Local, c.State, issuer, trusted, nil
}

// editAccounts reads the accounts file (creating it, empty, when create), lets
// edit change it, checks the result with the provider's parser, and replaces
// the file. Comments and the order of what was there are kept.
func editAccounts(cmd *cobra.Command, lb *localBlock, trusted []string, create bool, login string, edit func(*hclwrite.Body, func() *hclwrite.Block) error) error {
	if !loginSyntax.MatchString(login) {
		return badLogin(login)
	}
	path := lb.AccountsFile
	var src []byte
	mode := os.FileMode(0o640)
	if b, fi, err := readAccountsFile(path); err == nil {
		src, mode = b, fi.Mode().Perm()
	} else if create && errors.Is(err, os.ErrNotExist) {
		// a new file: 0640 and the invoking user, to be chgrp'd to the service's
		// group (docs/install.md).
	} else {
		return err
	}
	f, diags := hclwrite.ParseConfig(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return diags
	}
	find := func() *hclwrite.Block {
		for _, b := range f.Body().Blocks() {
			if b.Type() == "account" && slices.Equal(b.Labels(), []string{login}) {
				return b
			}
		}
		return nil
	}
	if err := edit(f.Body(), find); err != nil {
		return err
	}
	out := hclwrite.Format(f.Bytes())
	if _, err := parseAccounts(out, path, lb.Scope, trusted); err != nil {
		return fmt.Errorf("refusing to write a file the provider would refuse: %w", err)
	}
	if err := replaceFile(path, out, mode); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s %s: %s\n", cmd.Name(), login, path)
	return nil
}

// replaceFile writes data next to path and renames it over, so a reader sees
// the old file or the new one, never half of either. The owner and group of
// the file replaced are kept, where the system lets us.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".accounts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		copyOwner(tmp, fi)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
