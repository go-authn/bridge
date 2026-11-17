// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/spf13/cobra"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/term"
)

// `authn-bridge local-account add|passwd|remove <login>` manages the accounts
// file of the `local` block. The password is never an argument and never in
// the environment: it is read from the terminal, with no echo, or -- when
// standard input is not a terminal -- from its first line.
//
// The program writes the file the provider reads, so it checks what it wrote
// with the provider's own parser before replacing anything: it never leaves a
// file the provider would refuse.
func newLocalAccountCmd(configs func() []string) *cobra.Command {
	root := &cobra.Command{
		Use:   "local-account",
		Short: "add, change or remove the local accounts of the `local` block",
		Long: `Manage the accounts file named by the configuration's local { accounts_file }.

    authn-bridge local-account add    --config /etc/authn-bridge --name "Alice Martin" alice
    authn-bridge local-account passwd --config /etc/authn-bridge alice
    authn-bridge local-account remove --config /etc/authn-bridge alice

The password is read from the terminal without echo, asked twice; or, when
standard input is not a terminal, from its first line:

    printf '%s\n' "$PASSWORD" | authn-bridge local-account passwd --config ... alice

It is never an argument, so it is in no process list and no shell history.
The provider reads the file again when it changes: no restart.`,
	}

	var name, mail string
	var groups []string
	add := &cobra.Command{
		Use:   "add <login>",
		Short: "create an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return errors.New("give --name, the display name")
			}
			return editAccounts(cmd, configs(), true, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
				if find() != nil {
					return fmt.Errorf("account %q exists: use passwd to change its password", args[0])
				}
				pw, err := readNewPassword(cmd)
				if err != nil {
					return err
				}
				hash, err := hashPassword(pw)
				if err != nil {
					return err
				}
				if len(b.Blocks()) > 0 {
					b.AppendNewline()
				}
				body := b.AppendNewBlock("account", []string{args[0]}).Body()
				body.SetAttributeValue("password_hash", cty.StringVal(hash))
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
			}, args[0])
		},
	}
	add.Flags().StringVar(&name, "name", "", "the display name (the `name` claim)")
	add.Flags().StringVar(&mail, "mail", "", "the mail address (the `email` claim), optional")
	add.Flags().StringArrayVar(&groups, "group", nil, "a group, in the local scope; repeatable")

	passwd := &cobra.Command{
		Use:   "passwd <login>",
		Short: "set a new password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editAccounts(cmd, configs(), false, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
				blk := find()
				if blk == nil {
					return fmt.Errorf("no account %q", args[0])
				}
				pw, err := readNewPassword(cmd)
				if err != nil {
					return err
				}
				hash, err := hashPassword(pw)
				if err != nil {
					return err
				}
				blk.Body().SetAttributeValue("password_hash", cty.StringVal(hash))
				return nil
			}, args[0])
		},
	}
	remove := &cobra.Command{
		Use:   "remove <login>",
		Short: "delete an account, and with it everything it was given (refresh tokens, certificates)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editAccounts(cmd, configs(), false, func(b *hclwrite.Body, find func() *hclwrite.Block) error {
				blk := find()
				if blk == nil {
					return fmt.Errorf("no account %q", args[0])
				}
				b.RemoveBlock(blk)
				return nil
			}, args[0])
		},
	}
	root.AddCommand(add, passwd, remove)
	return root
}

// localSettings reads the local block of the configuration, and only that:
// the command works on a configuration whose other parts are not finished.
func localSettings(paths []string) (*localBlock, []string, error) {
	files, err := hclFiles(paths)
	if err != nil {
		return nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, errors.New("no configuration: give --config a file or a directory of .hcl files")
	}
	p := hclparse.NewParser()
	var bodies []*hcl.File
	for _, f := range files {
		hf, diags := p.ParseHCLFile(f)
		if diags.HasErrors() {
			return nil, nil, diags
		}
		bodies = append(bodies, hf)
	}
	var c struct {
		Issuer string       `hcl:"issuer"`
		Local  *localBlock  `hcl:"local,block"`
		Claims *claimsBlock `hcl:"claims,block"`
		Remain hcl.Body     `hcl:",remain"`
	}
	if diags := gohcl.DecodeBody(hcl.MergeFiles(bodies), nil, &c); diags.HasErrors() {
		return nil, nil, diags
	}
	if c.Local == nil {
		return nil, nil, errors.New("the configuration has no local block")
	}
	var trusted []string
	if c.Claims != nil {
		trusted = c.Claims.TrustedGroups[(&config{Issuer: strings.TrimRight(c.Issuer, "/")}).localEntityID()]
	}
	return c.Local, trusted, nil
}

// editAccounts reads the accounts file (creating it, empty, for `add`), lets
// edit change it, checks the result with the provider's parser, and replaces
// the file. Comments and the order of what was there are kept.
func editAccounts(cmd *cobra.Command, configs []string, create bool, edit func(*hclwrite.Body, func() *hclwrite.Block) error, login string) error {
	lb, trusted, err := localSettings(configs)
	if err != nil {
		return err
	}
	if !loginSyntax.MatchString(login) {
		return fmt.Errorf("login %q: 1-%d characters of a-z, 0-9, \".\", \"_\" and \"-\", starting with a letter or digit, and never an \"@\"", login, maxLoginLen)
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
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %s\n", cmd.Name(), login, path)
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

// readNewPassword asks for a password: twice, on the terminal, with no echo; or
// the first line of standard input when it is not a terminal.
func readNewPassword(cmd *cobra.Command) (string, error) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		ask := func(prompt string) (string, error) {
			fmt.Fprint(cmd.ErrOrStderr(), prompt)
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(cmd.ErrOrStderr())
			return string(b), err
		}
		pw, err := ask("Password: ")
		if err != nil {
			return "", err
		}
		again, err := ask("Again: ")
		if err != nil {
			return "", err
		}
		if pw != again {
			return "", errors.New("the two passwords differ")
		}
		return pw, checkNewPassword(pw)
	}
	line, err := bufio.NewReader(io.LimitReader(in, maxPasswordLen+3)).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("no password on standard input")
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	return pw, checkNewPassword(pw)
}
