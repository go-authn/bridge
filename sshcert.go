// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// `bridge ssh-cert` gets an SSH key certified: it logs in with a code the
// first time (as `bridge token` does, with the "ssh" scope), sends the
// public key, and writes the certificate beside it as <key>-cert.pub, which
// is where ssh and sftp look for one without being told.
//
//	bridge ssh-cert --issuer https://login.example.org --client sftp
//	sftp alice@univ-example.fr@files.example.org
func newSSHCertCmd(out io.Writer) *cobra.Command {
	var issuer, clientID, keyFile, cacheDir string
	cmd := &cobra.Command{
		Use:   "ssh-cert",
		Short: "have an SSH public key certified, and write <key>-cert.pub beside it",
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || clientID == "" {
				return errors.New("give --issuer and --client")
			}
			if keyFile == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				keyFile = filepath.Join(home, ".ssh", "id_ed25519.pub")
			}
			p, err := certifyKey(cmd.Context(), issuer, clientID, keyFile, cacheDir, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "wrote %s\n", p)
			return nil
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "", "the provider, e.g. https://login.example.org")
	cmd.Flags().StringVar(&clientID, "client", "", "the client ID it knows this program by")
	cmd.Flags().StringVar(&keyFile, "key", "", "the public key to certify (default ~/.ssh/id_ed25519.pub)")
	cmd.Flags().StringVar(&cacheDir, "cache", "", "where to keep the login (default: the user's configuration directory)")
	return cmd
}

func certifyKey(ctx context.Context, issuer, clientID, keyFile, cacheDir string, tell io.Writer) (string, error) {
	if !strings.HasSuffix(keyFile, ".pub") {
		// A private key sent to a server is a private key that has left the
		// machine.
		return "", fmt.Errorf("%s: give the PUBLIC key (a .pub file)", keyFile)
	}
	pub, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	tok, err := clientToken(ctx, issuer, clientID, []string{"openid", "ssh"}, cacheDir, tell)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/ssh/certificate", bytes.NewReader(pub))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the provider refused: %s", strings.TrimSpace(string(body)))
	}
	out := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return "", err
	}
	return out, nil
}
