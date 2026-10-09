// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// `authn-bridge app-password` sets, or with --remove deletes, the application
// password SMB and S3 clients use. It logs in with a code the first time,
// like `authn-bridge token`, with the "app_password" scope.
func newAppPasswordCmd(out io.Writer) *cobra.Command {
	var issuer, clientID, cacheDir string
	var remove bool
	cmd := &cobra.Command{
		Use:   "app-password",
		Short: "set (or --remove) the password for SMB and S3, which cannot carry a token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || clientID == "" {
				return errors.New("give --issuer and --client")
			}
			return appPasswordRequest(cmd.Context(), issuer, clientID, cacheDir, remove, out, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "", "the provider, e.g. https://login.example.org")
	cmd.Flags().StringVar(&clientID, "client", "", "the client ID it knows this program by")
	cmd.Flags().StringVar(&cacheDir, "cache", "", "where to keep the login (default: the user's configuration directory)")
	cmd.Flags().BoolVar(&remove, "remove", false, "delete the password instead of setting a new one")
	return cmd
}

func appPasswordRequest(ctx context.Context, issuer, clientID, cacheDir string, remove bool, out, tell io.Writer) error {
	tok, err := clientToken(ctx, issuer, clientID, []string{"openid", "app_password"}, cacheDir, tell)
	if err != nil {
		return err
	}
	method := http.MethodPost
	if remove {
		method = http.MethodDelete
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(issuer, "/")+"/app-password", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch {
	case remove && resp.StatusCode == http.StatusNoContent:
		fmt.Fprintln(out, "removed")
		return nil
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("the provider refused: %s", strings.TrimSpace(string(body)))
	}
	var r struct {
		Username, Password string
		Expires            int64
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	fmt.Fprintf(out, "username  %s\npassword  %s\nexpires   %s\n\nIt is shown once. It replaces any password set before.\n",
		r.Username, r.Password, time.Unix(r.Expires, 0).Format(time.RFC3339))
	return nil
}
