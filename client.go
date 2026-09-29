// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// `bridge token` is the other end of the device grant: it prints an access
// token on stdout, logging the person in through their institution the first
// time and refreshing quietly after that. It is what a client with no browser
// runs to get a token -- rclone, for one, mounts go-fileshare over WebDAV with
//
//	bearer_token_command = bridge token --issuer https://login.example.org --client rclone
//
// The OAuth itself is golang.org/x/oauth2's, not written here.

func newTokenCmd(out io.Writer) *cobra.Command {
	var issuer, clientID, scope, cacheDir string
	cmd := &cobra.Command{
		Use:   "token",
		Short: "print an access token, logging in with a code on another device the first time",
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || clientID == "" {
				return errors.New("give --issuer and --client")
			}
			tok, err := clientToken(cmd.Context(), issuer, clientID, strings.Fields(scope), cacheDir, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fmt.Fprintln(out, tok)
			return nil
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "", "the provider, e.g. https://login.example.org")
	cmd.Flags().StringVar(&clientID, "client", "", "the client ID it knows this program by")
	cmd.Flags().StringVar(&scope, "scope", "openid", "the scopes to ask for, space-separated")
	cmd.Flags().StringVar(&cacheDir, "cache", "", "where to keep the token (default: the user's configuration directory)")
	return cmd
}

// clientToken returns a valid access token: from the cache, by refreshing,
// or by a new device login.
func clientToken(ctx context.Context, issuer, clientID string, scopes []string, cacheDir string, tell io.Writer) (string, error) {
	issuer = strings.TrimRight(issuer, "/")
	ep, err := endpoints(ctx, issuer)
	if err != nil {
		return "", err
	}
	cfg := &oauth2.Config{ClientID: clientID, Endpoint: ep, Scopes: scopes}
	cache, err := cachePath(cacheDir, issuer, clientID, scopes)
	if err != nil {
		return "", err
	}

	if t := readCache(cache); t != nil {
		// A cached token is refreshed by the token source when it is near
		// its end; a refresh that fails (the family ended, or was revoked)
		// falls through to a new login rather than failing the command.
		fresh, err := cfg.TokenSource(ctx, t).Token()
		if err == nil {
			if fresh.AccessToken != t.AccessToken {
				writeCache(cache, fresh)
			}
			return fresh.AccessToken, nil
		}
		fmt.Fprintf(tell, "the saved login could not be renewed (%v); logging in again\n", err)
	}

	da, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("device authorization: %w", err)
	}
	fmt.Fprintf(tell, "To log in, open %s\nand enter the code %s\n(or open %s)\n", da.VerificationURI, da.UserCode, da.VerificationURIComplete)
	t, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		return "", err
	}
	writeCache(cache, t)
	return t.AccessToken, nil
}

// endpoints reads the provider's discovery document.
func endpoints(ctx context.Context, issuer string) (oauth2.Endpoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oauth2.Endpoint{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauth2.Endpoint{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oauth2.Endpoint{}, fmt.Errorf("%s: discovery answered %s", issuer, resp.Status)
	}
	var d struct {
		Issuer string `json:"issuer"`
		Token  string `json:"token_endpoint"`
		Device string `json:"device_authorization_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return oauth2.Endpoint{}, err
	}
	// The document must be about the issuer it was fetched from (OpenID
	// Connect Discovery 4.3), or anybody serving it could name other
	// endpoints.
	if d.Issuer != issuer {
		return oauth2.Endpoint{}, fmt.Errorf("the discovery document at %s names issuer %q", issuer, d.Issuer)
	}
	if d.Device == "" {
		return oauth2.Endpoint{}, fmt.Errorf("%s offers no device authorization", issuer)
	}
	return oauth2.Endpoint{TokenURL: d.Token, DeviceAuthURL: d.Device, AuthStyle: oauth2.AuthStyleInParams}, nil
}

// cachePath is where the token for one issuer, client and set of scopes is
// kept: the user's configuration directory, one file each, readable by them
// alone. It holds a refresh token, which is a password for as long as it
// lives.
//
// ⛔ The scopes are part of the name. `bridge token` asks for openid and
// `bridge ssh-cert` for openid and ssh; with one file per client, ssh-cert
// found token's login, refreshed it -- a refresh keeps the scopes it was
// given -- and was refused by the provider every time.
func cachePath(dir, issuer, clientID string, scopes []string) (string, error) {
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "go-authn-bridge")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientID + "\x00" + strings.Join(sorted, " ")))
	return filepath.Join(dir, hex.EncodeToString(sum[:8])+".json"), nil
}

func readCache(p string) *oauth2.Token {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var t oauth2.Token
	if json.Unmarshal(b, &t) != nil || t.AccessToken == "" {
		return nil
	}
	return &t
}

func writeCache(p string, t *oauth2.Token) {
	b, _ := json.Marshal(t)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, p)
	}
}
