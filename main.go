// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/go-authn/servercert"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd(os.Stdout).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge:", err)
		os.Exit(1)
	}
}

const longHelp = `bridge is an OpenID Connect provider in front of a SAML federation such as
RENATER or eduGAIN: people log in at their own institution, and applications
get an OpenID Connect token.

    bridge keygen --key /var/lib/bridge/oidc.key --salt /var/lib/bridge/salt
    bridge check  --config /etc/bridge.d
    bridge metadata --config /etc/bridge.d > sp.xml    # to register with the federation
    bridge --config /etc/bridge.d

What it refuses is the design:

  - federation metadata not signed by the certificate whose fingerprint the
    configuration pins, or past its validUntil;
  - an assertion that is unsigned, for somebody else, replayed, or carrying an
    identifier in a scope its institution does not own;
  - an authorization request without PKCE S256, or for a redirect URI the
    client did not register, or with a parameter twice;
  - a code used twice -- and the tokens the first use bought are revoked.`

func newRootCmd(out io.Writer) *cobra.Command {
	var files []string
	root := &cobra.Command{
		Use:           "bridge",
		Short:         "an OpenID Connect provider in front of a SAML federation",
		Long:          longHelp,
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(files)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, cfg, out)
		},
	}
	root.PersistentFlags().StringArrayVarP(&files, "config", "c", nil, "an HCL file, or a directory of .hcl files (repeatable)")

	root.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "read the configuration and the federation's metadata, and say what would be served",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(files)
			if err != nil {
				return err
			}
			defer cfg.close()
			s, err := newServer(cfg, out)
			if err != nil {
				return err
			}
			// servercert's Check touches nothing on disk; New reads the
			// certificate pair or the EAB key, which is what a check is for.
			tlsLine := "none (a reverse proxy in front)"
			if sc, ok := cfg.certConfig(s.logf); ok {
				src, err := servercert.New(sc)
				if err != nil {
					return fmt.Errorf("tls: %w", err)
				}
				src.Close()
				tlsLine = "from " + cfg.CertFile
				if a := cfg.ACME; a != nil {
					tlsLine = "ACME, " + a.host + " from " + orDefault(a.DirectoryURL, "Let's Encrypt")
				}
			}
			if err := s.fed.Refresh(cmd.Context()); err != nil {
				return fmt.Errorf("the federation's metadata: %w", err)
			}
			md := s.fed.Metadata()
			usable := 0
			for id := range md.IdPs {
				if s.allowedIdP(id) {
					usable++
				}
			}
			fmt.Fprintf(out, "issuer        %s\n", cfg.Issuer)
			fmt.Fprintf(out, "SAML entity   %s\n", cfg.SAML.EntityID)
			fmt.Fprintf(out, "tls           %s\n", tlsLine)
			fmt.Fprintf(out, "federation    %d IdPs, %d usable here, valid until %s\n", len(md.IdPs), usable, md.ValidUntil.Format(time.RFC3339))
			for _, id := range cfg.SAML.IdPs {
				if _, ok := md.IdPs[id]; !ok {
					return fmt.Errorf("idps names %q, which the federation does not list", id)
				}
			}
			for _, c := range cfg.Clients {
				kind := "confidential"
				if c.public() {
					kind = "public"
				}
				fmt.Fprintf(out, "client        %s (%s, %s subject, audience %v)\n", c.ID, kind, c.Subject, c.Audience)
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "metadata",
		Short: "print this provider's SAML metadata, to register with the federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(files)
			if err != nil {
				return err
			}
			defer cfg.close()
			s, err := newServer(cfg, io.Discard)
			if err != nil {
				return err
			}
			b, err := s.spMetadata()
			if err != nil {
				return err
			}
			_, err = out.Write(b)
			return err
		},
	})

	var keyFile, saltFile, sshCAFile, atKeyFile, x509CADir string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "write a new token signing key and subject salt, refusing to overwrite either",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyFile == "" && saltFile == "" && sshCAFile == "" && atKeyFile == "" && x509CADir == "" {
				return errors.New("give --key, --salt, --ssh-ca, --access-token-key, --x509-ca, or several")
			}
			if sshCAFile != "" {
				pub, err := generateSSHCA(sshCAFile)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s; its public half, for go-fileshare's trusted_user_ca_file:\n%s\n", sshCAFile, pub)
			}
			if keyFile != "" {
				if err := generateKey(keyFile, 3072); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s\n", keyFile)
			}
			if x509CADir != "" {
				crt, err := generateX509CA(x509CADir, "go-authn bridge NFS client CA")
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s and its key; the certificate is what go-fileshare trusts for NFS over TLS\n", crt)
			}
			if atKeyFile != "" {
				if err := generateECKey(atKeyFile); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s (P-256, ES256 access tokens)\n", atKeyFile)
			}
			if saltFile != "" {
				if err := generateSalt(saltFile); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s -- keep it: a new salt is a new subject for everybody\n", saltFile)
			}
			return nil
		},
	}
	keygen.Flags().StringVar(&keyFile, "key", "", "where to write the RSA signing key")
	keygen.Flags().StringVar(&atKeyFile, "access-token-key", "", "where to write a P-256 key for ES256 access tokens")
	keygen.Flags().StringVar(&x509CADir, "x509-ca", "", "a directory to write an X.509 CA in (ca.key, ca.crt), for NFS client certificates")
	keygen.Flags().StringVar(&saltFile, "salt", "", "where to write the subject salt")
	keygen.Flags().StringVar(&sshCAFile, "ssh-ca", "", "where to write an Ed25519 SSH certificate authority key")
	root.AddCommand(keygen)
	root.AddCommand(newTokenCmd(out))
	root.AddCommand(newSSHCertCmd(out))
	root.AddCommand(newNFSCertCmd(out))
	root.AddCommand(newAppPasswordCmd(out))
	return root
}

// serve runs until ctx ends.
func serve(ctx context.Context, cfg *config, out io.Writer) error {
	defer cfg.close()
	s, err := newServer(cfg, out)
	if err != nil {
		return err
	}
	// The metadata is fetched before listening: a provider that cannot
	// name a single institution is one nobody can log in through, and it
	// should say so rather than start.
	if err := s.refreshMetadata(ctx); err != nil {
		return fmt.Errorf("the federation's metadata: %w", err)
	}
	go s.refreshLoop(ctx)
	admin, err := s.openAdmin()
	if err != nil {
		return err
	}
	metrics, err := s.openMetrics()
	if err != nil {
		return err
	}
	tc, httpChallenges, err := s.publicTLS()
	if err != nil {
		return err
	}
	for name, run := range map[string]func(context.Context) error{"admin": admin, "metrics": metrics, "acme": httpChallenges} {
		if run == nil {
			continue
		}
		go func() {
			if err := run(ctx); err != nil {
				s.logf("%s: %v", name, err)
			}
		}()
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	// A body that arrives a byte a minute, a connection kept open for nothing:
	// each holds a goroutine and a socket, so each is timed (measured: with
	// ReadHeaderTimeout alone, a slow POST held its connection indefinitely).
	// No request here is large: 1 MiB is four times the SAML size limit.
	srv := s.httpServer(tc)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	s.logf("bridge %s: %s on %s", version(), cfg.Issuer, ln.Addr())
	if tc != nil {
		// The certificate comes from tc.GetCertificate, so no files here.
		// ⛔ ServeTLS, not Serve(tls.NewListener(ln, tc)): ServeTLS appends
		// "h2" and "http/1.1" to NextProtos, which with ACME holds
		// "acme-tls/1" alone -- and a Go server refuses every client whose
		// ALPN shares nothing with it ("no application protocol").
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
