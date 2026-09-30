// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

// `bridge nfs-cert` gets an X.509 client certificate for NFS over TLS: it
// makes a P-256 key here (it never leaves the machine), logs in with a code
// the first time (the "nfs" scope), sends a certificate request, and writes
// the certificate and the key, in PEM and in the DER the kernel keyring
// takes (ktls-utils tlshd reads DER only, src/tlshd/keyring.c).
//
//	bridge nfs-cert --issuer https://login.example.org --client nfs
func newNFSCertCmd(out io.Writer) *cobra.Command {
	var issuer, clientID, dir, cacheDir string
	cmd := &cobra.Command{
		Use:   "nfs-cert",
		Short: "have an NFS-over-TLS client certificate issued, with a key made here",
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || clientID == "" {
				return errors.New("give --issuer and --client")
			}
			if dir == "" {
				cfg, err := os.UserConfigDir()
				if err != nil {
					return err
				}
				dir = filepath.Join(cfg, "go-authn-bridge", "nfs")
			}
			res, err := issueNFSCert(cmd.Context(), issuer, clientID, dir, cacheDir, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return nfsCertTold.Execute(out, res)
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "", "the provider, e.g. https://login.example.org")
	cmd.Flags().StringVar(&clientID, "client", "", "the client ID it knows this program by")
	cmd.Flags().StringVar(&dir, "dir", "", "where to write the certificate and key (default: the user's configuration directory)")
	cmd.Flags().StringVar(&cacheDir, "cache", "", "where to keep the login (default: the user's configuration directory)")
	return cmd
}

type nfsCertResult struct {
	Name, Cert, Key, CertDER, KeyDER, Until string
}

// ⛔ What the person has to know before they mount: the Linux client sets a
// certificate per MOUNT (the cert_serial and privkey_serial mount options,
// fs/nfs/fs_context.c), so whoever uses that mount is this person to the
// server -- RFC 9289: the TLS identity is the peer's, not the RPC user's.
var nfsCertTold = template.Must(template.New("").Parse(`wrote {{.Cert}} and {{.Key}} (valid until {{.Until}}),
and {{.CertDER}}, {{.KeyDER}} in DER for the kernel keyring.

⛔ This certificate says the MACHINE is {{.Name}}. Linux presents one
   certificate per NFS mount: everybody who uses that mount is {{.Name}} to
   the server. Mount with it on a machine only you use.

On Linux with ktls-utils (tlshd running), as root -- see nfs(5) and tlshd(8):

  cert=$(keyctl padd user nfs-cert @u < {{.CertDER}})
  key=$(keyctl padd user nfs-key @u < {{.KeyDER}})
  mount -t nfs -o vers=4.2,xprtsec=mtls,cert_serial=$cert,privkey_serial=$key SERVER:/SHARE /mnt

What tlshd does not say (measured against Linux 6.17, ktls-utils 0.9):

- The SERVER's certificate must verify against this machine's SYSTEM trust
  store: on the client side tlshd ignores x509.truststore.
- If you name the certificate in /etc/tlshd.conf instead ([authenticate.client]
  x509.certificate, x509.private_key), both files must be owned by root and the
  key mode 600. Either mistake shows only as
  "gnutls: Error in the certificate (-43)".
- A person the server refuses sees "access denied" at the first access, not at
  mount: the kernel sends MOUNT's MNT call in the clear.
`))

func issueNFSCert(ctx context.Context, issuer, clientID, dir, cacheDir string, tell io.Writer) (nfsCertResult, error) {
	var res nfsCertResult
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return res, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nfs"}}, key)
	if err != nil {
		return res, err
	}
	tok, err := clientToken(ctx, issuer, clientID, []string{"openid", "nfs"}, cacheDir, tell)
	if err != nil {
		return res, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/x509/cert",
		bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})))
	if err != nil {
		return res, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("the provider refused: %s", strings.TrimSpace(string(body)))
	}
	blk, _ := pem.Decode(body)
	if blk == nil {
		return res, errors.New("the provider answered with no certificate")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return res, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return res, err
	}
	res = nfsCertResult{
		Name:    leaf.Subject.CommonName,
		Cert:    filepath.Join(dir, "nfs.crt"),
		Key:     filepath.Join(dir, "nfs.key"),
		CertDER: filepath.Join(dir, "nfs.crt.der"),
		KeyDER:  filepath.Join(dir, "nfs.key.der"),
		Until:   leaf.NotAfter.Local().Format(time.RFC1123),
	}
	if res.Name == "" { // past 64 characters, the name is in the SAN only
		res.Name = "the person you logged in as"
	}
	for _, w := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{res.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600},
		{res.KeyDER, keyDER, 0o600},
		{res.Cert, body, 0o644},
		{res.CertDER, blk.Bytes, 0o644},
	} {
		if err := os.WriteFile(w.path, w.data, w.mode); err != nil {
			return res, err
		}
		// WriteFile keeps the mode of a file that is already there.
		if err := os.Chmod(w.path, w.mode); err != nil {
			return res, err
		}
	}
	return res, nil
}
