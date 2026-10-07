// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The EuroHPC SSH CA profile end to end: a certificate this provider issues
// to an EFP-profile client, with a domain grant and a source-address, logs in
// to go-fileshare (the released binary) configured as a site trusting EFP's
// CA would be -- the CA key fetched from GET /ssh/config, as EFP's trust page
// says, into trusted_user_ca_file, and ssh_domains naming the host. It is let
// in only where the grant names the host AND the address is one the
// certificate allows.
//
// go-fileshare v0.22.1 is the first release that accepts a source-address
// certificate under ssh_domains; older ones refused every certificate pinned
// to an address there.

// efpClients are EFP-profile clients that differ in what they grant: the
// host, another host, an address that is not this one.
const efpClients = `
client "efp-here" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"
  ssh_validity        = "1h"
  ssh_source_address  = ["127.0.0.1"]
  ssh_domain_grants   = ["files.example.org"]
}
client "efp-wildcard" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"
  ssh_source_address  = ["127.0.0.0/8"]
  ssh_domain_grants   = ["login.example.eu", "*.example.org"]
}
client "efp-other-host" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"
  ssh_source_address  = ["127.0.0.1"]
  ssh_domain_grants   = ["login.example.org"]
}
client "efp-other-address" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"
  ssh_source_address  = ["192.0.2.0/24"]
  ssh_domain_grants   = ["files.example.org"]
}
`

// sshCAFromConfig is the CA key as a site gets it: GET /ssh/config, then the
// value of PublicKey -- jq -r '.PublicKey', in Go.
func sshCAFromConfig(t *testing.T, issuer string) string {
	t.Helper()
	res, err := http.Get(issuer + "/ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var doc struct{ PublicKey string }
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &doc) != nil || doc.PublicKey == "" {
		t.Fatalf("GET /ssh/config: %s %s", res.Status, body)
	}
	return doc.PublicKey
}

// startFileshare runs the fileshare binary on the configuration directory d
// and waits until it listens on addr.
func startFileshare(t *testing.T, bin, d, addr string) *syncWriter {
	t.Helper()
	var log syncWriter
	cmd := exec.Command(bin, "--config", d)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("fileshare:\n%s", log.String())
		}
	})
	for n := 0; ; n++ {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return &log
		}
		if n == 100 {
			t.Fatalf("fileshare does not listen on %s:\n%s", addr, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sftpDialFrom is sftpDial from the local address from.
func sftpDialFrom(from, addr, user string, certLine []byte, priv ed25519.PrivateKey) (*sftp.Client, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	cs, err := ssh.NewCertSigner(k.(*ssh.Certificate), signer)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: 5 * time.Second}
	nc, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialling from %s: %w", from, err)
	}
	if got := nc.LocalAddr().(*net.TCPAddr).IP.String(); got != from {
		nc.Close()
		return nil, fmt.Errorf("dialled from %s, not %s", got, from)
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)},
		// The host key is fileshare's, made for this test: not what is judged.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	conn := ssh.NewClient(sc, chans, reqs)
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// secondLoopback says whether 127.0.0.2 can be dialled from here. Linux
// routes all of 127.0.0.0/8 on lo; macOS only 127.0.0.1, unless aliased.
func secondLoopback(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err == nil {
		ln.Close()
		return true
	}
	if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" && runtime.GOOS == "linux" {
		t.Fatalf("127.0.0.2 is required on Linux here: %v", err)
	}
	t.Logf("127.0.0.2 is not available (%v): the same-certificate, other-address case is not run", err)
	return false
}

func TestInteropEFPProfileDomainGrant(t *testing.T) {
	bin := fileshareBin(t)
	f, _ := efpFixture(t, efpClients)
	cuid := strings.ToLower(alice.subjectID)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "bridge-ssh-ca.pub")
	os.WriteFile(caFile, []byte(sshCAFromConfig(t, f.s.cfg.Issuer)+"\n"), 0o644)
	share := filepath.Join(dir, "share")
	os.MkdirAll(share, 0o755)
	os.WriteFile(filepath.Join(share, "x.txt"), []byte("hello from fileshare\n"), 0o644)
	addr := "127.0.0.1:" + freePort(t)
	d := filepath.Join(dir, "fileshare.d")
	os.MkdirAll(d, 0o700)
	// The principal is the person's voperson_id, so that is the local
	// account: a user block of that name, with no credential of its own,
	// is what a certificate from trusted_user_ca_file logs in as.
	os.WriteFile(filepath.Join(d, "fileshare.hcl"), []byte(fmt.Sprintf(`
trusted_user_ca_file = %q
ssh_domains          = ["files.example.org"]

user %q {}

share "t" {
  directory = %q
  allow     = [%q]
}
serve "sftp" { addr = %q }
`, hclP(caFile), cuid, hclP(share), cuid, addr)), 0o600)
	log := startFileshare(t, bin, d, addr)

	// One certificate per client, for one key each.
	issue := func(client string) ([]byte, ed25519.PrivateKey) {
		t.Helper()
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		tok := f.deviceToken(client, "openid", "ssh", "eduperson")
		status, body := certify(t, f, tok.AccessToken, authorizedKey(t, pub))
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", client, status, body)
		}
		c := parseCert(t, body)
		if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != cuid || c.CriticalOptions["source-address"] == "" ||
			c.Extensions[DomainGrantExtension] == "" {
			t.Fatalf("%s: not an EFP-profile certificate with a grant and a source-address: %+v", client, c)
		}
		return body, priv
	}
	reads := func(from string, cert []byte, priv ed25519.PrivateKey) error {
		t.Helper()
		c, err := sftpDialFrom(from, addr, cuid, cert, priv)
		if err != nil {
			return err
		}
		defer c.Close()
		fh, err := c.Open("/t/x.txt")
		if err != nil {
			return err
		}
		defer fh.Close()
		buf := make([]byte, 5)
		if _, err := fh.ReadAt(buf, 0); err != nil || string(buf) != "hello" {
			return fmt.Errorf("read %q: %v", buf, err)
		}
		return nil
	}

	here, herePriv := issue("efp-here")
	wild, wildPriv := issue("efp-wildcard")
	otherHost, otherHostPriv := issue("efp-other-host")
	otherAddr, otherAddrPriv := issue("efp-other-address")

	if err := reads("127.0.0.1", here, herePriv); err != nil {
		t.Errorf("granted this host, from the address it allows: %v", err)
	}
	if err := reads("127.0.0.1", wild, wildPriv); err != nil {
		t.Errorf("granted *.example.org, from 127.0.0.0/8: %v", err)
	}
	if err := reads("127.0.0.1", otherHost, otherHostPriv); err == nil {
		t.Error("a certificate granted login.example.org logged in to files.example.org")
	}
	if !strings.Contains(log.String(), "names none of this host's names") {
		t.Errorf("the other-host refusal was not logged as the grant's:\n%s", log.String())
	}
	if err := reads("127.0.0.1", otherAddr, otherAddrPriv); err == nil {
		t.Error("a certificate pinned to 192.0.2.0/24 logged in from 127.0.0.1")
	}
	// The same certificate that got in from 127.0.0.1, from 127.0.0.2: its
	// source-address is 127.0.0.1, not "loopback". And the wildcard one,
	// pinned to 127.0.0.0/8, still gets in from there.
	if secondLoopback(t) {
		if err := reads("127.0.0.2", here, herePriv); err == nil {
			t.Error("a certificate pinned to 127.0.0.1 logged in from 127.0.0.2")
		}
		if err := reads("127.0.0.2", wild, wildPriv); err != nil {
			t.Errorf("a certificate pinned to 127.0.0.0/8, from 127.0.0.2: %v", err)
		}
	}
}
