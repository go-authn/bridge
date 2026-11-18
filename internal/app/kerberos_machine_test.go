// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// A machine with a registered key (private_key_jwt) and kerberos_tickets buys
// a TGT for ITSELF: <client>@<issuer host>, derived from the client the token
// was issued to. The controls: a machine without the flag, a machine token
// without the scope, and a scope-less request that must not change.
func TestKerberosTGTForAMachine(t *testing.T) {
	dir := t.TempDir()
	stub, kdcURL := newStubKDC(t, dir)
	keys := newMachineKeys(t)
	jf := filepath.Join(dir, "jwks.json")
	os.WriteFile(jf, []byte(keys.set), 0o600)
	f := newFixture(t, deviceClients+`
kerberos {
  kdc_url   = "`+kdcURL+`"
  ca_file   = "`+filepath.ToSlash(filepath.Join(dir, "kdc-ca.pem"))+`"
  cert_file = "`+filepath.ToSlash(filepath.Join(dir, "bridge.pem"))+`"
  key_file  = "`+filepath.ToSlash(filepath.Join(dir, "bridge.key"))+`"
}
client "winpc" {
  jwks_file        = "`+filepath.ToSlash(jf)+`"
  audience         = ["fileshare-s3"]
  kerberos_tickets = true
}
client "plainpc" {
  jwks_file = "`+filepath.ToSlash(jf)+`"
  audience  = ["fileshare-s3"]
}
`)
	token := func(client, scope string) (int, map[string]any) {
		a := assertion(t, jose.ES256, keys.es, "es", f.claims(client, nil))
		v := assertionForm(a)
		if scope != "" {
			v.Set("scope", scope)
		}
		return f.postToken(t, v)
	}

	status, body := token("winpc", "kerberos")
	if status != http.StatusOK {
		t.Fatalf("the machine's kerberos token: %d %v", status, body)
	}
	at := body["access_token"].(string)
	claims, _ := f.s.cfg.accessKey.verify("at+jwt", at)
	if claims["aud"] != f.s.cfg.Issuer {
		t.Errorf("aud %v: a kerberos token is for this provider alone", claims["aud"])
	}
	code, cred, _ := postTGT(t, f, at)
	if code != http.StatusOK || len(cred) == 0 || cred[0] != 0x76 {
		t.Fatalf("%d %.40q", code, cred)
	}
	host := f.s.cfg.rpID()
	if len(stub.asked) != 1 || stub.asked[0]["principal"] != "winpc@"+host {
		t.Errorf("the KDC was asked %v, want winpc@%s", stub.asked, host)
	}

	// Controls. No flag on the client: no scope.
	if status, body := token("plainpc", "kerberos"); status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("a machine without kerberos_tickets: %d %v", status, body)
	}
	// A scope-less request is what it always was: the machine scope, for the
	// client's audience, and no ticket from it.
	status, body = token("winpc", "")
	if status != http.StatusOK || body["scope"] != "machine" {
		t.Fatalf("the default request changed: %d %v", status, body)
	}
	if claims, _ := f.s.cfg.accessKey.verify("at+jwt", body["access_token"].(string)); claims["aud"] != "fileshare-s3" {
		t.Errorf("the default token's aud %v", claims["aud"])
	}
	if code, _, _ := postTGT(t, f, body["access_token"].(string)); code != http.StatusForbidden {
		t.Errorf("a machine-scope token bought a ticket: %d", code)
	}
	if len(stub.asked) != 1 {
		t.Errorf("the KDC was asked %d times", len(stub.asked))
	}
}

func TestMachineName(t *testing.T) {
	f := localFixture(t, "")
	s := f.s
	host := s.cfg.rpID()
	for name, c := range map[string]struct {
		claims map[string]any
		want   string
		isM    bool
	}{
		"a machine":                        {map[string]any{"client_id": "winpc-17", "sub": "winpc-17"}, "winpc-17@" + host, true},
		"a person (an idp)":                {map[string]any{"client_id": "kinit", "sub": "abc", "idp": "https://i", "preferred_username": "a@b"}, "", false},
		"a person whose sub is the client": {map[string]any{"client_id": "x", "sub": "x", "idp": "https://i"}, "", false},
		"a username":                       {map[string]any{"client_id": "x", "sub": "x", "preferred_username": "a@b"}, "", false},
		"a client ID with an @":            {map[string]any{"client_id": "evil@univ.example", "sub": "evil@univ.example"}, "", true},
		"a client ID with a slash":         {map[string]any{"client_id": "nfs/host", "sub": "nfs/host"}, "", true},
		"a client ID with a space":         {map[string]any{"client_id": "a b", "sub": "a b"}, "", true},
	} {
		got, isM := s.machineName(c.claims)
		if got != c.want || isM != c.isM {
			t.Errorf("%s: %q,%v want %q,%v", name, got, isM, c.want, c.isM)
		}
	}
}
