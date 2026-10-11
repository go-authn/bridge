package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// access_token_groups = false is for a client whose token is pasted as an
// SSH keyboard-interactive answer (ssh-oidc: oidc-agent, mccli, motley-cue),
// where OpenSSH reads 1023 characters and nothing bounds how many groups an
// IdP sends. motley-cue reads the groups at /userinfo; the token need not.
const sshOIDCClient = `
client "oidc-agent" {
  device              = true
  audience            = ["ssh"]
  access_token_groups = false
}
`

// fiftyGroups is somebody in fifty distinct groups of their own IdP's
// namespace: what made the token's length unbounded.
func fiftyGroups() assertionOpts {
	var ents []string
	for i := 0; i < 50; i++ {
		ents = append(ents, fmt.Sprintf("urn:geant:%s:group:physique:calcul:projet-%02d#login.example.org", idpScope, i))
	}
	return assertionOpts{eppn: "jean-baptiste.delaplace@" + idpScope, entitlement: ents}
}

func tokenPayload(t *testing.T, at string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(at, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func TestAccessTokenWithoutGroups(t *testing.T) {
	// ES256 access tokens, as the README says to configure for ssh-oidc.
	key := filepath.Join(t.TempDir(), "at.key")
	if err := generateECKey(key); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, deviceClients+sshOIDCClient+"\naccess_token_key_file = \""+filepath.ToSlash(key)+"\"\n")
	f.s.poll = 1e9
	who := fiftyGroups()

	// Through the ssh-oidc client: no groups in the token...
	tok := f.deviceTokenAs("oidc-agent", who, "openid", "eduperson", "groups")
	if g, ok := tokenPayload(t, tok.AccessToken)["groups"]; ok {
		t.Fatalf("the access token carries groups: %v", g)
	}
	// ...and a bounded length: recomputed for the longest RENATER scope (44)
	// and a real issuer, as TestES256AccessTokens does, fifty groups or not.
	parts := strings.Split(tok.AccessToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	p := strings.ReplaceAll(string(payload), f.s.cfg.Issuer, "https://login.renater-member.example")
	p = strings.ReplaceAll(p, idpScope, strings.Repeat("u", 44))
	n := len(parts[0]) + 1 + base64.RawURLEncoding.EncodedLen(len(p)) + 1 + len(parts[2])
	t.Logf("oidc-agent token, 50 groups, longest scope: %d characters", n)
	if n > 1023 {
		t.Errorf("%d characters: over what OpenSSH reads as an answer", n)
	}

	// ...while /userinfo still has all fifty, where motley-cue reads them.
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo: %v %v", err, res)
	}
	var info map[string]any
	json.NewDecoder(res.Body).Decode(&info)
	res.Body.Close()
	for _, claim := range []string{"groups", "eduperson_entitlement"} {
		if v, _ := info[claim].([]any); len(v) != 50 {
			t.Errorf("/userinfo %s: %d values, want 50", claim, len(v))
		}
	}

	// Another client, the default: the same person's token carries them.
	other := f.deviceTokenAs("rclone", who, "openid")
	if g, _ := tokenPayload(t, other.AccessToken)["groups"].([]any); len(g) != 50 {
		t.Errorf("the default client's token carries %d groups, want 50", len(g))
	}
}

// Refused with certificates, which take the groups from the access token:
// they would carry none, silently.
func TestAccessTokenGroupsOffRefusedWithCertificates(t *testing.T) {
	c := newConf(t)
	ca := filepath.ToSlash(filepath.Join(c.dir, "ca"))
	if _, err := generateSSHCA(ca); err != nil {
		t.Fatal(err)
	}
	head := c.hcl(nil) + "certificates_file = \"" + c.dir + "/certs.json\"\n" +
		"ssh_ca {\nkey_file = \"" + ca + "\"\nvalidity = \"2h\"\n}\n"
	client := func(body string) string {
		return head + "client \"p\" {\ndevice = true\n" + body + "\n}\n"
	}
	if _, err := c.load(t, client("ssh_certificates = true\naccess_token_groups = false")); err == nil ||
		!strings.Contains(err.Error(), "access_token_groups = false with ssh_certificates") {
		t.Errorf("ssh_certificates without groups in the token: %v", err)
	}
	for _, ok := range []string{"ssh_certificates = true", "ssh_certificates = true\naccess_token_groups = true", "access_token_groups = false"} {
		if _, err := c.load(t, client(ok)); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}
