// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// panva/openid-client is an OpenID Certified relying party, and strict in
// ways the Go clients the other tests use are not: the issuer of discovery
// compared character for character, the RFC 9207 iss response parameter
// once advertised, a kid to pick the key, the RFC 9068 shape of an access
// token as a resource server checks it. testdata/openid-client/judge.mjs is
// the application; this is the person in the browser.
//
// It needs node and `npm ci` in testdata/openid-client. Where
// BRIDGE_REQUIRE_JUDGE is set, their absence is a failure, not a skip.
func TestOpenIDClientJudge(t *testing.T) {
	dir, _ := filepath.Abs(filepath.Join("testdata", "openid-client"))
	node, err := exec.LookPath("node")
	if err == nil {
		_, err = os.Stat(filepath.Join(dir, "node_modules", "openid-client"))
	}
	if err != nil {
		if os.Getenv("BRIDGE_REQUIRE_JUDGE") != "" {
			t.Fatalf("openid-client is required here (node, then npm ci in %s): %v", dir, err)
		}
		t.Skip("openid-client is not installed")
	}

	// openid-client refuses a plain http issuer, as it should.
	secret := filepath.Join(t.TempDir(), "oc.secret")
	os.WriteFile(secret, []byte("another-secret-long-enough-to-pass"), 0o600)
	f := newFixtureTLS(t, deviceClients+`
client "oc" {
  secret_file      = "`+filepath.ToSlash(secret)+`"
  redirect_uris    = ["http://127.0.0.1:9/callback"]
  audience         = ["fileshare"]
  refresh_lifetime = "24h"
}
`)
	f.s.poll = 1e9
	ca := filepath.Join(f.dir, "issuer.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o644)

	conf, _ := json.Marshal(map[string]any{
		"issuer": f.s.cfg.Issuer,
		"web": map[string]string{"client_id": "oc", "secret": "another-secret-long-enough-to-pass",
			"redirect_uri": f.redirect, "audience": "fileshare"},
		"device": map[string]string{"client_id": "rclone"},
	})
	cmd := exec.CommandContext(t.Context(), node, "judge.mjs")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "JUDGE_CONFIG="+string(conf), "NODE_EXTRA_CA_CERTS="+ca)
	cmd.Stderr = &testLog{t}
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer in.Close()

	var msg judgeLine
	sc := bufio.NewScanner(out)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		msg = judgeLine{}
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			t.Fatalf("the judge said %q: %v", sc.Text(), err)
		}
		switch {
		case msg.Walk != "" && msg.Kind == "login":
			back := f.login(newBrowser(t), msg.Walk, alice)
			json.NewEncoder(in).Encode(map[string]string{"url": back.String()})
		case msg.Walk != "" && msg.Kind == "device":
			res := f.approve(newBrowser(t), msg.Walk, true, alice)
			io.Copy(io.Discard, res.Body)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("approving the device: %d", res.StatusCode)
			}
			json.NewEncoder(in).Encode(map[string]string{"url": ""})
		default:
			goto end
		}
	}
end:
	if msg.Error != "" {
		t.Fatalf("openid-client refused at %q: %s (%s) %s\nso far: %v", msg.Step, msg.Error, msg.Code, msg.Cause, msg.Results)
	}
	if msg.Done == nil {
		t.Fatalf("the judge ended without a verdict (scanner: %v)", sc.Err())
	}
	b, _ := json.MarshalIndent(msg.Done, "", "  ")
	t.Logf("openid-client:\n%s", b)

	r := msg.Done
	sub := r["code"].(map[string]any)["sub"]
	if sub == nil || sub == "" {
		t.Error("no sub")
	}
	if r["userinfo"].(map[string]any)["sub"] != sub || r["access_token"].(map[string]any)["sub"] != sub {
		t.Errorf("the ID Token, userinfo and access token disagree on who it is")
	}
	if r["refresh"].(map[string]any)["rotated"] != true {
		t.Error("the refresh token was not rotated")
	}
	if r["reuse"] != "invalid_grant" {
		t.Errorf("a spent refresh token, used again: %v", r["reuse"])
	}
	if d := r["device"].(map[string]any); d["has_refresh"] != true || d["sub"] == nil {
		t.Errorf("device grant: %v", d)
	}
}

// judgeLine is one line from judge.mjs.
type judgeLine struct {
	Walk    string         `json:"walk"`
	Kind    string         `json:"kind"`
	Done    map[string]any `json:"done"`
	Error   string         `json:"error"`
	Code    string         `json:"code"`
	Cause   string         `json:"cause"`
	Step    string         `json:"step"`
	Results map[string]any `json:"results"`
}
