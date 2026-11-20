// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Application passwords were removed in v0.30.0, totally: no password of any
// kind is issued, no configuration brings it back, and what this provider used
// to answer for it is refused. Each refusal sits beside the same call that
// still works, so that "refused" cannot be a fixture that never worked.

const noAppPwClients = `
client "files" {
  device = true
}
`

func TestApplicationPasswordScopeIsRefused(t *testing.T) {
	f := newFixture(t, noAppPwClients)
	ask := func(scope string) (int, string) {
		t.Helper()
		r, err := http.PostForm(f.s.cfg.Issuer+"/device_authorization", url.Values{"client_id": {"files"}, "scope": {scope}})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if st, body := ask("openid"); st != http.StatusOK {
		t.Fatalf("control: a device code for openid: %d %s", st, body)
	}
	st, body := ask("openid app_password")
	if st != http.StatusBadRequest || !strings.Contains(body, "invalid_scope") || !strings.Contains(body, "no longer exist") {
		t.Errorf("a device code for the app_password scope: %d %s", st, body)
	}
}

func TestApplicationPasswordEndpointIsGone(t *testing.T) {
	f := newFixture(t, noAppPwClients)
	tok := f.deviceToken("files", "openid")
	call := func(method, path string) int {
		t.Helper()
		req, _ := http.NewRequest(method, f.s.cfg.Issuer+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if st := call(http.MethodGet, "/userinfo"); st != http.StatusOK {
		t.Fatalf("control: the same token at /userinfo: %d", st)
	}
	for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodGet} {
		if st := call(m, "/app-password"); st != http.StatusNotFound {
			t.Errorf("%s /app-password with a valid token: %d, want 404", m, st)
		}
	}
}

// A configuration that still has the block or the client option is refused at
// load, naming it: nothing is read and ignored, and there is no option that
// turns the feature back on.
func TestApplicationPasswordConfigurationIsRefused(t *testing.T) {
	c := newConf(t)
	if _, err := c.load(t, c.hcl(nil)); err != nil {
		t.Fatalf("control: %v", err)
	}
	dsn := c.dir + "/dsn"
	for name, extra := range map[string]string{
		"the block":         "app_passwords {\n  driver   = \"sqlite\"\n  dsn_file = \"" + dsn + "\"\n}\n",
		"the client option": "client \"f\" {\n  device        = true\n  app_passwords = true\n}\n",
	} {
		_, err := c.load(t, c.hcl(nil)+extra)
		if err == nil {
			t.Errorf("%s: ACCEPTED", name)
		} else if !strings.Contains(err.Error(), "app_passwords") {
			t.Errorf("%s: refused without naming it: %v", name, err)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

func TestApplicationPasswordCommandIsGone(t *testing.T) {
	var buf bytes.Buffer
	help := newRootCmd(&buf)
	help.SetOut(&buf)
	help.SetArgs([]string{"--help"})
	if err := help.Execute(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "metadata") {
		t.Fatalf("control: --help does not list the other commands:\n%s", out)
	}
	if strings.Contains(out, "app-password") {
		t.Errorf("--help still lists app-password:\n%s", out)
	}
	if _, err := runCmd(t, "app-password", "--issuer", "https://login.example.org", "--client", "files"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("app-password: %v, want unknown command", err)
	}
}
