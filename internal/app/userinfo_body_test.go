// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The access token at /userinfo: in the Authorization header, or in a
// form-encoded POST body (RFC 6750 2.2, OIDC Core 5.3.1) -- the OpenID
// Foundation's oidcc-userinfo-post-body warned that the body was refused.
// Never in the query (2.3), and never two ways at once (2).
func TestUserinfoTakesTheTokenInAFormBody(t *testing.T) {
	f := newFixture(t, deviceClients)
	f.s.poll = 1e9
	tok := f.deviceToken("rclone", "openid").AccessToken
	ui := f.s.cfg.Issuer + "/userinfo"
	do := func(method, target, body, contentType, header string) int {
		t.Helper()
		req, _ := http.NewRequest(method, target, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if header != "" {
			req.Header.Set("Authorization", "Bearer "+header)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	form := url.Values{"access_token": {tok}}.Encode()
	for _, c := range []struct {
		name                                string
		method, target, body, ctype, header string
		want                                int
	}{
		{"header", "GET", ui, "", "", tok, 200},
		{"POST body", "POST", ui, form, "application/x-www-form-urlencoded", "", 200},
		{"POST body, charset", "POST", ui, form, "application/x-www-form-urlencoded; charset=utf-8", "", 200},
		{"query", "GET", ui + "?" + form, "", "", "", 401},
		{"body not form-encoded", "POST", ui, form, "text/plain", "", 401},
		{"header and body", "POST", ui, form, "application/x-www-form-urlencoded", tok, 400},
		{"body twice", "POST", ui, form + "&" + form, "application/x-www-form-urlencoded", "", 400},
		{"a wrong token in the body", "POST", ui, "access_token=nope", "application/x-www-form-urlencoded", "", 401},
	} {
		if got := do(c.method, c.target, c.body, c.ctype, c.header); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
