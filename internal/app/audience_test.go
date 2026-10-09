// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A token that opens an endpoint of this provider's own is addressed to it
// alone, and those endpoints refuse a token addressed to anybody else.
// Measured before this fix: a token for "fileshare" carrying app_password
// reset the person's application password here -- what a resource server
// receives, it could replay.
func TestABridgeTokenIsForTheBridgeAlone(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "app.db"))), 0o600)
	f := newFixture(t, fmt.Sprintf(`
app_passwords {
  driver   = "sqlite"
  dsn_file = %q
}
client "files" {
  device        = true
  app_passwords = true
  audience      = ["fileshare"]
}
`, filepath.ToSlash(dsn)))
	f.s.poll = 1e9

	tok := f.deviceTokenAs("files", alice, "openid", "app_password")
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != f.s.cfg.Issuer {
		t.Errorf("a token with app_password is addressed to %v, want this provider alone", claims["aud"])
	}
	if code, _ := setPassword(t, f, tok.AccessToken, "POST"); code != http.StatusOK {
		t.Fatalf("the person's own token was refused: %d", code)
	}
	// Without a bridge scope, the client's audience as before.
	plain := f.deviceTokenAs("files", alice, "openid")
	if c, _ := f.s.cfg.accessKey.verify("at+jwt", plain.AccessToken); c["aud"] != "fileshare" {
		t.Errorf("a plain token is addressed to %v, want fileshare", c["aud"])
	}

	// A token addressed to fileshare -- one issued before this fix -- is
	// refused here even with the scope.
	jti := token()
	now := time.Now()
	forged, err := f.s.cfg.accessKey.sign("at+jwt", map[string]any{
		"iss": f.s.cfg.Issuer, "sub": claims["sub"], "aud": "fileshare", "client_id": "files",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "jti": jti, "scope": "openid app_password",
		"preferred_username": "alice@" + idpScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.issued.put(jti, issuedToken{info: map[string]any{"sub": claims["sub"]}, username: "alice@" + idpScope, idp: idpEntity}, now.Add(time.Hour))
	if code, _ := setPassword(t, f, forged, "POST"); code != http.StatusUnauthorized {
		t.Errorf("a token addressed to fileshare set an application password here: %d", code)
	}
}
