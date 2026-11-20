// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"net/http"
	"testing"
	"time"
)

// A token that opens an endpoint of this provider's own is addressed to it
// alone, and those endpoints refuse a token addressed to anybody else.
// Measured before this fix, with the application password endpoint (since
// removed, v0.30.0): a token for "fileshare" carrying the scope reset the
// person's password here -- what a resource server receives, it could replay.
// The same rule now holds for what is left: a Kerberos ticket.
func TestABridgeTokenIsForTheBridgeAlone(t *testing.T) {
	f, _ := kerberosFixture(t)
	c, _ := f.s.cfg.client("kinit")
	c.Audience = []string{"fileshare"}

	tok := f.deviceTokenAs("kinit", alice, "openid", "kerberos")
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != f.s.cfg.Issuer {
		t.Errorf("a token with the kerberos scope is addressed to %v, want this provider alone", claims["aud"])
	}
	if code, _, _ := postTGT(t, f, tok.AccessToken); code != http.StatusOK {
		t.Fatalf("the person's own token was refused: %d", code)
	}
	// Without a bridge scope, the client's audience as before.
	plain := f.deviceTokenAs("kinit", alice, "openid")
	if c, _ := f.s.cfg.accessKey.verify("at+jwt", plain.AccessToken); c["aud"] != "fileshare" {
		t.Errorf("a plain token is addressed to %v, want fileshare", c["aud"])
	}

	// A token addressed to fileshare is refused here even with the scope.
	jti := token()
	now := time.Now()
	forged, err := f.s.cfg.accessKey.sign("at+jwt", map[string]any{
		"iss": f.s.cfg.Issuer, "sub": claims["sub"], "aud": "fileshare", "client_id": "kinit",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "jti": jti, "scope": "openid kerberos",
		"preferred_username": "alice@" + idpScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.issued.put(jti, issuedToken{info: map[string]any{"sub": claims["sub"]}, username: "alice@" + idpScope, idp: idpEntity}, now.Add(time.Hour))
	if code, _, _ := postTGT(t, f, forged); code != http.StatusUnauthorized {
		t.Errorf("a token addressed to fileshare bought a ticket here: %d", code)
	}
}
