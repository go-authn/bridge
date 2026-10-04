// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// caepFixture is ssfFixture with a third receiver, one that asked for
// iss_sub subjects (the CAEP Interoperability Profile's).
func caepFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "dsn")
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(dir, "state.db"))), 0o600)
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("an-ssf-receiver-secret-long-enough"), 0o600)
	f := newFixture(t, deviceClients+`
disabled_file = "`+filepath.ToSlash(filepath.Join(dir, "disabled.json"))+`"
state {
  driver   = "sqlite"
  dsn_file = "`+filepath.ToSlash(dsn)+`"
}
ssf {}
client "fileshare-ssf" {
  secret_file  = "`+filepath.ToSlash(secret)+`"
  ssf_receiver = true
}
client "caep-ssf" {
  secret_file        = "`+filepath.ToSlash(secret)+`"
  ssf_receiver       = true
  ssf_subject_format = "iss_sub"
}
`)
	f.s.poll = 1e9
	return f
}

// Each receiver gets the person named as it asked: go-fileshare its
// account, a CAEP Interoperability Profile receiver iss_sub with the very
// sub its relying parties were given (2.5); and session-revoked always
// carries a reason_admin (3.1), an operator's empty reason included. The
// OpenID Foundation's CAEP Interop plan refused the account format.
func TestSSFNamesThePersonAsEachReceiverAsked(t *testing.T) {
	f := caepFixture(t)
	v := f.setVerifier(t)
	streams := map[string]string{}
	for _, id := range []string{"fileshare-ssf", "caep-ssf"} {
		st, err := f.ssfClient(t, id).CreateConfig(t.Context(), &ssfStreamConfig)
		if err != nil {
			t.Fatal(err)
		}
		streams[id] = st.StreamID
	}
	tok := f.deviceToken("rclone", "openid") // alice, public sub
	claims, err := f.s.cfg.accessKey.verify("at+jwt", tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := claims["sub"].(string)

	if _, err := f.s.revokePerson("alice@" + idpScope); err != nil {
		t.Fatal(err)
	}
	revoked := func(id string) []set {
		var out []set
		for _, e := range pollAll(t, f.ssfClient(t, id), v, streams[id]) {
			if ev, ok := e.Events[eventSessionRevoked]; ok {
				if r, _ := ev["reason_admin"].(map[string]any); len(r) == 0 {
					t.Errorf("%s: session-revoked without a reason_admin", id)
				}
				out = append(out, e)
			}
		}
		return out
	}
	fs := revoked("fileshare-ssf")
	if len(fs) != 1 || fs[0].SubID["format"] != "aliases" {
		t.Fatalf("fileshare-ssf: %+v", fs)
	}
	cp := revoked("caep-ssf")
	if len(cp) != 1 || cp[0].SubID["format"] != "iss_sub" || cp[0].SubID["iss"] != f.s.cfg.Issuer || cp[0].SubID["sub"] != sub {
		t.Fatalf("caep-ssf: %+v, want iss_sub %s / %s", cp, f.s.cfg.Issuer, sub)
	}

	// Nobody known under the name: the account all the same -- a
	// revocation that does not arrive fails open.
	if _, err := f.s.revokePerson("ghost@" + idpScope); err != nil {
		t.Fatal(err)
	}
	var ghost []set
	for _, e := range revoked("caep-ssf") {
		if e.SubID["format"] == "aliases" {
			ghost = append(ghost, e)
		}
	}
	if len(ghost) != 1 {
		t.Errorf("an unknown person reached the iss_sub receiver %d times, want once, by account", len(ghost))
	}
}

func TestSSFSubjectFormatIsChecked(t *testing.T) {
	c := newConf(t)
	cfg := c.hcl(func(s string) string {
		return s + "client \"x\" {\n  redirect_uris = [\"http://127.0.0.1/cb\"]\n  ssf_subject_format = \"email\"\n}\n"
	})
	if _, err := c.load(t, cfg); err == nil {
		t.Error("ssf_subject_format = \"email\" was accepted")
	}
}
