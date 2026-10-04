// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hstern/go-ssf/client"
)

// What SSF 1.0 says the transmitter answers, as the OpenID Foundation's
// CAEP Interop transmitter plan checks it: spec_version in the specs' own
// notation (7.1; CAEP Interop 2.3.1 "MUST be 1_0 or greater"), and an empty
// 204 to a verification request (8.1.4.2) and to a subject removed
// (8.1.3.3). go-ssf v0.1.1 answered "1.0" and 200; the suite failed five
// modules on it.
func TestSSFAnswersAsTheSpecSays(t *testing.T) {
	f := ssfFixture(t)
	cfg, err := client.FetchTransmitterConfig(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpecVersion != "1_0" {
		t.Errorf("spec_version %q, want 1_0", cfg.SpecVersion)
	}
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssfStreamConfig)
	if err != nil {
		t.Fatal(err)
	}
	token := f.receiverToken(t, "fileshare-ssf")
	post := func(endpoint, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", endpoint+"?stream_id="+stream.StreamID, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	subject, _ := json.Marshal(map[string]any{"subject": map[string]string{"format": "email", "email": "alice@univ-example.fr"}})
	for name, c := range map[string]struct{ endpoint, body string }{
		"verification":   {cfg.VerificationEndpoint, `{"state":"s1"}`},
		"remove subject": {cfg.RemoveSubjectEndpoint, string(subject)},
	} {
		if code, body := post(c.endpoint, c.body); code != http.StatusNoContent || body != "" {
			t.Errorf("%s: %d %q, want 204 and nothing", name, code, body)
		}
	}
	// A refusal is not turned into a 204: an unknown stream still says so.
	req, _ := http.NewRequest("POST", cfg.VerificationEndpoint+"?stream_id=nope", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == http.StatusNoContent || res.StatusCode < 400 || len(b) == 0 {
		t.Errorf("verification of an unknown stream: %d %q", res.StatusCode, b)
	}
}
