// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/client"
	"github.com/hstern/go-ssf/receiver"
	subjectid "github.com/hstern/go-subjectid"
	"golang.org/x/oauth2/clientcredentials"
)

// ssfFixture is a provider with a state database, an SSF transmitter and
// two receivers, fileshare and other.
func ssfFixture(t *testing.T) *fixture {
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
  audience     = ["fileshare"]
}
client "other-ssf" {
  secret_file  = "`+filepath.ToSlash(secret)+`"
  ssf_receiver = true
  audience     = ["other"]
}
`)
	f.s.poll = 1e9
	return f
}

// receiverToken is what a receiver gets with client credentials, through
// x/oauth2's clientcredentials -- what go-fileshare uses.
func (f *fixture) receiverToken(t *testing.T, id string) string {
	t.Helper()
	cc := &clientcredentials.Config{ClientID: id, ClientSecret: "an-ssf-receiver-secret-long-enough", TokenURL: f.s.cfg.Issuer + "/token", Scopes: []string{"ssf"}}
	tok, err := cc.Token(t.Context())
	if err != nil {
		t.Fatalf("client credentials for %s: %v", id, err)
	}
	return tok.AccessToken
}

// ssfClient is go-ssf's client, authenticated as id.
func (f *fixture) ssfClient(t *testing.T, id string) client.Client {
	t.Helper()
	cfg, err := client.FetchTransmitterConfig(t.Context(), f.s.cfg.Issuer)
	if err != nil {
		t.Fatalf("the SSF configuration: %v", err)
	}
	base := strings.TrimSuffix(cfg.ConfigurationEndpoint, "/streams")
	c, err := client.NewClient(base, client.WithAuthorizationHeader("Bearer "+f.receiverToken(t, id)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verifier checks SETs against the provider's published key set, with
// go-jose, as a receiver does.
func (f *fixture) setVerifier(t *testing.T) *ssf.JOSESetVerifier {
	t.Helper()
	res, err := http.Get(f.s.cfg.Issuer + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var ks jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&ks); err != nil {
		t.Fatal(err)
	}
	return ssf.NewJOSESetVerifier(ks)
}

type set struct {
	Iss    string                    `json:"iss"`
	Aud    any                       `json:"aud"`
	Jti    string                    `json:"jti"`
	Iat    int64                     `json:"iat"`
	Exp    *int64                    `json:"exp"`
	Sub    *string                   `json:"sub"`
	SubID  map[string]any            `json:"sub_id"`
	Events map[string]map[string]any `json:"events"`
}

// pollAll polls once and verifies every SET, without acknowledging.
func pollAll(t *testing.T, c client.Client, v *ssf.JOSESetVerifier, stream string) map[string]set {
	t.Helper()
	ret := true
	resp, err := c.PollEvents(t.Context(), stream, &ssf.PollRequest{ReturnImmediately: &ret})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	out := map[string]set{}
	for jti, compact := range resp.Sets {
		payload, err := v.Verify(compact)
		if err != nil {
			t.Fatalf("a SET that does not verify against the key set: %v", err)
		}
		var s set
		json.Unmarshal(payload, &s)
		out[jti] = s
	}
	return out
}

// A receiver creates its stream; disabling a person puts a signed CAEP
// session-revoked there, for their account, until it is acknowledged.
func TestSSFSessionRevoked(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	aud, _ := json.Marshal("fileshare")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{
		Aud:             aud,
		EventsRequested: []string{eventSessionRevoked},
		Delivery:        ssf.Delivery{Method: deliveryPoll},
	})
	if err != nil {
		t.Fatalf("creating the stream: %v", err)
	}
	if len(stream.EventsDelivered) != 1 || stream.Iss != f.s.cfg.Issuer || !strings.Contains(stream.Delivery.EndpointURL, "stream_id="+stream.StreamID) {
		t.Errorf("stream %+v", stream)
	}
	v := f.setVerifier(t)
	if got := pollAll(t, c, v, stream.StreamID); len(got) != 0 {
		t.Fatalf("events before anything happened: %v", got)
	}

	before := time.Now().Unix()
	if _, _, err := f.s.disablePerson("alice@"+idpScope, "left", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := pollAll(t, c, v, stream.StreamID)
	if len(got) != 1 {
		t.Fatalf("%d events after disabling alice", len(got))
	}
	for jti, s := range got {
		ev, ok := s.Events[eventSessionRevoked]
		ids, _ := s.SubID["identifiers"].([]any)
		first, _ := ids[0].(map[string]any)
		if !ok || s.Iss != f.s.cfg.Issuer || s.Aud != "fileshare" || s.Jti != jti || s.Exp != nil || s.Sub != nil ||
			s.SubID["format"] != "aliases" || first["format"] != "account" || first["uri"] != "acct:alice@"+idpScope {
			t.Errorf("SET %+v", s)
		}
		if ts, _ := ev["event_timestamp"].(float64); int64(ts) < before || ev["initiating_entity"] != "admin" {
			t.Errorf("event %v", ev)
		}
	}
	// Still there until acknowledged; then gone.
	if again := pollAll(t, c, v, stream.StreamID); len(again) != 1 {
		t.Errorf("an unacknowledged event went away: %d", len(again))
	}
	var jtis []string
	for j := range got {
		jtis = append(jtis, j)
	}
	ret := true
	if _, err := c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{Ack: jtis, ReturnImmediately: &ret}); err != nil {
		t.Fatal(err)
	}
	if left := pollAll(t, c, v, stream.StreamID); len(left) != 0 {
		t.Errorf("%d events after the acknowledgement", len(left))
	}

	// Another receiver sees neither the stream nor its events.
	other := f.ssfClient(t, "other-ssf")
	if _, err := other.GetConfig(t.Context(), stream.StreamID); err == nil {
		t.Error("another receiver read the stream")
	}
	if _, err := other.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{ReturnImmediately: &ret}); err == nil {
		t.Error("another receiver polled the stream")
	}
}

// go-ssf's own Poller, the receiver side as a library runs it: it verifies
// each SET, hands it to the sink and acknowledges it.
func TestSSFWithGoSSFPoller(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{EventsRequested: []string{eventSessionRevoked}, Delivery: ssf.Delivery{Method: deliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	f.s.revokePerson("alice@" + idpScope)
	var mu sync.Mutex
	var delivered [][]byte
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	p := receiver.NewPoller(stream.Delivery.EndpointURL, f.setVerifier(t), receiver.SinkFunc(func(_ context.Context, payload []byte) error {
		mu.Lock()
		defer mu.Unlock()
		delivered = append(delivered, payload)
		cancel()
		return nil
	}), receiver.WithAuthorizationHeader("Bearer "+f.receiverToken(t, "fileshare-ssf")), receiver.WithNoEventsBackoff(50*time.Millisecond, 200*time.Millisecond))
	p.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != 1 || !strings.Contains(string(delivered[0]), "acct:alice@"+idpScope) {
		t.Fatalf("delivered %q", delivered)
	}
}

// Disabling an institution: one event per person this provider knows of
// there, and one for the tenant with its scopes.
func TestSSFInstitutionDisabled(t *testing.T) {
	f := ssfFixture(t)
	f.deviceToken("rclone", "openid")
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{EventsRequested: []string{eventSessionRevoked}, Delivery: ssf.Delivery{Method: deliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.disableIdP(idpEntity, "compromised", "test", time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := pollAll(t, c, f.setVerifier(t), stream.StreamID)
	var person, tenant bool
	for _, s := range got {
		ev := s.Events[eventSessionRevoked]
		if tn, ok := s.SubID["tenant"].(map[string]any); ok {
			sc, _ := ev["scopes"].([]any)
			tenant = tn["id"] == idpEntity && len(sc) == 1 && sc[0] == idpScope
		} else if strings.Contains(string(mustJSON(s.SubID)), "acct:alice@"+idpScope) {
			person = true
		}
	}
	if !person || !tenant || len(got) != 2 {
		t.Errorf("person %v tenant %v, %d events: %v", person, tenant, len(got), got)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// Events outlive a restart until they are acknowledged; so do streams.
func TestSSFEventsSurviveARestart(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{EventsRequested: []string{eventSessionRevoked}, Delivery: ssf.Delivery{Method: deliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	f.s.revokePerson("alice@" + idpScope)
	f.restart(t)
	c = f.ssfClient(t, "fileshare-ssf")
	if got := pollAll(t, c, f.setVerifier(t), stream.StreamID); len(got) != 1 {
		t.Errorf("%d events after a restart, want the 1 not yet acknowledged", len(got))
	}
}

// Verification (SSF 1.0 8.1.4), status, subjects, update, delete.
func TestSSFStreamManagement(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{EventsRequested: []string{"urn:example:nothing"}, Delivery: ssf.Delivery{Method: deliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.EventsDelivered) != 0 {
		t.Errorf("delivered %v, of nothing it supports", stream.EventsDelivered)
	}
	// Nothing asked for, nothing sent.
	f.s.revokePerson("alice@" + idpScope)
	v := f.setVerifier(t)
	if got := pollAll(t, c, v, stream.StreamID); len(got) != 0 {
		t.Errorf("%d events on a stream that did not ask", len(got))
	}
	up, err := c.UpdateConfig(t.Context(), &ssf.StreamConfig{StreamID: stream.StreamID, EventsRequested: []string{eventSessionRevoked}})
	if err != nil || len(up.EventsDelivered) != 1 {
		t.Fatalf("update: %v %+v", err, up)
	}
	if err := c.Verify(t.Context(), stream.StreamID, &ssf.VerificationRequest{State: "xyz"}); err != nil {
		t.Fatal(err)
	}
	got := pollAll(t, c, v, stream.StreamID)
	found := false
	for _, s := range got {
		if ev, ok := s.Events[eventVerification]; ok && ev["state"] == "xyz" {
			found = true
		}
	}
	if !found {
		t.Errorf("no verification event: %v", got)
	}
	// Paused: nothing queued.
	if st, err := c.UpdateStatus(t.Context(), stream.StreamID, &ssf.StatusUpdateRequest{Status: ssf.StreamStatusPaused}); err != nil || st.Status != ssf.StreamStatusPaused {
		t.Fatalf("pause: %v %+v", err, st)
	}
	if st, _ := c.GetStatus(t.Context(), stream.StreamID, nil); st.Status != ssf.StreamStatusPaused {
		t.Errorf("status %+v", st)
	}
	// Paused: a poll is refused -- an empty 200 would read as "up to date"
	// -- and what happens meanwhile waits for it (SSF 1.0 8.1.1).
	ret := true
	if _, err := c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{ReturnImmediately: &ret}); err == nil {
		t.Error("a paused stream answered a poll")
	}
	f.s.revokePerson("alice@" + idpScope)
	setStatus := func(s ssf.StreamStatus) {
		if _, err := c.UpdateStatus(t.Context(), stream.StreamID, &ssf.StatusUpdateRequest{Status: s}); err != nil {
			t.Fatal(err)
		}
	}
	setStatus(ssf.StreamStatusEnabled)
	var seen []string
	revokedWhilePaused := false
	for j, s := range pollAll(t, c, v, stream.StreamID) {
		seen = append(seen, j)
		revokedWhilePaused = revokedWhilePaused || s.Events[eventSessionRevoked] != nil
	}
	if !revokedWhilePaused {
		t.Error("a revocation made while the stream was paused was lost")
	}
	c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{Ack: seen, ReturnImmediately: &ret})
	// Disabled: refused too, and nothing is kept.
	setStatus(ssf.StreamStatusDisabled)
	if _, err := c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{ReturnImmediately: &ret}); err == nil {
		t.Error("a disabled stream answered a poll")
	}
	f.s.revokePerson("alice@" + idpScope)
	setStatus(ssf.StreamStatusEnabled)
	if got := pollAll(t, c, v, stream.StreamID); len(got) != 0 {
		t.Errorf("%d events kept for a disabled stream", len(got))
	}
	setStatus(ssf.StreamStatusPaused)
	subj, err := subjectid.Parse(json.RawMessage(`{"format":"account","uri":"acct:bob@x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddSubject(t.Context(), stream.StreamID, &ssf.AddSubjectRequest{Subject: subj}); err != nil {
		t.Errorf("add subject: %v", err)
	}
	if err := c.RemoveSubject(t.Context(), stream.StreamID, &ssf.RemoveSubjectRequest{Subject: subj}); err != nil {
		t.Errorf("remove subject: %v", err)
	}
	if list, _, err := c.ListConfig(t.Context(), ""); err != nil || len(list) != 1 {
		t.Errorf("list: %v %d", err, len(list))
	}
	if err := c.DeleteConfig(t.Context(), stream.StreamID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetConfig(t.Context(), stream.StreamID); err == nil {
		t.Error("a deleted stream is still there")
	}
}

// Who may do what: client credentials for an ssf_receiver only, the ssf
// scope only; the SSF endpoints for its tokens only.
func TestSSFRefusals(t *testing.T) {
	f := ssfFixture(t)
	post := func(v url.Values, user, pass string) int {
		req, _ := http.NewRequest("POST", f.s.cfg.Issuer+"/token", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	const secret = "an-ssf-receiver-secret-long-enough"
	if s := post(url.Values{"grant_type": {"client_credentials"}, "client_id": {"rclone"}}, "", ""); s != http.StatusBadRequest {
		t.Errorf("a public client: %d", s)
	}
	if s := post(url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}}, "fileshare-ssf", secret); s != http.StatusBadRequest {
		t.Errorf("another scope: %d", s)
	}
	if s := post(url.Values{"grant_type": {"client_credentials"}}, "fileshare-ssf", "wrong"); s != http.StatusUnauthorized {
		t.Errorf("a wrong secret: %d", s)
	}
	// A person's access token is not a receiver's.
	tok := f.deviceToken("rclone", "openid")
	req, _ := http.NewRequest("GET", f.s.cfg.Issuer+"/ssf/streams", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a person's token on the SSF endpoints: %d", res.StatusCode)
	}
	res, _ = http.Get(f.s.cfg.Issuer + "/ssf/streams")
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d", res.StatusCode)
	}
	// And the configuration names the grant.
	res, _ = http.Get(f.s.cfg.Issuer + "/.well-known/openid-configuration")
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "client_credentials") {
		t.Error("discovery does not list client_credentials")
	}
	_ = base64.RawURLEncoding
}

func TestSSFConfigRefusals(t *testing.T) {
	c := newConf(t)
	dsn := filepath.ToSlash(filepath.Join(c.dir, "dsn"))
	os.WriteFile(dsn, []byte("file:"+filepath.ToSlash(filepath.Join(c.dir, "s.db"))), 0o600)
	state := "state {\ndriver = \"sqlite\"\ndsn_file = \"" + dsn + "\"\n}\n"
	for name, extra := range map[string]string{
		"ssf without state":       "ssf {}\n",
		"a retention that is not": state + "ssf {\nevent_retention = \"soon\"\n}\n",
		"a receiver with no ssf":  state + "client \"r\" {\nsecret_file = \"" + c.secret + "\"\nssf_receiver = true\n}\n",
		"a public receiver":       state + "ssf {}\nclient \"r\" {\nssf_receiver = true\n}\n",
	} {
		if _, err := c.load(t, c.hcl(nil)+extra); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	if _, err := c.load(t, c.hcl(nil)+state+"ssf {}\nclient \"r\" {\nsecret_file = \""+c.secret+"\"\nssf_receiver = true\n}\n"); err != nil {
		t.Errorf("the control: %v", err)
	}
}

// A set error is a report, not an acknowledgement: the event comes back,
// and is dropped only after maxSetErrs reports.
func TestSSFSetErrorsRedeliver(t *testing.T) {
	f := ssfFixture(t)
	c := f.ssfClient(t, "fileshare-ssf")
	stream, err := c.CreateConfig(t.Context(), &ssf.StreamConfig{EventsRequested: []string{eventSessionRevoked}, Delivery: ssf.Delivery{Method: deliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	f.s.revokePerson("alice@" + idpScope)
	v := f.setVerifier(t)
	got := pollAll(t, c, v, stream.StreamID)
	if len(got) != 1 {
		t.Fatalf("%d events", len(got))
	}
	var jti string
	for j := range got {
		jti = j
	}
	ret := true
	report := func() {
		if _, err := c.PollEvents(t.Context(), stream.StreamID, &ssf.PollRequest{
			SetErrs:           map[string]ssf.SetErr{jti: {Err: "invalid_key", Description: "a key rotated inside my refresh window"}},
			ReturnImmediately: &ret,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i < maxSetErrs; i++ {
		report()
		if again := pollAll(t, c, v, stream.StreamID); len(again) != 1 {
			t.Fatalf("after %d reports the event is gone: a passing failure lost a revocation", i)
		}
	}
	report()
	if left := pollAll(t, c, v, stream.StreamID); len(left) != 0 {
		t.Errorf("still handed out after %d reports", maxSetErrs)
	}
}
