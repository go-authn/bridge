// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// A Shared Signals transmitter (OpenID SSF 1.0, CAEP 1.0): what reaches a
// resource server that verifies this provider's tokens on its own, when
// somebody is disabled here.
//
// An access token, an opkssh PK Token, an SSH or X.509 certificate is
// checked where it is used, against keys, and nothing brings it back here.
// The KRL and the CRL cover the certificates this provider issued; nothing
// covers a token until it expires, nor an opkssh certificate, which its
// holder signs. So on DisablePerson, RevokePerson and DisableIdP this
// provider says so, as a CAEP session-revoked event -- "everything issued
// to this subject before event_timestamp is void" -- and a receiver such as
// go-fileshare refuses accordingly.
//
// Delivery is poll only (RFC 8936): the receiver asks, nothing here dials
// out. Streams and undelivered events are in the state database, and SSF
// is refused without one: a revocation a restart empties from the queue is
// one the receiver never hears of.
//
// The events are SETs (RFC 8417) signed with the ID token key, typ
// secevent+jwt, with no exp and no sub (SSF 1.0 4.1). The subject is
// "aliases" with the account (acct:<username>, what the tokens and
// certificates name) -- not iss_sub: a sub here may be pairwise, one per
// client, and no single value is right for every client. An institution
// disabled is also one event whose subject is the tenant, its entity ID,
// with the institution's scopes: its people this provider has no trace of
// (an opkssh token long expired from memory) are covered by their domain.
//
// HTTP, wire types and handlers are github.com/hstern/go-ssf's.

const (
	eventSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	eventVerification   = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	deliveryPoll        = "urn:ietf:rfc:8936"
	ssfPrefix           = "/ssf"
)

// ssfBlock turns the transmitter on.
type ssfBlock struct {
	// EventRetention is how long an event nobody has polled is kept:
	// 192h by default, longer than the longest certificate (168h) and
	// opkssh's longest PK Token (a week).
	EventRetention string `hcl:"event_retention,optional"`

	retention time.Duration
}

func (b *ssfBlock) check(c *config) error {
	if c.State == nil {
		return errors.New("needs a state block: a queue a restart empties loses revocations")
	}
	b.retention = 192 * time.Hour
	if b.EventRetention != "" {
		d, err := time.ParseDuration(b.EventRetention)
		if err != nil || d <= 0 {
			return fmt.Errorf("event_retention = %q: a positive duration like \"192h\"", b.EventRetention)
		}
		b.retention = d
	}
	return nil
}

// storedStream is a stream, with the client it belongs to.
type storedStream struct {
	Owner  string            `json:"owner"`
	Config *ssf.StreamConfig `json:"config"`
	Status ssf.StreamStatus  `json:"status"`
	Reason string            `json:"reason,omitempty"`
}

// A far end for what does not expire by itself: a stream lives until it
// is deleted.
var never = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

type ctxKey struct{}

// ssfTx is the transmitter: go-ssf's interface over this provider's
// state.
type ssfTx struct {
	transmitter.NotImplementedTransmitter
	s *server
}

func (t *ssfTx) owner(ctx context.Context) string {
	c, _ := ctx.Value(ctxKey{}).(string)
	return c
}

// stream is the caller's stream by ID.
func (t *ssfTx) stream(ctx context.Context, id string) (storedStream, error) {
	st, ok := t.s.ssfStreams.get(id)
	if !ok || st.Owner != t.owner(ctx) {
		return storedStream{}, ssf.ErrStreamNotFound
	}
	return st, nil
}

func (t *ssfTx) GetConfig(ctx context.Context, id string) (*ssf.StreamConfig, error) {
	st, err := t.stream(ctx, id)
	return st.Config, err
}

func (t *ssfTx) ListConfig(ctx context.Context, _ string) ([]*ssf.StreamConfig, string, error) {
	var out []*ssf.StreamConfig
	t.s.ssfStreams.each(func(_ string, st storedStream) {
		if st.Owner == t.owner(ctx) {
			out = append(out, st.Config)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].StreamID < out[j].StreamID })
	return out, "", nil
}

func (t *ssfTx) CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	s, owner := t.s, t.owner(ctx)
	// A few streams per receiver: each is a copy of every revocation.
	owned := 0
	s.ssfStreams.each(func(_ string, st storedStream) {
		if st.Owner == owner {
			owned++
		}
	})
	if owned >= maxStreamsPerReceiver {
		return nil, &ssf.ValidationError{Reason: fmt.Sprintf("a receiver has at most %d streams", maxStreamsPerReceiver), Rule: "streams_per_receiver"}
	}
	client, _ := s.cfg.client(owner)
	if cfg.Delivery.Method != "" && cfg.Delivery.Method != deliveryPoll {
		return nil, ssf.ErrUnsupportedDelivery
	}
	id := token()[:22]
	out := &ssf.StreamConfig{
		StreamID:        id,
		Iss:             s.cfg.Issuer,
		Aud:             streamAudience(cfg.Aud, client),
		EventsSupported: []string{eventSessionRevoked},
		EventsRequested: cfg.EventsRequested,
		Delivery:        ssf.Delivery{Method: deliveryPoll, EndpointURL: s.cfg.Issuer + ssfPrefix + transmitter.DefaultPollPath + "?stream_id=" + id},
	}
	for _, e := range cfg.EventsRequested {
		if e == eventSessionRevoked {
			out.EventsDelivered = []string{eventSessionRevoked}
		}
	}
	s.ssfStreams.put(id, storedStream{Owner: owner, Config: out, Status: ssf.StreamStatusEnabled}, never)
	s.logf("ssf: %s created stream %s for %s", owner, id, strings.Join(out.EventsDelivered, " "))
	return out, nil
}

// streamAudience is the audience a stream's events carry: what the
// receiver asked for when it is one of its client's audiences, else those.
func streamAudience(asked json.RawMessage, client *clientBlock) json.RawMessage {
	var one string
	var many []string
	if json.Unmarshal(asked, &one) == nil && slices.Contains(client.Audience, one) {
		return asked
	}
	if json.Unmarshal(asked, &many) == nil && len(many) > 0 {
		ok := true
		for _, a := range many {
			ok = ok && slices.Contains(client.Audience, a)
		}
		if ok {
			return asked
		}
	}
	b, _ := json.Marshal(audience(client.Audience))
	return b
}

func (t *ssfTx) UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	st, err := t.stream(ctx, cfg.StreamID)
	if err != nil {
		return nil, err
	}
	// What a receiver may change is what it wants delivered.
	if len(cfg.EventsRequested) > 0 {
		st.Config.EventsRequested = cfg.EventsRequested
		st.Config.EventsDelivered = nil
		if slices.Contains(cfg.EventsRequested, eventSessionRevoked) {
			st.Config.EventsDelivered = []string{eventSessionRevoked}
		}
	}
	t.s.ssfStreams.put(cfg.StreamID, st, never)
	return st.Config, nil
}

func (t *ssfTx) DeleteConfig(ctx context.Context, id string) error {
	if _, err := t.stream(ctx, id); err != nil {
		return err
	}
	t.s.ssfStreams.take(id)
	var keys []string
	t.s.ssfEvents.each(func(k string, _ string) {
		if strings.HasPrefix(k, id+"/") {
			keys = append(keys, k)
		}
	})
	for _, k := range keys {
		t.s.ssfEvents.take(k)
	}
	t.s.logf("ssf: %s deleted stream %s", t.owner(ctx), id)
	return nil
}

func (t *ssfTx) GetStatus(ctx context.Context, id string, _ json.RawMessage) (*ssf.StatusResponse, error) {
	st, err := t.stream(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ssf.StatusResponse{Status: st.Status, Reason: st.Reason}, nil
}

func (t *ssfTx) UpdateStatus(ctx context.Context, id string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	st, err := t.stream(ctx, id)
	if err != nil {
		return nil, err
	}
	switch req.Status {
	case ssf.StreamStatusEnabled, ssf.StreamStatusPaused, ssf.StreamStatusDisabled:
	default:
		return nil, ssf.ErrInvalidConfig
	}
	st.Status, st.Reason = req.Status, req.Reason
	t.s.ssfStreams.put(id, st, never)
	return &ssf.StatusResponse{Status: st.Status, Reason: st.Reason}, nil
}

// Every subject is delivered: this provider sends revocations for all its
// people, and a receiver keeps what it recognises. Adding or removing one
// is accepted and changes nothing (SSF 1.0 9.1 lets a transmitter decide).
func (t *ssfTx) AddSubject(ctx context.Context, id string, _ *ssf.AddSubjectRequest) error {
	_, err := t.stream(ctx, id)
	return err
}

func (t *ssfTx) RemoveSubject(ctx context.Context, id string, _ *ssf.RemoveSubjectRequest) error {
	_, err := t.stream(ctx, id)
	return err
}

func (t *ssfTx) Verify(ctx context.Context, id string, req *ssf.VerificationRequest) error {
	st, err := t.stream(ctx, id)
	if err != nil {
		return err
	}
	ev := map[string]any{}
	if req.State != "" {
		ev["state"] = req.State
	}
	// One verification waiting per stream: a newer one replaces it, so a
	// receiver asking in a loop does not fill the queue.
	verifyMu.Lock()
	if old, ok := pendingVerify[id]; ok {
		t.s.ssfEvents.take(old)
	}
	verifyMu.Unlock()
	// SSF 1.0 8.1.4.1: a verification event's subject is the stream.
	key, err := t.s.enqueueKey(id, st.Config, map[string]any{"format": "opaque", "id": id}, eventVerification, ev)
	if err == nil {
		verifyMu.Lock()
		pendingVerify[id] = key
		verifyMu.Unlock()
	}
	return err
}

// PollEvents acknowledges what the receiver says it has, and hands it what
// is waiting, oldest first. It answers at once, events or not (RFC 8936
// 2.4 lets a transmitter).
func (t *ssfTx) PollEvents(ctx context.Context, id string, req *ssf.PollRequest) (*ssf.PollResponse, error) {
	st, err := t.stream(ctx, id)
	if err != nil {
		return nil, err
	}
	// ⛔ A stream that is not enabled answers an error, not an empty 200: a
	// receiver that counts a 200 as "heard" would believe itself up to date
	// while nothing reaches it -- failing open. Paused, its events are kept
	// for when it is enabled again (SSF 1.0 8.1.1); disabled, none are made.
	if st.Status != ssf.StreamStatusEnabled {
		return nil, &ssf.ValidationError{Reason: "the stream is " + string(st.Status) + "; nothing is delivered until it is enabled", Rule: "stream_status", Field: "status"}
	}
	for _, jti := range req.Ack {
		t.s.ssfEvents.take(id + "/" + jti)
		t.s.forgetSetErrs(id + "/" + jti)
	}
	// ⛔ A set error is a report, not an acknowledgement (RFC 8936 2.4 lets
	// a receiver report; nothing asks the transmitter to discard). Its causes
	// are often passing -- a key rotated inside the receiver's key set
	// refresh, a full disk -- so the event is kept and handed out again, and
	// dropped only after maxSetErrs reports, or at event_retention.
	for jti, e := range req.SetErrs {
		key := id + "/" + jti
		// Only an event that is there is counted: a receiver naming jtis
		// that never were would grow the count without end.
		if _, there := t.s.ssfEvents.get(key); !there {
			continue
		}
		n := t.s.countSetErr(key)
		t.s.logf("ssf: stream %s: %s refused %s (%d of %d): %s %s", id, t.owner(ctx), jti, n, maxSetErrs, e.Err, e.Description)
		if n >= maxSetErrs {
			t.s.logf("ssf: stream %s: dropping %s after %d refusals", id, jti, n)
			t.s.ssfEvents.take(key)
			t.s.forgetSetErrs(key)
		}
	}
	max := 100
	if req.MaxEvents != nil && *req.MaxEvents >= 0 {
		max = *req.MaxEvents
	}
	type waiting struct{ jti, set, key string }
	var all []waiting
	t.s.ssfEvents.each(func(k string, set string) {
		if jti, ok := strings.CutPrefix(k, id+"/"); ok {
			all = append(all, waiting{jti, set, k})
		}
	})
	// The key holds the time it was queued first: oldest first.
	sort.Slice(all, func(i, j int) bool { return all[i].jti < all[j].jti })
	resp := &ssf.PollResponse{Sets: map[string]string{}}
	for i, w := range all {
		if i >= max {
			more := true
			resp.MoreAvailable = &more
			break
		}
		resp.Sets[w.jti] = w.set
	}
	return resp, nil
}

// enqueue signs an event for one stream and keeps it until it is polled.
func (s *server) enqueue(streamID string, cfg *ssf.StreamConfig, subject map[string]any, event string, body map[string]any) error {
	_, err := s.enqueueKey(streamID, cfg, subject, event, body)
	return err
}

// enqueueKey is enqueue, saying under which key the event is kept.
func (s *server) enqueueKey(streamID string, cfg *ssf.StreamConfig, subject map[string]any, event string, body map[string]any) (string, error) {
	now := s.now()
	// The jti begins with the time, so that the queue sorts oldest first.
	jti := fmt.Sprintf("%016x-%s", now.UnixNano(), token()[:16])
	claims := map[string]any{
		"iss":    s.cfg.Issuer,
		"jti":    jti,
		"iat":    now.Unix(),
		"aud":    cfg.Aud,
		"sub_id": subject,
		"events": map[string]any{event: body},
	}
	set, err := s.cfg.signingKey.sign(ssf.SETMediaType, claims)
	if err != nil {
		return "", err
	}
	key := streamID + "/" + jti
	s.ssfEvents.put(key, set, now.Add(s.cfg.SSF.retention))
	return key, nil
}

// broadcast sends a session-revoked to every stream that asked for it.
func (s *server) broadcast(subjectsFor func(owner string) []map[string]any, at time.Time, reason string, extra map[string]any) {
	if s.cfg.SSF == nil {
		return
	}
	body := map[string]any{
		"event_timestamp":   at.Unix(),
		"initiating_entity": "admin",
	}
	// CAEP Interoperability Profile 3.1: reason_admin "MUST be populated
	// with a non-empty object" -- an operator who gave no reason still
	// revoked something.
	if reason == "" {
		reason = "revoked by an operator of the provider"
	}
	body["reason_admin"] = map[string]string{"en": reason}
	for k, v := range extra {
		body[k] = v
	}
	type target struct {
		id    string
		owner string
		cfg   *ssf.StreamConfig
	}
	var targets []target
	s.ssfStreams.each(func(id string, st storedStream) {
		// Paused streams too: their events wait until they are enabled.
		if st.Status != ssf.StreamStatusDisabled && slices.Contains(st.Config.EventsDelivered, eventSessionRevoked) {
			targets = append(targets, target{id, st.Owner, st.Config})
		}
	})
	for _, tg := range targets {
		for _, subject := range subjectsFor(tg.owner) {
			if err := s.enqueue(tg.id, tg.cfg, subject, eventSessionRevoked, body); err != nil {
				s.logf("ssf: stream %s: %v", tg.id, err)
			}
		}
	}
	if len(targets) > 0 {
		s.logf("ssf: session-revoked on %d streams", len(targets))
	}
}

// personSubjects names a person for each receiver as it asked
// (ssf_subject_format): their account for "aliases"; for "iss_sub", the
// issuer and the public sub of each stable identity known under them --
// and, when none is known, their account anyway: a revocation that does not
// arrive fails open, and one in an unexpected format still says who.
func (s *server) personSubjects(username string, subjects []string) func(owner string) []map[string]any {
	return func(owner string) []map[string]any {
		c, ok := s.cfg.client(owner)
		if !ok || c.SSFSubjectFormat != "iss_sub" || len(subjects) == 0 {
			var out []map[string]any
			for _, u := range s.spellingsOf(username) {
				out = append(out, accountSubject(u))
			}
			return out
		}
		public := &clientBlock{Subject: "public"}
		out := make([]map[string]any, 0, len(subjects))
		for _, sj := range subjects {
			out = append(out, map[string]any{"format": "iss_sub", "iss": s.cfg.Issuer, "sub": (&person{subject: sj}).sub(s.cfg.salt, public)})
		}
		return out
	}
}

// only is one subject for every receiver.
func only(subject map[string]any) func(string) []map[string]any {
	return func(string) []map[string]any { return []map[string]any{subject} }
}

// accountSubject is a person as "aliases" with their account.
func accountSubject(username string) map[string]any {
	return map[string]any{
		"format":      "aliases",
		"identifiers": []map[string]any{{"format": "account", "uri": "acct:" + username}},
	}
}

// peopleOf is every username this provider has a trace of for an IdP:
// refresh families, honoured tokens, certificates, application passwords.
func (s *server) peopleOf(entityID string) []string {
	seen := map[string]bool{}
	s.refresh.each(func(_ string, g *refreshGrant) {
		if g.who.idp == entityID && g.who.username != "" {
			seen[g.who.username] = true
		}
	})
	s.issued.each(func(_ string, it issuedToken) {
		if it.idp == entityID && it.username != "" {
			seen[it.username] = true
		}
	})
	s.certs.mu.Lock()
	for _, c := range s.certs.Certs {
		if c.IdP == entityID && c.Principal != "" {
			seen[c.Principal] = true
		}
	}
	s.certs.mu.Unlock()
	if ap := s.cfg.AppPasswords; ap != nil {
		if rows, err := ap.db.Query(`SELECT login FROM `+ap.Table+` WHERE idp = `+ap.arg(1), entityID); err == nil {
			for rows.Next() {
				var l string
				if rows.Scan(&l) == nil {
					seen[l] = true
				}
			}
			rows.Close()
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// ssfAuthenticate is who is asking, for the SSF endpoints: an access token
// of this provider, from client credentials, with the ssf scope, for a
// client that is an ssf_receiver. The client ID goes into the context: a
// stream belongs to the client that made it.
func (s *server) ssfAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.bearerClaims(r)
		if err == nil {
			clientID, _ := claims["client_id"].(string)
			scope, _ := claims["scope"].(string)
			c, ok := s.cfg.client(clientID)
			sub, _ := claims["sub"].(string)
			// A client credentials token: its subject is the client. A token a
			// person logged in for is not a receiver's, whatever it carries.
			if !ok || !c.SSFReceiver || sub != clientID || !slices.Contains(strings.Fields(scope), "ssf") {
				err = errors.New("not an SSF receiver")
			} else {
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, clientID))
			}
		}
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			transmitter.Default401Handler(ssf.ErrUnauthorized).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ssfHandlers are the transmitter's endpoints and its configuration.
func (s *server) ssfHandlers(mux *http.ServeMux) {
	if s.cfg.SSF == nil {
		return
	}
	tx := &ssfTx{s: s}
	// Authentication is done before go-ssf's handlers, which then allow
	// what reached them; the stream is checked against its owner in tx.
	api := s.ssfAuthenticate(http.StripPrefix(ssfPrefix, noContentWhereSSFSaysSo(transmitter.MuxHandler(tx, transmitter.AlwaysAllow))))
	mux.Handle(ssfPrefix+"/", api)
	i := s.cfg.Issuer + ssfPrefix
	schemes, _ := json.Marshal([]map[string]string{{"spec_urn": "urn:ietf:rfc:6749"}})
	mux.Handle("GET "+transmitter.WellKnownPath, transmitter.WellKnownHandler(&ssf.TransmitterConfig{
		Issuer:                   s.cfg.Issuer,
		JWKSURI:                  s.cfg.Issuer + "/jwks",
		DeliveryMethodsSupported: []string{deliveryPoll},
		ConfigurationEndpoint:    i + transmitter.DefaultStreamsPath,
		StatusEndpoint:           i + transmitter.DefaultStatusPath,
		AddSubjectEndpoint:       i + transmitter.DefaultAddSubjectPath,
		RemoveSubjectEndpoint:    i + transmitter.DefaultRemoveSubjectPath,
		VerificationEndpoint:     i + transmitter.DefaultVerificationPath,
		// "1_0", the specs' own notation (SSF 1.0 7.1; CAEP Interop 2.3.1: "MUST
		// be 1_0 or greater"). go-ssf's SpecVersion is "1.0", which the OpenID
		// Foundation's suite rightly refuses.
		SpecVersion:          "1_0",
		AuthorizationSchemes: schemes,
	}))
}

// clientCredentials is the client_credentials grant (RFC 6749 4.4), for
// an SSF receiver and nothing else: a token for the ssf scope, its subject
// the client (RFC 9068 2.2), no refresh token.
func (s *server) clientCredentials(w http.ResponseWriter, r *http.Request, client *clientBlock) {
	// What a client's own credentials may buy: the SSF transmitter for a
	// receiver, the WireGuard list for a gateway. Nothing for a person.
	var allowed []string
	if !client.public() && client.SSFReceiver && s.cfg.SSF != nil {
		allowed = append(allowed, "ssf")
	}
	if !client.public() && len(client.WireGuardPeers) > 0 && s.cfg.WireGuard != nil {
		allowed = append(allowed, "wireguard_peers")
	}
	if len(allowed) == 0 {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "this client may not use the client_credentials grant")
		return
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	if len(scopes) == 0 {
		scopes = allowed
	}
	for _, sc := range scopes {
		if !slices.Contains(allowed, sc) {
			tokenError(w, http.StatusBadRequest, "invalid_scope", "this client's credentials are for "+strings.Join(allowed, " ")+" only")
			return
		}
	}
	scope := strings.Join(scopes, " ")
	now := s.now()
	jti := token()
	at := map[string]any{
		"iss": s.cfg.Issuer, "sub": client.ID, "aud": s.accessAudience(client, scopes), "client_id": client.ID,
		"exp": now.Add(s.cfg.tokenTTL).Unix(), "iat": now.Unix(), "jti": jti, "scope": scope,
	}
	access, err := s.cfg.accessKey.sign("at+jwt", at)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.issued.put(jti, issuedToken{info: map[string]any{"sub": client.ID}}, now.Add(s.cfg.tokenTTL))
	s.counters.inc("bridge_tokens_issued_total", "client_credentials")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(s.cfg.tokenTTL.Seconds()), "scope": scope,
	})
}

// maxSetErrs is how many times a receiver may report an event in error
// before it is dropped.
const maxSetErrs = 10

// setErrs counts the reports per event. In memory: a restart hands the
// event out again from zero, which errs on the side of delivering.
var (
	setErrsMu sync.Mutex
	setErrs   = map[string]int{}
)

func (s *server) countSetErr(key string) int {
	setErrsMu.Lock()
	defer setErrsMu.Unlock()
	setErrs[key]++
	return setErrs[key]
}

func (s *server) forgetSetErrs(key string) {
	setErrsMu.Lock()
	defer setErrsMu.Unlock()
	delete(setErrs, key)
}

// maxStreamsPerReceiver is how many streams one receiver may hold.
const maxStreamsPerReceiver = 10

// pendingVerify is the verification event waiting on each stream.
var (
	verifyMu      sync.Mutex
	pendingVerify = map[string]string{}
)

// noContentWhereSSFSaysSo makes go-ssf v0.1.1 answer as SSF 1.0 says.
//
// The stream: SSF 1.0 puts stream_id in the JSON BODY of a verification
// request (8.1.4.2) and of a subject added or removed (8.1.3.2, 8.1.3.3);
// go-ssf reads it from the query only, and answered a request as the spec
// writes it 400 "stream_id query parameter is required" -- every receiver
// that follows the spec, the OpenID Foundation's among them. The body's
// stream_id is copied into the query when the query has none.
//
// The answer: 204 No Content where SSF 1.0 says the
// transmitter answers with an empty 204 -- a verification request (8.1.4.2)
// and a subject removed (8.1.3.3) -- and go-ssf v0.1.1 answers 200 with an
// empty JSON object. The OpenID Foundation's CAEP Interop transmitter plan
// failed four modules on it. go-ssf's own client takes any 2xx.
func noContentWhereSSFSaysSo(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == transmitter.DefaultVerificationPath ||
			r.URL.Path == transmitter.DefaultAddSubjectPath || r.URL.Path == transmitter.DefaultRemoveSubjectPath) {
			streamFromBody(r)
		}
		if r.Method == http.MethodPost && (r.URL.Path == transmitter.DefaultVerificationPath || r.URL.Path == transmitter.DefaultRemoveSubjectPath) {
			w = &noContent{ResponseWriter: w}
		}
		h.ServeHTTP(w, r)
	})
}

// noContent turns a 200 into a 204 and drops its body; any other status
// passes untouched, body and all.
type noContent struct {
	http.ResponseWriter
	ok, decided bool
}

func (n *noContent) WriteHeader(code int) {
	if n.decided {
		return
	}
	n.decided = true
	if code == http.StatusOK {
		n.ok = true
		n.ResponseWriter.Header().Del("Content-Type")
		n.ResponseWriter.Header().Del("Content-Length")
		code = http.StatusNoContent
	}
	n.ResponseWriter.WriteHeader(code)
}

func (n *noContent) Write(b []byte) (int, error) {
	if !n.decided {
		n.WriteHeader(http.StatusOK)
	}
	if n.ok {
		return len(b), nil
	}
	return n.ResponseWriter.Write(b)
}

// streamFromBody copies the body's stream_id into the query, where go-ssf
// looks for it, unless the query already names one. The body is read once,
// within the server's limit, and handed on whole.
func streamFromBody(r *http.Request) {
	if r.URL.Query().Has("stream_id") || r.Body == nil {
		return
	}
	b, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil {
		return
	}
	var req struct {
		StreamID string `json:"stream_id"`
	}
	if json.Unmarshal(b, &req) != nil || req.StreamID == "" {
		return
	}
	q := r.URL.Query()
	q.Set("stream_id", req.StreamID)
	r.URL.RawQuery = q.Encode()
}

// spellingsOf is every way the person called username, without case, is
// written in what this provider handed out -- refresh families, honoured
// tokens, certificates -- and the name itself. An account subject is
// compared exactly by a receiver (go-fileshare's is), and the token it
// holds says "Alice@..." if the IdP wrote that, whatever case an operator
// typed: one event per spelling, so that each is revoked.
func (s *server) spellingsOf(username string) []string {
	if username == "" {
		return nil
	}
	seen := map[string]bool{username: true}
	add := func(u string) {
		if u != "" && strings.EqualFold(u, username) {
			seen[u] = true
		}
	}
	s.refresh.each(func(_ string, g *refreshGrant) { add(g.who.username) })
	s.issued.each(func(_ string, it issuedToken) { add(it.username) })
	s.certs.mu.Lock()
	for _, c := range s.certs.Certs {
		add(c.Principal)
	}
	s.certs.mu.Unlock()
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}
