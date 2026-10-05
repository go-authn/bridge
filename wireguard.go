package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/go-authn/wireguard"
)

// WireGuard keys.
//
// WireGuard authenticates a peer by its public key and nothing else: no
// certificate, no expiry, no revocation. So this provider keeps the answer
// to "whose is this key, and may it still connect?". A person's VPN client
// registers the public key of its device, here, with a token -- the private
// key never leaves the device -- for a lease it renews by registering again;
// a gateway reads the keys back as a list signed for it alone
// (go-authn/wireguard). The keys are recorded beside the certificates, so
// disabling a person or an institution takes them back as it takes back
// those: the gateway's next list no longer has them, and the SSF event it
// is sent says to fetch that list now.

// listLifetime is how long a signed list is an answer. Short: a gateway
// fetches often, and one that cannot fetch should find itself with no list
// rather than an old one.
const listLifetime = 5 * time.Minute

type keyRequest struct {
	PublicKey string `json:"public_key"`
	Device    string `json:"device,omitempty"`
}

// wireguardKey registers (POST) or takes back (DELETE) the key in the body,
// for the person the token is about.
func (s *server) wireguardKey(w http.ResponseWriter, r *http.Request) {
	wg := s.cfg.WireGuard
	if wg == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	claims, err := s.bearerClaims(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	clientID, _ := claims["client_id"].(string)
	client, ok := s.cfg.client(clientID)
	scope, _ := claims["scope"].(string)
	if !ok || !client.WireGuardKeys || !slices.Contains(strings.Fields(scope), wireguard.ScopeKeys) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="wireguard"`)
		http.Error(w, "this token may not register WireGuard keys", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	user, _ := claims["preferred_username"].(string)
	sub, _ := claims["sub"].(string)
	if user == "" || sub == "" {
		http.Error(w, "the institution released no username to register a key under", http.StatusForbidden)
		return
	}
	if err := certifiableName(user); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var req keyRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "the body is not {\"public_key\": ..., \"device\": ...}", http.StatusBadRequest)
		return
	}
	key, err := wireguard.ParseKey(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := deviceName(req.Device); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jti, _ := claims["jti"].(string)
	it, _ := s.issued.get(jti)
	who := issuedCert{Principal: user, IdP: it.idp}
	now := s.now()

	if r.Method == http.MethodDelete {
		if !s.certs.ownsKey(key.String(), who, now) {
			http.Error(w, "no such key of yours", http.StatusNotFound)
			return
		}
		if err := s.certs.revokeOne("wireguard", key.String(), now); err != nil {
			s.logf("wireguard: taking back a key: %v", err)
			http.Error(w, "the key could not be taken back", http.StatusInternalServerError)
			return
		}
		s.logf("wireguard: %s took back the key %s", user, key)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	until := now.Add(wg.lifetime)
	err = s.certs.registerKey(issuedCert{Kind: "wireguard", Serial: key.String(), KeyID: req.Device, Principal: user, IdP: it.idp, Client: clientID, Sub: sub, NotAfter: until}, wg.MaxKeys, now)
	switch {
	case errors.Is(err, errKeyTaken), errors.Is(err, errKeyRevoked), errors.Is(err, errTooMany):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "refused", "error_description": err.Error()})
		return
	case err != nil:
		s.logf("wireguard: recording a key: %v", err)
		http.Error(w, "the key could not be recorded, so it is not registered", http.StatusInternalServerError)
		return
	}
	// The same race the certificates have: a disabling while this was being
	// recorded takes the key back here, or its revocation already saw it.
	if s.withdrawn(w, jti, user, "wireguard", key.String(), now) {
		return
	}
	s.counters.inc("bridge_wireguard_keys_total", "")
	s.logf("wireguard: registered a key of %s (%q) until %s", user, req.Device, until.UTC().Format(time.RFC3339))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"public_key": key.String(), "device": req.Device, "expires_at": until.Unix()})
}

// deviceName refuses a device name that is not a short, printable label: it
// is shown in logs and on a gateway's console, where a newline or an escape
// sequence is a line or a colour somebody else wrote.
func deviceName(s string) error {
	if len(s) > 64 {
		return errors.New("the device name is longer than 64 bytes")
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return errors.New("the device name holds a character that does not print")
		}
	}
	return nil
}

// wireguardPeers is the list of live keys for a gateway: those registered
// through the clients its own client names, signed for it alone.
func (s *server) wireguardPeers(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WireGuard == nil {
		http.NotFound(w, r)
		return
	}
	claims, err := s.bearerClaims(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	clientID, _ := claims["client_id"].(string)
	client, ok := s.cfg.client(clientID)
	scope, _ := claims["scope"].(string)
	sub, _ := claims["sub"].(string)
	// The gateway's OWN token: its subject is the client. A token a person
	// logged in for is not a gateway's, whatever it carries.
	if !ok || len(client.WireGuardPeers) == 0 || sub != clientID || !slices.Contains(strings.Fields(scope), wireguard.ScopePeers) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="wireguard_peers"`)
		http.Error(w, "this token may not read the WireGuard peers", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	now := s.now()
	keys, version := s.certs.liveKeys(client.WireGuardPeers, now)
	l := wireguard.List{Version: version, IssuedAt: now, Expires: now.Add(listLifetime)}
	for _, c := range keys {
		k, err := wireguard.ParseKey(c.Serial)
		if err != nil {
			// Only ever recorded after ParseKey: a record that does not
			// parse was written by something else, and is not listed.
			s.logf("wireguard: a recorded key that is not one: %v", err)
			continue
		}
		l.Peers = append(l.Peers, wireguard.Peer{Key: k, Subject: c.Sub, Username: c.Principal, Device: c.KeyID, Expires: c.NotAfter})
	}
	jws, err := s.cfg.accessKey.sign(wireguard.ListType, l.Claims(s.cfg.Issuer, client.ID))
	if err != nil {
		http.Error(w, "the list could not be signed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, jws)
}
