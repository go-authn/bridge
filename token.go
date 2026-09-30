// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// A code verifier is 43 to 128 unreserved characters (RFC 7636 4.1).
var codeVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// tokenError answers the token endpoint with an OAuth error (RFC 6749 5.2).
func tokenError(w http.ResponseWriter, status int, code, desc string) {
	if code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 5.1: tokens are not to be cached by anybody.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// authenticateClient says which client is asking, from HTTP Basic or the
// form, and checks its secret (OIDC Core 9: client_secret_basic,
// client_secret_post).
//
// A public client sends only its ID, and one that sends a secret anyway is
// refused rather than ignored: it is configured as something it is not.
func (s *server) authenticateClient(r *http.Request) (*clientBlock, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 2.3.1: the Basic credentials are form-encoded first.
		var err1, err2 error
		id, err1 = urlUnescape(id)
		secret, err2 = urlUnescape(secret)
		if err1 != nil || err2 != nil || r.PostForm.Get("client_secret") != "" {
			return nil, false
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, ok := s.cfg.client(id)
	if !ok {
		return nil, false
	}
	if c.public() {
		return c, secret == ""
	}
	return c, subtle.ConstantTimeCompare([]byte(secret), []byte(c.secret)) == 1
}

// token is the token endpoint (OIDC Core 3.1.3).
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "the request could not be read")
		return
	}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			tokenError(w, http.StatusBadRequest, "invalid_request", k+" appears more than once")
			return
		}
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, client)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.pollDevice(w, r, client)
	case "refresh_token":
		s.rotate(w, r, client)
	case "client_credentials":
		s.clientCredentials(w, r, client)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *server) exchangeCode(w http.ResponseWriter, r *http.Request, client *clientBlock) {
	code := r.PostForm.Get("code")
	g, ok := s.codes.take(code)
	if !ok {
		// ⛔ A code used twice: somebody else has it too. RFC 6749 4.1.2 --
		// deny, and take back the tokens the first use bought, because one
		// of the two users of this code was not the client.
		if jtis, spent := s.spent.take(code); spent {
			for _, j := range jtis {
				s.issued.take(j)
			}
			s.logf("token: a code was used twice by %s; its tokens are revoked", client.ID)
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is not valid")
		return
	}
	// The code is bound to the client it was issued to, the redirect URI it
	// was sent to, and the PKCE challenge it was asked with.
	if g.client.ID != client.ID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	}
	if r.PostForm.Get("redirect_uri") != g.redirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	v := r.PostForm.Get("code_verifier")
	if !codeVerifier.MatchString(v) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is missing or malformed")
		return
	}
	sum := sha256.Sum256([]byte(v))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(g.challenge)) != 1 {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}
	resp, jti, err := s.issue(client, g.who, g.scopes, g.nonce)
	if err != nil {
		s.logf("token: %v", err)
		if errors.Is(err, errDisabled) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "access has been disabled")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.spent.put(code, []string{jti}, s.now().Add(s.cfg.tokenTTL))
	s.counters.inc("bridge_tokens_issued_total", "authorization_code")
	if rt := s.newRefresh(client, g.who, g.scopes, jti); rt != "" {
		resp["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, resp)
}

// issue makes an access token and an ID token for who, for client.
func (s *server) issue(client *clientBlock, who *person, scopes []string, nonce string) (map[string]any, string, error) {
	if why := s.refused(who); why != "" {
		return nil, "", fmt.Errorf("%w: %s (%s via %s)", errDisabled, why, orUnnamed(who.username), who.idp)
	}
	now := s.now()
	sub := who.sub(s.cfg.salt, client)
	jti := token()

	// The access token is for the RESOURCE servers named in the client's
	// audience -- go-fileshare, say -- and says what they need to decide:
	// who (preferred_username), and in which groups. RFC 9068.
	at := map[string]any{
		"iss":       s.cfg.Issuer,
		"sub":       sub,
		"aud":       audience(client.Audience),
		"client_id": client.ID,
		"exp":       now.Add(s.cfg.tokenTTL).Unix(),
		"iat":       now.Unix(),
		"jti":       jti,
		"scope":     strings.Join(scopes, " "),
		"auth_time": who.authTime.Unix(),
	}
	if who.acr != "" {
		at["acr"] = who.acr
	}
	if who.username != "" {
		at["preferred_username"] = who.username
	}
	if len(who.groups) > 0 {
		at["groups"] = who.groups
	}
	// When the IdP said its session ends, the token carries it, so that what
	// is derived from the token -- an SSH certificate -- does not outlive it.
	if !who.sessionEnd.IsZero() {
		at["session_end"] = who.sessionEnd.Unix()
	}
	access, err := s.cfg.accessKey.sign("at+jwt", at)
	if err != nil {
		return nil, "", err
	}

	info := who.claimsFor(scopes)
	info["sub"] = sub
	s.issued.put(jti, issuedToken{info: info, username: who.username, idp: who.idp}, now.Add(s.cfg.tokenTTL))

	// The ID token is for the CLIENT: aud is its ID, and it carries the
	// nonce back (OIDC Core 2, 3.1.3.6).
	id := map[string]any{
		"iss":       s.cfg.Issuer,
		"sub":       sub,
		"aud":       client.ID,
		"exp":       now.Add(s.cfg.idTokenTTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": who.authTime.Unix(),
		"at_hash":   halfHash(access),
	}
	if nonce != "" {
		id["nonce"] = nonce
	}
	if who.acr != "" {
		id["acr"] = who.acr
	}
	for k, v := range info {
		id[k] = v
	}
	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.tokenTTL.Seconds()),
		"scope":        strings.Join(scopes, " "),
	}
	// An ID token only for an OpenID Connect request: a device client such
	// as rclone may ask for plain OAuth, and gets an access token alone.
	if slices.Contains(scopes, "openid") {
		if resp["id_token"], err = s.cfg.signingKey.sign("JWT", id); err != nil {
			return nil, "", err
		}
	}
	return resp, jti, nil
}

// halfHash is at_hash: the left half of the SHA-256 of the token, base64url
// (OIDC Core 3.1.3.6).
func halfHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// userinfo answers with the claims an access token's scopes release (OIDC
// Core 5.3).
func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		http.Error(w, "a bearer token is required", http.StatusUnauthorized)
		return
	}
	claims, err := s.cfg.accessKey.verify("at+jwt", strings.TrimSpace(raw))
	var info map[string]any
	if err == nil {
		jti, _ := claims["jti"].(string)
		var it issuedToken
		it, ok = s.issued.get(jti)
		info = it.info
		if !ok {
			err = errRevoked
		}
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// audience is "aud" as a string when there is one, a list otherwise (RFC
// 7519 4.1.3 allows either). One string is what most tokens carry, and
// what some verifiers compare against: mccli, the KIT ssh-oidc client,
// tests `token_audience != audience` as strings (mccli init_utils.py), so
// a one-element list never matches there.
func audience(aud []string) any {
	if len(aud) == 1 {
		return aud[0]
	}
	return aud
}
