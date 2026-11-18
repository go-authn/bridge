// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// private_key_jwt: a confidential client proves who it is by signing a short
// JWT with a private key whose public half is registered in its client block,
// instead of sending a secret (RFC 7523 2.2; OpenID Connect Core 9). Nothing
// the provider holds can impersonate the client, and nothing travels that
// could be replayed later: a machine -- a Windows service nobody logs into --
// keeps a key, not a password.

const (
	// assertionType is client_assertion_type (RFC 7521 4.2, RFC 7523 2.2).
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// maxAssertionLifetime bounds exp (and exp - iat): a captured assertion is
	// usable once, for this long at most.
	maxAssertionLifetime = 5 * time.Minute
	// assertionSkew is the clock difference tolerated, either way.
	assertionSkew = time.Minute
	// maxAssertionBytes is what a client assertion may weigh.
	maxAssertionBytes = 8192
	maxJTIBytes       = 256
	maxClientKeys     = 16
)

// assertionAlgs are the algorithms an assertion may use. HMAC is not here, and
// is not an oversight: it takes a shared secret, which is what this replaces.
// "none" is not one either; go-jose refuses whatever is not listed.
var assertionAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}

// loadClientKeys reads a client's registered keys: a JWK Set (RFC 7517 5),
// inline or from a file. Private keys, symmetric keys, weak keys and
// algorithms outside assertionAlgs are refused here, at load, rather than
// being quietly never matched.
func loadClientKeys(inline, file string) (*jose.JSONWebKeySet, error) {
	raw := []byte(inline)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a JWK Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the JWK Set holds no key")
	}
	if len(set.Keys) > maxClientKeys {
		return nil, fmt.Errorf("%d keys; at most %d", len(set.Keys), maxClientKeys)
	}
	kids := map[string]bool{}
	for i, k := range set.Keys {
		if !k.Valid() {
			return nil, fmt.Errorf("key %d is not a valid JWK", i)
		}
		if !k.IsPublic() {
			return nil, fmt.Errorf("key %d is a PRIVATE key: register the public half only", i)
		}
		if k.Use != "" && k.Use != "sig" {
			return nil, fmt.Errorf("key %d has use=%q; a client key signs", i, k.Use)
		}
		if k.Algorithm != "" && !slices.Contains(assertionAlgs, jose.SignatureAlgorithm(k.Algorithm)) {
			return nil, fmt.Errorf("key %d is for %q; RS256, ES256 and EdDSA are accepted", i, k.Algorithm)
		}
		if k.KeyID != "" {
			if kids[k.KeyID] {
				return nil, fmt.Errorf("kid %q appears twice", k.KeyID)
			}
			kids[k.KeyID] = true
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				return nil, fmt.Errorf("key %d is a %d-bit RSA key; 2048 at least", i, pub.N.BitLen())
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() {
				return nil, fmt.Errorf("key %d is on %s; ES256 is P-256", i, pub.Curve.Params().Name)
			}
		case ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("key %d is a %T; RSA, P-256 and Ed25519 keys only", i, k.Key)
		}
	}
	return &set, nil
}

// authenticateAssertion verifies the client_assertion of a token request and
// says which client signed it. Every refusal is the same answer to the
// caller; the reason goes to the log.
func (s *server) authenticateAssertion(r *http.Request) (*clientBlock, bool) {
	fail := func(format string, a ...any) (*clientBlock, bool) {
		s.logf("token: client assertion refused: "+format, a...)
		return nil, false
	}
	// One way of authenticating at a time (RFC 6749 2.3: MUST NOT use more
	// than one method).
	if _, _, basic := r.BasicAuth(); basic || r.PostForm.Get("client_secret") != "" {
		return fail("sent with another credential")
	}
	if r.PostForm.Get("client_assertion_type") != assertionType {
		return fail("client_assertion_type %q", r.PostForm.Get("client_assertion_type"))
	}
	raw := r.PostForm.Get("client_assertion")
	if raw == "" || len(raw) > maxAssertionBytes {
		return fail("empty or oversize")
	}
	tok, err := jwt.ParseSigned(raw, assertionAlgs)
	if err != nil {
		return fail("%v", err)
	}
	if len(tok.Headers) != 1 {
		return fail("%d signatures", len(tok.Headers))
	}
	// Who claims to have signed it, to find which keys to check it with;
	// nothing read here is believed until the signature holds.
	var peek jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&peek); err != nil {
		return fail("%v", err)
	}
	client, ok := s.cfg.client(peek.Subject)
	if !ok || client.keys == nil {
		return fail("%q is not a client with registered keys", peek.Subject)
	}
	if id := r.PostForm.Get("client_id"); id != "" && id != client.ID {
		return fail("client_id %q, assertion for %q", id, client.ID)
	}
	var claims jwt.Claims
	kid := tok.Headers[0].KeyID
	var verified bool
	for _, k := range client.keys.Keys {
		if kid != "" && k.KeyID != kid {
			continue
		}
		// The key decides what its algorithm is as much as the header does:
		// a key of another kind makes Claims fail.
		if k.Algorithm != "" && k.Algorithm != tok.Headers[0].Algorithm {
			continue
		}
		if tok.Claims(k, &claims) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fail("no registered key of %q verifies it", client.ID)
	}
	now := s.now()
	if claims.Issuer != client.ID || claims.Subject != client.ID {
		return fail("iss and sub must both be the client ID")
	}
	endpoint := s.cfg.Issuer + "/token"
	if !claims.Audience.Contains(endpoint) && !claims.Audience.Contains(s.cfg.Issuer) {
		return fail("aud %v is neither the token endpoint nor the issuer", []string(claims.Audience))
	}
	if claims.Expiry == nil {
		return fail("no exp")
	}
	exp := claims.Expiry.Time()
	if !now.Before(exp.Add(assertionSkew)) {
		return fail("expired")
	}
	if exp.After(now.Add(maxAssertionLifetime + assertionSkew)) {
		return fail("exp is more than %s away", maxAssertionLifetime)
	}
	if claims.IssuedAt != nil {
		iat := claims.IssuedAt.Time()
		if iat.After(now.Add(assertionSkew)) || exp.Sub(iat) > maxAssertionLifetime+assertionSkew {
			return fail("iat out of range")
		}
	}
	if claims.NotBefore != nil && claims.NotBefore.Time().After(now.Add(assertionSkew)) {
		return fail("not yet valid")
	}
	if claims.ID == "" || len(claims.ID) > maxJTIBytes {
		return fail("jti missing or oversize")
	}
	// Single use (RFC 7523 3: the provider MAY reject a JWT whose jti it has
	// seen; a token endpoint that does not lets a captured assertion buy
	// tokens for the rest of its life). Not evicting: a full cache refuses
	// rather than forgets, or filling it would be a way to replay.
	if err := s.assertionJTIs.putNew(client.ID+"\x00"+claims.ID, true, exp.Add(assertionSkew)); err != nil {
		return fail("jti replayed or the replay cache is full (%v)", err)
	}
	return client, true
}

// machineScope is the scope of a machine identity's client_credentials token.
const machineScope = "machine"

// hasKeyClients says whether any client authenticates with a key.
func (c *config) hasKeyClients() bool {
	for i := range c.Clients {
		if c.Clients[i].keys != nil {
			return true
		}
	}
	return false
}
