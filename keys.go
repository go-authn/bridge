// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// signingKey is the RSA key tokens are signed with.
//
// RS256 and nothing else: OpenID Connect Discovery requires RS256 among the
// algorithms a provider offers, and offering one is what makes a relying
// party's allowlist short. The key's ID is derived from the key, so that a
// new key is a new kid without anybody having to remember to change one.
type signingKey struct {
	key *rsa.PrivateKey
	kid string
}

func loadSigningKey(file string) (*signingKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not PEM", file)
	}
	var k any
	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("%s holds a %q, not a private key", file, blk.Type)
	}
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA key", file)
	}
	if rk.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%s is a %d-bit key; relying parties refuse RSA under 2048 bits", file, rk.N.BitLen())
	}
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	sum := sha256.Sum256(der)
	return &signingKey{key: rk, kid: base64.RawURLEncoding.EncodeToString(sum[:12])}, nil
}

// generateKey writes a new RSA key to file, refusing to overwrite one: a
// signing key replaced by accident is every token invalidated at once.
func generateKey(file string, bits int) error {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// generateSalt writes 32 random bytes to file, refusing to overwrite: a new
// salt is a new subject for everybody.
func generateSalt(file string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// jwks is the key set relying parties verify with: the current key, then
// the retired ones.
func jwks(keys ...*signingKey) []byte {
	set := make([]map[string]string, 0, len(keys))
	for _, s := range keys {
		set = append(set, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": s.kid,
			"n":   base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
		})
	}
	b, _ := json.Marshal(map[string]any{"keys": set})
	return b
}

// sign makes a JWS compact serialisation of claims, with typ "JWT" for an ID
// token and "at+jwt" for an access token (RFC 9068 2.1, so that one cannot be
// passed off as the other).
func (s *signingKey) sign(typ string, claims map[string]any) (string, error) {
	h, err := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid, "typ": typ})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// verify checks a token this provider signed and returns its claims. It is
// used for the access tokens that come back to /userinfo; everything else
// verifies with the published key set, as a relying party should.
func (s *signingKey) verify(typ, raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var h struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, err
	}
	if h.Alg != "RS256" || h.Kid != s.kid || h.Typ != typ {
		return nil, errors.New("not a token of this provider's kind")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("the signature does not verify")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
