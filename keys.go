// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// signingKey is a key tokens are signed with: RSA for RS256, or P-256 for
// ES256.
//
// ID tokens are RS256 and nothing else: OpenID Connect Discovery requires
// RS256 among the algorithms a provider offers, OpenPubkey's GQ signatures
// need it, and offering one is what makes a relying party's allowlist short.
// Access tokens may be ES256 (access_token_key_file): a 3072-bit RS256
// signature is 512 characters and an ES256 one 86, which is what brings a
// token under the 1023 characters OpenSSH reads as a keyboard-interactive
// answer (ssh-oidc). The key's ID is derived from the key, so that a new key
// is a new kid without anybody having to remember to change one.
type signingKey struct {
	key *rsa.PrivateKey   // RS256, or
	ec  *ecdsa.PrivateKey // ES256
	kid string
}

func (s *signingKey) alg() string {
	if s.ec != nil {
		return "ES256"
	}
	return "RS256"
}

func (s *signingKey) public() any {
	if s.ec != nil {
		return &s.ec.PublicKey
	}
	return &s.key.PublicKey
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
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("%s holds a %q, not a private key", file, blk.Type)
	}
	if err != nil {
		return nil, err
	}
	s := &signingKey{}
	switch k := k.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%s is a %d-bit key; relying parties refuse RSA under 2048 bits", file, k.N.BitLen())
		}
		s.key = k
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s is on %s; ES256 is P-256", file, k.Curve.Params().Name)
		}
		s.ec = k
	default:
		return nil, fmt.Errorf("%s is neither an RSA nor a P-256 key", file)
	}
	der, _ := x509.MarshalPKIXPublicKey(s.public())
	sum := sha256.Sum256(der)
	s.kid = base64.RawURLEncoding.EncodeToString(sum[:12])
	return s, nil
}

// generateKey writes a new RSA key to file, refusing to overwrite one: a
// signing key replaced by accident is every token invalidated at once.
func generateKey(file string, bits int) error {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	return writeKey(file, k)
}

// generateECKey writes a new P-256 key to file, for ES256 access tokens.
func generateECKey(file string) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	return writeKey(file, k)
}

func writeKey(file string, k any) error {
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
		if s.ec != nil {
			// RFC 7518 6.2.1.2: x and y are the full 32 bytes, leading
			// zeros kept.
			pt, _ := s.ec.PublicKey.Bytes() // 0x04 || x || y
			set = append(set, map[string]string{
				"kty": "EC",
				"crv": "P-256",
				"use": "sig",
				"alg": "ES256",
				"kid": s.kid,
				"x":   base64.RawURLEncoding.EncodeToString(pt[1:33]),
				"y":   base64.RawURLEncoding.EncodeToString(pt[33:65]),
			})
			continue
		}
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
	h, err := json.Marshal(map[string]string{"alg": s.alg(), "kid": s.kid, "typ": typ})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	if s.ec != nil {
		// JWS wants r || s, 32 bytes each (RFC 7518 3.4), not ASN.1.
		r, ss, err := ecdsa.Sign(rand.Reader, s.ec, sum[:])
		if err != nil {
			return "", err
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	} else if sig, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:]); err != nil {
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
	if h.Alg != s.alg() || h.Kid != s.kid || h.Typ != typ {
		return nil, errors.New("not a token of this provider's kind")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if s.ec != nil {
		if len(sig) != 64 || !ecdsa.Verify(&s.ec.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("the signature does not verify")
		}
	} else if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
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

// publishedKeys is the key set: the ID token key, the access token key when
// it is another, then the retired ones.
func (c *config) publishedKeys() []*signingKey {
	keys := []*signingKey{c.signingKey}
	if c.accessKey != nil && c.accessKey != c.signingKey {
		keys = append(keys, c.accessKey)
	}
	return append(keys, c.retiredKeys...)
}
