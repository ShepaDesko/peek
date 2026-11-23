package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWS verification, by hand.
//
// The whole of what Peek needs from a JWT library is: split three parts,
// resolve a key by `kid`, verify one asymmetric signature, and parse a handful
// of claims. That is the file below. It avoids a dependency whose job is to be
// flexible — and flexibility is precisely what gets JWT verification wrong:
// the famous failures are all a library accepting an algorithm the caller did
// not mean to accept.
//
// So the algorithm set is closed, and it contains no symmetric entry at all.
// `alg: none` and the HMAC family cannot be selected by a token, because they
// are not in the table.

// b64 is the JWT encoding: base64url, unpadded.
var b64 = base64.RawURLEncoding

// ErrUnsupportedAlg is returned for an algorithm that is not in the table,
// including "none" and the HMAC family.
var ErrUnsupportedAlg = errors.New("oidc: unsupported signing algorithm")

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jsonWebKey is one key from a JWKS document. Only the fields needed to
// rebuild an RSA or EC public key are read.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`

	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type keySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// public rebuilds the public key. An unsupported key type returns nil, which
// the caller reads as "skip this one".
func (k jsonWebKey) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64BigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %q: modulus: %w", k.Kid, err)
		}
		e, err := b64BigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %q: exponent: %w", k.Kid, err)
		}
		if !e.IsInt64() || e.Int64() <= 0 {
			return nil, fmt.Errorf("oidc: key %q has an unusable exponent", k.Kid)
		}
		// A 1024-bit modulus is below what anyone should still be signing
		// with, and accepting it quietly would defeat the point of verifying.
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("oidc: key %q is a %d-bit RSA key; 2048 is the minimum", k.Kid, n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, size, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64Coordinate(k.X, size)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %q: x: %w", k.Kid, err)
		}
		y, err := b64Coordinate(k.Y, size)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %q: y: %w", k.Kid, err)
		}
		// The coordinates are reassembled into an uncompressed point and
		// parsed, rather than written into an ecdsa.PublicKey field by field:
		// the parser is what performs the on-curve check, and building the
		// struct directly would skip it.
		point := make([]byte, 0, 1+2*size)
		point = append(point, 4)
		point = append(point, x...)
		point = append(point, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %q is not a valid point on %s: %w", k.Kid, k.Crv, err)
		}
		return pub, nil
	default:
		// oct (symmetric), OKP (Ed25519) and anything else: not accepted.
		return nil, nil
	}
}

// verifySignature checks one JWS signature against one public key.
func verifySignature(alg string, pub crypto.PublicKey, signed, signature []byte) error {
	switch alg {
	case "RS256", "RS384", "RS512":
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("oidc: " + alg + " needs an RSA key")
		}
		h, digest := hashFor(alg, signed)
		return rsa.VerifyPKCS1v15(key, h, digest, signature)
	case "PS256", "PS384", "PS512":
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("oidc: " + alg + " needs an RSA key")
		}
		h, digest := hashFor(alg, signed)
		return rsa.VerifyPSS(key, h, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto, Hash: h,
		})
	case "ES256", "ES384", "ES512":
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("oidc: " + alg + " needs an EC key")
		}
		_, digest := hashFor(alg, signed)
		// JWS carries r and s as fixed-width halves, not as the DER sequence
		// ecdsa.VerifyASN1 expects.
		half := len(signature) / 2
		if len(signature)%2 != 0 || half == 0 {
			return errors.New("oidc: malformed ECDSA signature")
		}
		r := new(big.Int).SetBytes(signature[:half])
		sv := new(big.Int).SetBytes(signature[half:])
		if !ecdsa.Verify(key, digest, r, sv) {
			return errors.New("oidc: ECDSA signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
}

func hashFor(alg string, data []byte) (crypto.Hash, []byte) {
	switch alg[2:] {
	case "384":
		sum := sha512.Sum384(data)
		return crypto.SHA384, sum[:]
	case "512":
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:]
	default:
		sum := sha256.Sum256(data)
		return crypto.SHA256, sum[:]
	}
}

// claims is the raw claim set, kept as JSON so a configured group claim can be
// read without the struct having to know its name.
type rawClaims map[string]json.RawMessage

// splitJWT returns the header, the claim set, the signed input and the
// signature. It does not verify anything.
func splitJWT(token string) (jwtHeader, rawClaims, []byte, []byte, error) {
	var (
		header jwtHeader
		claims rawClaims
	)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, nil, nil, nil, errors.New("oidc: the ID token is not a three-part JWT")
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: ID token header: %w", err)
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: ID token header: %w", err)
	}
	rawClaimSet, err := b64.DecodeString(parts[1])
	if err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: ID token payload: %w", err)
	}
	if err := json.Unmarshal(rawClaimSet, &claims); err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: ID token payload: %w", err)
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: ID token signature: %w", err)
	}
	signed := []byte(parts[0] + "." + parts[1])
	return header, claims, signed, signature, nil
}

func b64BigInt(value string) (*big.Int, error) {
	raw, err := b64.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty")
	}
	return new(big.Int).SetBytes(raw), nil
}

// b64Coordinate decodes an EC coordinate, which RFC 7518 requires to be
// exactly the curve's field size. A short value is not left-padded on purpose:
// it means the key is malformed, and guessing would hide that.
func b64Coordinate(value string, size int) ([]byte, error) {
	raw, err := b64.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%d bytes, expected %d for this curve", len(raw), size)
	}
	return raw, nil
}

// stringOrSlice reads a claim that may be a string or an array of strings,
// which is how `aud` and most group claims are specified.
func stringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func stringClaim(claims rawClaims, name string) string {
	var out string
	if raw, ok := claims[name]; ok {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func boolClaim(claims rawClaims, name string) (value, present bool) {
	raw, ok := claims[name]
	if !ok {
		return false, false
	}
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	// Some providers send "true" as a string.
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text == "true", true
	}
	return false, false
}

func numberClaim(claims rawClaims, name string) (int64, bool) {
	raw, ok := claims[name]
	if !ok {
		return 0, false
	}
	var value json.Number
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	n, err := value.Int64()
	if err != nil {
		// A float timestamp: truncate rather than refuse the whole token.
		f, ferr := value.Float64()
		if ferr != nil {
			return 0, false
		}
		return int64(f), true
	}
	return n, true
}

// ecCurve maps a JWK curve name to its curve and field size in bytes.
func ecCurve(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		// 521 bits is 66 bytes, not 65: the rounding catches people out.
		return elliptic.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("oidc: unsupported curve %q", name)
	}
}
