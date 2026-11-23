package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// These tests exist for one reason: every famous JWT failure is a verifier
// accepting something it did not mean to accept. The algorithm table, the
// issuer comparison, the key size floor and the refusal of a symmetric
// algorithm are claims this project makes in docs/DECISIONS.md, so each one
// gets a test that fails if it stops being true.

const (
	testIssuer   = "https://login.example.com/tenant/v2.0"
	testClientID = "11111111-1111-1111-1111-111111111111"
	testNonce    = "n-0S6_WzA2Mj"
)

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// provider builds a Provider with a key set already cached, so no HTTP call is
// made and keyFor takes the fast path.
func provider(t *testing.T, cfg config.SSO, keys ...jsonWebKey) *Provider {
	t.Helper()
	cfg.Enabled = true
	if cfg.Issuer == "" {
		cfg.Issuer = testIssuer
	}
	if cfg.ClientID == "" {
		cfg.ClientID = testClientID
	}
	p, err := New(cfg, discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.keys = keys
	p.keysFetched = time.Now()
	return p
}

func claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            testIssuer,
		"aud":            testClientID,
		"sub":            "7a1f0e8c-sub",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          testNonce,
		"email":          "ops@example.com",
		"email_verified": true,
		"name":           "Ops Team",
		"groups":         []string{"3f6c-admins"},
	}
}

func part(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b64.EncodeToString(raw)
}

func signingInput(t *testing.T, alg, kid string, set map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	return part(t, header) + "." + part(t, set)
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	return key
}

func rsaJWK(kid string, pub *rsa.PublicKey) jsonWebKey {
	return jsonWebKey{
		Kty: "RSA", Kid: kid, Use: "sig",
		N: b64.EncodeToString(pub.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(t *testing.T, kid string, pub *ecdsa.PublicKey) jsonWebKey {
	t.Helper()
	// The uncompressed point, 0x04 || X || Y, which is also how the package
	// under test rebuilds a key: the raw coordinate fields are deprecated.
	point, err := pub.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	return jsonWebKey{
		Kty: "EC", Kid: kid, Use: "sig", Crv: "P-256",
		X: b64.EncodeToString(point[1 : 1+size]),
		Y: b64.EncodeToString(point[1+size:]),
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, set map[string]any) string {
	t.Helper()
	input := signingInput(t, "RS256", kid, set)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, set map[string]any) string {
	t.Helper()
	input := signingInput(t, "ES256", kid, set)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// JWS carries r and s as fixed-width halves, not as a DER sequence.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64.EncodeToString(sig)
}

func TestVerifyAcceptsRS256(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{AdminGroups: []string{"3f6c-admins"}}, rsaJWK("k1", &key.PublicKey))

	got, err := p.Verify(context.Background(), signRS256(t, key, "k1", claims()), testNonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "7a1f0e8c-sub" {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.Issuer != testIssuer {
		t.Errorf("issuer = %q, the issuer must come from the configuration and not from the token", got.Issuer)
	}
	if got.Email != "ops@example.com" || !got.EmailVerified || !got.EmailVerifiedPresent {
		t.Errorf("email = %q verified = %v present = %v", got.Email, got.EmailVerified, got.EmailVerifiedPresent)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "3f6c-admins" {
		t.Errorf("groups = %v", got.Groups)
	}
}

func TestVerifyAcceptsES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	p := provider(t, config.SSO{}, ecJWK(t, "ec1", &key.PublicKey))

	if _, err := p.Verify(context.Background(), signES256(t, key, "ec1", claims()), testNonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// The attack this closes: a token that asks to be verified with a symmetric
// algorithm, keyed on the public key the verifier already holds. Peek has no
// symmetric entry in the table, so the request is refused before any key is
// resolved.
func TestVerifyRefusesSymmetricAndNone(t *testing.T) {
	key := rsaKey(t, 2048)
	jwk := rsaJWK("k1", &key.PublicKey)
	p := provider(t, config.SSO{}, jwk)

	for _, alg := range []string{"HS256", "HS384", "HS512", "none"} {
		t.Run(alg, func(t *testing.T) {
			input := signingInput(t, alg, "k1", claims())
			token := input + "."
			if alg != "none" {
				// Keyed with the modulus, which is what an attacker has.
				mac := hmac.New(sha256.New, key.N.Bytes())
				mac.Write([]byte(input))
				token = input + "." + b64.EncodeToString(mac.Sum(nil))
			}
			_, err := p.Verify(context.Background(), token, testNonce)
			if err == nil {
				t.Fatal("a token signed with " + alg + " was accepted")
			}
			if !errors.Is(err, ErrToken) {
				t.Errorf("error does not wrap ErrToken: %v", err)
			}
			if !strings.Contains(err.Error(), "asymmetric") {
				t.Errorf("the message should say Peek verifies asymmetric signatures only: %v", err)
			}
		})
	}
}

// A key type Peek does not accept must be refused, not treated as a key.
func TestVerifyRefusesOctKey(t *testing.T) {
	p := provider(t, config.SSO{}, jsonWebKey{Kty: "oct", Kid: "k1", Use: "sig"})

	_, err := p.Verify(context.Background(), signRS256(t, rsaKey(t, 2048), "k1", claims()), testNonce)
	if err == nil {
		t.Fatal("a symmetric JWKS entry was used as a verification key")
	}
	if !strings.Contains(err.Error(), "oct") {
		t.Errorf("the message should name the key type it refused: %v", err)
	}
}

func TestVerifyRefusesUndersizedRSAKey(t *testing.T) {
	key := rsaKey(t, 1024)
	p := provider(t, config.SSO{}, rsaJWK("small", &key.PublicKey))

	_, err := p.Verify(context.Background(), signRS256(t, key, "small", claims()), testNonce)
	if err == nil {
		t.Fatal("a 1024-bit RSA key was accepted")
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Errorf("the message should name the minimum: %v", err)
	}
}

func TestVerifyRefusesTamperedClaims(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))

	token := signRS256(t, key, "k1", claims())
	parts := strings.Split(token, ".")
	elevated := claims()
	elevated["email"] = "root@example.com"
	parts[1] = part(t, elevated)

	if _, err := p.Verify(context.Background(), strings.Join(parts, "."), testNonce); err == nil {
		t.Fatal("a token whose payload was replaced after signing was accepted")
	}
}

func TestVerifyRefusesBadClaims(t *testing.T) {
	key := rsaKey(t, 2048)
	jwk := rsaJWK("k1", &key.PublicKey)

	cases := []struct {
		name  string
		want  string
		mutad func(map[string]any)
	}{
		{"issuer", "issued by", func(c map[string]any) {
			// A prefix of the configured issuer: the comparison is exact.
			c["iss"] = testIssuer + "/extra"
		}},
		{"issuer-another-tenant", "issued by", func(c map[string]any) {
			c["iss"] = "https://login.example.com/other-tenant/v2.0"
		}},
		{"audience", "another application", func(c map[string]any) {
			c["aud"] = "22222222-2222-2222-2222-222222222222"
		}},
		{"authorised-party", "authorised for", func(c map[string]any) {
			c["aud"] = []string{testClientID, "another-app"}
			c["azp"] = "another-app"
		}},
		{"expired", "expired at", func(c map[string]any) {
			c["exp"] = time.Now().Add(-2 * Leeway).Unix()
		}},
		{"no-expiry", "no expiry", func(c map[string]any) {
			delete(c, "exp")
		}},
		{"issued-in-the-future", "issued in the future", func(c map[string]any) {
			c["iat"] = time.Now().Add(2 * Leeway).Unix()
		}},
		{"not-yet-valid", "not valid yet", func(c map[string]any) {
			c["nbf"] = time.Now().Add(2 * Leeway).Unix()
		}},
		{"no-subject", "no subject", func(c map[string]any) {
			delete(c, "sub")
		}},
		{"nonce", "nonce of this sign-in attempt", func(c map[string]any) {
			c["nonce"] = "the nonce of another attempt"
		}},
		{"nonce-missing", "nonce of this sign-in attempt", func(c map[string]any) {
			delete(c, "nonce")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := provider(t, config.SSO{}, jwk)
			set := claims()
			tc.mutad(set)

			_, err := p.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce)
			if err == nil {
				t.Fatalf("a token with a bad %s was accepted", tc.name)
			}
			if !errors.Is(err, ErrToken) {
				t.Errorf("error does not wrap ErrToken: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q should contain %q", err, tc.want)
			}
		})
	}
}

// A multi-audience token whose azp is us is legitimate, and must still pass.
func TestVerifyAcceptsMultipleAudiencesAuthorisedToUs(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))

	set := claims()
	set["aud"] = []string{testClientID, "some-resource-api"}
	set["azp"] = testClientID

	if _, err := p.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRefusesMalformedToken(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))

	for _, token := range []string{
		"",
		"two.parts",
		"a.b.c.d",
		"!!!.eyJ9.sig",
		part(t, map[string]any{"alg": "RS256"}) + ".!!!.sig",
	} {
		if _, err := p.Verify(context.Background(), token, testNonce); err == nil {
			t.Errorf("a malformed token (%q) was accepted", token)
		}
	}
}

func TestVerifyRefusesTokenWithNoAlgorithm(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))

	token := part(t, map[string]any{"typ": "JWT"}) + "." + part(t, claims()) + ".c2ln"
	_, err := p.Verify(context.Background(), token, testNonce)
	if err == nil || !strings.Contains(err.Error(), "names no algorithm") {
		t.Fatalf("a token with no alg should be refused by name: %v", err)
	}
}

// Iterating over keys until one verifies is how a verifier ends up accepting a
// signature from a key that was never meant for tokens. With no kid, an
// ambiguous key set is refused rather than tried in turn.
func TestPickKeyRefusesAmbiguity(t *testing.T) {
	one := jsonWebKey{Kty: "RSA", Kid: "a", Use: "sig"}
	two := jsonWebKey{Kty: "RSA", Kid: "b", Use: "sig"}
	encryption := jsonWebKey{Kty: "RSA", Kid: "e", Use: "enc"}

	if got := pickKey([]jsonWebKey{one}, "", "RS256"); got == nil {
		t.Error("a single published key should be matched when the token carries no kid")
	}
	if got := pickKey([]jsonWebKey{one, two}, "", "RS256"); got != nil {
		t.Errorf("an ambiguous key set should be refused, got %q", got.Kid)
	}
	if got := pickKey([]jsonWebKey{one, two}, "b", "RS256"); got == nil || got.Kid != "b" {
		t.Errorf("the named key should be matched, got %v", got)
	}
	if got := pickKey([]jsonWebKey{one, two}, "c", "RS256"); got != nil {
		t.Errorf("an unpublished kid should be refused, got %q", got.Kid)
	}
	if got := pickKey([]jsonWebKey{encryption}, "", "RS256"); got != nil {
		t.Error("a key published for encryption should never verify a signature")
	}
	if got := pickKey([]jsonWebKey{{Kty: "RSA", Kid: "a", Alg: "RS512"}}, "", "RS256"); got != nil {
		t.Error("a key pinned to another algorithm should not be used")
	}
}

// An unknown kid must not let a stream of forged tokens hammer the JWKS
// endpoint: within the rate-limit window the answer comes from the cache.
func TestVerifyRefusesUnknownKidWithoutRefetching(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))
	// A fetch just happened, so a refetch is not allowed yet. The JWKS URL is
	// empty, so a refetch would also be an error rather than a silent pass.
	_, err := p.Verify(context.Background(), signRS256(t, key, "rotated-away", claims()), testNonce)
	if err == nil {
		t.Fatal("a token naming an unpublished key was accepted")
	}
	if !strings.Contains(err.Error(), "rotated-away") {
		t.Errorf("the message should name the key it could not find: %v", err)
	}
}

// Entra replaces the group list with a pointer to Microsoft Graph past roughly
// two hundred groups. Peek refuses the sign-in rather than seeing no groups
// and handing out the default role, which would quietly demote an admin.
func TestGroupOverflowIsRefusedWhenGroupsAreMapped(t *testing.T) {
	key := rsaKey(t, 2048)
	jwk := rsaJWK("k1", &key.PublicKey)

	set := claims()
	delete(set, "groups")
	set["_claim_names"] = map[string]string{"groups": "src1"}

	mapped := provider(t, config.SSO{AdminGroups: []string{"3f6c-admins"}}, jwk)
	_, err := mapped.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce)
	if err == nil {
		t.Fatal("a group overflow claim was accepted while groups decide roles")
	}
	if !strings.Contains(err.Error(), "groups_claim") {
		t.Errorf("the message should say what to do instead: %v", err)
	}

	// With no group mapping configured, groups decide nothing and the overflow
	// is not a reason to refuse somebody a sign-in.
	plain := provider(t, config.SSO{}, jwk)
	if _, err := plain.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce); err != nil {
		t.Fatalf("overflow should be harmless when no group maps roles: %v", err)
	}
}

func TestGroupsComeFromTheConfiguredClaim(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{GroupsClaim: "roles"}, rsaJWK("k1", &key.PublicKey))

	set := claims()
	set["roles"] = []string{"Peek.Admin"}

	got, err := p.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "Peek.Admin" {
		t.Errorf("groups = %v, the configured claim should win over `groups`", got.Groups)
	}
}

// Entra puts the address in preferred_username for a work account.
func TestVerifyFallsBackToPreferredUsername(t *testing.T) {
	key := rsaKey(t, 2048)
	p := provider(t, config.SSO{}, rsaJWK("k1", &key.PublicKey))

	set := claims()
	delete(set, "email")
	set["preferred_username"] = "ops@example.com"

	got, err := p.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Email != "ops@example.com" {
		t.Errorf("email = %q", got.Email)
	}

	// But a preferred_username that is not an address is a username, not a
	// mailbox, and must not become one.
	set["preferred_username"] = "ops"
	got, err = p.Verify(context.Background(), signRS256(t, key, "k1", set), testNonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Email != "" {
		t.Errorf("email = %q, a username is not an address", got.Email)
	}
}

// Feeding a point that is not on the curve into an ECDH or a verification is a
// known attack, and the parser is what closes it.
func TestECKeyOffCurveIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := ecJWK(t, "ec1", &key.PublicKey)
	// Move y off the curve.
	raw, err := b64.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	jwk.Y = b64.EncodeToString(raw)

	if _, err := jwk.public(); err == nil {
		t.Fatal("a point that is not on P-256 was accepted as a public key")
	}
}

func TestECKeyRefusesUnsupportedCurve(t *testing.T) {
	if _, _, err := ecCurve("P-192"); err == nil {
		t.Error("P-192 should not be a usable curve")
	}
	for _, name := range []string{"P-256", "P-384", "P-521"} {
		if _, _, err := ecCurve(name); err != nil {
			t.Errorf("ecCurve(%q): %v", name, err)
		}
	}
}

// A coordinate must be exactly the curve's width. RFC 7518 requires the
// fixed-width form, and accepting a short one would mean guessing whether it
// was left-padded or is a different point.
func TestECCoordinateWidthIsChecked(t *testing.T) {
	for _, width := range []int{0, 31, 33, 64} {
		if _, err := b64Coordinate(b64.EncodeToString(make([]byte, width)), 32); err == nil {
			t.Errorf("a %d-byte coordinate was accepted for a 32-byte curve", width)
		}
	}
	if _, err := b64Coordinate(b64.EncodeToString(make([]byte, 32)), 32); err != nil {
		t.Errorf("a correctly sized coordinate was refused: %v", err)
	}
	if _, err := b64Coordinate("not base64url!", 32); err == nil {
		t.Error("a coordinate that is not base64url was accepted")
	}
}

func TestStringOrSliceHandlesBothShapes(t *testing.T) {
	// A mixed array yields nothing rather than the entries that happened to
	// parse: a half-read group list is how somebody loses a role quietly.
	cases := map[string][]string{
		`"one"`:            {"one"},
		`["one","two"]`:    {"one", "two"},
		`[]`:               nil,
		`""`:               nil,
		`null`:             nil,
		`123`:              nil,
		`["one", 2, true]`: nil,
	}
	for raw, want := range cases {
		got := stringOrSlice(json.RawMessage(raw))
		if len(got) != len(want) {
			t.Errorf("stringOrSlice(%s) = %v, want %v", raw, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("stringOrSlice(%s) = %v, want %v", raw, got, want)
				break
			}
		}
	}
}

func TestVerifySignatureRejectsKeyTypeMismatch(t *testing.T) {
	rsa2048 := rsaKey(t, 2048)
	rsaPub := &rsa2048.PublicKey
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	if err := verifySignature("ES256", rsaPub, []byte("x"), make([]byte, 64)); err == nil {
		t.Error("ES256 verified against an RSA key")
	}
	if err := verifySignature("RS256", &ec.PublicKey, []byte("x"), make([]byte, 256)); err == nil {
		t.Error("RS256 verified against an EC key")
	}
	if err := verifySignature("EdDSA", rsaPub, []byte("x"), nil); !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("an algorithm outside the table should return ErrUnsupportedAlg, got %v", err)
	}
	// An odd-length ECDSA signature cannot be split into r and s.
	if err := verifySignature("ES256", &ec.PublicKey, []byte("x"), make([]byte, 63)); err == nil {
		t.Error("a malformed ECDSA signature was accepted")
	}
	if err := verifySignature("ES256", &ec.PublicKey, []byte("x"), nil); err == nil {
		t.Error("an empty ECDSA signature was accepted")
	}
}
