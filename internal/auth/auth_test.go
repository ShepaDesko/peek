package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/auth"
)

func TestPasswordRoundTrip(t *testing.T) {
	const password = "un-mot-de-passe-correct-2026"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if strings.Contains(hash, password) {
		t.Fatal("the hash contains the password")
	}
	if err := auth.VerifyPassword(hash, password); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := auth.VerifyPassword(hash, password+"x"); err == nil {
		t.Fatal("a wrong password was accepted")
	}

	// Two hashes of the same password must differ: the salt is random.
	other, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Fatal("two hashes of the same password are identical")
	}
	if auth.NeedsRehash(hash) {
		t.Fatal("a fresh hash wants rehashing")
	}
}

func TestPasswordStrength(t *testing.T) {
	for _, weak := range []string{"", "court", "password1234", "aaaaaaaaaaaaaaaa", "Motdepasse"} {
		if err := auth.CheckPasswordStrength(weak); err == nil {
			t.Errorf("%q was accepted", weak)
		}
		if _, err := auth.HashPassword(weak); err == nil {
			t.Errorf("HashPassword accepted %q", weak)
		}
	}
	for _, good := range []string{"correct horse battery staple", "un-mot-de-passe-correct-2026"} {
		if err := auth.CheckPasswordStrength(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

func TestRehashOnWeakerParameters(t *testing.T) {
	// A hash produced with yesterday's parameters must be upgraded on login.
	weak := "$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHRzb21lc2E$" +
		"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY"
	if !auth.NeedsRehash(weak) {
		t.Fatal("old parameters were not flagged for rehashing")
	}
	if !auth.NeedsRehash("not-a-hash") {
		t.Fatal("a malformed hash was not flagged")
	}
}

func TestTOTP(t *testing.T) {
	enrolment, err := auth.NewTOTP("Coffre ACME", "alice@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if enrolment.Secret == "" || !strings.HasPrefix(enrolment.URI, "otpauth://totp/") {
		t.Fatalf("unexpected enrolment: %+v", enrolment)
	}
	if !strings.Contains(enrolment.URI, "Coffre%20ACME") {
		t.Fatalf("the issuer is missing from the URI: %s", enrolment.URI)
	}

	now := time.Now()
	code := currentCode(t, enrolment.Secret, now)
	if err := auth.VerifyTOTP(enrolment.Secret, code, now); err != nil {
		t.Fatalf("the current code was refused: %v", err)
	}
	// Spaces and stray formatting are forgiven.
	if err := auth.VerifyTOTP(enrolment.Secret, " "+code+" ", now); err != nil {
		t.Fatalf("a padded code was refused: %v", err)
	}
	if err := auth.VerifyTOTP(enrolment.Secret, "000000", now); err == nil {
		t.Fatal("an arbitrary code was accepted")
	}
	// One period of drift is tolerated, five minutes is not.
	if err := auth.VerifyTOTP(enrolment.Secret, code, now.Add(30*time.Second)); err != nil {
		t.Fatalf("one period of skew was refused: %v", err)
	}
	if err := auth.VerifyTOTP(enrolment.Secret, code, now.Add(5*time.Minute)); err == nil {
		t.Fatal("a five-minute-old code was accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != auth.RecoveryCodeCount || len(hashes) != auth.RecoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes", len(codes), len(hashes))
	}

	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
		if len(auth.NormalizeRecoveryCode(c)) != 10 {
			t.Fatalf("unexpected code shape: %q", c)
		}
	}

	// Typing it back with different case and spacing still matches.
	typed := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " - "))
	if !auth.EqualHashes(auth.HashRecoveryCode(typed), hashes[0]) {
		t.Fatal("a code typed with different spacing did not match")
	}
	if auth.EqualHashes(auth.HashRecoveryCode(codes[1]), hashes[0]) {
		t.Fatal("two different codes hash the same")
	}
}

func TestTokens(t *testing.T) {
	token, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 {
		t.Fatalf("token length %d, want 43 (256 bits base64url)", len(token))
	}
	other, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if token == other {
		t.Fatal("two tokens came out identical")
	}
	if !auth.EqualHashes(auth.HashToken(token), auth.HashToken(token)) {
		t.Fatal("hashing is not deterministic")
	}
	if auth.EqualHashes(auth.HashToken(token), auth.HashToken(other)) {
		t.Fatal("two tokens hash the same")
	}
	if hex := auth.HashTokenHex(token); len(hex) != 64 {
		t.Fatalf("hex digest length %d, want 64", len(hex))
	}
	if !auth.EqualTokens(token, token) || auth.EqualTokens(token, other) {
		t.Fatal("token comparison is wrong")
	}
}

// currentCode computes the code an authenticator would show right now.
func currentCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totpNow(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}
