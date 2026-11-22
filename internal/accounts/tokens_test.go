package accounts

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// TestTokenRoundTripSurvivesEveryID is the regression test for the bug that a
// flaky server test uncovered: the format used `_` as the separator, which is
// in base64url's alphabet, so roughly one id in eight split in the wrong place
// and the token did not work. A few thousand real ids is enough to catch that
// kind of mistake immediately rather than one call in eight.
func TestTokenRoundTripSurvivesEveryID(t *testing.T) {
	for i := 0; i < 4000; i++ {
		id, err := pcrypto.NewID()
		if err != nil {
			t.Fatal(err)
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}

		raw := FormatToken(id, secret)
		gotID, gotSecret, err := ParseToken(raw)
		if err != nil {
			t.Fatalf("id %q: %v", id, err)
		}
		if gotID != id {
			t.Fatalf("id round trip: got %q, want %q (token %q)", gotID, id, raw)
		}
		if !bytes.Equal(gotSecret, secret) {
			t.Fatalf("secret round trip failed for id %q", id)
		}
	}
}

func TestParseTokenRejectsRubbish(t *testing.T) {
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, 32)
	good := FormatToken(id, secret)

	if !strings.HasPrefix(good, "peek_") {
		t.Fatalf("missing prefix: %q", good)
	}

	bad := []string{
		"",
		"peek_",
		id + "." + pcrypto.B64.EncodeToString(secret), // no prefix
		"peek_" + id,       // no secret
		"peek_" + id + ".", // empty secret
		"peek_short." + pcrypto.B64.EncodeToString(secret),
		"peek_" + id + "." + pcrypto.B64.EncodeToString(secret[:16]), // short secret
		"peek_" + id + "." + "not base64url!!",
		strings.ToUpper(good), // the prefix is case sensitive
	}
	for _, raw := range bad {
		if _, _, err := ParseToken(raw); err == nil {
			t.Errorf("ParseToken accepted %q", raw)
		}
	}
}

func TestNormaliseScopesIsStable(t *testing.T) {
	// Two tokens asking for the same powers must store the same string, so a
	// listing and an audit entry read the same whichever order was typed.
	a, err := store.NormaliseScopes([]string{store.ScopeAuditRead, store.ScopeSecretsWrite})
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.NormaliseScopes([]string{store.ScopeSecretsWrite, store.ScopeAuditRead, store.ScopeSecretsWrite})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a, " ") != strings.Join(b, " ") {
		t.Errorf("%v and %v normalise differently", a, b)
	}
	if _, err := store.NormaliseScopes(nil); err == nil {
		t.Error("a token with no scope was accepted")
	}
	if _, err := store.NormaliseScopes([]string{"secrets:everything"}); err == nil {
		t.Error("an unknown scope was accepted")
	}
}
