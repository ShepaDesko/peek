// Package auth holds the credential primitives: password hashing, TOTP,
// recovery codes and the tokens that identify a session.
//
// It knows nothing about HTTP or storage. Everything here is deliberately
// small enough to read in one sitting, because this is the code that decides
// who gets in.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for passwords.
//
// These are server-side and may be heavier than the browser's: 64 MiB and
// three passes take roughly 100 ms on a modest core, which is a sensible cost
// for a login and a painful one for an offline guessing attempt. They are
// stored in the hash string, so raising them later does not invalidate
// existing passwords — NeedsRehash notices and the next login upgrades them.
const (
	passwordMemoryKiB  uint32 = 65536
	passwordIterations uint32 = 3
	passwordThreads    uint8  = 2
	passwordSaltLen           = 16
	passwordKeyLen            = 32
)

// MinPasswordLength is the floor. Length beats composition rules, so there are
// no composition rules.
const MinPasswordLength = 12

var (
	// ErrWrongPassword is returned when a password does not match.
	ErrWrongPassword = errors.New("auth: wrong password")
	// ErrWeakPassword is returned when a new password is refused.
	ErrWeakPassword = errors.New("auth: password refused")
)

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(password string) (string, error) {
	if err := CheckPasswordStrength(password); err != nil {
		return "", err
	}
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemoryKiB, passwordThreads, passwordKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, passwordMemoryKiB, passwordIterations, passwordThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a stored hash in constant time.
func VerifyPassword(hash, password string) error {
	params, salt, want, err := parsePHC(hash)
	if err != nil {
		return err
	}
	// The stored key length comes from our own hash format and is 32 bytes;
	// anything absurd is rejected rather than converted.
	if len(want) < 16 || len(want) > 64 {
		return errors.New("auth: stored hash has an implausible length")
	}
	got := argon2.IDKey([]byte(password), salt, params.iterations, params.memoryKiB, params.threads, uint32(len(want))) //nolint:gosec // bounded just above
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// NeedsRehash reports whether a stored hash uses weaker parameters than the
// current ones, so that a successful login can quietly upgrade it.
func NeedsRehash(hash string) bool {
	params, _, _, err := parsePHC(hash)
	if err != nil {
		return true
	}
	return params.memoryKiB < passwordMemoryKiB ||
		params.iterations < passwordIterations ||
		params.threads < passwordThreads
}

// CheckPasswordStrength refuses what is obviously too weak.
func CheckPasswordStrength(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("%w: at least %d characters are required", ErrWeakPassword, MinPasswordLength)
	}
	if len(password) > 1024 {
		return fmt.Errorf("%w: at most 1024 bytes", ErrWeakPassword)
	}
	if isSingleRepeatedRune(password) {
		return fmt.Errorf("%w: the same character repeated is not a password", ErrWeakPassword)
	}
	for _, common := range commonPasswords {
		if strings.EqualFold(strings.TrimSpace(password), common) {
			return fmt.Errorf("%w: this password is among the most common ones", ErrWeakPassword)
		}
	}
	return nil
}

// commonPasswords is a deliberately short list: a long list belongs in a
// breach-corpus check, not in a binary, and length already does most of the
// work here.
var commonPasswords = []string{
	"password", "password1", "motdepasse", "123456789012", "azertyuiop123",
	"qwertyuiop12", "administrator", "changeme1234", "letmein12345",
	"password1234", "motdepasse12", "peekpeekpeek",
}

func isSingleRepeatedRune(s string) bool {
	runes := []rune(s)
	if len(runes) == 0 {
		return true
	}
	first := runes[0]
	for _, r := range runes {
		if r != first {
			return false
		}
	}
	return true
}

type argonParams struct {
	memoryKiB  uint32
	iterations uint32
	threads    uint8
}

func parsePHC(hash string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, errors.New("auth: unsupported password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, errors.New("auth: unsupported Argon2 version")
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.iterations, &p.threads); err != nil {
		return argonParams{}, nil, nil, errors.New("auth: malformed Argon2 parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, errors.New("auth: malformed salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, errors.New("auth: malformed hash")
	}
	return p, salt, key, nil
}

// --- tokens ------------------------------------------------------------------

// NewToken returns a 256-bit random token, base64url without padding.
// Session cookies, invitations, password resets and receipt tokens all use it.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the SHA-256 of a token, which is what gets stored.
//
// A token is already 256 bits of randomness, so it needs no password-style
// stretching: an attacker holding the hash has nothing to guess.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// HashTokenHex returns the hex form, used as a primary key for sessions.
func HashTokenHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(sum)*2)
	for _, b := range sum {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// EqualTokens compares two tokens in constant time.
func EqualTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// EqualHashes compares two digests in constant time.
func EqualHashes(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// Printable reports whether a string is safe to echo back in an error.
func Printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
