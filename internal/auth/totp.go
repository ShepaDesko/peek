package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Second factors: time-based one-time passwords, and the recovery codes that
// exist for the day the phone is lost.

// ErrBadCode is returned when a TOTP or recovery code does not match.
var ErrBadCode = errors.New("auth: wrong code")

// TOTPEnrolment is what the user needs to add the account to an authenticator.
type TOTPEnrolment struct {
	// Secret is the base32 seed. It is shown once, then stored encrypted.
	Secret string
	// URI is the otpauth:// URL that a QR code encodes.
	URI string
	// Issuer and Account are what the authenticator app displays.
	Issuer  string
	Account string
}

// NewTOTP generates an enrolment for a user.
//
// The period, digits and algorithm are the defaults every authenticator
// supports (30 seconds, six digits, SHA-1); choosing anything cleverer here
// mostly means users with an app that cannot read it.
func NewTOTP(issuer, account string) (TOTPEnrolment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        rand.Reader,
	})
	if err != nil {
		return TOTPEnrolment{}, fmt.Errorf("auth: generate TOTP: %w", err)
	}
	return TOTPEnrolment{
		Secret:  key.Secret(),
		URI:     key.URL(),
		Issuer:  issuer,
		Account: account,
	}, nil
}

// VerifyTOTP checks a six-digit code against a seed.
//
// One period of skew either way is allowed, which covers a phone whose clock
// drifts and a user who types slowly.
func VerifyTOTP(secret, code string, now time.Time) error {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if code == "" {
		return ErrBadCode
	}
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !ok {
		return ErrBadCode
	}
	return nil
}

// --- recovery codes ----------------------------------------------------------

// RecoveryCodeCount is how many codes are issued at a time.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns the codes to show the user once, and the hashes to
// store. Each code carries about 50 bits of entropy, so the stored SHA-256
// needs no stretching.
func NewRecoveryCodes() (codes []string, hashes [][]byte, err error) {
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// recoveryAlphabet avoids the characters people mistype when copying by hand.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

func newRecoveryCode() (string, error) {
	const groups, groupLen = 2, 5
	buf := make([]byte, groups*groupLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var b strings.Builder
	for i, v := range buf {
		if i > 0 && i%groupLen == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(recoveryAlphabet[int(v)%len(recoveryAlphabet)])
	}
	return b.String(), nil
}

// NormalizeRecoveryCode makes comparison forgiving about case and spacing,
// because these are typed by a person under stress.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	return code
}

// HashRecoveryCode returns the stored form of a code.
func HashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte("peek-recovery-v1:" + NormalizeRecoveryCode(code)))
	return sum[:]
}
