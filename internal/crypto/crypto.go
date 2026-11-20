// Package crypto implements the Peek zero-knowledge secret format (version v1).
//
// The server never sees any of the material produced here except the sealed
// ciphertext and SHA-256(read token). The reference description of the format
// lives in docs/CRYPTO.md; the shared test vectors live in crypto/vectors.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Version is the format version. Bumping it is a breaking change: old secrets
// must stay readable, so an existing version is never redefined in place.
const Version = "v1"

const (
	infoKey   = "peek-key-v1"
	infoEnc   = "peek-enc-v1"
	infoRead  = "peek-read-v1"
	aadPrefix = "peek-v1|"
)

const (
	// ContentKeyLen is the size of the random per-secret (and per-recipient) key.
	ContentKeyLen = 32
	// SaltLen is the size of the KDF salt stored as secret metadata.
	SaltLen = 16
	// NonceLen is the AES-GCM nonce size.
	NonceLen = 12
	// IDLen is the size in bytes of a public secret identifier (128 bits).
	IDLen = 16
)

// Default Argon2id parameters: usable on mobile browsers (~19 MiB, two passes)
// while matching current OWASP guidance.
const (
	DefaultMemoryKiB   uint32 = 19456
	DefaultIterations  uint32 = 2
	DefaultParallelism uint8  = 1
)

// ErrOpen is returned when a sealed blob cannot be authenticated.
var ErrOpen = errors.New("peek/crypto: cannot decrypt (wrong key, passphrase or corrupted data)")

// KDFParams are the public, server-stored parameters of the key derivation.
// They carry no secret: the salt is useless without the content key.
type KDFParams struct {
	Salt        []byte `json:"salt"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// DefaultKDFParams returns the default parameters with a fresh random salt.
func DefaultKDFParams() (KDFParams, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	return KDFParams{
		Salt:        salt,
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
	}, nil
}

func (p KDFParams) validate() error {
	if len(p.Salt) == 0 {
		return errors.New("peek/crypto: empty KDF salt")
	}
	if p.MemoryKiB < 8192 || p.Iterations < 1 || p.Parallelism < 1 {
		return fmt.Errorf("peek/crypto: KDF parameters below the accepted floor (m=%d t=%d p=%d)",
			p.MemoryKiB, p.Iterations, p.Parallelism)
	}
	return nil
}

// Keys is the set of keys derived from a content key (+ optional passphrase).
type Keys struct {
	// Final is the master key; everything else is expanded from it.
	Final []byte
	// Enc is the AES-256-GCM key protecting the payload.
	Enc []byte
	// ReadToken proves possession of the key to the server before it releases
	// the ciphertext and consumes a view.
	ReadToken []byte
	// ReadTokenHash is the only one of these the server ever stores.
	ReadTokenHash []byte
}

func newSHA256() hash.Hash { return sha256.New() }

func expand(key []byte, info string, n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.Expand(newSHA256, key, []byte(info)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeriveKeys derives every key of the v1 format.
//
//	A     = passphrase is empty ? nothing : Argon2id(passphrase, salt, params)
//	final = HKDF-SHA256(ikm = contentKey || A, salt = salt, info = peek-key-v1)
//	enc   = HKDF-Expand(final, peek-enc-v1)
//	token = HKDF-Expand(final, peek-read-v1)
func DeriveKeys(contentKey []byte, passphrase string, p KDFParams) (Keys, error) {
	if len(contentKey) != ContentKeyLen {
		return Keys{}, fmt.Errorf("peek/crypto: content key must be %d bytes, got %d", ContentKeyLen, len(contentKey))
	}
	if err := p.validate(); err != nil {
		return Keys{}, err
	}

	ikm := make([]byte, 0, ContentKeyLen+32)
	ikm = append(ikm, contentKey...)
	if passphrase != "" {
		ikm = append(ikm, argon2.IDKey([]byte(passphrase), p.Salt, p.Iterations, p.MemoryKiB, p.Parallelism, 32)...)
	}

	final := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(newSHA256, ikm, p.Salt, []byte(infoKey)), final); err != nil {
		return Keys{}, err
	}
	enc, err := expand(final, infoEnc, 32)
	if err != nil {
		return Keys{}, err
	}
	tok, err := expand(final, infoRead, 32)
	if err != nil {
		return Keys{}, err
	}
	sum := sha256.Sum256(tok)
	return Keys{Final: final, Enc: enc, ReadToken: tok, ReadTokenHash: sum[:]}, nil
}

// AAD returns the additional authenticated data binding a sealed payload to
// its public identifier, so a ciphertext cannot be moved to another secret.
func AAD(secretID string) []byte { return []byte(aadPrefix + secretID) }

// Seal encrypts plaintext with AES-256-GCM. The output is nonce || ciphertext.
func Seal(encKey, aad, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return SealWithNonce(encKey, nonce, aad, plaintext)
}

// SealWithNonce is Seal with a caller-supplied nonce. Only use it to reproduce
// test vectors: a reused nonce destroys the security of AES-GCM.
func SealWithNonce(encKey, nonce, aad, plaintext []byte) ([]byte, error) {
	gcm, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("peek/crypto: nonce must be %d bytes", NonceLen)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// Open authenticates and decrypts a nonce || ciphertext blob.
func Open(encKey, aad, blob []byte) ([]byte, error) {
	if len(blob) < NonceLen+16 {
		return nil, ErrOpen
	}
	gcm, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, blob[:NonceLen], blob[NonceLen:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("peek/crypto: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// HashReadToken returns SHA-256(token), the only read-path value stored server side.
func HashReadToken(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

// EqualHash compares two digests in constant time.
func EqualHash(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// B64 is the alphabet used everywhere in Peek: URL-safe, unpadded.
var B64 = base64.RawURLEncoding

// NewContentKey returns a fresh random 256-bit content key.
func NewContentKey() ([]byte, error) {
	k := make([]byte, ContentKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// NewID returns a fresh random public identifier (128 bits, base64url).
func NewID() (string, error) {
	b := make([]byte, IDLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return B64.EncodeToString(b), nil
}

// ValidID reports whether s is a well-formed public identifier.
func ValidID(s string) bool {
	if len(s) != B64.EncodedLen(IDLen) {
		return false
	}
	b, err := B64.DecodeString(s)
	return err == nil && len(b) == IDLen
}

// EncodeFragment renders the URL fragment that carries the content key. It is
// never sent to the server: browsers keep fragments local, and
// Referrer-Policy no-referrer stops them leaking sideways.
func EncodeFragment(contentKey []byte) string {
	return Version + "." + B64.EncodeToString(contentKey)
}

// DecodeFragment parses a fragment produced by EncodeFragment.
func DecodeFragment(fragment string) ([]byte, error) {
	f := strings.TrimPrefix(strings.TrimSpace(fragment), "#")
	v, b64, ok := strings.Cut(f, ".")
	if !ok || v != Version {
		return nil, errors.New("peek/crypto: unsupported fragment format")
	}
	k, err := B64.DecodeString(b64)
	if err != nil || len(k) != ContentKeyLen {
		return nil, errors.New("peek/crypto: malformed key in fragment")
	}
	return k, nil
}
