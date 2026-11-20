package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// Server-side encryption at rest.
//
// Secret payloads are sealed in the browser and the server cannot read them.
// A few pieces of metadata, however, are the server's own and must survive a
// stolen database file: TOTP seeds, SMTP and OIDC credentials, recipient
// e-mail addresses. Those are encrypted with a key derived from
// /etc/peek/master.key, which lives outside the database on purpose.
//
// Each purpose gets its own derived key, so a bug in one area cannot decrypt
// another, and every ciphertext is bound to a context string.

const (
	// MasterKeyLen is the size of the file in /etc/peek/master.key.
	MasterKeyLen = 32

	infoServer = "peek-server-v1"
)

// ErrNoMasterKey is returned when a feature needs the master key and the
// instance has none.
var ErrNoMasterKey = errors.New("peek/crypto: no master key configured")

// ServerCipher encrypts server-side metadata.
type ServerCipher struct {
	aead cipher.AEAD
}

// NewServerCipher derives the encryption key from the master key material.
func NewServerCipher(master []byte) (*ServerCipher, error) {
	if len(master) < MasterKeyLen {
		return nil, fmt.Errorf("peek/crypto: master key must be at least %d bytes, got %d", MasterKeyLen, len(master))
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(newSHA256, master, nil, []byte(infoServer)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ServerCipher{aead: aead}, nil
}

// LoadServerCipher reads the master key file and derives the cipher.
func LoadServerCipher(path string) (*ServerCipher, error) {
	if path == "" {
		return nil, ErrNoMasterKey
	}
	material, err := os.ReadFile(path) //nolint:gosec // the configured master key path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist (run sudo peek key rotate --init)", ErrNoMasterKey, path)
		}
		return nil, fmt.Errorf("peek/crypto: read %s: %w", path, err)
	}
	return NewServerCipher(material)
}

// Seal encrypts plaintext for a purpose. The purpose is authenticated, so a
// value cannot be moved from one column to another.
func (c *ServerCipher) Seal(purpose string, plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNoMasterKey
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, nonce...)
	return c.aead.Seal(out, nonce, plaintext, []byte(purpose)), nil
}

// SealString is Seal for text values.
func (c *ServerCipher) SealString(purpose, plaintext string) ([]byte, error) {
	return c.Seal(purpose, []byte(plaintext))
}

// Open decrypts a blob produced by Seal with the same purpose.
func (c *ServerCipher) Open(purpose string, blob []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNoMasterKey
	}
	n := c.aead.NonceSize()
	if len(blob) < n+16 {
		return nil, errors.New("peek/crypto: stored value is too short to be valid")
	}
	out, err := c.aead.Open(nil, blob[:n], blob[n:], []byte(purpose))
	if err != nil {
		return nil, fmt.Errorf("peek/crypto: cannot decrypt stored %s (wrong or rotated master key?)", purpose)
	}
	return out, nil
}

// OpenString is Open for text values.
func (c *ServerCipher) OpenString(purpose string, blob []byte) (string, error) {
	out, err := c.Open(purpose, blob)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Purposes used across the code base. Keep them stable: they are part of the
// stored format.
const (
	PurposeTOTP     = "totp-secret"
	PurposeSMTP     = "smtp-password"
	PurposeOIDC     = "oidc-client-secret"
	PurposeEmail    = "recipient-email"
	PurposeWebhook  = "webhook-secret"
	PurposeBranding = "branding-asset"
)
