package store

import (
	"crypto/rand"
	"encoding/base64"
)

// newID returns a random identifier for a row: 128 bits, base64url, unpadded.
//
// Row identifiers are random rather than sequential so that a user id in a URL
// or an audit entry reveals nothing about how many accounts exist or in which
// order they were created.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewID is the exported form, for callers that need one before an insert.
func NewID() (string, error) { return newID() }
