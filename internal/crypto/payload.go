package crypto

import (
	"encoding/json"
	"errors"
)

// Payload kinds. A payload is always sealed as a whole: the kind, the sender
// message and any file name are part of the ciphertext, never metadata.
const (
	KindText = "text"
	KindURL  = "url"
	KindFile = "file"
)

// FileRef describes one encrypted attachment. The name, the MIME type and the
// per-file key live inside the sealed payload; the server holds only the
// opaque storage id and the byte count.
type FileRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	MIME string `json:"mime,omitempty"`
	// Size is the plaintext length; the stored stream is a header and a tag
	// per chunk longer.
	Size int64 `json:"size"`
	// Key is the base64url per-file key. It is the reason this structure is
	// never written anywhere but inside a sealed payload.
	Key string `json:"key,omitempty"`
	// ChunkSize is the plaintext chunk size the stream was sealed with.
	ChunkSize int `json:"chunk_size,omitempty"`
}

// Payload is the plaintext structure sealed into every secret. Keep it in sync
// with web/src/crypto/payload.ts.
type Payload struct {
	V       int       `json:"v"`
	Kind    string    `json:"kind"`
	Text    string    `json:"text,omitempty"`
	URL     string    `json:"url,omitempty"`
	Message string    `json:"message,omitempty"`
	Files   []FileRef `json:"files,omitempty"`
}

// Marshal renders the payload as the canonical JSON that gets sealed.
func (p Payload) Marshal() ([]byte, error) {
	if p.V == 0 {
		p.V = 1
	}
	switch p.Kind {
	case KindText, KindURL, KindFile:
	default:
		return nil, errors.New("peek/crypto: unknown payload kind")
	}
	return json.Marshal(p)
}

// UnmarshalPayload parses a sealed payload.
func UnmarshalPayload(b []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(b, &p); err != nil {
		return Payload{}, err
	}
	if p.V != 1 {
		return Payload{}, errors.New("peek/crypto: unsupported payload version")
	}
	return p, nil
}
