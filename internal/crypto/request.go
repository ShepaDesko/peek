package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Secret requests ("send me the password for account X") invert the usual
// direction: the person asking is the one who must end up able to read, and
// the person depositing must not be able to read back what they deposited, nor
// anyone holding the request link.
//
// So the requester generates an ECDH key pair. The public key is stored with
// the request and handed to every depositor; the private key never leaves the
// requester's own "receipt" link fragment. A deposit is an ordinary v1 secret
// (random content key, sealed payload, read-token hash) whose content key is
// wrapped for the requester with ECIES: ephemeral ECDH + HKDF-SHA256 +
// AES-256-GCM.
//
// P-256 and not X25519: X25519 only reached Safari and Firefox recently and
// Peek targets managed enterprise browsers, several versions behind. P-256
// ECDH has been in every WebCrypto implementation for a decade. The reasoning
// is recorded in docs/DECISIONS.md.
const (
	// RequestPrivateKeyLen is the raw P-256 scalar, as carried in the fragment.
	RequestPrivateKeyLen = 32
	// RequestPublicKeyLen is an uncompressed SEC1 P-256 point (0x04 || X || Y).
	RequestPublicKeyLen = 65

	infoRequest       = "peek-request-v1"
	requestAADPrefix  = "peek-req-v1|"
	requestFragmentV1 = "v1r"
)

// RequestBoxLen is the exact size of a wrapped content key:
// ephemeral public key || nonce || ciphertext || tag.
const RequestBoxLen = RequestPublicKeyLen + NonceLen + ContentKeyLen + TagLen

// ErrRequestKey is returned for a malformed request key or box.
var ErrRequestKey = errors.New("peek/crypto: malformed secret-request key")

// NewRequestKeypair generates the requester's key pair. The private half is
// returned as a raw scalar because that is what goes in the URL fragment, and
// what the browser re-imports with WebCrypto.
func NewRequestKeypair() (priv, pub []byte, err error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// RequestAAD binds a wrapped key to one request, so a box captured from one
// request cannot be replayed into another.
func RequestAAD(requestID string) []byte { return []byte(requestAADPrefix + requestID) }

// requestKey derives the AES key wrapping the content key.
//
//	Z   = ECDH(ephemeral private, requester public)   // 32-byte X coordinate
//	key = HKDF-SHA256(ikm = Z || ephPub || reqPub, salt = nil, info = peek-request-v1)
//
// Both public keys are in the IKM so the derivation is bound to the exact pair
// of keys involved: an attacker who substitutes their own ephemeral key cannot
// land on the same key material.
func requestKey(z, ephPub, reqPub []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(z)+len(ephPub)+len(reqPub))
	ikm = append(ikm, z...)
	ikm = append(ikm, ephPub...)
	ikm = append(ikm, reqPub...)
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(newSHA256, ikm, nil, []byte(infoRequest)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// SealToRequest wraps a content key for the holder of the request private key.
func SealToRequest(requesterPub []byte, requestID string, contentKey []byte) ([]byte, error) {
	if len(contentKey) != ContentKeyLen {
		return nil, fmt.Errorf("peek/crypto: content key must be %d bytes", ContentKeyLen)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sealToRequestWith(eph, nil, requesterPub, requestID, contentKey)
}

// SealToRequestWithEphemeral is SealToRequest with a caller-supplied ephemeral
// key and nonce. It exists so the shared test vectors are reproducible; a
// reused ephemeral key or nonce breaks the construction completely.
func SealToRequestWithEphemeral(ephPriv, nonce, requesterPub []byte, requestID string, contentKey []byte) ([]byte, error) {
	if len(ephPriv) != RequestPrivateKeyLen {
		return nil, ErrRequestKey
	}
	eph, err := ecdh.P256().NewPrivateKey(ephPriv)
	if err != nil {
		return nil, ErrRequestKey
	}
	return sealToRequestWith(eph, nonce, requesterPub, requestID, contentKey)
}

func sealToRequestWith(eph *ecdh.PrivateKey, nonce, requesterPub []byte, requestID string, contentKey []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(requesterPub)
	if err != nil {
		return nil, ErrRequestKey
	}
	z, err := eph.ECDH(pub)
	if err != nil {
		return nil, ErrRequestKey
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := requestKey(z, ephPub, requesterPub)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = make([]byte, NonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	sealed, err := SealWithNonce(key, nonce, RequestAAD(requestID), contentKey)
	if err != nil {
		return nil, err
	}
	// sealed is nonce || ciphertext, so the box is ephPub || that.
	return append(append([]byte{}, ephPub...), sealed...), nil
}

// OpenFromRequest unwraps a content key with the requester's private key.
func OpenFromRequest(requesterPriv []byte, requestID string, box []byte) ([]byte, error) {
	if len(requesterPriv) != RequestPrivateKeyLen || len(box) != RequestBoxLen {
		return nil, ErrRequestKey
	}
	priv, err := ecdh.P256().NewPrivateKey(requesterPriv)
	if err != nil {
		return nil, ErrRequestKey
	}
	ephPub := box[:RequestPublicKeyLen]
	eph, err := ecdh.P256().NewPublicKey(ephPub)
	if err != nil {
		return nil, ErrRequestKey
	}
	z, err := priv.ECDH(eph)
	if err != nil {
		return nil, ErrRequestKey
	}
	key, err := requestKey(z, ephPub, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return Open(key, RequestAAD(requestID), box[RequestPublicKeyLen:])
}

// RequestPublicFromPrivate recovers the public key, so the receipt page can
// show the deposit link without storing anything extra.
func RequestPublicFromPrivate(requesterPriv []byte) ([]byte, error) {
	if len(requesterPriv) != RequestPrivateKeyLen {
		return nil, ErrRequestKey
	}
	priv, err := ecdh.P256().NewPrivateKey(requesterPriv)
	if err != nil {
		return nil, ErrRequestKey
	}
	return priv.PublicKey().Bytes(), nil
}

// ValidRequestPublicKey reports whether b is a point on P-256. The server
// checks it on the way in: an invalid point would be a way to attack the
// depositor's ECDH.
func ValidRequestPublicKey(b []byte) bool {
	if len(b) != RequestPublicKeyLen {
		return false
	}
	_, err := ecdh.P256().NewPublicKey(b)
	return err == nil
}

// RequestKey is a requester's key pair. Both halves travel together in the
// receipt fragment: WebCrypto cannot import a P-256 private key from the raw
// scalar alone (a JWK needs x and y, and PKCS#8 support for a key without its
// public half varies between browsers), so the fragment carries the point too.
// It costs 65 bytes in a link and removes a whole class of browser-specific
// failure.
type RequestKey struct {
	Priv []byte
	Pub  []byte
}

// RequestSecretLen is the size of the fragment payload: scalar || SEC1 point.
const RequestSecretLen = RequestPrivateKeyLen + RequestPublicKeyLen

// NewRequestKey generates a requester key pair.
func NewRequestKey() (RequestKey, error) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		return RequestKey{}, err
	}
	return RequestKey{Priv: priv, Pub: pub}, nil
}

// Fragment renders the fragment of the requester's receipt link. The prefix
// differs from a secret fragment so the two can never be confused: one is a
// symmetric key, the other a private key.
func (k RequestKey) Fragment() string {
	blob := make([]byte, 0, RequestSecretLen)
	blob = append(blob, k.Priv...)
	blob = append(blob, k.Pub...)
	return requestFragmentV1 + "." + B64.EncodeToString(blob)
}

// Open unwraps a content key deposited against this request.
func (k RequestKey) Open(requestID string, box []byte) ([]byte, error) {
	return OpenFromRequest(k.Priv, requestID, box)
}

// ParseRequestFragment parses a requester receipt fragment and checks that the
// two halves belong together, so a mangled link fails here rather than later
// with an opaque decryption error.
func ParseRequestFragment(fragment string) (RequestKey, error) {
	f := strings.TrimPrefix(strings.TrimSpace(fragment), "#")
	v, b64, ok := strings.Cut(f, ".")
	if !ok || v != requestFragmentV1 {
		return RequestKey{}, errors.New("peek/crypto: unsupported request fragment format")
	}
	blob, err := B64.DecodeString(b64)
	if err != nil || len(blob) != RequestSecretLen {
		return RequestKey{}, ErrRequestKey
	}
	k := RequestKey{
		Priv: blob[:RequestPrivateKeyLen],
		Pub:  blob[RequestPrivateKeyLen:],
	}
	derived, err := RequestPublicFromPrivate(k.Priv)
	if err != nil {
		return RequestKey{}, err
	}
	if !bytes.Equal(derived, k.Pub) {
		return RequestKey{}, ErrRequestKey
	}
	return k, nil
}

// DepositEnvelope is what a depositor sends to the server, and what the
// requester later gets back. The server cannot read any of it: it holds a
// wrapped key it has no private key for, and a payload sealed under the key
// inside that wrapper.
type DepositEnvelope struct {
	// WrappedKey is the ECIES box carrying the content key.
	WrappedKey []byte `json:"wrapped_key"`
	// Sealed is the ordinary v1 sealed payload (nonce || ciphertext).
	Sealed []byte `json:"sealed"`
}
