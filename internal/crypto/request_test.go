package crypto

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != RequestPrivateKeyLen || len(pub) != RequestPublicKeyLen {
		t.Fatalf("key sizes: priv %d, pub %d", len(priv), len(pub))
	}

	ck, err := NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	box, err := SealToRequest(pub, "req-1", ck)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != RequestBoxLen {
		t.Errorf("box is %d bytes, RequestBoxLen says %d", len(box), RequestBoxLen)
	}

	got, err := OpenFromRequest(priv, "req-1", box)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ck) {
		t.Error("unwrapped content key does not match")
	}
}

func TestRequestBoxIsBoundToTheRequest(t *testing.T) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := NewContentKey()
	box, err := SealToRequest(pub, "req-1", ck)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying a deposit into another request would let someone swap what a
	// requester believes they received.
	if _, err := OpenFromRequest(priv, "req-2", box); err == nil {
		t.Error("a box sealed for req-1 opened under req-2")
	}
}

func TestRequestWrongPrivateKeyFails(t *testing.T) {
	_, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := NewContentKey()
	box, err := SealToRequest(pub, "req", ck)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFromRequest(other, "req", box); err == nil {
		t.Error("opened with an unrelated private key")
	}
}

func TestRequestEphemeralKeySubstitutionFails(t *testing.T) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := NewContentKey()
	box, err := SealToRequest(pub, "req", ck)
	if err != nil {
		t.Fatal(err)
	}

	// Swapping in another ephemeral public key changes the IKM, because both
	// public keys are part of it, so the derived key no longer matches.
	_, otherEph, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, box...)
	copy(tampered[:RequestPublicKeyLen], otherEph)
	if _, err := OpenFromRequest(priv, "req", tampered); err == nil {
		t.Error("opened after the ephemeral public key was replaced")
	}
}

func TestRequestRejectsInvalidPublicKey(t *testing.T) {
	_, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidRequestPublicKey(pub) {
		t.Fatal("a freshly generated public key was rejected")
	}
	if ValidRequestPublicKey(pub[:len(pub)-1]) {
		t.Error("accepted a truncated public key")
	}

	// A point that is not on the curve: the server must refuse it on the way
	// in, because an invalid point is a way to attack the depositor's ECDH.
	off := append([]byte{}, pub...)
	off[len(off)-1] ^= 0x01
	if ValidRequestPublicKey(off) {
		t.Error("accepted a point that is not on P-256")
	}
	if _, err := SealToRequest(off, "req", make([]byte, ContentKeyLen)); err == nil {
		t.Error("sealed to a point that is not on P-256")
	}

	zero := make([]byte, RequestPublicKeyLen)
	if ValidRequestPublicKey(zero) {
		t.Error("accepted an all-zero public key")
	}
}

func TestRequestPublicFromPrivate(t *testing.T) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequestPublicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pub) {
		t.Error("recovered public key does not match")
	}
	if _, err := RequestPublicFromPrivate(priv[:8]); err == nil {
		t.Error("accepted a short private key")
	}
}

func TestRequestFragment(t *testing.T) {
	k, err := NewRequestKey()
	if err != nil {
		t.Fatal(err)
	}
	frag := k.Fragment()
	got, err := ParseRequestFragment("#" + frag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Priv, k.Priv) || !bytes.Equal(got.Pub, k.Pub) {
		t.Error("fragment round trip mismatch")
	}

	// A secret fragment and a request fragment must never be interchangeable:
	// one is a symmetric key, the other a private key.
	if _, err := DecodeFragment(frag); err == nil {
		t.Error("a request fragment parsed as a secret fragment")
	}
	ck, _ := NewContentKey()
	if _, err := ParseRequestFragment(EncodeFragment(ck)); err == nil {
		t.Error("a secret fragment parsed as a request fragment")
	}

	// Mismatched halves are caught at parse time, not at decryption time.
	other, err := NewRequestKey()
	if err != nil {
		t.Fatal(err)
	}
	mixed := RequestKey{Priv: k.Priv, Pub: other.Pub}
	if _, err := ParseRequestFragment(mixed.Fragment()); err == nil {
		t.Error("a fragment whose halves do not match was accepted")
	}

	// And the key still opens a real box.
	box, err := SealToRequest(got.Pub, "req", ck)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := got.Open("req", box)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, ck) {
		t.Error("key parsed from a fragment did not unwrap the content key")
	}
}

func TestSealToRequestWithEphemeralIsDeterministic(t *testing.T) {
	priv, pub, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, _, err := NewRequestKeypair()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{3}, NonceLen)
	ck, _ := NewContentKey()

	first, err := SealToRequestWithEphemeral(ephPriv, nonce, pub, "req", ck)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealToRequestWithEphemeral(ephPriv, nonce, pub, "req", ck)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("the vector seam is not deterministic")
	}
	got, err := OpenFromRequest(priv, "req", first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ck) {
		t.Error("deterministic box does not open to the content key")
	}
}
