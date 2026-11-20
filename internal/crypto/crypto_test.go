package crypto_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

type vectorFile struct {
	Version string `json:"version"`
	Cases   []struct {
		Name          string `json:"name"`
		ContentKeyB64 string `json:"content_key_b64"`
		Passphrase    string `json:"passphrase"`
		KDF           struct {
			SaltB64     string `json:"salt_b64"`
			MemoryKiB   uint32 `json:"memory_kib"`
			Iterations  uint32 `json:"iterations"`
			Parallelism uint8  `json:"parallelism"`
		} `json:"kdf"`
		SecretID      string `json:"secret_id"`
		NonceB64      string `json:"nonce_b64"`
		PlaintextUTF8 string `json:"plaintext_utf8"`
		Expect        struct {
			FinalKeyB64      string `json:"final_key_b64"`
			EncKeyB64        string `json:"enc_key_b64"`
			ReadTokenB64     string `json:"read_token_b64"`
			ReadTokenHashB64 string `json:"read_token_hash_b64"`
			SealedB64        string `json:"sealed_b64"`
			FragmentID       string `json:"fragment"`
		} `json:"expect"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "crypto", "vectors", "v1.json")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(buf, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if vf.Version != pcrypto.Version {
		t.Fatalf("vector file version %q, implementation %q", vf.Version, pcrypto.Version)
	}
	if len(vf.Cases) == 0 {
		t.Fatal("no vectors")
	}
	return vf
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := pcrypto.B64.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

// TestVectors is the contract between the Go and TypeScript implementations.
// web/src/crypto/crypto.test.ts runs the exact same assertions.
func TestVectors(t *testing.T) {
	for _, c := range loadVectors(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			ck := decode(t, c.ContentKeyB64)
			params := pcrypto.KDFParams{
				Salt:        decode(t, c.KDF.SaltB64),
				MemoryKiB:   c.KDF.MemoryKiB,
				Iterations:  c.KDF.Iterations,
				Parallelism: c.KDF.Parallelism,
			}
			keys, err := pcrypto.DeriveKeys(ck, c.Passphrase, params)
			if err != nil {
				t.Fatalf("DeriveKeys: %v", err)
			}

			eq := func(label string, got []byte, wantB64 string) {
				if want := decode(t, wantB64); !bytes.Equal(got, want) {
					t.Errorf("%s = %s, want %s", label, pcrypto.B64.EncodeToString(got), wantB64)
				}
			}
			eq("final", keys.Final, c.Expect.FinalKeyB64)
			eq("enc", keys.Enc, c.Expect.EncKeyB64)
			eq("read token", keys.ReadToken, c.Expect.ReadTokenB64)
			eq("read token hash", keys.ReadTokenHash, c.Expect.ReadTokenHashB64)

			sealed, err := pcrypto.SealWithNonce(keys.Enc, decode(t, c.NonceB64), pcrypto.AAD(c.SecretID), []byte(c.PlaintextUTF8))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			eq("sealed", sealed, c.Expect.SealedB64)

			pt, err := pcrypto.Open(keys.Enc, pcrypto.AAD(c.SecretID), decode(t, c.Expect.SealedB64))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(pt) != c.PlaintextUTF8 {
				t.Errorf("round trip mismatch")
			}
			if got := pcrypto.EncodeFragment(ck); got != c.Expect.FragmentID {
				t.Errorf("fragment = %q, want %q", got, c.Expect.FragmentID)
			}
		})
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	sealed, err := pcrypto.Seal(key, pcrypto.AAD("id-one"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pcrypto.Open(key, pcrypto.AAD("id-two"), sealed); err == nil {
		t.Fatal("ciphertext accepted under a different secret id")
	}
	if _, err := pcrypto.Open(key, pcrypto.AAD("id-one"), sealed[:len(sealed)-1]); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestWrongPassphraseYieldsDifferentReadToken(t *testing.T) {
	ck, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	params, err := pcrypto.DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	params.MemoryKiB = 8192
	params.Iterations = 1

	good, err := pcrypto.DeriveKeys(ck, "right", params)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := pcrypto.DeriveKeys(ck, "wrong", params)
	if err != nil {
		t.Fatal(err)
	}
	if pcrypto.EqualHash(good.ReadTokenHash, bad.ReadTokenHash) {
		t.Fatal("a wrong passphrase produced the same read token hash")
	}
	// The whole point of the proof of possession: the server can reject the
	// wrong passphrase without touching the ciphertext or a view counter.
	if !pcrypto.EqualHash(good.ReadTokenHash, pcrypto.HashReadToken(good.ReadToken)) {
		t.Fatal("HashReadToken disagrees with DeriveKeys")
	}
}

func TestFragmentRoundTrip(t *testing.T) {
	ck, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := pcrypto.DecodeFragment("#" + pcrypto.EncodeFragment(ck))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ck) {
		t.Fatal("fragment round trip mismatch")
	}
	for _, bad := range []string{"", "v0.AAAA", "v1.!!!", "v1." + pcrypto.B64.EncodeToString([]byte{1, 2, 3})} {
		if _, err := pcrypto.DecodeFragment(bad); err == nil {
			t.Errorf("DecodeFragment(%q) accepted", bad)
		}
	}
}

func TestIDs(t *testing.T) {
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !pcrypto.ValidID(id) {
		t.Fatalf("NewID produced an invalid id: %q", id)
	}
	for _, bad := range []string{"", "short", id + "x", "................."} {
		if pcrypto.ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	in := pcrypto.Payload{Kind: pcrypto.KindText, Text: "hello", Message: "salut"}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := pcrypto.UnmarshalPayload(buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != in.Text || out.Message != in.Message || out.V != 1 {
		t.Fatalf("payload mismatch: %+v", out)
	}
	if _, err := (pcrypto.Payload{Kind: "nope"}).Marshal(); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
