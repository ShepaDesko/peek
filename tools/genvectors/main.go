// Command genvectors writes crypto/vectors/v1.json, the shared test vectors
// that the Go, TypeScript and CLI implementations must all reproduce.
//
// Run it with: go run ./tools/genvectors
//
// The inputs are fixed and hand-written; only the expected outputs are
// computed, by the Go reference implementation.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

type kdf struct {
	SaltB64     string `json:"salt_b64"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

type expect struct {
	FinalKeyB64      string `json:"final_key_b64"`
	EncKeyB64        string `json:"enc_key_b64"`
	ReadTokenB64     string `json:"read_token_b64"`
	ReadTokenHashB64 string `json:"read_token_hash_b64"`
	SealedB64        string `json:"sealed_b64"`
	FragmentID       string `json:"fragment"`
}

type vector struct {
	Name          string `json:"name"`
	ContentKeyB64 string `json:"content_key_b64"`
	Passphrase    string `json:"passphrase"`
	KDF           kdf    `json:"kdf"`
	SecretID      string `json:"secret_id"`
	NonceB64      string `json:"nonce_b64"`
	PlaintextUTF8 string `json:"plaintext_utf8"`
	Expect        expect `json:"expect"`
}

// fileVector pins the chunked file format (internal/crypto/file.go and
// web/src/crypto/file.ts).
type fileVector struct {
	Name           string `json:"name"`
	FileKeyB64     string `json:"file_key_b64"`
	ChunkSize      int    `json:"chunk_size"`
	NoncePrefixB64 string `json:"nonce_prefix_b64"`
	PlaintextB64   string `json:"plaintext_b64"`
	Expect         struct {
		DerivedKeyB64 string `json:"derived_key_b64"`
		StreamB64     string `json:"stream_b64"`
		StreamLen     int    `json:"stream_len"`
	} `json:"expect"`
}

// requestVector pins the ECIES wrapping used by secret requests
// (internal/crypto/request.go and web/src/crypto/request.ts).
type requestVector struct {
	Name                string `json:"name"`
	RequesterPrivateB64 string `json:"requester_private_b64"`
	RequesterPublicB64  string `json:"requester_public_b64"`
	EphemeralPrivateB64 string `json:"ephemeral_private_b64"`
	NonceB64            string `json:"nonce_b64"`
	RequestID           string `json:"request_id"`
	ContentKeyB64       string `json:"content_key_b64"`
	Expect              struct {
		EphemeralPublicB64 string `json:"ephemeral_public_b64"`
		BoxB64             string `json:"box_b64"`
		Fragment           string `json:"fragment"`
	} `json:"expect"`
}

type file struct {
	Version  string          `json:"version"`
	Note     string          `json:"note"`
	Cases    []vector        `json:"cases"`
	Files    []fileVector    `json:"file_cases"`
	Requests []requestVector `json:"request_cases"`
}

// vectorPassphrase is an input of the published test vectors, not a
// credential: it exists so both implementations stretch the same string.
const vectorPassphrase = "Hunter2-Tr\u00e8s-Secret-\u00e9\u00e0\u00fc" //nolint:gosec // see above

func b(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)*7 + seed
	}
	return out
}

func main() {
	e := pcrypto.B64.EncodeToString

	cases := []vector{
		{
			Name:          "text-no-passphrase",
			ContentKeyB64: e(b(32, 1)),
			Passphrase:    "",
			KDF:           kdf{SaltB64: e(b(16, 9)), MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
			SecretID:      e(b(16, 3)),
			NonceB64:      e(b(12, 5)),
			PlaintextUTF8: `{"v":1,"kind":"text","text":"correct horse battery staple"}`,
		},
		{
			Name:          "text-with-passphrase-default-params",
			ContentKeyB64: e(b(32, 2)),
			Passphrase:    vectorPassphrase,
			KDF:           kdf{SaltB64: e(b(16, 11)), MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
			SecretID:      e(b(16, 4)),
			NonceB64:      e(b(12, 6)),
			PlaintextUTF8: `{"v":1,"kind":"text","text":"mot de passe: p@ssw0rd","message":"Bonjour"}`,
		},
		{
			Name:          "text-with-passphrase-cheap-params",
			ContentKeyB64: e(b(32, 3)),
			Passphrase:    "short",
			KDF:           kdf{SaltB64: e(b(16, 12)), MemoryKiB: 8192, Iterations: 1, Parallelism: 1},
			SecretID:      e(b(16, 5)),
			NonceB64:      e(b(12, 7)),
			PlaintextUTF8: `{"v":1,"kind":"url","url":"https://example.invalid/x"}`,
		},
		{
			Name:          "empty-plaintext",
			ContentKeyB64: e(b(32, 4)),
			Passphrase:    "",
			KDF:           kdf{SaltB64: e(b(16, 13)), MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
			SecretID:      e(b(16, 6)),
			NonceB64:      e(b(12, 8)),
			PlaintextUTF8: "",
		},
	}

	for i := range cases {
		c := &cases[i]
		ck, err := pcrypto.B64.DecodeString(c.ContentKeyB64)
		must(err)
		salt, err := pcrypto.B64.DecodeString(c.KDF.SaltB64)
		must(err)
		nonce, err := pcrypto.B64.DecodeString(c.NonceB64)
		must(err)

		keys, err := pcrypto.DeriveKeys(ck, c.Passphrase, pcrypto.KDFParams{
			Salt:        salt,
			MemoryKiB:   c.KDF.MemoryKiB,
			Iterations:  c.KDF.Iterations,
			Parallelism: c.KDF.Parallelism,
		})
		must(err)

		sealed, err := pcrypto.SealWithNonce(keys.Enc, nonce, pcrypto.AAD(c.SecretID), []byte(c.PlaintextUTF8))
		must(err)

		c.Expect = expect{
			FinalKeyB64:      e(keys.Final),
			EncKeyB64:        e(keys.Enc),
			ReadTokenB64:     e(keys.ReadToken),
			ReadTokenHashB64: e(keys.ReadTokenHash),
			SealedB64:        e(sealed),
			FragmentID:       pcrypto.EncodeFragment(ck),
		}
	}

	fileCases := buildFileCases()
	requestCases := buildRequestCases()

	out := file{
		Version:  pcrypto.Version,
		Note:     "Generated by go run ./tools/genvectors. All byte strings are base64url, unpadded. Every implementation (Go server, Go CLI, browser TS) must reproduce the expect block exactly.",
		Cases:    cases,
		Files:    fileCases,
		Requests: requestCases,
	}

	buf, err := json.MarshalIndent(out, "", "  ")
	must(err)
	buf = append(buf, '\n')

	path := filepath.Join("crypto", "vectors", "v1.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755)) //nolint:gosec // a repository directory
	must(os.WriteFile(path, buf, 0o644))         //nolint:gosec // a repository file, committed as is
	fmt.Printf("wrote %s (%d cases)\n", path, len(cases))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}

// buildFileCases covers the boundaries that have historically been got wrong:
// an empty file (one chunk, final), an exact multiple of the chunk size (no
// spurious empty chunk), and a stream of several chunks (counter in the nonce).
func buildFileCases() []fileVector {
	e := pcrypto.B64.EncodeToString
	const chunk = pcrypto.MinChunkSize

	type input struct {
		name  string
		key   []byte
		plain []byte
		pfx   []byte
	}
	inputs := []input{
		{"file-empty", b(32, 21), nil, b(7, 41)},
		{"file-short", b(32, 22), []byte("Peek file, one short chunk."), b(7, 42)},
		{"file-exact-one-chunk", b(32, 23), b(chunk, 43), b(7, 44)},
		{"file-three-chunks-and-a-bit", b(32, 24), b(3*chunk+17, 45), b(7, 46)},
	}

	out := make([]fileVector, 0, len(inputs))
	for _, in := range inputs {
		h := pcrypto.FileHeader{ChunkSize: chunk, NoncePrefix: in.pfx}
		stream, err := pcrypto.SealFileWithHeader(in.key, h, in.plain)
		must(err)
		derived, err := pcrypto.DeriveFileKey(in.key)
		must(err)

		// A vector nobody can open is worse than no vector at all.
		back, err := pcrypto.OpenFile(in.key, stream)
		must(err)
		if string(back) != string(in.plain) {
			must(fmt.Errorf("%s: round trip mismatch", in.name))
		}

		v := fileVector{
			Name:           in.name,
			FileKeyB64:     e(in.key),
			ChunkSize:      chunk,
			NoncePrefixB64: e(in.pfx),
			PlaintextB64:   e(in.plain),
		}
		v.Expect.DerivedKeyB64 = e(derived)
		v.Expect.StreamB64 = e(stream)
		v.Expect.StreamLen = len(stream)
		out = append(out, v)
	}
	return out
}

// buildRequestCases pins the ECIES wrapping. The scalars are fixed inputs of
// the vectors, never keys of a running instance.
func buildRequestCases() []requestVector {
	e := pcrypto.B64.EncodeToString

	type input struct {
		name    string
		reqPriv []byte
		ephPriv []byte
		nonce   []byte
		id      string
		ck      []byte
	}
	inputs := []input{
		{"request-wrap", b(32, 51), b(32, 52), b(12, 53), "cmVxLWFscGhhLTAwMDAwMA", b(32, 54)},
		{"request-wrap-other-id", b(32, 55), b(32, 56), b(12, 57), "cmVxLWJyYXZvLTAwMDAwMDA", b(32, 58)},
	}

	out := make([]requestVector, 0, len(inputs))
	for _, in := range inputs {
		reqPub, err := pcrypto.RequestPublicFromPrivate(in.reqPriv)
		must(err)
		ephPub, err := pcrypto.RequestPublicFromPrivate(in.ephPriv)
		must(err)
		box, err := pcrypto.SealToRequestWithEphemeral(in.ephPriv, in.nonce, reqPub, in.id, in.ck)
		must(err)

		back, err := pcrypto.OpenFromRequest(in.reqPriv, in.id, box)
		must(err)
		if string(back) != string(in.ck) {
			must(fmt.Errorf("%s: round trip mismatch", in.name))
		}

		v := requestVector{
			Name:                in.name,
			RequesterPrivateB64: e(in.reqPriv),
			RequesterPublicB64:  e(reqPub),
			EphemeralPrivateB64: e(in.ephPriv),
			NonceB64:            e(in.nonce),
			RequestID:           in.id,
			ContentKeyB64:       e(in.ck),
		}
		v.Expect.EphemeralPublicB64 = e(ephPub)
		v.Expect.BoxB64 = e(box)
		v.Expect.Fragment = pcrypto.RequestKey{Priv: in.reqPriv, Pub: reqPub}.Fragment()
		out = append(out, v)
	}
	return out
}
