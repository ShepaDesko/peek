package crypto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

// Benchmarks for the three operations that decide how Peek feels.
//
// They are here to be *compared*, not to produce an absolute number: the
// passphrase derivation is deliberately slow, and the useful question is
// whether it is still roughly as slow as it was meant to be after someone
// touches the parameters. `go test ./internal/crypto -bench . -benchmem`.

func BenchmarkSeal(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			b.Fatal(err)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			b.Fatal(err)
		}
		aad := pcrypto.AAD("KJh8s0LmNpQrStUvWxYz12")

		b.Run(humanBytes(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := pcrypto.Seal(key, aad, plaintext); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDeriveKeys is the passphrase path: Argon2id with the shipped
// parameters. It is meant to take a noticeable fraction of a second, because
// that is what makes an offline guess expensive. A benchmark that suddenly
// reports a tenth of the previous figure means the parameters were weakened.
func BenchmarkDeriveKeys(b *testing.B) {
	key, err := pcrypto.NewContentKey()
	if err != nil {
		b.Fatal(err)
	}
	params, err := pcrypto.DefaultKDFParams()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := pcrypto.DeriveKeys(key, "un-mot-de-passe-correct-2026", params); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeriveKeysNoPassphrase is the common path — no passphrase, so no
// Argon2id at all. The gap between this and the one above is the whole reason
// the passphrase is optional.
func BenchmarkDeriveKeysNoPassphrase(b *testing.B) {
	key, err := pcrypto.NewContentKey()
	if err != nil {
		b.Fatal(err)
	}
	params, err := pcrypto.DefaultKDFParams()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := pcrypto.DeriveKeys(key, "", params); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSealFileStream is the attachment path, chunk by chunk, which is how
// a 100 MiB file is encrypted without ever being held whole.
func BenchmarkSealFileStream(b *testing.B) {
	const size = 8 << 20
	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}
	key := make([]byte, pcrypto.FileKeyLen)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := pcrypto.SealFileStream(key, pcrypto.DefaultChunkSize,
			bytes.NewReader(plaintext), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenFileStream(b *testing.B) {
	const size = 8 << 20
	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}
	key := make([]byte, pcrypto.FileKeyLen)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	var sealed bytes.Buffer
	if _, err := pcrypto.SealFileStream(key, pcrypto.DefaultChunkSize,
		bytes.NewReader(plaintext), &sealed); err != nil {
		b.Fatal(err)
	}
	stream := sealed.Bytes()

	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := pcrypto.OpenFileStream(key, bytes.NewReader(stream), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return itoa(n>>20) + "MiB"
	case n >= 1<<10:
		return itoa(n>>10) + "KiB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
