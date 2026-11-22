package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func testFileKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFileRoundTripSizes(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize

	// Boundaries matter: an empty file still has one chunk, and a file that is
	// an exact multiple of the chunk size must not grow a spurious empty one.
	for _, size := range []int{0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3*chunk + 7} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i * 31)
		}

		stream, err := SealFile(key, chunk, plain)
		if err != nil {
			t.Fatalf("size %d: seal: %v", size, err)
		}
		if want := EncryptedFileSize(int64(size), chunk); int64(len(stream)) != want {
			t.Errorf("size %d: stream is %d bytes, EncryptedFileSize says %d", size, len(stream), want)
		}
		if got, err := PlainFileSize(int64(len(stream)), chunk); err != nil || got != int64(size) {
			t.Errorf("size %d: PlainFileSize = %d, %v", size, got, err)
		}

		got, err := OpenFile(key, stream)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("size %d: round trip mismatch", size)
		}
	}
}

func TestFileStreamMatchesInMemory(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize
	plain := make([]byte, 2*chunk+123)
	for i := range plain {
		plain[i] = byte(i)
	}

	var sealed bytes.Buffer
	n, err := SealFileStream(key, chunk, bytes.NewReader(plain), &sealed)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(sealed.Len()) {
		t.Errorf("SealFileStream reported %d bytes, wrote %d", n, sealed.Len())
	}

	// The streaming path must produce something the in-memory path can open,
	// and vice versa: they are one format, not two.
	got, err := OpenFile(key, sealed.Bytes())
	if err != nil {
		t.Fatalf("OpenFile on streamed output: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("streamed then opened in memory: mismatch")
	}

	inMemory, err := SealFile(key, chunk, plain)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := OpenFileStream(key, bytes.NewReader(inMemory), &out); err != nil {
		t.Fatalf("OpenFileStream on in-memory output: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("sealed in memory then streamed open: mismatch")
	}
}

func TestFileStreamEmptyAndExactMultiple(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize
	for _, size := range []int{0, chunk, 2 * chunk} {
		plain := bytes.Repeat([]byte{0xAB}, size)
		var sealed, out bytes.Buffer
		if _, err := SealFileStream(key, chunk, bytes.NewReader(plain), &sealed); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if _, err := OpenFileStream(key, bytes.NewReader(sealed.Bytes()), &out); err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Errorf("size %d: mismatch", size)
		}
	}
}

func TestFileTruncationIsDetected(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize
	plain := bytes.Repeat([]byte{7}, 3*chunk)
	stream, err := SealFile(key, chunk, plain)
	if err != nil {
		t.Fatal(err)
	}

	// Dropping the last chunk leaves a stream of perfectly valid chunks. Only
	// the final flag says the file is over, which is the whole point.
	cut := stream[:FileHeaderLen+2*(chunk+TagLen)]
	if _, err := OpenFile(key, cut); !errors.Is(err, ErrTruncated) {
		t.Errorf("OpenFile on truncated stream: got %v, want ErrTruncated", err)
	}
	var out bytes.Buffer
	if _, err := OpenFileStream(key, bytes.NewReader(cut), &out); !errors.Is(err, ErrTruncated) {
		t.Errorf("OpenFileStream on truncated stream: got %v, want ErrTruncated", err)
	}

	// Header only.
	if _, err := OpenFile(key, stream[:FileHeaderLen]); err == nil {
		t.Error("header-only stream opened")
	}
	out.Reset()
	if _, err := OpenFileStream(key, bytes.NewReader(stream[:FileHeaderLen]), &out); !errors.Is(err, ErrTruncated) {
		t.Errorf("OpenFileStream on header-only stream: got %v, want ErrTruncated", err)
	}
}

func TestFileChunkReorderingFails(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize
	plain := make([]byte, 3*chunk)
	for i := range plain {
		plain[i] = byte(i / chunk)
	}
	stream, err := SealFile(key, chunk, plain)
	if err != nil {
		t.Fatal(err)
	}

	sealedLen := chunk + TagLen
	swapped := append([]byte{}, stream...)
	a := swapped[FileHeaderLen : FileHeaderLen+sealedLen]
	b := swapped[FileHeaderLen+sealedLen : FileHeaderLen+2*sealedLen]
	tmp := append([]byte{}, a...)
	copy(a, b)
	copy(b, tmp)

	if _, err := OpenFile(key, swapped); err == nil {
		t.Error("reordered chunks opened; the counter is not authenticated")
	}
}

func TestFileHeaderIsAuthenticated(t *testing.T) {
	key := testFileKey(t)
	const chunk = MinChunkSize
	stream, err := SealFile(key, chunk, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Flipping a bit of the nonce prefix must not just shift the nonce: the
	// header is the AAD, so the chunk stops authenticating.
	tampered := append([]byte{}, stream...)
	tampered[FileHeaderLen-1] ^= 0x01
	if _, err := OpenFile(key, tampered); err == nil {
		t.Error("tampered nonce prefix opened")
	}

	// A different chunk size in the header, but the same bytes: also rejected.
	tampered = append([]byte{}, stream...)
	tampered[len(FileMagic)+3] ^= 0x01
	if _, err := OpenFile(key, tampered); err == nil {
		t.Error("tampered chunk size opened")
	}

	if _, err := ParseFileHeader([]byte("NOTPEEK0123456789")); !errors.Is(err, ErrFileFormat) {
		t.Errorf("ParseFileHeader on foreign data: got %v", err)
	}
}

func TestFileWrongKeyFails(t *testing.T) {
	key := testFileKey(t)
	other := testFileKey(t)
	stream, err := SealFile(key, MinChunkSize, []byte("some bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(other, stream); err == nil {
		t.Error("opened with the wrong file key")
	}
}

func TestFileSealerRefusesShortNonFinalChunk(t *testing.T) {
	key := testFileKey(t)
	s, _, err := NewFileSealer(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(make([]byte, 10), false); err == nil {
		t.Error("sealed a short non-final chunk; the stream would be unopenable")
	}
	if _, err := s.Seal(nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(nil, true); err == nil {
		t.Error("sealed a chunk after the final one")
	}
}

func TestChunkSizeBounds(t *testing.T) {
	if _, err := NewFileHeader(MinChunkSize - 1); err == nil {
		t.Error("accepted a chunk size below the floor")
	}
	if _, err := NewFileHeader(MaxChunkSize + 1); err == nil {
		t.Error("accepted a chunk size above the ceiling")
	}
}

func TestEncryptedFileSizeKnownValues(t *testing.T) {
	// The server rejects an upload whose announced length does not match, so
	// these numbers are part of the protocol, not an implementation detail.
	cases := []struct {
		plain int64
		chunk int
		want  int64
	}{
		{0, 1 << 20, int64(FileHeaderLen) + 16},
		{1, 1 << 20, int64(FileHeaderLen) + 1 + 16},
		{1 << 20, 1 << 20, int64(FileHeaderLen) + (1 << 20) + 16},
		{(1 << 20) + 1, 1 << 20, int64(FileHeaderLen) + (1 << 20) + 1 + 32},
		{100 << 20, 1 << 20, int64(FileHeaderLen) + (100 << 20) + 100*16},
	}
	for _, c := range cases {
		if got := EncryptedFileSize(c.plain, c.chunk); got != c.want {
			t.Errorf("EncryptedFileSize(%d, %d) = %d, want %d", c.plain, c.chunk, got, c.want)
		}
	}
}
