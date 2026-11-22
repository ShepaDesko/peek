package crypto

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The chunked file format (v1).
//
// A file is encrypted in the browser before it ever reaches the server, in
// chunks, so that a 100 MiB upload does not need 100 MiB of contiguous
// plaintext in a tab's memory and so that the server can stream the bytes
// straight to storage without ever holding a key.
//
// The construction is STREAM (Rogaway & Hoang, as used by age): a per-stream
// random nonce prefix, a chunk counter inside the nonce, and a final-chunk
// flag byte. That is what authenticates *order* and *end of stream*:
//
//   - reordering two chunks changes the counter each one was sealed under, so
//     both fail to open;
//   - truncating the stream removes the chunk carrying the final flag, so the
//     reader refuses the whole file instead of returning a short one;
//   - appending chunks after the final one fails for the same reason.
//
// The stream header is the AAD of every chunk, which binds the chunk size and
// the nonce prefix to the ciphertext. File names and MIME types are *not* in
// here: they live in the sealed Payload (see payload.go), so the server sees
// nothing but an opaque blob and its length.
const (
	// FileMagic identifies the stream and its version.
	FileMagic = "PEEKF1"
	// FileNoncePrefixLen is the random per-stream part of each chunk nonce.
	// 7 + 4 (counter) + 1 (final flag) = NonceLen.
	FileNoncePrefixLen = 7
	// FileHeaderLen is magic || chunk size (uint32 BE) || nonce prefix.
	FileHeaderLen = len(FileMagic) + 4 + FileNoncePrefixLen
	// FileKeyLen is the size of the per-file key carried in the payload.
	FileKeyLen = 32
	// TagLen is the AES-GCM authentication tag size.
	TagLen = 16

	infoFile = "peek-file-v1"
)

// Chunk sizes. 1 MiB keeps the per-chunk overhead negligible (16 bytes of tag
// per MiB) while staying small enough to encrypt and upload progressively.
const (
	DefaultChunkSize = 1 << 20
	MinChunkSize     = 1 << 10
	MaxChunkSize     = 8 << 20
)

// ErrFileFormat is returned for a stream that is not a Peek file stream.
var ErrFileFormat = errors.New("peek/crypto: not a Peek file stream")

// ErrTruncated is returned when a stream ends without its final chunk. It is
// deliberately distinct from ErrOpen: nothing is wrong with the key, the file
// is incomplete and must not be shown as if it were whole.
var ErrTruncated = errors.New("peek/crypto: file stream is truncated")

// FileHeader is the cleartext preamble of an encrypted file stream. It carries
// no secret: the nonce prefix is public by construction.
type FileHeader struct {
	ChunkSize   int
	NoncePrefix []byte
}

// NewFileHeader returns a header with a fresh random nonce prefix.
func NewFileHeader(chunkSize int) (FileHeader, error) {
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return FileHeader{}, fmt.Errorf("peek/crypto: chunk size %d out of range [%d, %d]",
			chunkSize, MinChunkSize, MaxChunkSize)
	}
	prefix := make([]byte, FileNoncePrefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return FileHeader{}, err
	}
	return FileHeader{ChunkSize: chunkSize, NoncePrefix: prefix}, nil
}

// Bytes renders the header exactly as it appears at the start of the stream
// and as it is used for the AAD of every chunk.
func (h FileHeader) Bytes() []byte {
	out := make([]byte, 0, FileHeaderLen)
	out = append(out, FileMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(h.ChunkSize)) //nolint:gosec // validated range
	return append(out, h.NoncePrefix...)
}

// ParseFileHeader reads a header from the front of a stream.
func ParseFileHeader(b []byte) (FileHeader, error) {
	if len(b) < FileHeaderLen || string(b[:len(FileMagic)]) != FileMagic {
		return FileHeader{}, ErrFileFormat
	}
	size := binary.BigEndian.Uint32(b[len(FileMagic) : len(FileMagic)+4])
	if size < MinChunkSize || size > MaxChunkSize {
		return FileHeader{}, ErrFileFormat
	}
	prefix := make([]byte, FileNoncePrefixLen)
	copy(prefix, b[len(FileMagic)+4:FileHeaderLen])
	return FileHeader{ChunkSize: int(size), NoncePrefix: prefix}, nil
}

// ChunkNonce builds the nonce for one chunk: prefix || counter || final flag.
func (h FileHeader) ChunkNonce(index uint32, final bool) []byte {
	nonce := make([]byte, 0, NonceLen)
	nonce = append(nonce, h.NoncePrefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, index)
	if final {
		return append(nonce, 1)
	}
	return append(nonce, 0)
}

// DeriveFileKey expands the per-file key carried in the payload into the key
// that actually encrypts chunks. The raw key is never used directly, so a
// future format can expand other sub-keys from the same material.
func DeriveFileKey(fileKey []byte) ([]byte, error) {
	if len(fileKey) != FileKeyLen {
		return nil, fmt.Errorf("peek/crypto: file key must be %d bytes, got %d", FileKeyLen, len(fileKey))
	}
	return expand(fileKey, infoFile, 32)
}

// NewFileKey returns a fresh random per-file key.
func NewFileKey() ([]byte, error) {
	k := make([]byte, FileKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncryptedFileSize returns the exact byte length of the stream produced for a
// plaintext of plainSize bytes. The server uses it to check an announced
// upload length before accepting a single byte.
func EncryptedFileSize(plainSize int64, chunkSize int) int64 {
	if plainSize < 0 || chunkSize <= 0 {
		return 0
	}
	chunks := plainSize / int64(chunkSize)
	if plainSize%int64(chunkSize) != 0 || plainSize == 0 {
		chunks++
	}
	return int64(FileHeaderLen) + plainSize + chunks*int64(TagLen)
}

// PlainFileSize is the inverse of EncryptedFileSize: it recovers the plaintext
// length from the stream length, or reports that no plaintext could produce it.
func PlainFileSize(streamSize int64, chunkSize int) (int64, error) {
	if chunkSize <= 0 || streamSize < int64(FileHeaderLen)+int64(TagLen) {
		return 0, ErrFileFormat
	}
	body := streamSize - int64(FileHeaderLen)
	sealed := int64(chunkSize) + int64(TagLen)
	full := body / sealed
	rest := body % sealed
	if rest == 0 {
		// A stream whose body divides exactly can only be full chunks, and the
		// last one is still a real chunk, so this is full*chunkSize.
		return full * int64(chunkSize), nil
	}
	if rest < int64(TagLen) {
		return 0, ErrFileFormat
	}
	return full*int64(chunkSize) + rest - int64(TagLen), nil
}

// FileSealer encrypts a file chunk by chunk. Chunks must be sealed in order,
// and the stream must be ended with Final, which is what makes truncation
// detectable.
type FileSealer struct {
	header FileHeader
	key    []byte
	index  uint32
	done   bool
}

// NewFileSealer starts a stream. The returned header bytes are the first bytes
// of the stream; write them before any chunk.
func NewFileSealer(fileKey []byte, chunkSize int) (*FileSealer, []byte, error) {
	h, err := NewFileHeader(chunkSize)
	if err != nil {
		return nil, nil, err
	}
	key, err := DeriveFileKey(fileKey)
	if err != nil {
		return nil, nil, err
	}
	return &FileSealer{header: h, key: key}, h.Bytes(), nil
}

// ChunkSize is the plaintext size every chunk but the last one must have.
func (s *FileSealer) ChunkSize() int { return s.header.ChunkSize }

// Seal encrypts one chunk. final marks the last chunk of the stream; every
// chunk before it must be exactly ChunkSize bytes of plaintext.
func (s *FileSealer) Seal(plaintext []byte, final bool) ([]byte, error) {
	if s.done {
		return nil, errors.New("peek/crypto: stream already finished")
	}
	if !final && len(plaintext) != s.header.ChunkSize {
		return nil, fmt.Errorf("peek/crypto: non-final chunk must be %d bytes, got %d",
			s.header.ChunkSize, len(plaintext))
	}
	if len(plaintext) > s.header.ChunkSize {
		return nil, fmt.Errorf("peek/crypto: chunk larger than %d bytes", s.header.ChunkSize)
	}
	if s.index == ^uint32(0) && !final {
		// The counter lives in the nonce; wrapping it would reuse a nonce.
		return nil, errors.New("peek/crypto: too many chunks")
	}
	gcm, err := gcmFor(s.key)
	if err != nil {
		return nil, err
	}
	nonce := s.header.ChunkNonce(s.index, final)
	out := gcm.Seal(nil, nonce, plaintext, s.header.Bytes())
	s.index++
	s.done = final
	return out, nil
}

// SealFileStream encrypts everything r returns and writes the whole stream
// (header included) to w. It is the CLI path; the browser seals chunk by chunk
// as it reads the File object.
func SealFileStream(fileKey []byte, chunkSize int, r io.Reader, w io.Writer) (int64, error) {
	s, header, err := NewFileSealer(fileKey, chunkSize)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(header)
	total := int64(n)
	if err != nil {
		return total, err
	}

	// One byte of look-ahead: a chunk can only be sealed as final once we know
	// nothing follows it, and an empty file still produces one (final) chunk.
	br := bufio.NewReaderSize(r, chunkSize+1)
	chunk := make([]byte, chunkSize)
	for {
		read, rerr := io.ReadFull(br, chunk)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			return total, rerr
		}
		final := read < chunkSize
		if !final {
			if _, perr := br.Peek(1); perr != nil {
				final = true
			}
		}
		out, err := s.Seal(chunk[:read], final)
		if err != nil {
			return total, err
		}
		n, err = w.Write(out)
		total += int64(n)
		if err != nil {
			return total, err
		}
		if final {
			return total, nil
		}
	}
}

// FileOpener decrypts a stream chunk by chunk, in order.
type FileOpener struct {
	header FileHeader
	key    []byte
	index  uint32
	done   bool
}

// NewFileOpener parses the header at the front of a stream.
func NewFileOpener(fileKey, header []byte) (*FileOpener, error) {
	h, err := ParseFileHeader(header)
	if err != nil {
		return nil, err
	}
	key, err := DeriveFileKey(fileKey)
	if err != nil {
		return nil, err
	}
	return &FileOpener{header: h, key: key}, nil
}

// ChunkSize is the plaintext chunk size announced by the header.
func (o *FileOpener) ChunkSize() int { return o.header.ChunkSize }

// SealedChunkSize is the on-the-wire size of a non-final chunk.
func (o *FileOpener) SealedChunkSize() int { return o.header.ChunkSize + TagLen }

// Open decrypts one chunk. final must say whether the caller believes this is
// the last chunk; if the stream disagrees, the chunk fails to authenticate.
func (o *FileOpener) Open(sealed []byte, final bool) ([]byte, error) {
	if o.done {
		return nil, errors.New("peek/crypto: stream already finished")
	}
	if len(sealed) < TagLen || len(sealed) > o.header.ChunkSize+TagLen {
		return nil, ErrOpen
	}
	gcm, err := gcmFor(o.key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, o.header.ChunkNonce(o.index, final), sealed, o.header.Bytes())
	if err != nil {
		return nil, ErrOpen
	}
	o.index++
	o.done = final
	return pt, nil
}

// OpenFileStream decrypts a whole stream from r into w. It fails rather than
// return a partial file: a stream that ends without its final chunk gives
// ErrTruncated. w may already hold the earlier chunks by then, so callers write
// to a temporary destination and only publish it once this returns nil.
func OpenFileStream(fileKey []byte, r io.Reader, w io.Writer) (int64, error) {
	br := bufio.NewReader(r)
	header := make([]byte, FileHeaderLen)
	if _, err := io.ReadFull(br, header); err != nil {
		return 0, ErrFileFormat
	}
	o, err := NewFileOpener(fileKey, header)
	if err != nil {
		return 0, err
	}

	sealedLen := o.SealedChunkSize()
	if br.Size() < sealedLen+1 {
		br = bufio.NewReaderSize(br, sealedLen+1)
	}
	sealed := make([]byte, sealedLen)
	var total int64
	for {
		read, rerr := io.ReadFull(br, sealed)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			return total, rerr
		}
		if read == 0 {
			// Header only: the final chunk never arrived.
			return total, ErrTruncated
		}
		final := read < sealedLen
		if !final {
			if _, perr := br.Peek(1); perr != nil {
				final = true
			}
		}
		pt, err := o.Open(sealed[:read], final)
		if err != nil {
			if final {
				// The last chunk we hold does not authenticate as final, which
				// is what truncation looks like from here.
				return total, ErrTruncated
			}
			return total, err
		}
		n, werr := w.Write(pt)
		total += int64(n)
		if werr != nil {
			return total, werr
		}
		if final {
			return total, nil
		}
	}
}

// SealFile encrypts a whole plaintext in memory. Convenience for tests, the
// vectors and small files.
func SealFile(fileKey []byte, chunkSize int, plaintext []byte) ([]byte, error) {
	s, header, err := NewFileSealer(fileKey, chunkSize)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, header...)
	for off := 0; ; off += chunkSize {
		end := off + chunkSize
		final := end >= len(plaintext)
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk, err := s.Seal(plaintext[off:end], final)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if final {
			return out, nil
		}
	}
}

// SealFileWithHeader is SealFile with a caller-supplied header, so the test
// vectors are reproducible. Never use it with a reused nonce prefix.
func SealFileWithHeader(fileKey []byte, h FileHeader, plaintext []byte) ([]byte, error) {
	key, err := DeriveFileKey(fileKey)
	if err != nil {
		return nil, err
	}
	if h.ChunkSize < MinChunkSize || h.ChunkSize > MaxChunkSize || len(h.NoncePrefix) != FileNoncePrefixLen {
		return nil, ErrFileFormat
	}
	s := &FileSealer{header: h, key: key}
	out := append([]byte{}, h.Bytes()...)
	for off := 0; ; off += h.ChunkSize {
		end := off + h.ChunkSize
		final := end >= len(plaintext)
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk, err := s.Seal(plaintext[off:end], final)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if final {
			return out, nil
		}
	}
}

// OpenFile decrypts a whole stream held in memory.
func OpenFile(fileKey, stream []byte) ([]byte, error) {
	if len(stream) < FileHeaderLen {
		return nil, ErrFileFormat
	}
	o, err := NewFileOpener(fileKey, stream[:FileHeaderLen])
	if err != nil {
		return nil, err
	}
	body := stream[FileHeaderLen:]
	sealedLen := o.SealedChunkSize()
	out := make([]byte, 0, len(body))
	for off := 0; ; off += sealedLen {
		end := off + sealedLen
		final := end >= len(body)
		if end > len(body) {
			end = len(body)
		}
		if off >= len(body) {
			return nil, ErrTruncated
		}
		pt, err := o.Open(body[off:end], final)
		if err != nil {
			if final {
				return nil, ErrTruncated
			}
			return nil, err
		}
		out = append(out, pt...)
		if final {
			return out, nil
		}
	}
}
