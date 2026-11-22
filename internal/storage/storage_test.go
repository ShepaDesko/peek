package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// runBackend is the contract every backend must satisfy. Running it twice, on
// the local directory and on a fake S3, is what keeps the two interchangeable.
func runBackend(t *testing.T, b Backend) {
	t.Helper()
	ctx := context.Background()
	blob := bytes.Repeat([]byte("peek"), 1000)
	key := "AAAAAAAAAAAAAAAAAAAAAA"

	if _, _, err := b.Open(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open on a missing object: got %v, want ErrNotFound", err)
	}
	if _, err := b.Size(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Size on a missing object: got %v, want ErrNotFound", err)
	}
	// Purge runs repeatedly; deleting what is already gone must stay quiet.
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete on a missing object: %v", err)
	}

	if err := b.Put(ctx, key, int64(len(blob)), bytes.NewReader(blob)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	size, err := b.Size(ctx, key)
	if err != nil || size != int64(len(blob)) {
		t.Fatalf("Size = %d, %v; want %d", size, err, len(blob))
	}
	rc, size, err := b.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, blob) || size != int64(len(blob)) {
		t.Errorf("round trip mismatch: %d bytes, announced %d", len(got), size)
	}

	keys, err := b.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List = %v, want [%s]", keys, key)
	}

	// An empty object is legal: the chunked format still has a header and a
	// final tag, but a backend must not special-case zero bytes.
	empty := "BBBBBBBBBBBBBBBBBBBBBB"
	if err := b.Put(ctx, empty, 0, bytes.NewReader(nil)); err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	if n, err := b.Size(ctx, empty); err != nil || n != 0 {
		t.Errorf("Size of an empty object = %d, %v", n, err)
	}

	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Size(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete: got %v, want ErrNotFound", err)
	}

	// Keys are secret identifiers; a traversal here would be a write outside
	// the data directory.
	for _, bad := range []string{"", "..", "../etc/passwd", "a/b", "short", strings.Repeat("x", 80)} {
		if err := b.Put(ctx, bad, 1, strings.NewReader("x")); err == nil {
			t.Errorf("Put accepted the key %q", bad)
		}
	}

	if b.Describe() == "" {
		t.Error("Describe is empty")
	}
}

func TestLocalBackend(t *testing.T) {
	b, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runBackend(t, b)
}

func TestLocalRefusesWrongLength(t *testing.T) {
	dir := t.TempDir()
	b, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "CCCCCCCCCCCCCCCCCCCCCC"

	// Announced ten, sent four: a short upload must leave nothing behind.
	if err := b.Put(ctx, key, 10, strings.NewReader("abcd")); err == nil {
		t.Error("Put accepted a short stream")
	}
	if _, err := b.Size(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("a failed Put left an object behind: %v", err)
	}

	// Announced four, sent ten.
	if err := b.Put(ctx, key, 4, strings.NewReader("abcdefghij")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Put on an overlong stream: got %v, want ErrTooLarge", err)
	}
	if _, err := b.Size(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("an overlong Put left an object behind: %v", err)
	}

	// And no temporary file is left under the final name or any other.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("leftover file after a failed upload: %s", e.Name())
	}
}

func TestLocalIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	b, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	// An operator's stray file, and a crashed upload's temporary, must not be
	// reported as objects: the purge deletes what List returns.
	for _, name := range []string{"README", ".upload-123", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("List = %v, want nothing", keys)
	}

	n, err := b.CleanTemporaries(0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("CleanTemporaries removed %d files, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "README")); err != nil {
		t.Error("CleanTemporaries removed a file that was not a temporary")
	}
}

// fakeS3 is a tiny S3-compatible server: enough of the protocol to exercise
// the client, and strict enough about SigV4 that a signing mistake fails here
// rather than in production.
type fakeS3 struct {
	mu        sync.Mutex
	objects   map[string][]byte
	accessKey string
	secretKey string
	region    string
	lastAuth  string
}

func (f *fakeS3) verify(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	f.mu.Lock()
	f.lastAuth = auth
	f.mu.Unlock()

	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("missing SigV4 authorization")
	}
	var credential, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			credential = v
		case "SignedHeaders":
			signedHeaders = v
		case "Signature":
			signature = v
		}
	}
	scopeParts := strings.SplitN(credential, "/", 2)
	if len(scopeParts) != 2 || scopeParts[0] != f.accessKey {
		return fmt.Errorf("bad credential %q", credential)
	}
	scope := scopeParts[1]
	if !strings.HasSuffix(scope, "/"+f.region+"/s3/aws4_request") {
		return fmt.Errorf("bad scope %q", scope)
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if _, err := time.Parse(iso8601, amzDate); err != nil {
		return fmt.Errorf("bad x-amz-date %q", amzDate)
	}
	if !strings.HasPrefix(scope, amzDate[:8]+"/") {
		return fmt.Errorf("scope date %q does not match x-amz-date %q", scope, amzDate)
	}

	// Recompute the signature from the request as received. This is the check
	// that matters: it fails if the canonical request is built differently.
	var canonicalHeaders strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	canonical := strings.Join([]string{
		r.Method,
		uriEncodePath(r.URL.Path),
		canonicalQuery(r.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		r.Header.Get("X-Amz-Content-Sha256"),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(sum[:]),
	}, "\n")

	key := hmacTest([]byte("AWS4"+f.secretKey), amzDate[:8])
	key = hmacTest(key, f.region)
	key = hmacTest(key, "s3")
	key = hmacTest(key, "aws4_request")
	want := hex.EncodeToString(hmacTest(key, stringToSign))
	if want != signature {
		return fmt.Errorf("signature mismatch\ncanonical request:\n%s", canonical)
	}
	return nil
}

func hmacTest(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f.verify(r); err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "<Error><Code>SignatureDoesNotMatch</Code><Message>%s</Message></Error>", err)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/peek-bucket")
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		prefix := r.URL.Query().Get("prefix")
		keys := make([]string, 0, len(f.objects))
		for k := range f.objects {
			if strings.HasPrefix(k, "/"+prefix) {
				keys = append(keys, strings.TrimPrefix(k, "/"))
			}
		}
		sort.Strings(keys)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
		for _, k := range keys {
			fmt.Fprintf(w, "<Contents><Key>%s</Key></Contents>", k)
		}
		_, _ = io.WriteString(w, "<IsTruncated>false</IsTruncated></ListBucketResult>")

	case r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.objects[name] = body
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		body, ok := f.objects[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}

	case r.Method == http.MethodDelete:
		if _, ok := f.objects[name]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.objects, name)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newFakeS3(t *testing.T, prefix string) (*S3, *fakeS3) {
	t.Helper()
	fake := &fakeS3{
		objects:   map[string][]byte{},
		accessKey: "PEEKTESTACCESSKEY",
		secretKey: "peek/test+secret+key+EXAMPLE",
		region:    "eu-west-3",
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	b, err := NewS3(config.Storage{
		Backend:     "s3",
		S3Bucket:    "peek-bucket",
		S3Region:    fake.region,
		S3Endpoint:  srv.URL,
		S3Prefix:    prefix,
		S3AccessKey: fake.accessKey,
		S3SecretKey: fake.secretKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, fake
}

func TestS3Backend(t *testing.T) {
	b, _ := newFakeS3(t, "")
	runBackend(t, b)
}

func TestS3BackendWithPrefix(t *testing.T) {
	b, fake := newFakeS3(t, "peek/blobs")
	runBackend(t, b)

	// The prefix must reach the bucket, and List must hand back bare keys.
	if err := b.Put(context.Background(), "DDDDDDDDDDDDDDDDDDDDDD", 1, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.objects["/peek/blobs/DDDDDDDDDDDDDDDDDDDDDD"]; !ok {
		stored := make([]string, 0, len(fake.objects))
		for k := range fake.objects {
			stored = append(stored, k)
		}
		t.Errorf("object not stored under the prefix; bucket holds %v", stored)
	}
}

func TestS3DescribeHidesCredentials(t *testing.T) {
	b, fake := newFakeS3(t, "")
	d := b.Describe()
	if strings.Contains(d, fake.secretKey) || strings.Contains(d, fake.accessKey) {
		t.Errorf("Describe leaks a credential: %s", d)
	}
}

func TestS3RejectsBadConfiguration(t *testing.T) {
	cases := []config.Storage{
		{Backend: "s3"},
		{Backend: "s3", S3Bucket: "b"},
		{Backend: "s3", S3Bucket: "b", S3AccessKey: "a"},
		{Backend: "s3", S3Bucket: "b", S3AccessKey: "a", S3SecretKey: "s", S3Prefix: "../escape"},
		{Backend: "s3", S3Bucket: "b", S3AccessKey: "a", S3SecretKey: "s", S3Endpoint: "://nope"},
	}
	for i, c := range cases {
		if _, err := NewS3(c); err == nil {
			t.Errorf("case %d: NewS3 accepted %+v", i, c)
		}
	}
}

func TestS3ReportsServerErrors(t *testing.T) {
	b, fake := newFakeS3(t, "")
	fake.secretKey = "a different key entirely"
	err := b.Put(context.Background(), "EEEEEEEEEEEEEEEEEEEEEE", 1, strings.NewReader("x"))
	if err == nil {
		t.Fatal("Put succeeded although the signature was wrong")
	}
	if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("error does not name the S3 code: %v", err)
	}
}

func TestOpenSelectsTheBackend(t *testing.T) {
	local, err := Open(config.Storage{Backend: "local", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := local.(*Local); !ok {
		t.Errorf("local backend is %T", local)
	}
	if _, err := Open(config.Storage{Backend: "gdrive"}); err == nil {
		t.Error("Open accepted an unknown backend")
	}
}

func TestURIEncodeMatchesSigV4(t *testing.T) {
	// SigV4 is specific about this: unreserved characters pass through, the
	// rest are percent-encoded in upper case, and a slash in a path stays.
	cases := map[string]string{
		"abcXYZ019-_.~": "abcXYZ019-_.~",
		"a b":           "a%20b",
		"a+b":           "a%2Bb",
		"a/b":           "a%2Fb",
		"é":             "%C3%A9",
		"*":             "%2A",
	}
	for in, want := range cases {
		if got := uriEncode(in); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := uriEncodePath("/peek bucket/key"); got != "/peek%20bucket/key" {
		t.Errorf("uriEncodePath = %q", got)
	}
	q := url.Values{"prefix": {"a b"}, "list-type": {"2"}}
	if got := canonicalQuery(q); got != "list-type=2&prefix=a%20b" {
		t.Errorf("canonicalQuery = %q", got)
	}
}
