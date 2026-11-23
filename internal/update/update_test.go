package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// This package is the trust chain of `peek update`: a signature over the
// checksum file, the checksum over the archive, and only then a binary is
// replaced. Every refusal below is a step an attacker would want skipped.

const testKeyID = "\x01\x02\x03\x04\x05\x06\x07\x08"

// minisignKeypair returns a public key in the form SigningPublicKey holds (the
// base64 line of a .pub file) and a signer for it.
func minisignKeypair(t *testing.T, keyID string) (pub string, sign func(data []byte, prehashed bool) []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := make([]byte, 0, 42)
	raw = append(raw, 'E', 'd')
	raw = append(raw, keyID...)
	raw = append(raw, public...)

	sign = func(data []byte, prehashed bool) []byte {
		algo := "Ed"
		message := data
		if prehashed {
			algo = "ED"
			sum := blake2b.Sum512(data)
			message = sum[:]
		}
		out := make([]byte, 0, 74)
		out = append(out, algo...)
		out = append(out, keyID...)
		out = append(out, ed25519.Sign(private, message)...)
		return out
	}
	return base64.StdEncoding.EncodeToString(raw), sign
}

func writeSignature(t *testing.T, dir string, sig []byte) string {
	t.Helper()
	path := filepath.Join(dir, "checksums.txt.minisig")
	body := "untrusted comment: signature from minisign secret key\n" +
		base64.StdEncoding.EncodeToString(sig) + "\n" +
		"trusted comment: timestamp:1795440397\tfile:checksums.txt\thashed\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	return path
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestSHA256AndVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	archive := write(t, dir, "peek_1.0.0_linux_amd64.tar.gz", "the archive bytes")

	sum, err := SHA256(archive)
	if err != nil {
		t.Fatalf("SHA256: %v", err)
	}

	cases := []struct {
		name      string
		checksums string
		wantErr   string
	}{
		{"match", sum + "  peek_1.0.0_linux_amd64.tar.gz\n", ""},
		{"match-binary-marker", sum + " *peek_1.0.0_linux_amd64.tar.gz\n", ""},
		{"match-uppercase", strings.ToUpper(sum) + "  peek_1.0.0_linux_amd64.tar.gz\n", ""},
		{"among-others", "aa  other.tar.gz\n" + sum + "  peek_1.0.0_linux_amd64.tar.gz\nbb  third\n", ""},
		{
			"mismatch",
			strings.Repeat("0", 64) + "  peek_1.0.0_linux_amd64.tar.gz\n",
			"checksum mismatch",
		},
		{"not-listed", sum + "  some-other-file.tar.gz\n", "is not listed"},
		{"empty", "", "is not listed"},
		{"garbage", "this file is not a checksum list\n", "is not listed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := write(t, t.TempDir(), "checksums.txt", tc.checksums)
			err := VerifyChecksum(archive, list)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("VerifyChecksum: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatal("a bad checksum file was accepted")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("message %q should contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	dir := t.TempDir()
	signed := write(t, dir, "checksums.txt", "aa  peek_1.0.0_linux_amd64.tar.gz\n")
	body, err := os.ReadFile(signed)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	pub, sign := minisignKeypair(t, testKeyID)

	// Recent minisign prehashes by default, which is what the released
	// signature uses, but the legacy form must still verify.
	for _, prehashed := range []bool{true, false} {
		name := "prehashed"
		if !prehashed {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			sig := writeSignature(t, t.TempDir(), sign(body, prehashed))
			if err := VerifySignature(signed, sig, pub); err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
		})
	}

	t.Run("tampered-file", func(t *testing.T) {
		sig := writeSignature(t, t.TempDir(), sign(body, true))
		tampered := write(t, t.TempDir(), "checksums.txt", "bb  peek_1.0.0_linux_amd64.tar.gz\n")
		err := VerifySignature(tampered, sig, pub)
		if err == nil {
			t.Fatal("a signature was accepted over a file it does not cover")
		}
		if !strings.Contains(err.Error(), "refusing to install") {
			t.Errorf("the message should say nothing is installed: %v", err)
		}
	})

	t.Run("another-key", func(t *testing.T) {
		otherPub, otherSign := minisignKeypair(t, "\x09\x09\x09\x09\x09\x09\x09\x09")
		sig := writeSignature(t, t.TempDir(), otherSign(body, true))
		err := VerifySignature(signed, sig, pub)
		if err == nil {
			t.Fatal("a signature from an untrusted key was accepted")
		}
		if !strings.Contains(err.Error(), "this build trusts") {
			t.Errorf("the message should name both key ids: %v", err)
		}
		// And the same signature verifies against its own key, so the refusal
		// above is about trust and not about a broken signature.
		if err := VerifySignature(signed, sig, otherPub); err != nil {
			t.Fatalf("the signature itself is valid: %v", err)
		}
	})

	t.Run("same-key-id-different-key", func(t *testing.T) {
		// A forged signature claiming the trusted key id must still fail.
		_, impostor := minisignKeypair(t, testKeyID)
		sig := writeSignature(t, t.TempDir(), impostor(body, true))
		if err := VerifySignature(signed, sig, pub); err == nil {
			t.Fatal("a forged signature carrying the trusted key id was accepted")
		}
	})

	t.Run("no-embedded-key", func(t *testing.T) {
		sig := writeSignature(t, t.TempDir(), sign(body, true))
		err := VerifySignature(signed, sig, "")
		if err == nil {
			t.Fatal("a build with no signing key verified a signature")
		}
		if !strings.Contains(err.Error(), "no signing key embedded") {
			t.Errorf("the message should say why: %v", err)
		}
	})

	t.Run("malformed-key", func(t *testing.T) {
		for _, key := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("short")),
			base64.StdEncoding.EncodeToString(append([]byte("XX"), make([]byte, 40)...))} {
			sig := writeSignature(t, t.TempDir(), sign(body, true))
			if err := VerifySignature(signed, sig, key); err == nil {
				t.Errorf("a malformed public key (%q) was used", key)
			}
		}
	})

	t.Run("unsupported-algorithm", func(t *testing.T) {
		raw := make([]byte, 74)
		copy(raw, "XX")
		copy(raw[2:], testKeyID)
		sig := writeSignature(t, t.TempDir(), raw)
		err := VerifySignature(signed, sig, pub)
		if !errors.Is(err, errUnsupportedSignature) {
			t.Fatalf("an unknown algorithm should be named as unsupported: %v", err)
		}
	})

	t.Run("no-signature-line", func(t *testing.T) {
		path := write(t, t.TempDir(), "checksums.txt.minisig", "untrusted comment: nothing here\n")
		if err := VerifySignature(signed, path, pub); err == nil {
			t.Fatal("an empty signature file was accepted")
		}
	})
}

// The public key line of a .pub file carries a comment above it; both forms
// must parse, because an operator may paste either.
func TestParsePublicKeyAcceptsBothForms(t *testing.T) {
	pub, _ := minisignKeypair(t, testKeyID)

	bare, id1, err := parseMinisignPublicKey(pub)
	if err != nil {
		t.Fatalf("bare line: %v", err)
	}
	withComment, id2, err := parseMinisignPublicKey("untrusted comment: minisign public key\n" + pub + "\n")
	if err != nil {
		t.Fatalf("whole file: %v", err)
	}
	if id1 != id2 || !bytes.Equal(bare, withComment) {
		t.Error("the two forms of the same key parsed differently")
	}
}

func tarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		typ := byte(tar.TypeReg)
		if strings.HasSuffix(name, "/") {
			typ = tar.TypeDir
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: typ,
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractBinary(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "release.tar.gz")
	if err := os.WriteFile(archive, tarGz(t, map[string]string{
		"README.md": "not the binary",
		"peek":      "#!/bin/sh\nthe binary\n",
	}), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	out := t.TempDir()
	path, err := ExtractBinary(archive, out)
	if err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	if filepath.Base(path) != "peek" {
		t.Errorf("extracted %q", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "the binary") {
		t.Errorf("content = %q", body)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("the extracted binary is not executable (%s)", info.Mode())
		}
	}
}

// A tar entry whose name escapes the destination must not be written there.
// The extractor only ever takes the base name, and only of an entry actually
// called peek, so both halves of the usual zip-slip are closed.
func TestExtractBinaryIgnoresTraversalAndOtherFiles(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")
	if err := os.WriteFile(archive, tarGz(t, map[string]string{
		"../../../../etc/cron.d/backdoor": "* * * * * root sh -c 'curl …'\n",
		"../../../../usr/bin/peek":        "the impostor\n",
	}), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	out := t.TempDir()
	path, err := ExtractBinary(archive, out)
	if err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	// The peek entry is taken, but by its base name inside the destination.
	if filepath.Dir(path) != out {
		t.Errorf("the binary landed outside the destination: %s", path)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "peek" {
		t.Errorf("the destination holds %v, want only peek", entries)
	}
}

func TestExtractBinaryRefusesWhatIsNotARelease(t *testing.T) {
	dir := t.TempDir()

	noBinary := filepath.Join(dir, "docs.tar.gz")
	if err := os.WriteFile(noBinary, tarGz(t, map[string]string{"README.md": "x"}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ExtractBinary(noBinary, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "no peek binary") {
		t.Errorf("an archive without a binary should be refused by name: %v", err)
	}

	notGzip := write(t, dir, "plain.tar.gz", "this is not gzip")
	if _, err := ExtractBinary(notGzip, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "not a gzip archive") {
		t.Errorf("a non-gzip file should be refused by name: %v", err)
	}
}

// A binary at or beyond the size cap is truncated by the copy. Installing a
// truncated binary is worse than refusing the update.
func TestExtractBinaryRefusesAnOversizedEntry(t *testing.T) {
	previous := maxBinaryBytes
	maxBinaryBytes = 64
	t.Cleanup(func() { maxBinaryBytes = previous })

	dir := t.TempDir()
	archive := filepath.Join(dir, "huge.tar.gz")
	if err := os.WriteFile(archive, tarGz(t, map[string]string{
		"peek": strings.Repeat("A", 200),
	}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ExtractBinary(archive, t.TempDir()); err == nil {
		t.Fatal("an entry larger than the cap was installed truncated")
	}
}

func TestSwapBinaryKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	target := write(t, dir, "peek", "version one")
	fresh := write(t, dir, "peek.new-build", "version two")
	previous := filepath.Join(dir, "lib", "peek.previous")

	if err := SwapBinary(fresh, target, previous); err != nil {
		t.Fatalf("SwapBinary: %v", err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "version two" {
		t.Errorf("target = %q (%v)", body, err)
	}
	if body, err := os.ReadFile(previous); err != nil || string(body) != "version one" {
		t.Errorf("previous = %q (%v), rollback would have nothing to go back to", body, err)
	}
	// The staging file must not be left behind.
	if _, err := os.Stat(target + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Error("the staged binary was left on disk")
	}
	// And swapping again rolls the previous forward rather than failing.
	third := write(t, dir, "peek.third", "version three")
	if err := SwapBinary(third, target, previous); err != nil {
		t.Fatalf("second SwapBinary: %v", err)
	}
	if body, _ := os.ReadFile(previous); string(body) != "version two" {
		t.Errorf("previous = %q after a second update", body)
	}
}

func TestSwapBinaryOnAFreshInstall(t *testing.T) {
	dir := t.TempDir()
	fresh := write(t, dir, "peek.new-build", "version one")
	target := filepath.Join(dir, "bin", "peek")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Nothing to keep aside, and that is not an error.
	if err := SwapBinary(fresh, target, filepath.Join(dir, "lib", "peek.previous")); err != nil {
		t.Fatalf("SwapBinary: %v", err)
	}
	if body, _ := os.ReadFile(target); string(body) != "version one" {
		t.Errorf("target = %q", body)
	}
}

// The release of a real instance carries both the server archive and the CLI
// archive for the same platform. Picking the wrong one would install the
// command-line client over the server.
func TestAssetForPicksTheServerArchive(t *testing.T) {
	suffix := runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	release := &Release{
		Version: "v1.0.0",
		Assets: []Asset{
			{Name: "checksums.txt"},
			{Name: "checksums.txt.minisig"},
			{Name: "peek_1.0.0_" + suffix},
			{Name: "peek_1.0.0_" + suffix + ".sbom.json"},
			// Deliberately last: the loop must not let it win.
			{Name: "peek-cli_1.0.0_" + suffix},
		},
	}

	archive, checksums, signature, err := AssetFor(release)
	if err != nil {
		t.Fatalf("AssetFor: %v", err)
	}
	if archive.Name != "peek_1.0.0_"+suffix {
		t.Errorf("archive = %q, want the server archive", archive.Name)
	}
	if checksums.Name != "checksums.txt" {
		t.Errorf("checksums = %q", checksums.Name)
	}
	if signature.Name != "checksums.txt.minisig" {
		t.Errorf("signature = %q", signature.Name)
	}
}

func TestAssetForRefusesAReleaseWithoutThisPlatform(t *testing.T) {
	release := &Release{Version: "v1.0.0", Assets: []Asset{
		{Name: "peek_1.0.0_plan9_mips.tar.gz"}, {Name: "checksums.txt"},
	}}
	if _, _, _, err := AssetFor(release); err == nil ||
		!strings.Contains(err.Error(), runtime.GOARCH) {
		t.Errorf("the error should name the platform it found nothing for: %v", err)
	}
}

func releaseServer(t *testing.T, releases []Release) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("User-Agent"); got != "peek-updater" {
			t.Errorf("user agent = %q; nothing about the customer may leave the box", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(releases)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestLatestSkipsDraftsAndPrereleasesOnStable(t *testing.T) {
	srv, _ := releaseServer(t, []Release{
		{Version: "v1.3.0", Draft: true},
		{Version: "v1.2.0", Prerelease: true},
		{Version: "v1.1.0"},
		{Version: "v1.0.0"},
	})

	stable := NewClient(srv.URL, "stable", "")
	got, err := stable.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.Version != "v1.1.0" {
		t.Errorf("stable channel returned %s", got.Version)
	}

	beta := NewClient(srv.URL, "beta", "")
	got, err = beta.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.Version != "v1.2.0" {
		t.Errorf("beta channel returned %s, a draft is never a release", got.Version)
	}
}

func TestFindByVersionIgnoresTheVPrefix(t *testing.T) {
	srv, _ := releaseServer(t, []Release{{Version: "v1.1.0"}, {Version: "v1.0.0"}})
	c := NewClient(srv.URL, "stable", "")

	for _, want := range []string{"1.0.0", "v1.0.0"} {
		got, err := c.Find(context.Background(), want)
		if err != nil {
			t.Fatalf("Find(%q): %v", want, err)
		}
		if got.Version != "v1.0.0" {
			t.Errorf("Find(%q) = %s", want, got.Version)
		}
	}
	if _, err := c.Find(context.Background(), "9.9.9"); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Errorf("an unknown version should be refused by name: %v", err)
	}
}

func TestTokenIsOnlySentWhenConfigured(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode([]Release{{Version: "v1.0.0"}})
	}))
	t.Cleanup(srv.Close)

	if _, err := NewClient(srv.URL, "stable", "").Latest(context.Background()); err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if _, err := NewClient(srv.URL, "stable", "ghp_x").Latest(context.Background()); err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if len(seen) != 2 || seen[0] != "" || seen[1] != "Bearer ghp_x" {
		t.Errorf("authorization headers = %q", seen)
	}
}

// A private repository answers 404 to an unauthenticated caller, which looks
// like "no releases" unless the message says otherwise.
func TestListExplainsA404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient(srv.URL, "stable", "").Latest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "private repository") {
		t.Errorf("a 404 should suggest the likely cause: %v", err)
	}
}

func TestDownloadWritesTheAssetWithRestrictivePermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("the archive"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	c := NewClient(srv.URL, "stable", "")
	path, err := c.Download(context.Background(), &Asset{Name: "peek_1.0.0.tar.gz", URL: srv.URL}, dir)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("downloaded to %q", path)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "the archive" {
		t.Fatalf("content = %q (%v)", body, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode = %s, a download in progress should not be world readable", info.Mode())
		}
	}
}

// An asset name is whatever the release source says it is, so it must not be
// able to place a file outside the download directory.
func TestDownloadKeepsTheAssetInsideTheDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	c := NewClient(srv.URL, "stable", "")
	path, err := c.Download(context.Background(),
		&Asset{Name: "../../../../etc/cron.d/backdoor", URL: srv.URL}, dir)
	if err != nil {
		// Refusing is a fine answer too; what matters is where it did not write.
		return
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("an asset name escaped the download directory: %s", path)
	}
}

func TestDownloadRefusesANonOKAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "stable", "")
	_, err := c.Download(context.Background(), &Asset{Name: "a.tar.gz", URL: srv.URL}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("the error should name the status: %v", err)
	}
}
