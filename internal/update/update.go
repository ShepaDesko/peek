// Package update implements peek update: fetch a release, verify it, swap the
// binary atomically, restart, check health, and roll back on its own if the
// new version does not come up.
//
// Three rules make this safe enough to run on a production box over SSH:
//
//  1. nothing is installed without a matching SHA-256 *and* a valid signature
//     from the key embedded in this binary;
//  2. a backup is taken before anything changes;
//  3. if /readyz does not answer after the restart, the previous binary is put
//     back and the database restored if a migration had run.
package update

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// DefaultReleaseAPI is the GitHub releases endpoint. It can be replaced by an
// internal mirror through update_url in peek.toml, which is what air-gapped
// customers use.
const DefaultReleaseAPI = "https://api.github.com/repos/ShepaDesko/peek/releases"

// SigningPublicKey is the minisign/ed25519 public key, injected at build time
// with -ldflags. An empty value means this build cannot verify signatures and
// will refuse to install anything unless the operator explicitly allows it.
var SigningPublicKey = ""

// PreviousBinaryPath is where the replaced binary is kept.
const PreviousBinaryPath = "/usr/lib/peek/peek.previous"

// errUnsupportedSignature is returned for a signature algorithm this
// build does not know how to verify.
var errUnsupportedSignature = errors.New("update: unsupported signature algorithm")

// maxBinaryBytes caps what is extracted from a release archive. The budget for
// the binary is sixty megabytes (see tools/budget), so this is generous by a
// factor of four and still refuses an archive that is not a Peek release. It
// is a variable only so a test can lower it.
var maxBinaryBytes int64 = 256 << 20

// Release is one available version.
type Release struct {
	Version    string    `json:"tag_name"`
	Name       string    `json:"name"`
	Body       string    `json:"body"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Published  time.Time `json:"published_at"`
	Assets     []Asset   `json:"assets"`
}

// Asset is one downloadable file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Client talks to the release source.
type Client struct {
	BaseURL string
	Channel string
	Token   string
	HTTP    *http.Client
}

// NewClient builds a client. A token is only sent when the operator configured
// one, for a private repository or an authenticated mirror.
func NewClient(baseURL, channel, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultReleaseAPI
	}
	if channel == "" {
		channel = "stable"
	}
	return &Client{
		BaseURL: baseURL,
		Channel: channel,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Latest returns the newest release of the configured channel.
func (c *Client) Latest(ctx context.Context) (*Release, error) {
	releases, err := c.list(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range releases {
		if r.Draft {
			continue
		}
		if r.Prerelease && c.Channel != "beta" {
			continue
		}
		return &r, nil
	}
	return nil, errors.New("update: no release found on channel " + c.Channel)
}

// Find returns a specific version, with or without the leading v.
func (c *Client) Find(ctx context.Context, version string) (*Release, error) {
	releases, err := c.list(ctx)
	if err != nil {
		return nil, err
	}
	want := strings.TrimPrefix(version, "v")
	for _, r := range releases {
		if strings.TrimPrefix(r.Version, "v") == want {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("update: version %s not found", version)
}

func (c *Client) list(ctx context.Context) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// A generic user agent: nothing about the customer leaves the box.
	req.Header.Set("User-Agent", "peek-updater")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: cannot reach the release source: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("update: the release source returned 404 (private repository? set update_url and a token in peek.toml)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: the release source returned HTTP %d", resp.StatusCode)
	}
	var releases []Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&releases); err != nil {
		// A mirror may expose a single release object instead of a list.
		return nil, fmt.Errorf("update: unreadable release index: %w", err)
	}
	return releases, nil
}

// AssetFor returns the archive, checksum and signature assets for this host.
func AssetFor(r *Release) (archive, checksums, signature *Asset, err error) {
	suffix := fmt.Sprintf("_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	for i := range r.Assets {
		a := &r.Assets[i]
		switch {
		// The prefix matters as much as the suffix: a release carries
		// peek-cli_<v>_<os>_<arch>.tar.gz beside the server archive, and the
		// suffix alone matches both. Which one won depended on the order the
		// release source happened to list them in, and installing the
		// command-line client over the server is not a recoverable mistake.
		case strings.HasPrefix(a.Name, "peek_") && strings.HasSuffix(a.Name, suffix):
			archive = a
		case strings.Contains(a.Name, "checksums") && strings.HasSuffix(a.Name, ".txt"):
			checksums = a
		case strings.Contains(a.Name, "checksums") && (strings.HasSuffix(a.Name, ".sig") || strings.HasSuffix(a.Name, ".minisig")):
			signature = a
		}
	}
	if archive == nil {
		return nil, nil, nil, fmt.Errorf("update: release %s has no asset for %s/%s", r.Version, runtime.GOOS, runtime.GOARCH)
	}
	return archive, checksums, signature, nil
}

// Download fetches an asset to dir and returns the local path.
func (c *Client) Download(ctx context.Context, a *Asset, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "peek-updater")
	req.Header.Set("Accept", "application/octet-stream")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("update: download %s: %w", a.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update: download %s returned HTTP %d", a.Name, resp.StatusCode)
	}
	path := filepath.Join(dir, filepath.Base(a.Name))
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: a release archive named by the operator
	if err != nil {
		return "", err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.CopyN(out, resp.Body, 512<<20); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return path, nil
}

// SHA256 returns the hex digest of a file.
func SHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a release archive named by the operator
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyChecksum looks the archive up in a GoReleaser checksums.txt file.
func VerifyChecksum(archivePath, checksumsPath string) error {
	want, err := SHA256(archivePath)
	if err != nil {
		return err
	}
	f, err := os.Open(checksumsPath) //nolint:gosec // a release artefact named by the operator
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	base := filepath.Base(archivePath)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") != base {
			continue
		}
		if strings.EqualFold(fields[0], want) {
			return nil
		}
		return fmt.Errorf("update: checksum mismatch for %s (expected %s, got %s)", base, fields[0], want)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("update: %s is not listed in the checksum file", base)
}

// VerifySignature checks a minisign signature over the checksum file using the
// public key embedded in this binary.
//
// Verifying the checksum file (and then the archive against it) is the same
// chain GoReleaser produces, and it means one signature covers every artefact
// of a release.
func VerifySignature(signedPath, signaturePath, publicKey string) error {
	if publicKey == "" {
		return errors.New("update: this build has no signing key embedded, so the release signature cannot be verified")
	}
	keyBytes, keyID, err := parseMinisignPublicKey(publicKey)
	if err != nil {
		return err
	}
	sigBytes, sigKeyID, prehashed, err := parseMinisignSignature(signaturePath)
	if err != nil {
		return err
	}
	if keyID != sigKeyID {
		return fmt.Errorf("update: the signature was made with key %x, this build trusts %x", sigKeyID, keyID)
	}
	data, err := os.ReadFile(signedPath) //nolint:gosec // G304: a release archive named by the operator
	if err != nil {
		return err
	}
	message := data
	if prehashed {
		sum := blake2b512(data)
		message = sum
	}
	if !ed25519.Verify(ed25519.PublicKey(keyBytes), message, sigBytes) {
		return errors.New("update: invalid signature — refusing to install")
	}
	return nil
}

// parseMinisignPublicKey accepts the raw base64 line of a minisign public key
// (the second line of a .pub file, or the value of SigningPublicKey).
func parseMinisignPublicKey(key string) (publicKey []byte, keyID uint64, err error) {
	key = strings.TrimSpace(key)
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		key = line
		break
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, 0, fmt.Errorf("update: malformed signing key: %w", err)
	}
	if len(raw) != 42 || string(raw[:2]) != "Ed" {
		return nil, 0, errors.New("update: unsupported signing key format (expected minisign Ed25519)")
	}
	return raw[10:], leUint64(raw[2:10]), nil
}

func parseMinisignSignature(path string) (sig []byte, keyID uint64, prehashed bool, err error) {
	buf, err := os.ReadFile(path) //nolint:gosec // G304: a release archive named by the operator
	if err != nil {
		return nil, 0, false, err
	}
	for _, line := range strings.Split(string(buf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") || strings.HasPrefix(line, "trusted comment:") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		if len(raw) != 74 {
			continue
		}
		algo := string(raw[:2])
		switch algo {
		case "Ed":
			prehashed = false
		case "ED":
			prehashed = true
		default:
			return nil, 0, false, fmt.Errorf("%w: %q", errUnsupportedSignature, algo)
		}
		return raw[10:], leUint64(raw[2:10]), prehashed, nil
	}
	return nil, 0, false, errors.New("update: no usable signature line found")
}

func leUint64(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// ExtractBinary pulls the peek binary out of a release archive.
func ExtractBinary(archivePath, destDir string) (string, error) {
	f, err := os.Open(archivePath) //nolint:gosec // a release archive named by the operator
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("update: %s is not a gzip archive: %w", filepath.Base(archivePath), err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		name := filepath.Base(filepath.Clean(header.Name))
		if header.Typeflag != tar.TypeReg || (name != "peek" && name != "peek.exe") {
			continue
		}
		dest := filepath.Join(destDir, name)
		// 0755: this is the executable being installed.
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) //nolint:gosec // see above
		if err != nil {
			return "", err
		}
		written, err := io.CopyN(out, tr, maxBinaryBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			_ = out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		// CopyN stops at the limit without an error, so an entry at or beyond
		// the cap would be installed truncated — a binary that cannot run,
		// swapped over one that could. Refuse the update instead.
		if written >= maxBinaryBytes {
			return "", fmt.Errorf("update: the binary in %s is at least %d bytes, which is not a Peek release",
				filepath.Base(archivePath), maxBinaryBytes)
		}
		return dest, nil
	}
	return "", errors.New("update: the archive contains no peek binary")
}

// SwapBinary replaces target with newBinary, keeping the old one aside.
// The rename is atomic, so a crash mid-update cannot leave a half-written
// binary on disk.
func SwapBinary(newBinary, target, previous string) error {
	// /usr/lib/peek holds the previous binary and is world readable like /usr/bin.
	if err := os.MkdirAll(filepath.Dir(previous), 0o755); err != nil { //nolint:gosec // see above
		return err
	}
	staged := target + ".new"
	if err := copyFileMode(newBinary, staged, 0o755); err != nil {
		return err
	}
	if current, err := os.ReadFile(target); err == nil { //nolint:gosec // G304: a binary path this process installs, from the operator
		if err := os.WriteFile(previous, current, 0o755); err != nil { //nolint:gosec // an executable
			return fmt.Errorf("update: cannot keep the previous binary: %w", err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		return fmt.Errorf("update: cannot install the new binary: %w", err)
	}
	return nil
}

// WaitReady polls a /readyz URL until it answers 200 or the deadline passes.
func WaitReady(ctx context.Context, url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("update: %s did not become ready in %s (last error: %w)", url, timeout, lastErr)
}

// blake2b512 is what minisign hashes a file with before signing it in
// prehashed mode, which is the default of recent minisign versions.
func blake2b512(data []byte) []byte {
	sum := blake2b.Sum512(data)
	return sum[:]
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // G304: a binary path this process installs, from the operator
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) //nolint:gosec // G304: a binary path this process installs, from the operator
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
