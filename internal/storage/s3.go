package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// The S3 backend speaks the subset of the API Peek needs — PUT, GET, HEAD,
// DELETE and ListObjectsV2 — and signs requests with SigV4 directly.
//
// No AWS SDK on purpose. Two reasons, both about this product rather than
// about the SDK's quality: it would add roughly ten megabytes to a binary that
// has a sixty-megabyte budget, and its default credential chain probes the
// instance metadata endpoint, which is an outbound call Peek never promised to
// make (CLAUDE.md, rule 4). Credentials come from peek.toml and nowhere else.
// The signing code below is the whole of it, and it is tested against the
// published AWS test vectors.

const (
	s3Service        = "s3"
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedPayload  = "UNSIGNED-PAYLOAD"
	iso8601          = "20060102T150405Z"
	yyyymmdd         = "20060102"
)

// S3 is an S3-compatible object store: AWS, MinIO, Scaleway, OVH, NetApp
// StorageGRID, Ceph — anything that implements SigV4 and ListObjectsV2.
type S3 struct {
	bucket    string
	region    string
	endpoint  *url.URL
	prefix    string
	accessKey string
	secretKey string
	pathStyle bool
	client    *http.Client
	now       func() time.Time
}

// NewS3 builds the backend from the configuration.
func NewS3(cfg config.Storage) (*S3, error) {
	if cfg.S3Bucket == "" {
		return nil, errors.New("peek/storage: storage.s3_bucket is required")
	}
	if cfg.S3AccessKey == "" || cfg.S3SecretKey == "" {
		return nil, errors.New("peek/storage: storage.s3_access_key and storage.s3_secret_key are required")
	}
	region := cfg.S3Region
	if region == "" {
		region = "us-east-1"
	}

	raw := cfg.S3Endpoint
	if raw == "" {
		raw = "https://s3." + region + ".amazonaws.com"
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	ep, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("peek/storage: bad storage.s3_endpoint: %w", err)
	}
	if ep.Host == "" {
		return nil, errors.New("peek/storage: storage.s3_endpoint has no host")
	}

	prefix := strings.Trim(cfg.S3Prefix, "/")
	if prefix != "" {
		if strings.Contains(prefix, "..") || !validPrefix(prefix) {
			return nil, errors.New("peek/storage: storage.s3_prefix may only contain letters, digits, '-', '_' and '/'")
		}
		prefix += "/"
	}

	return &S3{
		bucket:    cfg.S3Bucket,
		region:    region,
		endpoint:  ep,
		prefix:    prefix,
		accessKey: cfg.S3AccessKey,
		secretKey: cfg.S3SecretKey,
		// Path style by default for a custom endpoint: MinIO and most
		// appliances serve the bucket as a path, and a wildcard certificate
		// for virtual-hosted buckets is the exception rather than the rule.
		pathStyle: cfg.S3PathStyle || cfg.S3Endpoint != "",
		client:    &http.Client{Timeout: 10 * time.Minute},
		now:       time.Now,
	}, nil
}

func validPrefix(p string) bool {
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '/', r == '.':
		default:
			return false
		}
	}
	return true
}

// objectPath is the canonical URI of one object, bucket included when the
// endpoint is addressed path-style.
func (s *S3) objectPath(key string) string {
	if s.pathStyle {
		return "/" + s.bucket + "/" + s.prefix + key
	}
	return "/" + s.prefix + key
}

func (s *S3) host() string {
	if s.pathStyle {
		return s.endpoint.Host
	}
	return s.bucket + "." + s.endpoint.Host
}

func (s *S3) urlFor(path string, query url.Values) string {
	u := url.URL{Scheme: s.endpoint.Scheme, Host: s.host(), Path: path}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func (s *S3) Put(ctx context.Context, key string, size int64, r io.Reader) error {
	if err := checkKey(key); err != nil {
		return err
	}
	path := s.objectPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.urlFor(path, nil),
		io.NopCloser(&limitedReader{r: r, left: size}))
	if err != nil {
		return err
	}
	// The length is known before the first byte is read (the chunked format
	// makes it exact), so the request is not chunked and the payload does not
	// need the streaming signature.
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.do(req, path, nil, unsignedPayload)
	if err != nil {
		return err
	}
	defer drain(resp)
	return s3Error(resp, "PUT")
}

func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if err := checkKey(key); err != nil {
		return nil, 0, err
	}
	path := s.objectPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.urlFor(path, nil), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.do(req, path, nil, emptyPayloadHash)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, 0, ErrNotFound
	}
	if err := s3Error(resp, "GET"); err != nil {
		drain(resp)
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

func (s *S3) Size(ctx context.Context, key string) (int64, error) {
	if err := checkKey(key); err != nil {
		return 0, err
	}
	path := s.objectPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.urlFor(path, nil), nil)
	if err != nil {
		return 0, err
	}
	resp, err := s.do(req, path, nil, emptyPayloadHash)
	if err != nil {
		return 0, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return 0, ErrNotFound
	}
	if err := s3Error(resp, "HEAD"); err != nil {
		return 0, err
	}
	return resp.ContentLength, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	path := s.objectPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.urlFor(path, nil), nil)
	if err != nil {
		return err
	}
	resp, err := s.do(req, path, nil, emptyPayloadHash)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil // deleting what is gone is not an error
	}
	return s3Error(resp, "DELETE")
}

type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func (s *S3) List(ctx context.Context) ([]string, error) {
	path := "/"
	if s.pathStyle {
		path = "/" + s.bucket
	}

	var keys []string
	token := ""
	for page := 0; ; page++ {
		if page > 10000 {
			return nil, errors.New("peek/storage: listing did not terminate")
		}
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("max-keys", "1000")
		if s.prefix != "" {
			q.Set("prefix", s.prefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.urlFor(path, q), nil)
		if err != nil {
			return nil, err
		}
		resp, err := s.do(req, path, q, emptyPayloadHash)
		if err != nil {
			return nil, err
		}
		if err := s3Error(resp, "LIST"); err != nil {
			drain(resp)
			return nil, err
		}
		var out listBucketResult
		err = xml.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out)
		drain(resp)
		if err != nil {
			return nil, fmt.Errorf("peek/storage: cannot parse the bucket listing: %w", err)
		}
		for _, c := range out.Contents {
			k := strings.TrimPrefix(c.Key, s.prefix)
			if ValidKey(k) {
				keys = append(keys, k)
			}
		}
		if !out.IsTruncated || out.NextContinuationToken == "" {
			return keys, nil
		}
		token = out.NextContinuationToken
	}
}

// Describe names the bucket and endpoint. Credentials never appear here: this
// string goes to `peek doctor`, the logs and the support bundle.
func (s *S3) Describe() string {
	style := "virtual-hosted"
	if s.pathStyle {
		style = "path-style"
	}
	return fmt.Sprintf("S3 bucket %s at %s (%s, region %s, prefix %q)",
		s.bucket, s.endpoint.Host, style, s.region, s.prefix)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

type s3ErrorBody struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// s3Error turns a non-2xx answer into an error that says what happened without
// echoing the object key, which is a secret identifier.
func s3Error(resp *http.Response, op string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var body s3ErrorBody
	_ = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	if body.Code != "" {
		return fmt.Errorf("peek/storage: S3 %s refused (%s: %s)", op, resp.Status, body.Code)
	}
	return fmt.Errorf("peek/storage: S3 %s refused (%s)", op, resp.Status)
}

// do signs and sends one request.
func (s *S3) do(req *http.Request, canonicalPath string, query url.Values, payloadHash string) (*http.Response, error) {
	now := s.now().UTC()
	// Go sends req.Host, not the header; SigV4 signs the same value.
	req.Host = s.host()
	req.Header.Set("X-Amz-Date", now.Format(iso8601))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	auth := s.authorization(req, canonicalPath, query, payloadHash, now)
	req.Header.Set("Authorization", auth)
	return s.client.Do(req)
}

// authorization builds the SigV4 Authorization header (AWS Signature Version
// 4, "Authenticating Requests: Using the Authorization Header").
func (s *S3) authorization(req *http.Request, canonicalPath string, query url.Values, payloadHash string, now time.Time) string {
	signed, canonicalHeaders := canonicalHeaderBlock(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		uriEncodePath(canonicalPath),
		canonicalQuery(query),
		canonicalHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{now.Format(yyyymmdd), s.region, s3Service, "aws4_request"}, "/")
	sum := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		now.Format(iso8601),
		scope,
		hex.EncodeToString(sum[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+s.secretKey), now.Format(yyyymmdd))
	key = hmacSHA256(key, s.region)
	key = hmacSHA256(key, s3Service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signed, signature)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// canonicalHeaderBlock returns the signed header list and the canonical header
// string. SigV4 requires host and the x-amz-* headers; content-type,
// content-md5 and range are signed when present because S3 treats them as part
// of the request. Nothing else is signed, so a proxy that adds a header on the
// way out does not invalidate the signature.
func canonicalHeaderBlock(req *http.Request) (string, string) {
	headers := map[string]string{"host": req.Host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		switch {
		case strings.HasPrefix(lower, "x-amz-"), lower == "content-type",
			lower == "content-md5", lower == "range":
			if len(values) > 0 {
				headers[lower] = strings.Join(values, ",")
			}
		}
	}

	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(strings.Fields(headers[n]), " "))
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

// canonicalQuery sorts and encodes the query string the way SigV4 wants it:
// RFC 3986, every parameter present, sorted by name then value.
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		values := append([]string{}, q[k]...)
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode is the encoding SigV4 specifies: unreserved characters pass
// through, everything else becomes %XX in upper case. net/url is close but not
// identical (it leaves '+' alone in paths and encodes spaces differently).
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// uriEncodePath encodes a path, keeping the separators.
func uriEncodePath(p string) string {
	segments := strings.Split(p, "/")
	for i, seg := range segments {
		segments[i] = uriEncode(seg)
	}
	return strings.Join(segments, "/")
}
