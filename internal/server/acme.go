package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Let's Encrypt, when Peek terminates TLS itself.
//
// Behind Kemp, F5, HAProxy or nginx this is dead code: the proxy holds the
// certificate and `tls.mode = "none"` is correct. It exists for the one
// topology where Peek is the only thing listening — a small instance exposed
// directly — and for that case the alternative is a certificate somebody has
// to remember to renew every ninety days.
//
// The challenge is TLS-ALPN-01, not HTTP-01. HTTP-01 needs port 80 open and a
// second listener whose only job is to answer a challenge, which is one more
// thing exposed for no benefit. ALPN is answered on the TLS listener that is
// already there, so nothing extra is published.

// acmeTLS builds the TLS configuration for `tls.mode = "acme"`.
func (s *Server) acmeTLS() (*tls.Config, error) {
	hosts := s.cfg.TLS.ACMEHosts
	if len(hosts) == 0 {
		return nil, errors.New("tls.mode = acme requires tls.acme_hosts")
	}
	for _, host := range hosts {
		// A certificate authority will not issue for an address or for a
		// name nobody can resolve, and finding that out from a rate-limited
		// authority is a bad way to learn it.
		if host == "" || strings.ContainsAny(host, ":/ ") {
			return nil, fmt.Errorf("tls.acme_hosts: %q is not a hostname", host)
		}
		if host == "localhost" || looksLikeAddress(host) {
			return nil, fmt.Errorf("tls.acme_hosts: %q is an address or a local name; "+
				"a public certificate authority cannot issue for it. Use tls.mode = \"file\"", host)
		}
	}

	dir := s.cfg.TLS.ACMEDir
	if dir == "" {
		dir = filepath.Join(s.cfg.DataDir, "acme")
	}
	// 0700: the cache holds the account key and every private key issued.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tls.acme_dir %s: %w", dir, err)
	}
	if err := writableDir(dir); err != nil {
		return nil, fmt.Errorf("tls.acme_dir %s is not writable by the service account: %w", dir, err)
	}

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(dir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      s.cfg.TLS.ACMEEmail,
	}
	if url := strings.TrimSpace(s.cfg.TLS.ACMEDirectoryURL); url != "" {
		// Pointing at the staging directory is how an operator rehearses
		// without burning a weekly issuance quota on a typo.
		manager.Client = &acme.Client{DirectoryURL: url}
	}

	cfg := manager.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	// manager.TLSConfig() sets NextProtos to the ALPN challenge protocol plus
	// h2 and http/1.1. Keep the challenge entry — removing it is the usual way
	// people break ALPN issuance — and only make sure h2 is there.
	if !contains(cfg.NextProtos, "h2") {
		cfg.NextProtos = append([]string{"h2"}, cfg.NextProtos...)
	}

	s.log.Info("ACME enabled",
		"hosts", strings.Join(hosts, ", "),
		"cache", dir,
		"challenge", "tls-alpn-01",
		"directory", orDefaultDirectory(s.cfg.TLS.ACMEDirectoryURL))
	s.log.Warn("the first connection to each host will be slow: the certificate is issued on demand")
	return cfg, nil
}

// writableDir checks that the service account can actually write to the
// cache. Finding out at the first handshake instead means the first visitor
// gets a TLS error and the log says "permission denied" from inside autocert.
func writableDir(dir string) error {
	probe := filepath.Join(dir, ".peek-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // inside the cache directory
	if err != nil {
		return err
	}
	_ = f.Close()
	return os.Remove(probe)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func orDefaultDirectory(url string) string {
	if strings.TrimSpace(url) == "" {
		return "Let's Encrypt production"
	}
	return url
}

// looksLikeAddress reports whether a host is an IP address rather than a name.
// It is deliberately crude: anything with a colon, or made only of digits and
// dots, is not a name a public certificate authority will sign.
func looksLikeAddress(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
