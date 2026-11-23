package server_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
)

// ACME, without talking to a certificate authority.
//
// Every assertion here is about what Peek decides before the first handshake:
// which host lists it refuses, where it keeps the account key, and the fact
// that building the configuration makes no network call at all. Issuance
// itself is autocert's, and testing it would mean running Pebble for no new
// information.

// tlsConfigFor builds a server with a TLS mode and returns what it would
// serve. The handler is exercised too, so a configuration that cannot be
// built shows up as a failure to start rather than at the first visitor.
func tlsConfigFor(t *testing.T, tweak func(*config.Config)) (*tls.Config, error) {
	t.Helper()
	h := newHarness(t, tweak)
	return h.srv.TLSConfigForTest()
}

// TestACMERefusesWhatCannotBeIssued covers the host lists that are valid TOML
// and valid hostnames, so configuration validation lets them through, and
// that a public certificate authority still cannot sign. The malformed ones —
// a URL, a host with a port, an empty list — are refused by Validate, which
// is the earlier and better place; TestACMEConfigurationIsValidated covers
// those.
func TestACMERefusesWhatCannotBeIssued(t *testing.T) {
	cases := []struct {
		name  string
		hosts []string
		want  string
	}{
		{"an IPv4 address", []string{"192.0.2.10"}, "address"},
		{"localhost", []string{"localhost"}, "local name"},
		{"a loopback address", []string{"127.0.0.1"}, "address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tlsConfigFor(t, func(cfg *config.Config) {
				cfg.TLS = config.TLS{
					Mode: "acme", ACMEHosts: tc.hosts,
					ACMEEmail: "ops@acme.test", ACMEDir: t.TempDir(),
				}
			})
			if err == nil {
				t.Fatalf("%v was accepted; a public authority cannot issue for it", tc.hosts)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the message does not say why:\n%s", err.Error())
			}
		})
	}
}

func TestACMEServesTheChallengeProtocol(t *testing.T) {
	cache := t.TempDir()
	cfg, err := tlsConfigFor(t, func(c *config.Config) {
		c.TLS = config.TLS{
			Mode: "acme", ACMEHosts: []string{"secrets.acme.test"},
			ACMEEmail: "ops@acme.test", ACMEDir: cache,
		}
	})
	if err != nil {
		t.Fatalf("a valid ACME configuration was refused: %v", err)
	}
	if cfg == nil {
		t.Fatal("no TLS configuration")
	}

	// The ALPN entry is what answers the challenge. Removing it is the usual
	// way people break issuance while believing they tidied the list.
	if !hasProto(cfg.NextProtos, "acme-tls/1") {
		t.Errorf("NextProtos = %v, without the tls-alpn-01 challenge protocol", cfg.NextProtos)
	}
	if !hasProto(cfg.NextProtos, "h2") || !hasProto(cfg.NextProtos, "http/1.1") {
		t.Errorf("NextProtos = %v: HTTP/2 and HTTP/1.1 both have to be offered", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x", cfg.MinVersion)
	}
	if cfg.GetCertificate == nil {
		t.Error("no GetCertificate: certificates are obtained on demand")
	}

	// Nothing was fetched: the cache holds no account key yet, because
	// building the configuration talks to nobody.
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the cache already holds %v: building the configuration made a network call", names)
	}
}

// TestACMECacheMustBeWritable: autocert discovers this at the first handshake,
// where it becomes a TLS error for a visitor and a line inside a library in
// the log. Peek discovers it at start.
func TestACMECacheMustBeWritable(t *testing.T) {
	parent := t.TempDir()
	// A path whose parent is a file cannot be created as a directory.
	blocker := filepath.Join(parent, "blocked")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := tlsConfigFor(t, func(cfg *config.Config) {
		cfg.TLS = config.TLS{
			Mode: "acme", ACMEHosts: []string{"secrets.acme.test"},
			ACMEEmail: "ops@acme.test", ACMEDir: filepath.Join(blocker, "acme"),
		}
	})
	if err == nil {
		t.Fatal("an unusable cache directory was accepted")
	}
	if !strings.Contains(err.Error(), "acme_dir") {
		t.Errorf("the message does not name the setting:\n%s", err.Error())
	}
}

// TestFileModeStillWorks guards the common case while ACME exists beside it.
func TestTLSModesBesideEachOther(t *testing.T) {
	if cfg, err := tlsConfigFor(t, func(c *config.Config) {
		c.TLS = config.TLS{Mode: "none"}
	}); err != nil || cfg != nil {
		t.Errorf("mode none: %v %v — Peek must serve plain HTTP and let the proxy terminate", cfg, err)
	}
	if _, err := tlsConfigFor(t, func(c *config.Config) {
		c.TLS = config.TLS{Mode: "file", CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"}
	}); err == nil {
		t.Error("mode file with no certificate was accepted")
	}
}

// TestACMEConfigurationIsValidated covers the other half: peek config check
// has to refuse what the server would refuse, so the mistake is found by the
// command an operator runs before restarting rather than by the restart.
func TestACMEConfigurationIsValidated(t *testing.T) {
	base := func() config.Config {
		cfg := config.Default()
		cfg.PublicURL = "https://secrets.acme.test"
		cfg.TLS = config.TLS{
			Mode: "acme", ACMEHosts: []string{"secrets.acme.test"}, ACMEEmail: "ops@acme.test",
		}
		return cfg
	}
	valid := base()
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid ACME configuration was refused: %v", err)
	}
	for _, tc := range []struct {
		name  string
		tweak func(*config.Config)
		want  string
	}{
		{"no hosts", func(c *config.Config) { c.TLS.ACMEHosts = nil }, "acme_hosts"},
		{"a URL as a host", func(c *config.Config) {
			c.TLS.ACMEHosts = []string{"https://secrets.acme.test"}
		}, "hostname"},
		{"a host with a port", func(c *config.Config) {
			c.TLS.ACMEHosts = []string{"secrets.acme.test:8443"}
		}, "hostname"},
		{"an IPv6 address", func(c *config.Config) {
			c.TLS.ACMEHosts = []string{"2001:db8::1"}
		}, "hostname"},
		{"no contact address", func(c *config.Config) { c.TLS.ACMEEmail = "" }, "acme_email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.tweak(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the message does not mention %q:\n%s", tc.want, err.Error())
			}
		})
	}
}

func hasProto(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}
