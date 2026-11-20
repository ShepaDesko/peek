// Package config loads and validates /etc/peek/peek.toml.
//
// Every field has a defensible default so that a minimal file works, and
// Validate refuses anything that would silently weaken the security model
// (for example honouring forwarded headers without declaring trusted proxies).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// DefaultPath is where the packages install the configuration file.
const DefaultPath = "/etc/peek/peek.toml"

// Config is the whole instance configuration.
type Config struct {
	// PublicURL is the URL users see. Links, cookies, CSP and OIDC redirects
	// are all derived from it.
	PublicURL       string `toml:"public_url"`
	DefaultLanguage string `toml:"default_language"`
	MultiOrg        bool   `toml:"multi_org"`
	UpdateCheck     bool   `toml:"update_check"`
	UpdateURL       string `toml:"update_url"`
	UpdateChannel   string `toml:"update_channel"`
	MasterKeyFile   string `toml:"master_key_file"`
	DataDir         string `toml:"data_dir"`

	Server   Server   `toml:"server"`
	TLS      TLS      `toml:"tls"`
	Database Database `toml:"database"`
	Storage  Storage  `toml:"storage"`
	Security Security `toml:"security"`
	Policy   Policy   `toml:"policy"`
	Mail     Mail     `toml:"mail"`
	Log      Log      `toml:"log"`
	Branding Branding `toml:"branding"`
	Backup   Backup   `toml:"backup"`
}

// Server holds the listeners and the proxy trust configuration.
type Server struct {
	// InternalListen serves everything: creation, dashboard, admin, API.
	InternalListen string `toml:"internal_listen"`
	// PublicListen, when set, serves only the recipient-facing routes. Publish
	// this one through the load balancer and keep the internal one on the LAN.
	PublicListen string `toml:"public_listen"`
	// TrustedProxies are the only sources whose X-Forwarded-* / Forwarded
	// headers Peek honours. Empty means: never trust them.
	TrustedProxies []string `toml:"trusted_proxies"`
	// ProxyProtocol enables HAProxy PROXY protocol v1/v2 on the listeners.
	ProxyProtocol  bool     `toml:"proxy_protocol"`
	ReadTimeout    Duration `toml:"read_timeout"`
	WriteTimeout   Duration `toml:"write_timeout"`
	IdleTimeout    Duration `toml:"idle_timeout"`
	ShutdownGrace  Duration `toml:"shutdown_grace"`
	MaxBodyBytes   int64    `toml:"max_body_bytes"`
	MaxHeaderBytes int      `toml:"max_header_bytes"`
}

// TLS configures the built-in TLS terminator. Mode none is the right choice
// behind Kemp, F5, HAProxy or nginx.
type TLS struct {
	Mode      string   `toml:"mode"` // none | file | acme
	CertFile  string   `toml:"cert_file"`
	KeyFile   string   `toml:"key_file"`
	ACMEEmail string   `toml:"acme_email"`
	ACMEHosts []string `toml:"acme_hosts"`
	ACMEDir   string   `toml:"acme_dir"`
	// HSTS should stay off when TLS is terminated elsewhere and the proxy
	// already sends the header.
	HSTS       bool `toml:"hsts"`
	HSTSMaxAge int  `toml:"hsts_max_age"`
}

// Database selects the backing store. SQLite is the default; PostgreSQL is for
// multi-node deployments.
type Database struct {
	Driver string `toml:"driver"` // sqlite | postgres
	DSN    string `toml:"dsn"`
}

// Storage selects where encrypted file blobs live.
type Storage struct {
	Backend    string `toml:"backend"` // local | s3
	Path       string `toml:"path"`
	S3Bucket   string `toml:"s3_bucket"`
	S3Region   string `toml:"s3_region"`
	S3Endpoint string `toml:"s3_endpoint"`
}

// Security covers network gating and abuse limits.
type Security struct {
	// AdminAllowedCIDRs restricts login, dashboard, admin and API routes.
	AdminAllowedCIDRs []string `toml:"admin_allowed_cidrs"`
	// CreateAllowedCIDRs restricts secret creation.
	CreateAllowedCIDRs []string `toml:"create_allowed_cidrs"`
	AnonymousCreate    bool     `toml:"anonymous_create"`
	MaxPassphraseTries int      `toml:"max_passphrase_attempts"`

	// Sessions. Idle expiry slides forward on activity; the absolute one
	// never does, so a stolen cookie has a hard lifetime.
	SessionIdle     Duration `toml:"session_idle"`
	SessionAbsolute Duration `toml:"session_absolute"`
	// Failed logins before an account is locked for LoginLockFor. The lock is
	// temporary on purpose: a permanent one turns guessing into a denial of
	// service against the real user.
	LoginAttempts int      `toml:"login_attempts"`
	LoginLockFor  Duration `toml:"login_lock_for"`
	// RequireTOTP forces every account to enrol a second factor.
	RequireTOTP bool `toml:"require_totp"`
	// AllowPasskeys enables WebAuthn.
	AllowPasskeys  bool     `toml:"allow_passkeys"`
	AnonymizeIPs   bool     `toml:"anonymize_ips"`
	AuditRetention Duration `toml:"audit_retention"`

	RateCreate RateLimit `toml:"rate_create"`
	RateRead   RateLimit `toml:"rate_read"`
	RateLogin  RateLimit `toml:"rate_login"`
	RateAPI    RateLimit `toml:"rate_api"`
}

// RateLimit is a token bucket: Burst requests immediately, then Rate per
// Window sustained, per client IP.
type RateLimit struct {
	Burst  int      `toml:"burst"`
	Rate   int      `toml:"rate"`
	Window Duration `toml:"window"`
}

// Policy bounds what users may ask for at creation time.
type Policy struct {
	MaxTTL             Duration `toml:"max_ttl"`
	DefaultTTL         Duration `toml:"default_ttl"`
	MaxViews           int      `toml:"max_views"`
	DefaultViews       int      `toml:"default_views"`
	RequirePassphrase  bool     `toml:"require_passphrase"`
	ForceRetrievalStep bool     `toml:"force_retrieval_step"`
	AllowedKinds       []string `toml:"allowed_kinds"`
	MaxFileBytes       int64    `toml:"max_file_bytes"`
	MaxRecipients      int      `toml:"max_recipients"`
	MaxSecretBytes     int64    `toml:"max_secret_bytes"`
}

// Mail configures outbound SMTP. Empty host disables every e-mail feature.
type Mail struct {
	Host           string   `toml:"host"`
	Port           int      `toml:"port"`
	Username       string   `toml:"username"`
	Password       string   `toml:"password"`
	Encryption     string   `toml:"encryption"` // none | starttls | tls
	FromName       string   `toml:"from_name"`
	FromAddress    string   `toml:"from_address"`
	SkipVerify     bool     `toml:"skip_tls_verify"`
	AllowedDomains []string `toml:"allowed_recipient_domains"`
}

// Log configures structured logging. Secrets never reach it.
type Log struct {
	Level  string `toml:"level"`  // debug | info | warn | error
	Format string `toml:"format"` // json | text
	File   string `toml:"file"`   // empty: stdout, i.e. journald
}

// Branding holds the fallback identity used before anything is set in the
// database, and on a fresh install.
type Branding struct {
	ServiceName   string `toml:"service_name"`
	PrimaryColor  string `toml:"primary_color"`
	AccentColor   string `toml:"accent_color"`
	HidePoweredBy bool   `toml:"hide_powered_by"`
	SupportURL    string `toml:"support_url"`
	LegalURL      string `toml:"legal_url"`
	PrivacyURL    string `toml:"privacy_url"`
}

// Backup configures the scheduled local backup.
type Backup struct {
	Enabled    bool     `toml:"enabled"`
	Dir        string   `toml:"dir"`
	Keep       int      `toml:"keep"`
	Passphrase string   `toml:"passphrase"`
	Interval   Duration `toml:"interval"`
}

// Default returns a configuration that is safe to run on a LAN out of the box.
func Default() Config {
	return Config{
		PublicURL:       "http://localhost:8080",
		DefaultLanguage: "fr",
		MultiOrg:        false,
		UpdateCheck:     true,
		UpdateChannel:   "stable",
		MasterKeyFile:   "/etc/peek/master.key",
		DataDir:         "/var/lib/peek",
		Server: Server{
			InternalListen: "127.0.0.1:8080",
			PublicListen:   "",
			TrustedProxies: nil,
			ReadTimeout:    Secs(30),
			WriteTimeout:   Secs(120),
			IdleTimeout:    Secs(90),
			ShutdownGrace:  Secs(20),
			MaxBodyBytes:   8 << 20,
			MaxHeaderBytes: 1 << 20,
		},
		TLS:      TLS{Mode: "none", HSTS: false, HSTSMaxAge: 31536000, ACMEDir: "/var/lib/peek/acme"},
		Database: Database{Driver: "sqlite", DSN: "/var/lib/peek/peek.db"},
		Storage:  Storage{Backend: "local", Path: "/var/lib/peek/files"},
		Security: Security{
			AnonymousCreate:    false,
			MaxPassphraseTries: 5,
			SessionIdle:        Duration(12 * time.Hour),
			SessionAbsolute:    Days(7),
			LoginAttempts:      5,
			LoginLockFor:       Duration(15 * time.Minute),
			RequireTOTP:        false,
			AllowPasskeys:      true,
			AnonymizeIPs:       false,
			AuditRetention:     Days(365),
			RateCreate:         RateLimit{Burst: 20, Rate: 60, Window: Duration(time.Hour)},
			RateRead:           RateLimit{Burst: 30, Rate: 300, Window: Duration(time.Hour)},
			RateLogin:          RateLimit{Burst: 10, Rate: 60, Window: Duration(time.Hour)},
			RateAPI:            RateLimit{Burst: 60, Rate: 1200, Window: Duration(time.Hour)},
		},
		Policy: Policy{
			MaxTTL:             Days(30),
			DefaultTTL:         Days(1),
			MaxViews:           100,
			DefaultViews:       1,
			RequirePassphrase:  false,
			ForceRetrievalStep: false,
			AllowedKinds:       []string{"text", "url", "file"},
			MaxFileBytes:       100 << 20,
			MaxRecipients:      10,
			MaxSecretBytes:     1 << 20,
		},
		Mail: Mail{Port: 587, Encryption: "starttls", FromName: "Peek"},
		Log:  Log{Level: "info", Format: "json"},
		Branding: Branding{
			ServiceName:  "Peek",
			PrimaryColor: "#4f46e5",
			AccentColor:  "#0ea5e9",
		},
		Backup: Backup{Enabled: true, Dir: "/var/backups/peek", Keep: 7, Interval: Days(1)},
	}
}

// Load reads a TOML file on top of the defaults. A missing path returns the
// defaults when allowMissing is set, which is what peek setup needs.
func Load(path string, allowMissing bool) (Config, error) {
	cfg := Default()
	buf, err := os.ReadFile(path) //nolint:gosec // the configuration path, from the operator
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return cfg, nil
		}
		if errors.Is(err, os.ErrPermission) {
			// The usual cause: the service runs as peek and the file is
			// root:root. Say so, instead of leaving a restart loop in journald.
			return cfg, fmt.Errorf("cannot read %s: %w\n"+
				"the service runs as the peek user, so the file must be readable by it:\n"+
				"    sudo chown root:peek %s && sudo chmod 0640 %s", path, err, path, path)
		}
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	dec := toml.NewDecoder(strings.NewReader(string(buf)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		var se *toml.StrictMissingError
		if errors.As(err, &se) {
			return cfg, fmt.Errorf("%s: unknown setting(s):\n%s", path, se.String())
		}
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	cfg.applyEnv()
	return cfg, cfg.Validate()
}

// applyEnv lets packaging and tests override a few values without rewriting
// the file. Only non-secret plumbing is exposed this way.
func (c *Config) applyEnv() {
	if v := os.Getenv("PEEK_PUBLIC_URL"); v != "" {
		c.PublicURL = v
	}
	if v := os.Getenv("PEEK_INTERNAL_LISTEN"); v != "" {
		c.Server.InternalListen = v
	}
	if v := os.Getenv("PEEK_PUBLIC_LISTEN"); v != "" {
		c.Server.PublicListen = v
	}
	if v := os.Getenv("PEEK_DB_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("PEEK_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("PEEK_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
}

// Validate checks the configuration and rejects dangerous combinations.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		add("public_url must be an absolute URL such as https://secrets.example.com (got %q)", c.PublicURL)
	} else if u.Scheme != "http" && u.Scheme != "https" {
		add("public_url scheme must be http or https (got %q)", u.Scheme)
	}

	if c.Server.InternalListen == "" {
		add("server.internal_listen cannot be empty")
	}
	if c.Server.PublicListen != "" && c.Server.PublicListen == c.Server.InternalListen {
		add("server.public_listen and server.internal_listen must differ")
	}
	for _, cidr := range c.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if ip := net.ParseIP(cidr); ip == nil {
				add("server.trusted_proxies: %q is neither an IP nor a CIDR", cidr)
			}
		}
	}
	for field, list := range map[string][]string{
		"security.admin_allowed_cidrs":  c.Security.AdminAllowedCIDRs,
		"security.create_allowed_cidrs": c.Security.CreateAllowedCIDRs,
	} {
		for _, cidr := range list {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				if ip := net.ParseIP(cidr); ip == nil {
					add("%s: %q is neither an IP nor a CIDR", field, cidr)
				}
			}
		}
	}

	switch c.TLS.Mode {
	case "none":
	case "file":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			add("tls.mode = file requires tls.cert_file and tls.key_file")
		}
	case "acme":
		if len(c.TLS.ACMEHosts) == 0 {
			add("tls.mode = acme requires tls.acme_hosts")
		}
	default:
		add("tls.mode must be none, file or acme (got %q)", c.TLS.Mode)
	}

	switch c.Database.Driver {
	case "sqlite":
		if c.Database.DSN == "" {
			add("database.dsn cannot be empty")
		}
	case "postgres":
		if c.Database.DSN == "" {
			add("database.dsn cannot be empty for postgres")
		}
	default:
		add("database.driver must be sqlite or postgres (got %q)", c.Database.Driver)
	}

	switch c.Storage.Backend {
	case "local":
		if c.Storage.Path == "" {
			add("storage.path cannot be empty for the local backend")
		}
	case "s3":
		if c.Storage.S3Bucket == "" {
			add("storage.s3_bucket is required for the s3 backend")
		}
	default:
		add("storage.backend must be local or s3 (got %q)", c.Storage.Backend)
	}

	if c.Policy.DefaultTTL > c.Policy.MaxTTL {
		add("policy.default_ttl (%s) cannot exceed policy.max_ttl (%s)", c.Policy.DefaultTTL, c.Policy.MaxTTL)
	}
	if c.Policy.MaxTTL <= 0 {
		add("policy.max_ttl must be positive")
	}
	if c.Policy.DefaultViews > c.Policy.MaxViews || c.Policy.MaxViews <= 0 {
		add("policy.default_views must be <= policy.max_views, and max_views must be positive")
	}
	if c.Policy.MaxSecretBytes <= 0 {
		add("policy.max_secret_bytes must be positive")
	}
	if c.Security.MaxPassphraseTries <= 0 {
		add("security.max_passphrase_attempts must be positive")
	}
	if c.Security.SessionIdle.Std() <= 0 {
		add("security.session_idle must be positive")
	}
	if c.Security.SessionAbsolute.Std() < c.Security.SessionIdle.Std() {
		add("security.session_absolute (%s) cannot be shorter than security.session_idle (%s)",
			c.Security.SessionAbsolute, c.Security.SessionIdle)
	}
	if c.Security.LoginAttempts < 0 {
		add("security.login_attempts cannot be negative")
	}
	for _, k := range c.Policy.AllowedKinds {
		switch k {
		case "text", "url", "file":
		default:
			add("policy.allowed_kinds: unknown kind %q", k)
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level must be debug, info, warn or error (got %q)", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		add("log.format must be json or text (got %q)", c.Log.Format)
	}
	if c.Mail.Host != "" {
		if c.Mail.FromAddress == "" {
			add("mail.from_address is required when mail.host is set")
		}
		switch c.Mail.Encryption {
		case "none", "starttls", "tls":
		default:
			add("mail.encryption must be none, starttls or tls (got %q)", c.Mail.Encryption)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// Host returns the host[:port] part of the public URL.
func (c *Config) Host() string {
	if u, err := url.Parse(c.PublicURL); err == nil {
		return u.Host
	}
	return ""
}

// HTTPS reports whether the public URL is https, which drives Secure cookies.
func (c *Config) HTTPS() bool {
	u, err := url.Parse(c.PublicURL)
	return err == nil && u.Scheme == "https"
}

// SecretURL builds the recipient link for an id. The key fragment is appended
// by the browser; the server never assembles it.
func (c *Config) SecretURL(id string) string {
	return strings.TrimRight(c.PublicURL, "/") + "/s/" + id
}

// SQLitePath returns the on-disk path of the SQLite database, if that is the driver.
func (c *Config) SQLitePath() string {
	if c.Database.Driver != "sqlite" {
		return ""
	}
	return c.Database.DSN
}

// Redacted returns a copy with every secret replaced, for peek config show.
func (c Config) Redacted() Config {
	if c.Mail.Password != "" {
		c.Mail.Password = "***"
	}
	if c.Backup.Passphrase != "" {
		c.Backup.Passphrase = "***"
	}
	return c
}

// Marshal renders the configuration as TOML.
func (c Config) Marshal() ([]byte, error) { return toml.Marshal(c) }

// Dirs lists the directories Peek needs to exist and own, without repeats:
// the SQLite file usually lives in the data directory.
func (c *Config) Dirs() []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		seen[clean] = true
		dirs = append(dirs, clean)
	}
	add(c.DataDir)
	if c.Storage.Backend == "local" {
		add(c.Storage.Path)
	}
	if p := c.SQLitePath(); p != "" {
		add(filepath.Dir(p))
	}
	if c.Backup.Enabled {
		add(c.Backup.Dir)
	}
	return dirs
}
