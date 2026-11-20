// Package setup is the first-install assistant behind peek setup.
//
// It is interactive by default and fully scriptable through flags, because an
// on-premise product gets installed both by hand and by Ansible.
package setup

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// Options drive a run. Anything left empty is asked for interactively, or
// defaulted when NonInteractive is set.
type Options struct {
	ConfigPath     string
	NonInteractive bool
	In             io.Reader
	Out            io.Writer

	PublicURL       string
	Mode            string // internal | direct | proxy
	InternalListen  string
	PublicListen    string
	TrustedProxies  string
	TLSMode         string
	CertFile        string
	KeyFile         string
	DBDriver        string
	DBDSN           string
	DataDir         string
	Language        string
	SMTPHost        string
	SMTPPort        int
	SMTPFrom        string
	ServiceName     string
	AnonymousCreate bool
	Force           bool
}

// Result reports what the assistant did.
type Result struct {
	ConfigPath    string
	MasterKeyPath string
	Config        config.Config
	Created       bool
	ServiceAction string
}

type wizard struct {
	in   *bufio.Reader
	out  io.Writer
	auto bool
}

// Run asks the questions, writes the configuration and the master key, creates
// the directories and (on Linux, as root) enables the service.
func Run(opts Options) (*Result, error) {
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = config.DefaultPath
	}
	w := &wizard{in: bufio.NewReader(opts.In), out: opts.Out, auto: opts.NonInteractive}

	existing, statErr := os.Stat(opts.ConfigPath)
	fresh := errors.Is(statErr, os.ErrNotExist)
	if !fresh && statErr != nil {
		return nil, statErr
	}

	cfg, err := config.Load(opts.ConfigPath, true)
	if err != nil && !fresh {
		// A broken file should not block reconfiguration: start from defaults
		// and keep the old one aside.
		w.sayf("warning: %s could not be parsed (%v); starting from the defaults\n", opts.ConfigPath, err)
		cfg = config.Default()
	}

	if !fresh && !opts.Force && !opts.NonInteractive {
		w.sayf("\n%s already exists (last modified %s).\n", opts.ConfigPath, existing.ModTime().Format("2006-01-02 15:04"))
		if !w.confirm("Reconfigure this instance?", true) {
			return nil, errors.New("cancelled")
		}
	}

	w.say("\nPeek — installation\n")
	w.say(strings.Repeat("=", 40) + "\n\n")

	// --- Identity -----------------------------------------------------------
	cfg.Branding.ServiceName = w.ask("Service name shown to users", pick(opts.ServiceName, cfg.Branding.ServiceName))
	cfg.PublicURL = w.askValidated("Public URL (as users will type it)", pick(opts.PublicURL, cfg.PublicURL), func(v string) error {
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			return errors.New("must start with http:// or https://")
		}
		return nil
	})
	cfg.DefaultLanguage = w.askChoice("Default language", pick(opts.Language, cfg.DefaultLanguage), []string{"fr", "en"})

	// --- Exposure -----------------------------------------------------------
	w.say("\nHow is this instance reached?\n")
	w.say("  internal  only from the LAN or VPN\n")
	w.say("  proxy     behind Kemp, F5, HAProxy, nginx… (TLS terminated there)\n")
	w.say("  direct    exposed on the internet, Peek terminates TLS itself\n")
	mode := w.askChoice("Mode", pick(opts.Mode, "internal"), []string{"internal", "proxy", "direct"})

	cfg.Server.InternalListen = w.askValidated("Internal listen address (everything: creation, dashboard, admin, API)",
		pick(opts.InternalListen, cfg.Server.InternalListen), validAddr)

	switch mode {
	case "internal":
		cfg.Server.PublicListen = ""
		cfg.Server.TrustedProxies = nil
		cfg.TLS.Mode = "none"
	case "proxy":
		w.say("\nThe recipient pages can be served on a second, separate port.\n")
		w.say("Publish only that one through the load balancer and the admin surface stays on the LAN.\n")
		if w.confirm("Enable the second (public) listener?", true) {
			cfg.Server.PublicListen = w.askValidated("Public listen address (recipient routes only)",
				pick(opts.PublicListen, "0.0.0.0:8081"), validAddr)
		} else {
			cfg.Server.PublicListen = ""
		}
		proxies := w.ask("Load balancer addresses or CIDRs, comma separated (forwarded headers are honoured only from these)",
			pick(opts.TrustedProxies, strings.Join(cfg.Server.TrustedProxies, ",")))
		cfg.Server.TrustedProxies = splitList(proxies)
		cfg.TLS.Mode = "none"
		cfg.TLS.HSTS = false
	case "direct":
		cfg.Server.PublicListen = ""
		cfg.TLS.Mode = w.askChoice("TLS", pick(opts.TLSMode, "file"), []string{"file", "none"})
		if cfg.TLS.Mode == "file" {
			cfg.TLS.CertFile = w.ask("Certificate file (fullchain PEM)", pick(opts.CertFile, "/etc/peek/tls/fullchain.pem"))
			cfg.TLS.KeyFile = w.ask("Private key file (PEM)", pick(opts.KeyFile, "/etc/peek/tls/privkey.pem"))
			cfg.TLS.HSTS = w.confirm("Send Strict-Transport-Security?", true)
		}
	}

	// --- Storage ------------------------------------------------------------
	cfg.Database.Driver = w.askChoice("Database", pick(opts.DBDriver, cfg.Database.Driver), []string{"sqlite", "postgres"})
	switch cfg.Database.Driver {
	case "sqlite":
		cfg.Database.DSN = w.ask("SQLite file", pick(opts.DBDSN, defaultIfOther(cfg.Database.DSN, "/var/lib/peek/peek.db")))
	case "postgres":
		cfg.Database.DSN = w.ask("PostgreSQL DSN", pick(opts.DBDSN, "postgres://peek:password@127.0.0.1:5432/peek?sslmode=require"))
		w.say("\nnote: the PostgreSQL driver lands in milestone M9. Until then the service will refuse to start with it.\n")
	}
	cfg.DataDir = w.ask("Data directory", pick(opts.DataDir, cfg.DataDir))
	cfg.Storage.Path = filepath.ToSlash(filepath.Join(cfg.DataDir, "files"))

	// --- Mail ---------------------------------------------------------------
	if w.confirm("\nConfigure SMTP now (for sending links and notifications)?", opts.SMTPHost != "") {
		cfg.Mail.Host = w.ask("SMTP host", pick(opts.SMTPHost, cfg.Mail.Host))
		cfg.Mail.Port = w.askInt("SMTP port", orInt(opts.SMTPPort, cfg.Mail.Port))
		cfg.Mail.Encryption = w.askChoice("Encryption", cfg.Mail.Encryption, []string{"starttls", "tls", "none"})
		cfg.Mail.FromAddress = w.ask("From address", pick(opts.SMTPFrom, cfg.Mail.FromAddress))
		cfg.Mail.FromName = w.ask("From name", pick(cfg.Branding.ServiceName, cfg.Mail.FromName))
	}

	// --- Policy -------------------------------------------------------------
	cfg.Security.AnonymousCreate = opts.AnonymousCreate ||
		w.confirm("\nAllow creating secrets without an account? (accounts arrive in milestone M5)", true)
	if cfg.Security.AnonymousCreate && mode != "internal" {
		w.say("  tip: restrict who may create with security.create_allowed_cidrs in peek.toml.\n")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// --- Write it all -------------------------------------------------------
	res := &Result{ConfigPath: opts.ConfigPath, Config: cfg, Created: fresh}

	// 0750 root:peek: this directory holds the master key and the SMTP password.
	if err := os.MkdirAll(filepath.Dir(opts.ConfigPath), 0o750); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(opts.ConfigPath), err)
	}
	if !fresh {
		backup := opts.ConfigPath + ".bak"
		if data, err := os.ReadFile(opts.ConfigPath); err == nil {
			if err := os.WriteFile(backup, data, 0o600); err == nil { //nolint:gosec // G703: the path comes from the operator, not from a request
				w.sayf("\nprevious configuration saved to %s\n", backup)
			}
		}
	}
	if err := writeConfig(opts.ConfigPath, cfg); err != nil {
		return nil, err
	}
	w.sayf("wrote %s\n", opts.ConfigPath)

	keyPath := cfg.MasterKeyFile
	created, err := ensureMasterKey(keyPath)
	if err != nil {
		return nil, err
	}
	res.MasterKeyPath = keyPath
	if created {
		w.sayf("generated %s — back this file up separately from the database\n", keyPath)
	} else {
		w.sayf("kept the existing master key %s\n", keyPath)
	}

	for _, dir := range cfg.Dirs() {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := chownToService(cfg); err == nil {
		w.say("set ownership of the data directories to the peek user\n")
	}

	if action := enableService(w); action != "" {
		res.ServiceAction = action
	}

	w.say("\nDone. Next steps:\n")
	w.sayf("  1. sudo peek doctor            # check the installation\n")
	w.sayf("  2. open %s\n", cfg.PublicURL)
	if cfg.Server.PublicListen != "" {
		w.sayf("  3. publish only %s on the load balancer (see docs/REVERSE-PROXY.md)\n", cfg.Server.PublicListen)
	}
	return res, nil
}

// writeConfig writes the file atomically, mode 0640, with a header.
func writeConfig(path string, cfg config.Config) error {
	buf, err := cfg.Marshal()
	if err != nil {
		return err
	}
	header := []byte("# Peek configuration.\n" +
		"# Written by peek setup. Every setting is documented in docs/CONFIG.md.\n" +
		"# Check it after editing with: peek config check\n\n")
	tmp := path + ".tmp"
	// 0640 root:peek is deliberate: the service reads this through its group.
	if err := os.WriteFile(tmp, append(header, buf...), 0o640); err != nil { //nolint:gosec // see above
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil { //nolint:gosec // the configured configuration path
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// ensureMasterKey creates a 32-byte key with mode 0400 if it does not exist.
// It never overwrites: that would make existing encrypted metadata unreadable.
func ensureMasterKey(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, key, 0o400); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// chownToService gives the data directories to the peek user when running as
// root on Linux. A missing user is not an error: a developer runs as themself.
func chownToService(cfg config.Config) error {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		return errors.New("not root")
	}
	u, err := user.Lookup("peek")
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, dir := range cfg.Dirs() {
		// The tree was just created by this process, from a configured path.
		_ = filepath.Walk(dir, func(p string, _ os.FileInfo, walkErr error) error { //nolint:gosec // see above
			if walkErr != nil {
				// An unreadable entry is not worth failing an install over; doctor reports it.
				return nil //nolint:nilerr // deliberate
			}
			_ = os.Chown(p, uid, gid) //nolint:gosec // G122: the tree was created by this process moments earlier
			return nil
		})
	}
	if cfg.MasterKeyFile != "" {
		_ = os.Chown(cfg.MasterKeyFile, uid, gid)
	}
	return nil
}

// enableService enables and starts the systemd unit when it is installed.
func enableService(w *wizard) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	if _, err := os.Stat("/usr/lib/systemd/system/peek.service"); err != nil {
		if _, err := os.Stat("/etc/systemd/system/peek.service"); err != nil {
			return ""
		}
	}
	if !w.confirm("\nEnable and (re)start the peek service now?", true) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	if out, err := exec.CommandContext(ctx, "systemctl", "enable", "--now", "peek.service").CombinedOutput(); err != nil {
		w.sayf("systemctl: %v\n%s\n", err, strings.TrimSpace(string(out)))
		return "failed"
	}
	w.say("peek.service enabled and started\n")
	return "enabled"
}

// --- prompt helpers ---------------------------------------------------------

func (w *wizard) say(s string)               { _, _ = fmt.Fprint(w.out, s) }
func (w *wizard) sayf(f string, args ...any) { _, _ = fmt.Fprintf(w.out, f, args...) }

func (w *wizard) read() string {
	line, err := w.in.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func (w *wizard) ask(label, def string) string {
	if w.auto {
		return def
	}
	if def != "" {
		w.sayf("%s [%s]: ", label, def)
	} else {
		w.sayf("%s: ", label)
	}
	v := w.read()
	if v == "" {
		return def
	}
	return v
}

func (w *wizard) askValidated(label, def string, validate func(string) error) string {
	for {
		v := w.ask(label, def)
		if err := validate(v); err != nil {
			if w.auto {
				return def
			}
			w.sayf("  %v\n", err)
			continue
		}
		return v
	}
}

func (w *wizard) askChoice(label, def string, choices []string) string {
	for {
		v := w.ask(fmt.Sprintf("%s (%s)", label, strings.Join(choices, "/")), def)
		for _, c := range choices {
			if strings.EqualFold(v, c) {
				return c
			}
		}
		if w.auto {
			return def
		}
		w.sayf("  pick one of: %s\n", strings.Join(choices, ", "))
	}
}

func (w *wizard) askInt(label string, def int) int {
	for {
		v := w.ask(label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		if w.auto {
			return def
		}
		w.say("  enter a number\n")
	}
}

func (w *wizard) confirm(label string, def bool) bool {
	suffix := "y/N"
	if def {
		suffix = "Y/n"
	}
	for {
		if w.auto {
			return def
		}
		w.sayf("%s [%s]: ", label, suffix)
		switch strings.ToLower(w.read()) {
		case "":
			return def
		case "y", "yes", "o", "oui":
			return true
		case "n", "no", "non":
			return false
		}
	}
}

func validAddr(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return errors.New("use host:port, for example 0.0.0.0:8080")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return errors.New("the port must be a number")
	}
	if host != "" && net.ParseIP(host) == nil {
		return errors.New("the host part must be an IP address, or empty")
	}
	return nil
}

func pick(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func defaultIfOther(current, fallback string) string {
	if current == "" {
		return fallback
	}
	return current
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
