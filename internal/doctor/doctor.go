// Package doctor diagnoses an installation: configuration, permissions,
// database, storage, TLS, SMTP, clock, disk, and — with --external — whether
// the public URL really answers and whether the admin surface is exposed.
//
// It is the first thing to run after an install and the first thing to ask for
// in a support ticket.
package doctor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/oidc"
	"github.com/ShepaDesko/peek/internal/storage"
	"github.com/ShepaDesko/peek/internal/store"
)

// Level is the severity of one check.
type Level string

const (
	OK   Level = "OK"
	WARN Level = "WARN"
	FAIL Level = "FAIL"
	SKIP Level = "SKIP"
)

// Result is one diagnostic line.
type Result struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

// Report is the full diagnosis.
type Report struct {
	Results []Result `json:"results"`
}

func (r *Report) add(name string, level Level, detail string, hint ...string) {
	res := Result{Name: name, Level: level, Detail: detail}
	if len(hint) > 0 {
		res.Hint = hint[0]
	}
	r.Results = append(r.Results, res)
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool {
	for _, res := range r.Results {
		if res.Level == FAIL {
			return true
		}
	}
	return false
}

// Warned reports whether any check warned.
func (r *Report) Warned() bool {
	for _, res := range r.Results {
		if res.Level == WARN {
			return true
		}
	}
	return false
}

// Write renders the report as aligned text.
func (r *Report) Write(w io.Writer) {
	width := 0
	for _, res := range r.Results {
		if len(res.Name) > width {
			width = len(res.Name)
		}
	}
	for _, res := range r.Results {
		_, _ = fmt.Fprintf(w, "[%-4s] %-*s  %s\n", res.Level, width, res.Name, res.Detail)
		if res.Hint != "" {
			_, _ = fmt.Fprintf(w, "         %-*s  → %s\n", width, "", res.Hint)
		}
	}
	_, _ = fmt.Fprintln(w)
	switch {
	case r.Failed():
		_, _ = fmt.Fprintln(w, "Diagnosis: problems found. Fix the FAIL lines above and run peek doctor again.")
	case r.Warned():
		_, _ = fmt.Fprintln(w, "Diagnosis: usable, with warnings.")
	default:
		_, _ = fmt.Fprintln(w, "Diagnosis: everything checks out.")
	}
}

// Options drive a run.
type Options struct {
	ConfigPath string
	Config     *config.Config
	External   bool
	Version    string
	// SendTestEmail asks for a real test message instead of a connection test.
	SendTestEmail string
}

// Run performs every check.
func Run(ctx context.Context, opts Options) *Report {
	r := &Report{}
	cfg := opts.Config

	r.add("version", OK, fmt.Sprintf("peek %s on %s/%s", orDash(opts.Version), runtime.GOOS, runtime.GOARCH))
	checkConfigFile(r, opts.ConfigPath)
	if cfg == nil {
		r.add("configuration", FAIL, "configuration could not be loaded; later checks were skipped")
		return r
	}
	r.add("configuration", OK, fmt.Sprintf("valid, public URL %s", cfg.PublicURL))

	checkInstalledBinary(r)
	checkMasterKey(r, cfg)
	checkDirs(r, cfg)
	checkStorage(ctx, r, cfg)
	checkDatabase(ctx, r, cfg)
	checkListeners(r, cfg)
	checkProxyTrust(r, cfg)
	checkTLS(ctx, r, cfg)
	checkClock(r)
	checkMail(r, cfg, opts.SendTestEmail)
	checkSSO(ctx, r, cfg)
	checkWebhooks(ctx, r, cfg)

	if opts.External {
		checkExternal(ctx, r, cfg)
	} else {
		r.add("external reachability", SKIP, "run peek doctor --external to test the public URL from this host")
	}
	return r
}

// checkInstalledBinary warns when the host has more than one copy of peek and
// they are not the same file.
//
// Found the hard way on a test host: an upgrade dropped a binary in
// /usr/local/bin, which comes first in root's PATH, while systemd kept running
// /usr/bin/peek from the package. Every command typed at the prompt was the
// new version and the service was the old one, which made a configuration the
// new binary accepted into a restart loop for the old one — with nothing in
// the obvious places to explain it.
func checkInstalledBinary(r *Report) {
	type found struct {
		path string
		sum  string
	}
	var copies []found
	for _, candidate := range []string{"/usr/bin/peek", "/usr/local/bin/peek", "/opt/peek/peek"} {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		sum, err := fileDigest(candidate)
		if err != nil {
			continue
		}
		copies = append(copies, found{path: candidate, sum: sum})
	}
	switch {
	case len(copies) == 0:
		// Running from a build directory, which is normal in development.
		if self, err := os.Executable(); err == nil {
			r.add("installed binary", OK, self)
		}
		return
	case len(copies) == 1:
		r.add("installed binary", OK, copies[0].path)
		return
	}

	same := true
	for _, copy := range copies[1:] {
		if copy.sum != copies[0].sum {
			same = false
			break
		}
	}
	paths := make([]string, 0, len(copies))
	for _, copy := range copies {
		paths = append(paths, copy.path)
	}
	if same {
		r.add("installed binary", OK, strings.Join(paths, " and ")+" (identical)")
		return
	}
	r.add("installed binary", FAIL,
		"this host has different versions of peek at "+strings.Join(paths, " and "),
		"the service runs the one named in the unit file (usually /usr/bin/peek) while your "+
			"shell runs whichever comes first in PATH. Remove the copy you did not install: "+
			"systemctl cat peek | grep ExecStart")
}

// fileDigest hashes a file, for comparing two installed copies.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a fixed list of installation paths
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

func checkConfigFile(r *Report, path string) {
	if path == "" {
		r.add("config file", WARN, "no path given")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		r.add("config file", FAIL, fmt.Sprintf("%s: %v", path, err),
			"run sudo peek setup to create it")
		return
	}
	mode := info.Mode().Perm()
	detail := fmt.Sprintf("%s (mode %04o)", path, mode)
	// The file holds the SMTP password and the backup passphrase. Group read is
	// how the service gets to it (root:peek 0640); anything wider is a problem.
	if runtime.GOOS != "windows" && mode&0o027 != 0 {
		r.add("config file", WARN, detail,
			fmt.Sprintf("tighten it: sudo chmod 0640 %s && sudo chown root:peek %s", path, path))
		return
	}
	r.add("config file", OK, detail)
}

func checkMasterKey(r *Report, cfg *config.Config) {
	path := cfg.MasterKeyFile
	if path == "" {
		r.add("master key", WARN, "master_key_file is empty: metadata encryption at rest is disabled")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		r.add("master key", FAIL, fmt.Sprintf("%s: %v", path, err),
			"run sudo peek setup, or sudo peek key rotate --init, to create it")
		return
	}
	if info.Size() < 32 {
		r.add("master key", FAIL, fmt.Sprintf("%s is only %d bytes", path, info.Size()),
			"the key must be at least 32 bytes; restore it from your backup")
		return
	}
	mode := info.Mode().Perm()
	if runtime.GOOS != "windows" && mode&0o177 != 0 {
		r.add("master key", FAIL, fmt.Sprintf("%s has mode %04o", path, mode),
			fmt.Sprintf("sudo chmod 0400 %s && sudo chown peek:peek %s", path, path))
		return
	}
	r.add("master key", OK, fmt.Sprintf("%s (mode %04o)", path, mode))
}

func checkDirs(r *Report, cfg *config.Config) {
	for _, dir := range cfg.Dirs() {
		info, err := os.Stat(dir)
		if err != nil {
			r.add("directory "+dir, FAIL, err.Error(), "sudo install -d -o peek -g peek -m 0750 "+dir)
			continue
		}
		if !info.IsDir() {
			r.add("directory "+dir, FAIL, "not a directory")
			continue
		}
		if err := writable(dir); err != nil {
			r.add("directory "+dir, FAIL, "not writable by this user: "+err.Error(),
				"sudo chown -R peek:peek "+dir)
			continue
		}
		detail := fmt.Sprintf("writable (mode %04o)", info.Mode().Perm())
		if free, total, err := diskFree(dir); err == nil {
			detail += fmt.Sprintf(", %s free of %s", humanBytes(free), humanBytes(total))
			if total > 0 && free*100/total < 10 {
				r.add("directory "+dir, WARN, detail, "less than 10% free: backups and WAL growth will fail first")
				continue
			}
		}
		r.add("directory "+dir, OK, detail)
	}
}

func checkDatabase(ctx context.Context, r *Report, cfg *config.Config) {
	// Do not create the database from a diagnostic command: on a fresh install
	// the service has not started yet, and creating it here (usually under
	// sudo) would hand the service a set of files it cannot write.
	if path := cfg.SQLitePath(); path != "" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			r.add("database", OK, "not created yet; the service creates it at first start")
			return
		}
	}
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		r.add("database", FAIL, err.Error())
		return
	}
	defer func() { _ = st.Close() }()

	if err := st.Ping(ctx); err != nil {
		r.add("database", FAIL, "cannot reach the database: "+err.Error())
		return
	}
	applied, pending, err := st.MigrationStatus(ctx)
	if err != nil {
		r.add("database", FAIL, "cannot read the schema version: "+err.Error())
		return
	}
	active, err := st.CountActive(ctx)
	if err != nil {
		r.add("database", WARN, "schema up to date but counting secrets failed: "+err.Error())
		return
	}
	detail := fmt.Sprintf("%s, %d migration(s) applied, %d active secret(s)", cfg.Database.Driver, len(applied), active)
	if len(pending) > 0 {
		r.add("database", WARN, detail+fmt.Sprintf(", %d pending", len(pending)),
			"restart the service, or run sudo peek migrate up")
		return
	}
	r.add("database", OK, detail)
}

func checkListeners(r *Report, cfg *config.Config) {
	type binding struct {
		role string
		addr string
	}
	bindings := []binding{{"internal", cfg.Server.InternalListen}}
	if cfg.Server.PublicListen != "" {
		bindings = append(bindings, binding{"public", cfg.Server.PublicListen})
	} else {
		r.add("listener split", WARN,
			"a single listener serves recipients, creation and administration",
			"to expose Peek on the internet, set server.public_listen and publish only that port (see docs/REVERSE-PROXY.md)")
	}
	for _, b := range bindings {
		name := "listener " + b.role
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := dialer.DialContext(context.Background(), "tcp", dialable(b.addr))
		if err == nil {
			_ = conn.Close()
			r.add(name, OK, fmt.Sprintf("%s answers (service appears to be running)", b.addr))
			continue
		}
		var lc net.ListenConfig
		ln, lerr := lc.Listen(context.Background(), "tcp", b.addr)
		if lerr == nil {
			_ = ln.Close()
			r.add(name, WARN, fmt.Sprintf("%s is free: nothing is listening", b.addr),
				"start the service: sudo systemctl start peek")
			continue
		}
		r.add(name, FAIL, fmt.Sprintf("%s is neither reachable nor bindable: %v", b.addr, lerr),
			"another process may hold the port")
	}
}

func checkProxyTrust(r *Report, cfg *config.Config) {
	switch {
	case len(cfg.Server.TrustedProxies) == 0 && cfg.Server.ProxyProtocol:
		r.add("proxy trust", FAIL, "proxy_protocol is on but no trusted proxy is declared",
			"set server.trusted_proxies to the load balancer addresses")
	case len(cfg.Server.TrustedProxies) == 0:
		r.add("proxy trust", OK, "no trusted proxy: forwarded headers are ignored (correct for a direct exposure)")
	default:
		r.add("proxy trust", OK, fmt.Sprintf("forwarded headers honoured only from %s",
			strings.Join(cfg.Server.TrustedProxies, ", ")))
	}
	if len(cfg.Security.AdminAllowedCIDRs) == 0 && cfg.Server.PublicListen == "" {
		r.add("admin exposure", WARN, "administration is not restricted by network",
			"set security.admin_allowed_cidrs, or use the two-listener split")
	}
}

func checkTLS(ctx context.Context, r *Report, cfg *config.Config) {
	switch cfg.TLS.Mode {
	case "", "none":
		if strings.HasPrefix(cfg.PublicURL, "https://") {
			r.add("TLS", OK, "terminated upstream (tls.mode = none, public URL is https)")
		} else {
			r.add("TLS", WARN, "no TLS anywhere: public_url is http",
				"terminate TLS on the proxy, or set tls.mode = file")
		}
		if cfg.TLS.HSTS {
			r.add("HSTS", WARN, "hsts is on while Peek does not terminate TLS",
				"let the proxy own the header, or make sure it does not duplicate it")
		}
		return
	case "file":
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			r.add("TLS", FAIL, "cannot load the key pair: "+err.Error())
			return
		}
		leaf := cert.Leaf
		if leaf == nil && len(cert.Certificate) > 0 {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				r.add("TLS", WARN, "certificate loaded but could not be parsed: "+err.Error())
				return
			}
		}
		if leaf == nil {
			r.add("TLS", WARN, "certificate loaded, no leaf to inspect")
			return
		}
		left := time.Until(leaf.NotAfter)
		detail := fmt.Sprintf("certificate for %s, expires %s (%d days)",
			certNames(leaf), leaf.NotAfter.Format(time.DateOnly), int(left.Hours()/24))
		switch {
		case left <= 0:
			r.add("TLS", FAIL, detail, "the certificate has expired")
		case left < 14*24*time.Hour:
			r.add("TLS", WARN, detail, "renew it soon")
		default:
			r.add("TLS", OK, detail)
		}
		if host := hostOnly(cfg.Host()); host != "" {
			if err := leaf.VerifyHostname(host); err != nil {
				r.add("TLS hostname", FAIL, fmt.Sprintf("the certificate does not cover %s", host),
					"public_url and the certificate must agree")
			} else {
				r.add("TLS hostname", OK, host+" is covered")
			}
		}
	case "acme":
		checkACME(ctx, r, cfg)
	}
}

// checkACME inspects what can be inspected without asking a certificate
// authority for anything: the host list, the cache directory, and whether a
// certificate is already there.
//
// It deliberately makes no ACME call. Those are rate-limited per account and
// per domain, and a diagnostic command an operator runs in a loop must not be
// able to exhaust a weekly quota.
func checkACME(ctx context.Context, r *Report, cfg *config.Config) {
	hosts := cfg.TLS.ACMEHosts
	if len(hosts) == 0 {
		r.add("TLS", FAIL, "tls.mode = acme with no tls.acme_hosts")
		return
	}
	// A host no public authority could sign is a service that will not start,
	// so it is a FAIL here rather than a note further down.
	impossible := false
	for _, host := range hosts {
		if problem := config.ACMEHostProblem(host); problem != "" {
			r.add("TLS", FAIL, fmt.Sprintf("tls.acme_hosts: %q %s", host, problem),
				"use tls.mode = \"file\" with a certificate you supply, or terminate TLS on the proxy")
			impossible = true
		}
	}
	if impossible {
		return
	}

	r.add("TLS", OK, fmt.Sprintf("ACME for %s, challenge tls-alpn-01", strings.Join(hosts, ", ")),
		"the TLS listener must be reachable on port 443 from the internet: "+
			"tls-alpn-01 is answered on the same port, so nothing else needs publishing")

	// The names have to resolve to this host, or issuance fails at the
	// challenge with a message from the authority rather than from Peek.
	lookup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, host := range hosts {
		addrs, err := net.DefaultResolver.LookupHost(lookup, host)
		switch {
		case err != nil:
			r.add("ACME hostname "+host, FAIL, "does not resolve: "+err.Error(),
				"the certificate authority resolves this name to find this host")
		case len(addrs) == 0:
			r.add("ACME hostname "+host, FAIL, "resolves to nothing")
		default:
			r.add("ACME hostname "+host, OK, strings.Join(addrs, ", "))
		}
	}

	dir := cfg.TLS.ACMEDir
	if dir == "" {
		dir = filepath.Join(cfg.DataDir, "acme")
	}
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		r.add("ACME cache", WARN, dir+" does not exist yet",
			"it is created at the first start; the first connection to each host will be slow")
	case err != nil:
		r.add("ACME cache", FAIL, dir+": "+err.Error())
	default:
		certificates := 0
		for _, entry := range entries {
			if !entry.IsDir() && !strings.HasPrefix(entry.Name(), "acme_account") {
				certificates++
			}
		}
		if certificates == 0 {
			r.add("ACME cache", WARN, dir+" holds no certificate yet",
				"the first connection to each host obtains one, which takes a few seconds")
		} else {
			r.add("ACME cache", OK, fmt.Sprintf("%s, %d cached certificate(s)", dir, certificates))
		}
		if info, statErr := os.Stat(dir); statErr == nil && info.Mode().Perm() != 0o700 {
			r.add("ACME cache mode", WARN,
				fmt.Sprintf("%s is %04o", dir, info.Mode().Perm()),
				"it holds the account key and every private key issued; 0700 is right")
		}
	}

	if cfg.TLS.ACMEEmail == "" {
		r.add("ACME contact", WARN, "no tls.acme_email",
			"it is the only way the authority can warn you before a certificate stops renewing")
	}
	if url := cfg.TLS.ACMEDirectoryURL; url != "" {
		r.add("ACME directory", WARN, url,
			"this is not the Let’s Encrypt production directory; certificates from a staging directory are not trusted by browsers")
	}
}

func checkClock(r *Report) {
	now := time.Now()
	_, offset := now.Zone()
	detail := fmt.Sprintf("%s (UTC%+d)", now.Format(time.RFC3339), offset/3600)
	if now.Year() < 2024 {
		r.add("clock", FAIL, detail, "the system clock is wrong; expiries and TLS validation will misbehave")
		return
	}
	r.add("clock", OK, detail)
}

func checkMail(r *Report, cfg *config.Config, testTo string) {
	if cfg.Mail.Host == "" {
		r.add("SMTP", SKIP, "not configured: e-mail features are off")
		return
	}
	addr := net.JoinHostPort(cfg.Mail.Host, fmt.Sprint(cfg.Mail.Port))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		r.add("SMTP", FAIL, fmt.Sprintf("cannot connect to %s: %v", addr, err))
		return
	}
	_ = conn.Close()

	client, err := smtp.Dial(addr)
	if err != nil {
		r.add("SMTP", FAIL, fmt.Sprintf("SMTP handshake with %s failed: %v", addr, err))
		return
	}
	defer func() { _ = client.Close() }()

	if cfg.Mail.Encryption == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			r.add("SMTP", FAIL, addr+" does not offer STARTTLS although mail.encryption = starttls")
			return
		}
		if err := client.StartTLS(&tls.Config{
			ServerName:         cfg.Mail.Host,
			InsecureSkipVerify: cfg.Mail.SkipVerify, //nolint:gosec // operator opt-in for internal relays
			MinVersion:         tls.VersionTLS12,
		}); err != nil {
			r.add("SMTP", FAIL, "STARTTLS failed: "+err.Error())
			return
		}
	}
	if cfg.Mail.Username != "" {
		auth := smtp.PlainAuth("", cfg.Mail.Username, cfg.Mail.Password, cfg.Mail.Host)
		if err := client.Auth(auth); err != nil {
			r.add("SMTP", FAIL, "authentication refused: "+err.Error())
			return
		}
	}
	detail := fmt.Sprintf("%s reachable, encryption %s", addr, cfg.Mail.Encryption)
	if testTo != "" {
		r.add("SMTP", WARN, detail, "sending a test message is wired to the mail templates in milestone M6")
		return
	}
	r.add("SMTP", OK, detail)
}

// checkExternal tests the deployment from the outside in: does the public URL
// answer, is the certificate valid, which client IP does Peek see, and — the
// one that matters for an internet-facing install — is the admin surface
// reachable on the public listener.
func checkExternal(ctx context.Context, r *Report, cfg *config.Config) {
	base := strings.TrimRight(cfg.PublicURL, "/")
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := get(ctx, client, base+"/healthz")
	if err != nil {
		r.add("public URL", FAIL, fmt.Sprintf("GET %s/healthz failed: %v", base, err),
			"check DNS, the proxy, and that public_url matches what the proxy publishes")
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.add("public URL", FAIL, fmt.Sprintf("GET %s/healthz returned %d", base, resp.StatusCode))
	} else {
		r.add("public URL", OK, base+"/healthz answers 200")
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		r.add("public certificate", OK, fmt.Sprintf("issued by %s, expires %s",
			leaf.Issuer.CommonName, leaf.NotAfter.Format(time.DateOnly)))
	}

	// What client IP does Peek resolve for a request coming through the proxy?
	if resp, err := get(ctx, client, base+"/api/v1/ip"); err == nil {
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			ClientIP    string `json:"client_ip"`
			PeerAddr    string `json:"peer_addr"`
			Scheme      string `json:"scheme"`
			TrustedPeer bool   `json:"trusted_peer"`
			Listener    string `json:"listener"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) == nil {
			detail := fmt.Sprintf("Peek sees client %s (peer %s, scheme %s, listener %s)",
				body.ClientIP, body.PeerAddr, body.Scheme, body.Listener)
			switch {
			case len(cfg.Server.TrustedProxies) > 0 && !body.TrustedPeer:
				r.add("client IP", WARN, detail,
					"the request did not come from a trusted proxy: forwarded headers were ignored. Add the proxy address to server.trusted_proxies")
			case len(cfg.Server.TrustedProxies) > 0 && body.ClientIP == body.PeerAddr:
				r.add("client IP", WARN, detail,
					"the resolved client IP equals the proxy address: make the proxy send X-Forwarded-For")
			default:
				r.add("client IP", OK, detail)
			}
		}
	}

	// The one check that an exposed instance really needs.
	resp, err = get(ctx, client, base+"/api/v1/audit")
	if err != nil {
		r.add("admin surface", WARN, "could not probe /api/v1/audit: "+err.Error())
		return
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		r.add("admin surface", OK, fmt.Sprintf("/api/v1/audit is not served publicly (HTTP %d)", resp.StatusCode))
	case http.StatusOK:
		r.add("admin surface", FAIL, "/api/v1/audit answered 200 through the public URL",
			"publish only server.public_listen, or set security.admin_allowed_cidrs")
	default:
		r.add("admin surface", WARN, fmt.Sprintf("/api/v1/audit returned %d through the public URL", resp.StatusCode))
	}
}

func get(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	if _, err := url.Parse(target); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "peek-doctor")
	return client.Do(req)
}

func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".peek-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func dialable(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func hostOnly(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// unusedPath keeps filepath imported for the platform-specific helpers.
var _ = filepath.Clean

// certNames describes who a certificate is for, the way an operator reading
// one line needs it: every DNS name and every IP address it covers, and the
// subject when it covers neither.
//
// Listing only DNSNames was misleading in exactly the case that matters on a
// lab or an appliance — a certificate issued for an IP address reported itself
// as being "for localhost", because that was the only DNS name in it.
func certNames(leaf *x509.Certificate) string {
	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		if leaf.Subject.CommonName != "" {
			return leaf.Subject.CommonName
		}
		return "an unnamed subject"
	}
	return strings.Join(names, ", ")
}

// checkStorage reports where encrypted attachments live, and for a remote
// backend whether Peek can actually reach it.
//
// The local backend is already covered by checkDirs, which inspects the
// directory and its free space. An S3 bucket was covered by nothing at all: a
// wrong key, a wrong region or an unreachable endpoint only showed up when a
// user tried to send their first file. A listing is the lightest request that
// proves credentials, signature and reachability at once, and it writes
// nothing.
// checkSSO reaches the identity provider's discovery document and key set.
//
// This is the check that turns a silent "sign-in failed" into a sentence: a
// wrong issuer, an unreachable provider, a private certificate authority that
// is not trusted, all look identical from a browser.
func checkSSO(ctx context.Context, r *Report, cfg *config.Config) {
	if !cfg.SSO.Enabled {
		r.add("single sign-on", SKIP, "not configured")
		return
	}
	provider, err := oidc.New(cfg.SSO, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		r.add("single sign-on", FAIL, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	meta, err := provider.Metadata(ctx)
	if err != nil {
		r.add("single sign-on", FAIL, err.Error(),
			"check sso.issuer, and sso.ca_file if the provider has a private certificate authority")
		return
	}
	r.add("single sign-on", OK, fmt.Sprintf("%s — %s reachable", cfg.SSO.Label(), meta.Issuer))

	// The redirect URI has to be registered at the provider, character for
	// character, and getting it wrong is the single most common failure.
	r.add("sso redirect URI", OK, cfg.RedirectURI(),
		"this exact value must be registered as a redirect URI in the application at the provider")

	if usable, err := provider.CheckKeys(ctx); err != nil {
		r.add("sso signing keys", FAIL, err.Error())
	} else {
		r.add("sso signing keys", OK,
			fmt.Sprintf("%d usable signing key(s) at %s", usable, meta.JWKSURI))
	}

	switch {
	case cfg.SSO.RequireGroup && !cfg.SSO.MapsGroups():
		r.add("sso role mapping", FAIL, "require_group is set but no group is mapped")
	case cfg.SSO.MapsGroups():
		r.add("sso role mapping", OK, fmt.Sprintf("claim %q, %d admin / %d manager / %d auditor / %d member group(s)",
			cfg.SSO.Claim(), len(cfg.SSO.AdminGroups), len(cfg.SSO.ManagerGroups),
			len(cfg.SSO.AuditorGroups), len(cfg.SSO.MemberGroups)))
	default:
		r.add("sso role mapping", WARN,
			fmt.Sprintf("no group is mapped: everyone gets the %s role", orDash(cfg.SSO.DefaultRole)),
			"map your directory groups with sso.admin_groups and the rest")
	}

	if cfg.SSO.Required {
		if len(cfg.SSO.PasswordExempt) == 0 {
			r.add("sso break-glass account", FAIL,
				"sso.required is set and sso.password_exempt is empty",
				"one provider outage, or one expired client secret, and nobody can sign in. "+
					"Name at least one local account in sso.password_exempt and give it a second factor")
		} else {
			r.add("sso break-glass account", OK,
				fmt.Sprintf("%d account(s) may still sign in locally", len(cfg.SSO.PasswordExempt)))
		}
	}
}

// checkWebhooks reports the configuration and, more usefully, the state of the
// queue. A backlog whose oldest row keeps ageing is a receiver that is down,
// and that is invisible from everywhere else: the deliveries are retried
// quietly by design, so nothing fails loudly until an operator looks.
func checkWebhooks(ctx context.Context, r *Report, cfg *config.Config) {
	if len(cfg.Webhooks) == 0 {
		r.add("webhooks", SKIP, "none configured")
		return
	}
	var names []string
	insecure := 0
	for _, hook := range cfg.Webhooks {
		label := hook.Name
		if hook.Disabled {
			label += " (disabled)"
		}
		if hook.SkipVerify {
			insecure++
		}
		names = append(names, label)
	}
	line := fmt.Sprintf("%d endpoint(s): %s", len(cfg.Webhooks), strings.Join(names, ", "))
	if insecure > 0 {
		r.add("webhooks", WARN, line,
			fmt.Sprintf("%d endpoint(s) have skip_tls_verify = true: the signature proves who sent the body, not who read it", insecure))
	} else {
		r.add("webhooks", OK, line)
	}

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		// checkDatabase has already said so; do not say it twice.
		return
	}
	defer func() { _ = st.Close() }()

	stats, err := st.DeliveryStats(ctx)
	if err != nil {
		r.add("webhook queue", FAIL, err.Error())
		return
	}
	line = fmt.Sprintf("%d pending, %d delivered, %d given up on", stats.Pending, stats.Delivered, stats.Failed)
	switch {
	case stats.Failed > 0:
		r.add("webhook queue", WARN, line,
			"peek webhook queue --state failed says why; peek webhook retry sends them again once the receiver is back")
	case !stats.Oldest.IsZero() && time.Since(stats.Oldest) > time.Hour:
		r.add("webhook queue", WARN, line+fmt.Sprintf(", oldest %s old", time.Since(stats.Oldest).Round(time.Minute)),
			"a pending delivery older than an hour means the receiver is refusing or unreachable")
	default:
		r.add("webhook queue", OK, line)
	}
}

func checkStorage(ctx context.Context, r *Report, cfg *config.Config) {
	backend, err := storage.Open(cfg.Storage)
	if err != nil {
		r.add("file storage", FAIL, err.Error(), "check the [storage] section of peek.toml")
		return
	}
	if cfg.Storage.Backend == "local" || cfg.Storage.Backend == "" {
		r.add("file storage", OK, backend.Describe())
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	keys, err := backend.List(ctx)
	if err != nil {
		r.add("file storage", FAIL, backend.Describe()+": "+err.Error(),
			"check storage.s3_endpoint, the credentials and the region; the bucket must exist and allow listing")
		return
	}
	r.add("file storage", OK, fmt.Sprintf("%s — reachable, %d object(s)", backend.Describe(), len(keys)))
}
