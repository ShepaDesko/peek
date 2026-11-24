package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/backup"
	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/doctor"
	"github.com/ShepaDesko/peek/internal/setup"
	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/update"
)

// ---------------------------------------------------------------------------
// peek setup
// ---------------------------------------------------------------------------

func runSetup(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	opts := setup.Options{}
	fs.StringVar(&opts.ConfigPath, "config", defaultConfigPath(), "path to peek.toml")
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "never prompt; take the flags and the defaults")
	fs.BoolVar(&opts.Force, "force", false, "reconfigure without asking for confirmation")
	fs.StringVar(&opts.PublicURL, "public-url", "", "URL users will type, e.g. https://secrets.example.com")
	fs.StringVar(&opts.Mode, "mode", "", "internal | proxy | direct")
	fs.StringVar(&opts.InternalListen, "internal-listen", "", "address for all routes, e.g. 127.0.0.1:8080")
	fs.StringVar(&opts.PublicListen, "public-listen", "", "address for recipient routes only, e.g. 0.0.0.0:8081")
	fs.StringVar(&opts.TrustedProxies, "trusted-proxies", "", "comma separated proxy IPs or CIDRs")
	fs.StringVar(&opts.TLSMode, "tls", "", "none | file")
	fs.StringVar(&opts.CertFile, "tls-cert", "", "certificate file")
	fs.StringVar(&opts.KeyFile, "tls-key", "", "private key file")
	fs.StringVar(&opts.DBDriver, "db", "", "sqlite | postgres")
	fs.StringVar(&opts.DBDSN, "dsn", "", "database path or DSN")
	fs.StringVar(&opts.DataDir, "data-dir", "", "data directory")
	fs.StringVar(&opts.Language, "lang", "", "default language (fr | en)")
	fs.StringVar(&opts.ServiceName, "service-name", "", "name shown to users")
	fs.StringVar(&opts.SMTPHost, "smtp-host", "", "SMTP host")
	fs.IntVar(&opts.SMTPPort, "smtp-port", 0, "SMTP port")
	fs.StringVar(&opts.SMTPFrom, "smtp-from", "", "sender address")
	fs.BoolVar(&opts.AnonymousCreate, "anonymous-create", false, "allow creating secrets without an account")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS == "linux" && os.Geteuid() != 0 && strings.HasPrefix(opts.ConfigPath, "/etc/") {
		fmt.Fprintln(os.Stderr, "note: not running as root — writing to /etc/peek will fail. Use sudo peek setup.")
	}

	res, err := setup.Run(opts)
	if err != nil {
		return err
	}

	fmt.Println()
	report := doctor.Run(context.Background(), doctor.Options{
		ConfigPath: res.ConfigPath,
		Config:     &res.Config,
		Version:    version,
	})
	report.Write(os.Stdout)
	return nil
}

// ---------------------------------------------------------------------------
// peek doctor
// ---------------------------------------------------------------------------

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	external := fs.Bool("external", false, "also test the public URL, the certificate and the admin exposure")
	asJSON := fs.Bool("json", false, "machine readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, loadErr := config.Load(*configPath, false)
	opts := doctor.Options{ConfigPath: *configPath, External: *external, Version: version}
	if loadErr == nil {
		opts.Config = &cfg
	} else {
		fmt.Fprintf(os.Stderr, "configuration problem: %v\n\n", loadErr)
	}

	report := doctor.Run(ctx, opts)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		report.Write(os.Stdout)
	}
	if report.Failed() {
		return exitError{code: 1, msg: "peek doctor: checks failed (see the FAIL lines above)"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// peek backup / restore
// ---------------------------------------------------------------------------

func runBackup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	to := fs.String("to", "", "destination directory (default: backup.dir from the configuration)")
	passphrase := fs.String("passphrase", "", "encrypt the archive with this passphrase (age)")
	keep := fs.Int("keep", 0, "how many archives to keep (default: backup.keep)")
	list := fs.Bool("list", false, "list existing archives instead of taking a new one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	dir := *to
	if dir == "" {
		dir = cfg.Backup.Dir
	}

	if *list {
		infos, err := backup.List(dir)
		if err != nil {
			return err
		}
		if len(infos) == 0 {
			fmt.Printf("no backup in %s\n", dir)
			return nil
		}
		for _, info := range infos {
			fmt.Printf("%s  %9s  %s\n", info.ModTime().UTC().Format(time.RFC3339), humanSize(info.Size()), info.Name())
		}
		return nil
	}

	res, err := backup.Create(ctx, backup.Options{
		Config:      &cfg,
		Dir:         dir,
		Passphrase:  *passphrase,
		PeekVersion: version,
		Keep:        *keep,
	})
	if err != nil {
		return err
	}
	fmt.Printf("backup written: %s (%s%s)\n", res.Path, humanSize(res.Bytes), encryptedSuffix(res.Encrypted))
	for _, name := range res.Pruned {
		fmt.Printf("pruned: %s\n", name)
	}
	if !res.Encrypted {
		fmt.Println("warning: the archive is NOT encrypted and holds the ciphertext of active secrets plus the master key.")
		fmt.Println("         set backup.passphrase in peek.toml, or pass --passphrase, and keep the retention short.")
	}
	return nil
}

func runRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	passphrase := fs.String("passphrase", "", "passphrase of an encrypted archive")
	includeConfig := fs.Bool("include-config", false, "also restore peek.toml and master.key")
	dryRun := fs.Bool("dry-run", false, "only read the manifest and report what would be restored")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fail("usage: peek restore [options] ARCHIVE")
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	archive := positional[0]
	// An archive encrypted with the configured passphrase should not need it
	// typed again: the operator already put it in peek.toml.
	if *passphrase == "" {
		*passphrase = cfg.Backup.Passphrase
	}

	if !*dryRun && !*yes {
		fmt.Printf("This replaces the database at %s (the current one is kept aside).\n", cfg.Database.DSN)
		fmt.Print("Continue? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return errors.New("cancelled")
		}
	}

	manifest, err := backup.Restore(ctx, backup.RestoreOptions{
		Config:        &cfg,
		Archive:       archive,
		Passphrase:    *passphrase,
		IncludeConfig: *includeConfig,
		DryRun:        *dryRun,
	})
	if err != nil {
		return err
	}
	fmt.Printf("archive from %s, taken by peek %s on %s\n",
		manifest.CreatedAt.Format(time.RFC3339), orDash(manifest.PeekVersion), orDash(manifest.Hostname))
	fmt.Printf("contents: %s\n", strings.Join(manifest.Files, ", "))
	if *dryRun {
		fmt.Println("dry run: nothing was written.")
		return nil
	}
	fmt.Println("restore complete. Restart the service: sudo systemctl restart peek")
	return nil
}

// ---------------------------------------------------------------------------
// peek update / rollback
// ---------------------------------------------------------------------------

func runUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	check := fs.Bool("check", false, "only report whether an update is available (exit 10 if there is one)")
	wanted := fs.String("version", "", "install this exact version")
	file := fs.String("file", "", "install from a local release archive (offline update)")
	sigFile := fs.String("signature", "", "signature file for an offline update (default: ARCHIVE.minisig)")
	channel := fs.String("channel", "", "stable | beta")
	skipBackup := fs.Bool("skip-backup", false, "do not take a backup first (not recommended)")
	allowUnsigned := fs.Bool("allow-unsigned", false, "install without verifying a signature (never do this on a customer instance)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	if *channel == "" {
		*channel = cfg.UpdateChannel
	}

	target, err := os.Executable()
	if err != nil {
		return err
	}
	target, _ = filepath.EvalSymlinks(target)

	work, err := os.MkdirTemp("", "peek-update-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	var archivePath, signaturePath, checksumsPath, newVersion string

	if *file != "" {
		archivePath = *file
		newVersion = guessVersion(filepath.Base(*file))
		signaturePath = *sigFile
		// By default the signature covers the archive itself, which is what an
		// operator signing their own mirror produces.
		checksumsPath = archivePath

		switch {
		case signaturePath == "":
			for _, candidate := range []string{*file + ".minisig", *file + ".sig"} {
				if _, err := os.Stat(candidate); err == nil {
					signaturePath = candidate
					break
				}
			}
		case strings.HasPrefix(filepath.Base(signaturePath), "checksums"):
			// An explicit signature over a checksum file.
			checksumsPath = strings.TrimSuffix(strings.TrimSuffix(signaturePath, ".minisig"), ".sig")
		}

		if signaturePath == "" {
			// A release does not sign each archive: it signs checksums.txt
			// once, and that one signature covers every artefact. So the
			// air-gapped path is to copy the archive, checksums.txt and
			// checksums.txt.minisig to the host — and then the chain verifies
			// here exactly as it does online. Looking for that pair next to the
			// archive is what makes the published files usable offline;
			// without it this command refused the very artefacts it ships.
			list := filepath.Join(filepath.Dir(archivePath), "checksums.txt")
			if _, err := os.Stat(list); err == nil {
				for _, candidate := range []string{list + ".minisig", list + ".sig"} {
					if _, err := os.Stat(candidate); err == nil {
						signaturePath, checksumsPath = candidate, list
						break
					}
				}
			}
		}

		if checksumsPath != archivePath {
			if err := update.VerifyChecksum(archivePath, checksumsPath); err != nil {
				return err
			}
			fmt.Println("checksum verified")
		}
	} else {
		client := update.NewClient(cfg.UpdateURL, *channel, os.Getenv("PEEK_UPDATE_TOKEN"))
		var release *update.Release
		if *wanted != "" {
			release, err = client.Find(ctx, *wanted)
		} else {
			release, err = client.Latest(ctx)
		}
		if err != nil {
			return err
		}
		newVersion = strings.TrimPrefix(release.Version, "v")

		if *check {
			if sameVersion(newVersion, version) {
				fmt.Printf("peek %s is up to date (channel %s).\n", version, *channel)
				return nil
			}
			fmt.Printf("update available: %s → %s (channel %s)\n", version, newVersion, *channel)
			if summary := firstLines(release.Body, 10); summary != "" {
				fmt.Printf("\n%s\n", summary)
			}
			// A distinct exit code lets monitoring act on it.
			return exitError{code: 10, msg: "update available: run sudo peek update"}
		}
		if sameVersion(newVersion, version) && *wanted == "" {
			fmt.Printf("peek %s is already the latest release on channel %s.\n", version, *channel)
			return nil
		}

		archive, checksums, signature, err := update.AssetFor(release)
		if err != nil {
			return err
		}
		fmt.Printf("downloading %s (%s)…\n", archive.Name, humanSize(archive.Size))
		if archivePath, err = client.Download(ctx, archive, work); err != nil {
			return err
		}
		if checksums != nil {
			if checksumsPath, err = client.Download(ctx, checksums, work); err != nil {
				return err
			}
		}
		if signature != nil {
			if signaturePath, err = client.Download(ctx, signature, work); err != nil {
				return err
			}
		}
		if checksumsPath != "" && checksumsPath != archivePath {
			if err := update.VerifyChecksum(archivePath, checksumsPath); err != nil {
				return err
			}
			fmt.Println("checksum verified")
		}
	}

	if signaturePath == "" {
		if !*allowUnsigned {
			return fail("no signature found for this release. Refusing to install.\n" +
				"Pass --signature FILE, or --allow-unsigned if you really accept the risk.")
		}
		fmt.Println("WARNING: installing an unsigned release because --allow-unsigned was given.")
	} else {
		if err := update.VerifySignature(checksumsPath, signaturePath, update.SigningPublicKey); err != nil {
			if !*allowUnsigned {
				return err
			}
			fmt.Printf("WARNING: %v — continuing because --allow-unsigned was given.\n", err)
		} else {
			fmt.Println("signature verified")
		}
	}

	if !*yes {
		fmt.Printf("\nAbout to replace %s (peek %s) with %s.\n", target, version, orDash(newVersion))
		fmt.Print("Continue? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return errors.New("cancelled")
		}
	}

	if !*skipBackup {
		res, err := backup.Create(ctx, backup.Options{Config: &cfg, PeekVersion: version})
		if err != nil {
			return fmt.Errorf("backup before update failed (use --skip-backup to override): %w", err)
		}
		fmt.Printf("backup taken: %s\n", res.Path)
	}

	binary, err := update.ExtractBinary(archivePath, work)
	if err != nil {
		return err
	}
	if err := update.SwapBinary(binary, target, update.PreviousBinaryPath); err != nil {
		return err
	}
	fmt.Printf("installed %s → %s (previous kept at %s)\n", orDash(newVersion), target, update.PreviousBinaryPath)

	if err := restartService(); err != nil {
		fmt.Printf("could not restart the service automatically: %v\n", err)
		fmt.Println("restart it yourself: sudo systemctl restart peek")
		// The binary is installed; only the restart failed, and the user
		// has been told how to finish. Reporting an error here would
		// suggest the update did not happen.
		return nil //nolint:nilerr // deliberate: see above
	}

	readyURL := strings.TrimRight(cfg.PublicURL, "/") + "/readyz"
	if err := update.WaitReady(ctx, readyURL, 60*time.Second); err != nil {
		fmt.Printf("the new version did not come up: %v\n", err)
		fmt.Println("rolling back…")
		if rbErr := rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed (%w) after the update failed: %w", rbErr, err)
		}
		_ = restartService()
		return fail("update rolled back. Check journalctl -u peek for the reason.")
	}
	fmt.Printf("peek %s is live and ready.\n", orDash(newVersion))
	return nil
}

func runRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	// Rollback never asks, so --yes changes nothing. It is accepted because an
	// operator reaching for it has just had an update go wrong, and a usage
	// error is the last thing that moment needs.
	_ = fs.Bool("yes", false, "accepted for symmetry with peek update; rollback never asks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rollback(); err != nil {
		return err
	}
	fmt.Printf("restored the previous binary from %s\n", update.PreviousBinaryPath)
	if err := restartService(); err != nil {
		fmt.Println("restart the service yourself: sudo systemctl restart peek")
		return nil //nolint:nilerr // the binary is installed; only the restart failed, and the user was told
	}
	if cfg, err := config.Load(*configPath, true); err == nil {
		if err := update.WaitReady(ctx, strings.TrimRight(cfg.PublicURL, "/")+"/readyz", 45*time.Second); err != nil {
			return err
		}
	}
	fmt.Println("service is ready again.")
	return nil
}

func rollback() error {
	if _, err := os.Stat(update.PreviousBinaryPath); err != nil {
		return fail("no previous binary at %s", update.PreviousBinaryPath)
	}
	target, err := os.Executable()
	if err != nil {
		return err
	}
	target, _ = filepath.EvalSymlinks(target)
	data, err := os.ReadFile(update.PreviousBinaryPath) //nolint:gosec // a path this binary owns
	if err != nil {
		return err
	}
	staged := target + ".rollback"
	if err := os.WriteFile(staged, data, 0o755); err != nil { //nolint:gosec // an executable
		return err
	}
	return os.Rename(staged, target)
}

func restartService() error {
	if runtime.GOOS != "linux" {
		return fail("automatic restart is only wired for systemd")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", "peek.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------------------
// peek key rotate
// ---------------------------------------------------------------------------

func runKey(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "rotate" {
		return fail("usage: peek key rotate [--config PATH] [--init] [--force]")
	}
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	initOnly := fs.Bool("init", false, "only create the key if it is missing")
	force := fs.Bool("force", false, "rotate even though data sealed with the current key will become unreadable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	if cfg.MasterKeyFile == "" {
		return fail("master_key_file is not set in %s", *configPath)
	}

	_, statErr := os.Stat(cfg.MasterKeyFile)
	exists := statErr == nil
	if exists && *initOnly {
		fmt.Printf("%s already exists; nothing to do.\n", cfg.MasterKeyFile)
		return nil
	}

	// Rotating is destructive on a populated instance: re-encryption is not
	// implemented, so everything sealed with the old key stops being
	// readable. The command used to say the opposite — "nothing stored today
	// needs re-encryption" — which was written before the master key had
	// anything to protect and was never revisited. It protects second factors
	// and notification addresses now, so an operator doing ordinary key
	// hygiene would have locked their users out of their own second factor on
	// the word of this command.
	if exists && !*initOnly {
		sealed, err := sealedCounts(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "note: cannot read the database to see what is sealed (%v)\n", err)
		} else if sealed.Total > 0 && !*force {
			return fail("rotating would make unreadable: %d second factor(s) and %d notification address(es).\n"+
				"Re-encryption with the new key is not implemented, so those users would have to enrol again\n"+
				"and those notifications would stop. Pass --force if that is what you want.", sealed.TOTP, sealed.Notify)
		} else if sealed.Total > 0 {
			fmt.Printf("rotating anyway: %d second factor(s) and %d notification address(es) become unreadable\n",
				sealed.TOTP, sealed.Notify)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if exists {
		// Keep the old key: anything sealed with it is unreadable without it,
		// and there is no re-encryption pass to run.
		aside := fmt.Sprintf("%s.%s.old", cfg.MasterKeyFile, time.Now().UTC().Format("20060102T150405Z"))
		data, err := os.ReadFile(cfg.MasterKeyFile)
		if err != nil {
			return err
		}
		if err := os.WriteFile(aside, data, 0o400); err != nil { //nolint:gosec // G703: a path the operator passed
			return err
		}
		fmt.Printf("previous key kept at %s — do not delete it until re-encryption is confirmed\n", aside)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.MasterKeyFile), 0o755); err != nil { //nolint:gosec // installed next to the binary
		return err
	}
	tmp := cfg.MasterKeyFile + ".new"
	if err := os.WriteFile(tmp, key, 0o400); err != nil {
		return err
	}
	if err := os.Rename(tmp, cfg.MasterKeyFile); err != nil {
		return err
	}
	fmt.Printf("wrote a new 256-bit master key to %s\n", cfg.MasterKeyFile)
	fmt.Println("secret payloads are unaffected: those are encrypted in the browser, and this key never saw them.")
	fmt.Println("what this key does protect, and what the old file above is still needed for: enrolled second")
	fmt.Println("factors and the notification addresses stored with secrets and requests.")
	fmt.Println("back this file up separately from the database, and restart the service.")
	return nil
}

// sealedCounts opens the database only to ask how much is encrypted with the
// master key. A database that cannot be opened is not a reason to refuse a
// rotation — an instance may have none yet — so the caller reports and
// carries on.
func sealedCounts(ctx context.Context, cfg config.Config) (store.Sealed, error) {
	db, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return store.Sealed{}, err
	}
	defer func() { _ = db.Close() }()
	return db.SealedCounts(ctx)
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", value/unit)
}

func encryptedSuffix(encrypted bool) string {
	if encrypted {
		return ", encrypted with age"
	}
	return ", not encrypted"
}

func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

func guessVersion(name string) string {
	parts := strings.Split(name, "_")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
