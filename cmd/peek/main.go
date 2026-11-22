// Command peek is the whole product: the HTTP server and every
// administration command, in one static binary.
//
//	peek serve                 run the service (this is what systemd starts)
//	peek setup                 interactive first install / reconfiguration
//	peek doctor [--external]   diagnose an installation
//	peek config check|show     validate or print the configuration
//	peek migrate status|up     database schema
//	peek backup|restore        hot backup and restore
//	peek update|rollback       signed update, offline or online
//	peek key rotate            rotate the server master key
//	peek branding export|import
//	peek version
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// Build information, set by the linker in release builds (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

// main keeps no deferred work of its own: run owns the signal context and
// returns an exit code, so os.Exit never skips a cleanup.
func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	commands := []command{
		{"serve", "run the HTTP service", runServe},
		{"setup", "interactive install or reconfiguration", runSetup},
		{"doctor", "diagnose the installation", runDoctor},
		{"config", "check or show the configuration", runConfig},
		{"migrate", "show or apply database migrations", runMigrate},
		{"backup", "take a consistent hot backup", runBackup},
		{"restore", "restore a backup", runRestore},
		{"update", "update Peek from a signed release", runUpdate},
		{"rollback", "go back to the previous binary", runRollback},
		{"key", "rotate the server master key", runKey},
		{"branding", "export or import the brand", runBranding},
		{"admin", "manage administrator accounts", runAdmin},
		{"token", "issue, list and revoke API tokens", runToken},
		{"version", "print the version", runVersion},
	}

	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(commands)
		if len(args) == 0 {
			return 2
		}
		return 0
	}

	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		if err := c.run(ctx, args[1:]); err != nil {
			if errors.Is(err, context.Canceled) {
				return 0
			}
			// A command may ask for a specific exit code, which is what makes
			// `peek update --check` usable in a monitoring script.
			var coded exitError
			if errors.As(err, &coded) {
				fmt.Fprintln(os.Stderr, coded.Error())
				return coded.code
			}
			fmt.Fprintf(os.Stderr, "peek %s: %v\n", c.name, err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "peek: unknown command %q\n\n", args[0])
	usage(commands)
	return 2
}

// exitError carries a specific exit code out of a command.
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

func usage(commands []command) {
	out := os.Stdout
	_, _ = fmt.Fprintf(out, "Peek %s — ephemeral secret sharing, self-hosted.\n\n", version)
	_, _ = fmt.Fprintln(out, "Usage: peek <command> [options]")
	_, _ = fmt.Fprintln(out)
	for _, c := range commands {
		_, _ = fmt.Fprintf(out, "  %-9s %s\n", c.name, c.summary)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Run peek <command> --help for the options of a command.")
	_, _ = fmt.Fprintf(out, "Configuration: %s\n", defaultConfigPath())
}

func runVersion(_ context.Context, _ []string) error {
	fmt.Printf("peek %s (commit %s, built %s)\n", version, commit, date)
	return nil
}

// defaultConfigPath honours PEEK_CONFIG, then the FHS location, then a local
// file so that a developer can run the binary from a checkout.
func defaultConfigPath() string {
	if v := os.Getenv("PEEK_CONFIG"); v != "" {
		return v
	}
	const fhs = "/etc/peek/peek.toml"
	if _, err := os.Stat(fhs); err == nil {
		return fhs
	}
	if _, err := os.Stat("peek.toml"); err == nil {
		abs, err := filepath.Abs("peek.toml")
		if err == nil {
			return abs
		}
		return "peek.toml"
	}
	return fhs
}

// fail builds a user-facing error without a stack trace.
func fail(format string, args ...any) error {
	return fmt.Errorf(strings.TrimSpace(format), args...)
}
