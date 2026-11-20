package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

func runConfig(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek config check|show [--config PATH]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch sub {
	case "check":
		cfg, err := config.Load(*configPath, false)
		if err != nil {
			return err
		}
		fmt.Printf("%s is valid.\n", *configPath)
		fmt.Printf("  public URL       %s\n", cfg.PublicURL)
		fmt.Printf("  internal listen  %s\n", cfg.Server.InternalListen)
		if cfg.Server.PublicListen != "" {
			fmt.Printf("  public listen    %s (recipient routes only)\n", cfg.Server.PublicListen)
		}
		fmt.Printf("  database         %s %s\n", cfg.Database.Driver, cfg.Database.DSN)
		return nil

	case "show":
		cfg, err := config.Load(*configPath, false)
		if err != nil {
			return err
		}
		buf, err := cfg.Redacted().Marshal()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(buf)
		return err

	default:
		return fail("unknown subcommand %q (expected check or show)", sub)
	}
}

func runMigrate(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek migrate status|up [--config PATH]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("migrate "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}

	// Opening the store already applies pending migrations, which is exactly
	// what the service does at startup.
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	applied, pending, err := st.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	switch sub {
	case "status", "up":
		fmt.Printf("database: %s %s\n", cfg.Database.Driver, cfg.Database.DSN)
		fmt.Printf("applied : %v\n", applied)
		if len(pending) == 0 {
			fmt.Println("pending : none")
			return nil
		}
		for _, m := range pending {
			fmt.Printf("pending : %d %s\n", m.Version, m.Name)
		}
		return nil
	default:
		return fail("unknown subcommand %q (expected status or up)", sub)
	}
}
