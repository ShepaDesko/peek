package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// peek token — API tokens from the server.
//
// The interface can do this too, but a token is usually wanted by whatever is
// provisioning the machine, before anybody has signed in. This runs as root on
// the host and needs no session.

func runToken(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek token create|list|revoke [options]\n\nscopes: " +
			strings.Join(store.AllScopes, ", "))
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("token "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	email := fs.String("email", "", "account the token belongs to")
	name := fs.String("name", "", "what to call the token")
	scopes := fs.String("scopes", store.ScopeSecretsWrite, "comma-separated: "+strings.Join(store.AllScopes, ", "))
	ttl := fs.String("ttl", "", "expiry, for example 90d (default: never)")
	id := fs.String("id", "", "token identifier, for revoke")
	all := fs.Bool("all", false, "list every token of the instance")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	cipher, _ := pcrypto.LoadServerCipher(cfg.MasterKeyFile)
	svc := accounts.New(st, &cfg, cipher)

	switch sub {
	case "create":
		return tokenCreate(ctx, svc, st, *email, *name, *scopes, *ttl)
	case "list":
		return tokenList(ctx, st, *email, *all)
	case "revoke":
		return tokenRevoke(ctx, svc, *id)
	default:
		return fail("unknown subcommand %q: expected create, list or revoke", sub)
	}
}

func tokenCreate(ctx context.Context, svc *accounts.Service, st *store.Store, email, name, scopes, ttl string) error {
	if email == "" || name == "" {
		return fail("peek token create needs --email and --name")
	}
	user, err := st.UserByEmail(ctx, store.DefaultOrgID, email)
	if err != nil {
		return fail("no account for %s", email)
	}

	var lifetime time.Duration
	if ttl != "" {
		var d config.Duration
		if err := d.UnmarshalText([]byte(ttl)); err != nil {
			return fail("cannot read --ttl %q: %v", ttl, err)
		}
		lifetime = d.Std()
	}

	list := strings.FieldsFunc(scopes, func(r rune) bool { return r == ',' || r == ' ' })
	issued, err := svc.CreateToken(ctx, user.ID, name, list, lifetime)
	if err != nil {
		return fail("%v", err)
	}

	expiry := "never"
	if !issued.Token.ExpiresAt.IsZero() {
		expiry = issued.Token.ExpiresAt.Format(time.RFC3339)
	}
	fmt.Printf("token created for %s\n", email)
	fmt.Printf("  id      %s\n", issued.Token.ID)
	fmt.Printf("  scopes  %s\n", strings.Join(issued.Token.Scopes, " "))
	fmt.Printf("  expires %s\n\n", expiry)
	// On stdout and once: this is the only moment the clear text exists
	// anywhere but in the caller's own storage.
	fmt.Println(issued.Secret)
	fmt.Fprintln(os.Stderr, "\nStore it now. It is not recoverable, and the database holds only its digest.")
	return nil
}

func tokenList(ctx context.Context, st *store.Store, email string, all bool) error {
	owner := ""
	if !all {
		if email == "" {
			return fail("peek token list needs --email, or --all for the whole instance")
		}
		user, err := st.UserByEmail(ctx, store.DefaultOrgID, email)
		if err != nil {
			return fail("no account for %s", email)
		}
		owner = user.ID
	}

	tokens, err := st.ListAPITokens(ctx, owner)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Println("no token")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tNAME\tSCOPES\tCREATED\tLAST USED\tSTATE")
	for _, t := range tokens {
		state := "active"
		switch {
		case !t.RevokedAt.IsZero():
			state = "revoked"
		case !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(time.Now()):
			state = "expired"
		}
		last := "never"
		if !t.LastUsedAt.IsZero() {
			last = t.LastUsedAt.Format(time.DateOnly)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Name, strings.Join(t.Scopes, " "),
			t.CreatedAt.Format(time.DateOnly), last, state)
	}
	return w.Flush()
}

func tokenRevoke(ctx context.Context, svc *accounts.Service, id string) error {
	if id == "" {
		return fail("peek token revoke needs --id (peek token list --all shows them)")
	}
	if err := svc.RevokeToken(ctx, id, ""); err != nil {
		return fail("no active token with id %s", id)
	}
	fmt.Printf("token %s revoked\n", id)
	return nil
}
