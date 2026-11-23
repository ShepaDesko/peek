package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/auth"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// peek admin — account management from the server, for the cases the
// interface cannot help with: the first account, a lost second factor, a
// forgotten password on an instance with no e-mail.

func runAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail("usage: peek admin create|list|reset-password|disable-2fa|set-role [options]")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("admin "+sub, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	email := fs.String("email", "", "account e-mail address")
	name := fs.String("name", "", "display name")
	role := fs.String("role", "", "admin | manager | member | auditor | platform_admin")
	password := fs.String("password", "", "password (prompted when omitted)")
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

	// The master key is only needed to read or clear a second factor.
	cipher, cipherErr := pcrypto.LoadServerCipher(cfg.MasterKeyFile)
	svc := accounts.New(st, &cfg, cipher)

	switch sub {
	case "create":
		return adminCreate(ctx, svc, st, *email, *name, *role, *password)
	case "list":
		return adminList(ctx, st)
	case "reset-password":
		return adminResetPassword(ctx, st, *email, *password)
	case "disable-2fa":
		if cipherErr != nil {
			fmt.Fprintf(os.Stderr, "note: %v\n", cipherErr)
		}
		return adminDisable2FA(ctx, st, *email)
	case "set-role":
		return adminSetRole(ctx, st, *email, *role)
	default:
		return fail("unknown subcommand %q (expected create, list, reset-password, disable-2fa or set-role)", sub)
	}
}

func adminCreate(ctx context.Context, svc *accounts.Service, st *store.Store, email, name, role, password string) error {
	if email == "" {
		return fail("--email is required")
	}
	if role == "" {
		role = store.RoleAdmin
	}
	if password == "" {
		var err error
		if password, err = promptNewPassword(); err != nil {
			return err
		}
	}

	// The very first account goes through Bootstrap, which refuses to run
	// twice; later ones are created directly, since there is no session here
	// to act on behalf of.
	empty, err := svc.NeedsBootstrap(ctx, store.DefaultOrgID)
	if err != nil {
		return err
	}
	if empty {
		user, err := svc.Bootstrap(ctx, store.DefaultOrgID, email, password, name)
		if err != nil {
			return err
		}
		fmt.Printf("created the first administrator: %s\n", user.Email)
		return nil
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	user, err := st.CreateUser(ctx, store.User{
		OrgID:        store.DefaultOrgID,
		Email:        email,
		DisplayName:  name,
		Role:         role,
		Status:       store.UserActive,
		PasswordHash: hash,
		// Set from a terminal by someone else: the owner changes it on first use.
		MustChangePassword: true,
	})
	if err != nil {
		if errors.Is(err, store.ErrUserExists) {
			return fail("an account already exists for %s", email)
		}
		return err
	}
	if err := st.Append(ctx, store.AuditEvent{
		OrgID: user.OrgID, UserID: user.ID, Event: store.EventUserCreated,
		Detail: map[string]string{"role": user.Role, "via": "cli"},
	}); err != nil {
		return err
	}
	fmt.Printf("created %s (%s). They must change this password on first use.\n", user.Email, user.Role)
	return nil
}

func adminList(ctx context.Context, st *store.Store) error {
	users, err := st.ListUsers(ctx, store.DefaultOrgID)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("no account yet. Create the first one with: sudo peek admin create --email you@example.com")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "E-MAIL\tROLE\tSTATUS\t2FA\tLAST LOGIN")
	for _, u := range users {
		last := "-"
		if !u.LastLoginAt.IsZero() {
			last = u.LastLoginAt.Local().Format("2006-01-02 15:04")
		}
		totp := "no"
		if u.HasTOTP() {
			totp = "yes"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", u.Email, u.Role, u.Status, totp, last)
	}
	return w.Flush()
}

func adminResetPassword(ctx context.Context, st *store.Store, email, password string) error {
	if email == "" {
		return fail("--email is required")
	}
	user, err := st.UserByEmail(ctx, store.DefaultOrgID, email)
	if err != nil {
		return fail("no account for %s", email)
	}
	if password == "" {
		if password, err = promptNewPassword(); err != nil {
			return err
		}
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if err := st.SetPassword(ctx, user.ID, hash, true); err != nil {
		return err
	}
	// A password change ends every session, here as well as in the interface.
	if _, err := st.RevokeUserSessions(ctx, user.ID, "", time.Now()); err != nil {
		return err
	}
	if err := st.Append(ctx, store.AuditEvent{
		OrgID: user.OrgID, UserID: user.ID, Event: store.EventPasswordReset,
		Detail: map[string]string{"via": "cli"},
	}); err != nil {
		return err
	}
	fmt.Printf("password reset for %s. Every session was signed out, and they must change it on next sign-in.\n", user.Email)
	return nil
}

func adminDisable2FA(ctx context.Context, st *store.Store, email string) error {
	if email == "" {
		return fail("--email is required")
	}
	user, err := st.UserByEmail(ctx, store.DefaultOrgID, email)
	if err != nil {
		return fail("no account for %s", email)
	}
	if !user.HasTOTP() {
		fmt.Printf("%s has no second factor enrolled.\n", user.Email)
		return nil
	}
	if err := st.DisableTOTP(ctx, user.ID); err != nil {
		return err
	}
	if _, err := st.RevokeUserSessions(ctx, user.ID, "", time.Now()); err != nil {
		return err
	}
	if err := st.Append(ctx, store.AuditEvent{
		OrgID: user.OrgID, UserID: user.ID, Event: store.EventTOTPDisabled,
		Detail: map[string]string{"via": "cli"},
	}); err != nil {
		return err
	}
	fmt.Printf("second factor removed for %s, and every session signed out.\n", user.Email)
	fmt.Println("tell them to enrol a new authenticator at their next sign-in.")
	return nil
}

func adminSetRole(ctx context.Context, st *store.Store, email, role string) error {
	if email == "" || role == "" {
		return fail("--email and --role are required")
	}
	switch role {
	case store.RoleAdmin, store.RoleManager, store.RoleMember, store.RoleAuditor,
		store.RolePlatformAdmin:
	default:
		return fail("unknown role %q (admin, manager, member, auditor or platform_admin)", role)
	}
	user, err := st.UserByEmail(ctx, store.DefaultOrgID, email)
	if err != nil {
		return fail("no account for %s", email)
	}
	if user.Role == store.RoleAdmin && role != store.RoleAdmin {
		if err := ensureAnotherAdmin(ctx, st, user.ID); err != nil {
			return err
		}
	}
	if err := st.UpdateUserProfile(ctx, user.ID, user.DisplayName, role, user.Status); err != nil {
		return err
	}
	fmt.Printf("%s is now %s.\n", user.Email, role)
	return nil
}

// ensureAnotherAdmin refuses to leave the instance without an administrator,
// the same rule the interface enforces.
func ensureAnotherAdmin(ctx context.Context, st *store.Store, excluding string) error {
	users, err := st.ListUsers(ctx, store.DefaultOrgID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.ID != excluding && u.Role == store.RoleAdmin && u.Status != store.UserDisabled {
			return nil
		}
	}
	return fail("this is the last administrator of the instance")
}

// promptNewPassword asks twice, without echo.
func promptNewPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fail("no terminal to read a password from; pass --password")
	}
	_, _ = fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	_, _ = fmt.Fprint(os.Stderr, "Repeat: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", fail("the two passwords differ")
	}
	return string(first), nil
}

// hashPassword is the one place the CLI creates a credential.
func hashPassword(password string) (string, error) {
	return auth.HashPassword(password)
}
