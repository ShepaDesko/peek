package accounts_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/auth"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

const (
	goodPassword  = "un-mot-de-passe-correct-2026"
	otherPassword = "un-autre-mot-de-passe-2026"
)

type fixture struct {
	svc   *accounts.Service
	store *store.Store
	cfg   *config.Config
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default()
	cfg.PublicURL = "https://secrets.example.test"
	cfg.Security.LoginAttempts = 3
	cfg.Security.LoginLockFor = config.Secs(60)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("configuration: %v", err)
	}

	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	cipher, err := pcrypto.NewServerCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: accounts.New(st, &cfg, cipher), store: st, cfg: &cfg}
}

func (f *fixture) admin(t *testing.T) store.User {
	t.Helper()
	user, err := f.svc.Bootstrap(context.Background(), store.DefaultOrgID,
		"admin@acme.example", goodPassword, "Admin ACME")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return user
}

func (f *fixture) principal(t *testing.T, email, password string) *accounts.Principal {
	t.Helper()
	res, err := f.svc.Login(context.Background(), store.DefaultOrgID, email, password, "203.0.113.5", "test")
	if err != nil {
		t.Fatalf("login as %s: %v", email, err)
	}
	if res.MFARequired {
		t.Fatalf("login as %s unexpectedly needs a second factor", email)
	}
	p, err := f.svc.Authenticate(context.Background(), res.SessionToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return p
}

func TestBootstrapOnlyOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	needs, err := f.svc.NeedsBootstrap(ctx, store.DefaultOrgID)
	if err != nil || !needs {
		t.Fatalf("a fresh instance should need bootstrapping (needs=%v err=%v)", needs, err)
	}

	user := f.admin(t)
	if user.Role != store.RoleAdmin || user.Status != store.UserActive {
		t.Fatalf("unexpected first user: %+v", user)
	}
	if user.PasswordHash == "" || strings.Contains(user.PasswordHash, goodPassword) {
		t.Fatal("the password was not hashed")
	}

	if _, err := f.svc.Bootstrap(ctx, store.DefaultOrgID, "second@acme.example", goodPassword, ""); err == nil {
		t.Fatal("a second bootstrap was allowed")
	}
	needs, err = f.svc.NeedsBootstrap(ctx, store.DefaultOrgID)
	if err != nil || needs {
		t.Fatalf("instance still reports needing bootstrap (needs=%v err=%v)", needs, err)
	}
}

func TestLoginAndSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	res, err := f.svc.Login(ctx, store.DefaultOrgID, "ADMIN@acme.example ", goodPassword, "203.0.113.5", "Firefox")
	if err != nil {
		t.Fatalf("login with a differently cased address failed: %v", err)
	}
	if res.SessionToken == "" || res.CSRFToken == "" {
		t.Fatal("login returned no tokens")
	}
	if res.MFARequired {
		t.Fatal("a second factor was required without enrolment")
	}

	p, err := f.svc.Authenticate(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.User.Email != "admin@acme.example" || !p.Can(store.RoleAdmin) {
		t.Fatalf("unexpected principal: %+v", p.User)
	}
	if !f.svc.CheckCSRF(p, res.CSRFToken) {
		t.Fatal("the CSRF token was rejected")
	}
	if f.svc.CheckCSRF(p, "not-the-token") {
		t.Fatal("a wrong CSRF token was accepted")
	}

	// The cookie value itself is never stored.
	if _, err := f.store.Session(ctx, res.SessionToken); err == nil {
		t.Fatal("the session is stored under the raw cookie value")
	}
	if _, err := f.store.Session(ctx, auth.HashTokenHex(res.SessionToken)); err != nil {
		t.Fatalf("the session is not stored under the hashed cookie: %v", err)
	}

	if err := f.svc.Logout(ctx, res.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, accounts.ErrNoSession) {
		t.Fatalf("a revoked session still authenticates: %v", err)
	}
}

func TestLoginFailuresAreIndistinguishableAndLock(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	unknown := f.svc
	_, errUnknown := unknown.Login(ctx, store.DefaultOrgID, "nobody@acme.example", goodPassword, "", "")
	_, errWrong := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", "wrong-password-here", "", "")
	if !errors.Is(errUnknown, accounts.ErrInvalidCredentials) || !errors.Is(errWrong, accounts.ErrInvalidCredentials) {
		t.Fatalf("unknown=%v wrong=%v, both should be ErrInvalidCredentials", errUnknown, errWrong)
	}

	// Three failures lock the account (configured above).
	_, _ = f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", "wrong-password-here", "", "")
	_, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", "wrong-password-here", "", "")
	if !errors.Is(err, accounts.ErrAccountLocked) {
		t.Fatalf("after three failures: %v, want ErrAccountLocked", err)
	}
	// Even the right password is refused while locked.
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", ""); !errors.Is(err, accounts.ErrAccountLocked) {
		t.Fatalf("the right password during a lock: %v", err)
	}

	// The lock is temporary.
	f.svc.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", ""); err != nil {
		t.Fatalf("login after the lock expired: %v", err)
	}
}

func TestDisabledAccountCannotSignIn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	member, err := f.svc.CreateUser(ctx, p, accounts.CreateUserInput{
		Email: "member@acme.example", Role: store.RoleMember, Password: otherPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	memberRes, err := f.svc.Login(ctx, store.DefaultOrgID, "member@acme.example", otherPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := f.svc.UpdateUser(ctx, p, member.ID, "Member", store.RoleMember, store.UserDisabled); err != nil {
		t.Fatal(err)
	}
	// Disabling ends the live session immediately, not at its next expiry.
	if _, err := f.svc.Authenticate(ctx, memberRes.SessionToken); err == nil {
		t.Fatal("a disabled account kept its session")
	}
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "member@acme.example", otherPassword, "", ""); !errors.Is(err, accounts.ErrAccountDisabled) {
		t.Fatalf("a disabled account signed in: %v", err)
	}
	_ = admin
}

func TestTOTPEnrolmentAndLogin(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	enrolment, err := f.svc.StartTOTP(ctx, p, "Coffre ACME")
	if err != nil {
		t.Fatalf("start TOTP: %v", err)
	}

	// Enrolling is not enough: the login must still be single-factor until the
	// first code is confirmed.
	res, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil || res.MFARequired {
		t.Fatalf("unconfirmed enrolment already demands a code (err=%v)", err)
	}

	if _, err := f.svc.ConfirmTOTP(ctx, p, "000000"); err == nil {
		t.Fatal("a wrong confirmation code was accepted")
	}
	codes, err := f.svc.ConfirmTOTP(ctx, p, code(t, enrolment.Secret, time.Now()))
	if err != nil {
		t.Fatalf("confirm TOTP: %v", err)
	}
	if len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("got %d recovery codes", len(codes))
	}

	// From now on the password alone opens a pending session only.
	res, err = f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.MFARequired {
		t.Fatal("the second factor was not demanded")
	}
	if _, err := f.svc.Authenticate(ctx, res.SessionToken); err == nil {
		t.Fatal("a pending session authenticated as a full one")
	}
	pending, err := f.svc.PendingMFA(ctx, res.SessionToken)
	if err != nil || !pending {
		t.Fatalf("PendingMFA = %v, %v", pending, err)
	}

	if _, err := f.svc.CompleteMFA(ctx, res.SessionToken, "000000"); err == nil {
		t.Fatal("a wrong code completed the login")
	}
	if _, err := f.svc.CompleteMFA(ctx, res.SessionToken, code(t, enrolment.Secret, time.Now())); err != nil {
		t.Fatalf("complete MFA: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, res.SessionToken); err != nil {
		t.Fatalf("the promoted session does not authenticate: %v", err)
	}
}

func TestRecoveryCodeIsSpentOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	enrolment, err := f.svc.StartTOTP(ctx, p, "Coffre ACME")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := f.svc.ConfirmTOTP(ctx, p, code(t, enrolment.Secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}

	res, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CompleteMFA(ctx, res.SessionToken, codes[0]); err != nil {
		t.Fatalf("a recovery code was refused: %v", err)
	}

	left, err := f.svc.RemainingRecoveryCodes(ctx, p.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if left != auth.RecoveryCodeCount-1 {
		t.Fatalf("%d codes left, want %d", left, auth.RecoveryCodeCount-1)
	}

	// The same code cannot be used twice.
	again, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CompleteMFA(ctx, again.SessionToken, codes[0]); err == nil {
		t.Fatal("a recovery code was accepted twice")
	}
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	first := f.principal(t, "admin@acme.example", goodPassword)
	second, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := f.svc.ChangePassword(ctx, first, "wrong-current-password", otherPassword); !errors.Is(err, accounts.ErrInvalidCredentials) {
		t.Fatalf("a wrong current password was accepted: %v", err)
	}
	if err := f.svc.ChangePassword(ctx, first, goodPassword, "short"); err == nil {
		t.Fatal("a weak new password was accepted")
	}
	if err := f.svc.ChangePassword(ctx, first, goodPassword, otherPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}

	// The session that made the change survives; the other does not.
	if _, err := f.svc.Authenticate(ctx, second.SessionToken); err == nil {
		t.Fatal("another session survived a password change")
	}
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", otherPassword, "", ""); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
}

func TestInvitationFlow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	inv, err := f.svc.Invite(ctx, p, "new@acme.example", store.RoleManager)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if inv.Token == "" {
		t.Fatal("no invitation token")
	}

	preview, err := f.svc.PreviewInvitation(ctx, inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Email != "new@acme.example" || preview.Role != store.RoleManager || !preview.NewAccount {
		t.Fatalf("unexpected preview: %+v", preview)
	}

	user, err := f.svc.AcceptInvitation(ctx, inv.Token, otherPassword, "Nouvelle Personne")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if user.Role != store.RoleManager || user.Status != store.UserActive || user.DisplayName != "Nouvelle Personne" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "new@acme.example", otherPassword, "", ""); err != nil {
		t.Fatalf("the invited user cannot sign in: %v", err)
	}

	// An invitation is single use, and an unknown token is simply not found.
	if _, err := f.svc.AcceptInvitation(ctx, inv.Token, otherPassword, ""); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("an invitation was accepted twice: %v", err)
	}
	if _, err := f.svc.PreviewInvitation(ctx, "not-a-real-token"); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("an unknown token resolved: %v", err)
	}
}

func TestInvitationExpires(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	inv, err := f.svc.Invite(ctx, p, "late@acme.example", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SetClock(func() time.Time { return time.Now().Add(accounts.InvitationTTL + time.Hour) })
	if _, err := f.svc.AcceptInvitation(ctx, inv.Token, otherPassword, ""); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("an expired invitation was accepted: %v", err)
	}
}

func TestRolesAreEnforced(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)
	admin := f.principal(t, "admin@acme.example", goodPassword)

	if _, err := f.svc.CreateUser(ctx, admin, accounts.CreateUserInput{
		Email: "member@acme.example", Role: store.RoleMember, Password: otherPassword,
	}); err != nil {
		t.Fatal(err)
	}
	member := f.principal(t, "member@acme.example", otherPassword)

	// A member manages nobody.
	if _, err := f.svc.Invite(ctx, member, "x@acme.example", store.RoleMember); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("a member invited someone: %v", err)
	}
	if _, err := f.svc.ListUsers(ctx, member); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("a member listed the users: %v", err)
	}

	// A manager may invite, but not create an administrator.
	if _, err := f.svc.CreateUser(ctx, admin, accounts.CreateUserInput{
		Email: "manager@acme.example", Role: store.RoleManager, Password: otherPassword,
	}); err != nil {
		t.Fatal(err)
	}
	manager := f.principal(t, "manager@acme.example", otherPassword)
	if _, err := f.svc.Invite(ctx, manager, "someone@acme.example", store.RoleMember); err != nil {
		t.Fatalf("a manager could not invite: %v", err)
	}
	if _, err := f.svc.Invite(ctx, manager, "boss@acme.example", store.RoleAdmin); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("a manager invited an administrator: %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, manager, accounts.CreateUserInput{
		Email: "boss2@acme.example", Role: store.RoleAdmin,
	}); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatal("a manager created an administrator")
	}
}

func TestLastAdministratorIsProtected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.admin(t)
	p := f.principal(t, "admin@acme.example", goodPassword)

	// Demoting yourself is refused outright.
	if err := f.svc.UpdateUser(ctx, p, admin.ID, "Admin", store.RoleMember, store.UserActive); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("an administrator demoted itself: %v", err)
	}

	// And so is removing the last one from another administrator account.
	second, err := f.svc.CreateUser(ctx, p, accounts.CreateUserInput{
		Email: "admin2@acme.example", Role: store.RoleAdmin, Password: otherPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	other := f.principal(t, "admin2@acme.example", otherPassword)
	if err := f.svc.UpdateUser(ctx, other, admin.ID, "Admin", store.RoleMember, store.UserActive); err != nil {
		t.Fatalf("demoting one of two administrators failed: %v", err)
	}
	if err := f.svc.DeleteUser(ctx, p, second.ID); err == nil {
		t.Fatal("the last administrator was deleted")
	}
}

func TestPasswordResetDoesNotLeakAddresses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	token, _, err := f.svc.StartPasswordReset(ctx, store.DefaultOrgID, "nobody@acme.example")
	if err != nil {
		t.Fatalf("an unknown address errored: %v", err)
	}
	if token != "" {
		t.Fatal("a reset token was issued for an unknown address")
	}

	token, user, err := f.svc.StartPasswordReset(ctx, store.DefaultOrgID, "admin@acme.example")
	if err != nil || token == "" {
		t.Fatalf("no token for a known address (err=%v)", err)
	}
	if user.Email != "admin@acme.example" {
		t.Fatalf("unexpected user: %+v", user)
	}

	if err := f.svc.CompletePasswordReset(ctx, token, otherPassword); err != nil {
		t.Fatalf("complete reset: %v", err)
	}
	if _, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", otherPassword, "", ""); err != nil {
		t.Fatalf("the reset password does not work: %v", err)
	}
	// A reset token is single use.
	if err := f.svc.CompletePasswordReset(ctx, token, goodPassword); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("a reset token was reused: %v", err)
	}
}

func TestSessionsCanBeListedAndRevoked(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	here := f.principal(t, "admin@acme.example", goodPassword)
	elsewhere, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "198.51.100.9", "Chrome")
	if err != nil {
		t.Fatal(err)
	}

	sessions, err := f.svc.Sessions(ctx, here.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("%d sessions listed, want 2", len(sessions))
	}

	n, err := f.svc.RevokeOtherSessions(ctx, here.User.ID, here.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("revoked %d sessions, want 1", n)
	}
	if _, err := f.svc.Authenticate(ctx, elsewhere.SessionToken); err == nil {
		t.Fatal("the other session survived")
	}
	if _, err := f.svc.Authenticate(ctx, ""); !errors.Is(err, accounts.ErrNoSession) {
		t.Fatal("an empty cookie authenticated")
	}
}

func TestSessionExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.admin(t)

	res, err := f.svc.Login(ctx, store.DefaultOrgID, "admin@acme.example", goodPassword, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Idle beyond the window: gone.
	f.svc.SetClock(func() time.Time { return time.Now().Add(f.cfg.Security.SessionIdle.Std() + time.Minute) })
	if _, err := f.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, accounts.ErrNoSession) {
		t.Fatalf("an idle session survived: %v", err)
	}
}

// code produces what an authenticator would show, for the tests only.
func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totpCode(secret, at)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return c
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
