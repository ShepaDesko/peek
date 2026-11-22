// Package accounts is the account lifecycle: signing in, the second factor,
// sessions, invitations and password changes.
//
// It sits between the credential primitives in internal/auth and the rows in
// internal/store, and it is where the policy decisions live: how long a
// session lasts, when an account locks, whether a second factor is required.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/auth"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// Errors the HTTP layer maps to answers. Login failures are deliberately all
// the same error: the caller must not learn whether an address exists.
var (
	ErrInvalidCredentials = errors.New("accounts: invalid credentials")
	ErrAccountLocked      = errors.New("accounts: account temporarily locked")
	ErrAccountDisabled    = errors.New("accounts: account disabled")
	ErrMFARequired        = errors.New("accounts: second factor required")
	ErrNoSession          = errors.New("accounts: no valid session")
	ErrNotFound           = errors.New("accounts: not found")
	ErrForbidden          = errors.New("accounts: not allowed")
	ErrTOTPNotEnrolled    = errors.New("accounts: no authenticator enrolled")
)

// Service is the account lifecycle.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	cipher *pcrypto.ServerCipher
	nowFn  func() time.Time
}

// New builds a Service. The cipher may be nil on an instance without a master
// key; everything except TOTP enrolment then still works.
func New(st *store.Store, cfg *config.Config, cipher *pcrypto.ServerCipher) *Service {
	return &Service{store: st, cfg: cfg, cipher: cipher, nowFn: time.Now}
}

// SetClock overrides the clock. Tests only.
func (s *Service) SetClock(f func() time.Time) { s.nowFn = f }

func (s *Service) now() time.Time { return s.nowFn().UTC() }

// Store exposes the underlying store to the HTTP layer.
func (s *Service) Store() *store.Store { return s.store }

// Principal is an authenticated caller.
type Principal struct {
	User      store.User
	Session   store.Session
	CSRFToken string
	// Token is set when the caller authenticated with an API token rather
	// than a session cookie. It narrows what the principal may do: the role
	// is the ceiling, the token's scopes the actual permission.
	Token *store.APIToken
}

// IsToken reports a bearer-token caller.
func (p *Principal) IsToken() bool { return p != nil && p.Token != nil }

// HasScope reports whether the principal may act under one of these scopes.
// A session caller is limited only by their role, so they always may; a token
// caller must carry the scope.
func (p *Principal) HasScope(wanted ...string) bool {
	if p == nil {
		return false
	}
	if p.Token == nil {
		return true
	}
	return p.Token.HasScope(wanted...)
}

// Can reports whether the principal holds at least the required role.
func (p *Principal) Can(role string) bool {
	return p != nil && p.User.Status == store.UserActive && p.User.Can(role)
}

// IsAuditor reports the read-only audit role, which sits outside the ladder.
func (p *Principal) IsAuditor() bool { return p != nil && p.User.Role == store.RoleAuditor }

// LoginResult is what a password check produced.
type LoginResult struct {
	// SessionToken is the cookie value. It is returned once and never stored.
	SessionToken string
	// CSRFToken goes to the client as a readable cookie and must come back in
	// a header on every state-changing request.
	CSRFToken string
	// MFARequired means the session exists but carries no authority yet.
	MFARequired bool
	// MustEnrolTOTP means the policy requires a second factor this account
	// does not have, so the next step is enrolment rather than work.
	MustEnrolTOTP bool
	User          store.User
	ExpiresAt     time.Time
}

// Login checks an e-mail and password.
//
// Every failure path costs about the same: a missing account still runs a
// password verification against a dummy hash, so response time does not say
// whether an address exists.
func (s *Service) Login(ctx context.Context, orgID, email, password, ip, userAgent string) (LoginResult, error) {
	now := s.now()
	user, err := s.store.UserByEmail(ctx, orgID, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = auth.VerifyPassword(dummyHash, password)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}

	if user.Locked(now) {
		return LoginResult{}, ErrAccountLocked
	}
	if user.Status == store.UserDisabled {
		return LoginResult{}, ErrAccountDisabled
	}
	if user.PasswordHash == "" {
		// An SSO-only or not-yet-activated account has no password to check.
		return LoginResult{}, ErrInvalidCredentials
	}

	if err := auth.VerifyPassword(user.PasswordHash, password); err != nil {
		locked, ferr := s.store.RecordFailedLogin(ctx, user.ID,
			s.cfg.Security.LoginAttempts, s.cfg.Security.LoginLockFor.Std(), now)
		if ferr != nil {
			return LoginResult{}, ferr
		}
		if locked {
			return LoginResult{}, ErrAccountLocked
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	// A correct password on weaker parameters is upgraded quietly.
	if auth.NeedsRehash(user.PasswordHash) {
		if upgraded, err := auth.HashPassword(password); err == nil {
			_ = s.store.SetPassword(ctx, user.ID, upgraded, user.MustChangePassword)
		}
	}

	mfaPending := user.HasTOTP()
	result, err := s.openSession(ctx, user, mfaPending, ip, userAgent, now)
	if err != nil {
		return LoginResult{}, err
	}
	result.MFARequired = mfaPending
	result.MustEnrolTOTP = !user.HasTOTP() && s.cfg.Security.RequireTOTP

	if !mfaPending {
		if err := s.store.RecordLogin(ctx, user.ID, now); err != nil {
			return LoginResult{}, err
		}
	}
	return result, nil
}

// dummyHash is a real Argon2id hash of an unguessable value. Verifying against
// it keeps the timing of an unknown address close to a known one.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$fh8ybmhtyibo9pg6ubk10A$eglMKthzoh1kPuP/VHkuR+uQhuWOv/sfjJZ0efQOzvA"

func (s *Service) openSession(ctx context.Context, user store.User, mfaPending bool, ip, userAgent string, now time.Time) (LoginResult, error) {
	token, err := auth.NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := auth.NewToken()
	if err != nil {
		return LoginResult{}, err
	}

	idle := s.cfg.Security.SessionIdle.Std()
	absolute := s.cfg.Security.SessionAbsolute.Std()
	expires := now.Add(idle)
	if mfaPending {
		// A half-finished login is short-lived.
		expires = now.Add(10 * time.Minute)
	}

	sess := store.Session{
		ID:                auth.HashTokenHex(token),
		UserID:            user.ID,
		OrgID:             user.OrgID,
		CSRFHash:          auth.HashToken(csrf),
		CreatedAt:         now,
		LastSeenAt:        now,
		ExpiresAt:         expires,
		AbsoluteExpiresAt: now.Add(absolute),
		IP:                ip,
		UserAgent:         userAgent,
		MFAPending:        mfaPending,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: token,
		CSRFToken:    csrf,
		User:         user,
		ExpiresAt:    expires,
	}, nil
}

// CompleteMFA finishes a login with a TOTP or recovery code.
func (s *Service) CompleteMFA(ctx context.Context, sessionToken, code string) (LoginResult, error) {
	now := s.now()
	sess, err := s.store.Session(ctx, auth.HashTokenHex(sessionToken))
	if err != nil || !sess.Active(now) || !sess.MFAPending {
		return LoginResult{}, ErrNoSession
	}
	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return LoginResult{}, ErrNoSession
	}

	if err := s.verifySecondFactor(ctx, user, code, now); err != nil {
		if _, ferr := s.store.RecordFailedLogin(ctx, user.ID,
			s.cfg.Security.LoginAttempts, s.cfg.Security.LoginLockFor.Std(), now); ferr != nil {
			return LoginResult{}, ferr
		}
		return LoginResult{}, err
	}

	expires := now.Add(s.cfg.Security.SessionIdle.Std())
	if err := s.store.PromoteSession(ctx, sess.ID, expires); err != nil {
		return LoginResult{}, err
	}
	if err := s.store.RecordLogin(ctx, user.ID, now); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{User: user, ExpiresAt: expires}, nil
}

// verifySecondFactor accepts either a TOTP code or an unused recovery code.
func (s *Service) verifySecondFactor(ctx context.Context, user store.User, code string, now time.Time) error {
	if !user.HasTOTP() {
		return ErrTOTPNotEnrolled
	}
	secret, err := s.cipher.OpenString(pcrypto.PurposeTOTP, user.TOTPSecretEnc)
	if err != nil {
		return err
	}
	if err := auth.VerifyTOTP(secret, code, now); err == nil {
		return nil
	}
	// Not a TOTP code: it may be a recovery code, which is spent on use.
	used, err := s.store.UseRecoveryCode(ctx, user.ID, auth.HashRecoveryCode(code), now)
	if err != nil {
		return err
	}
	if !used {
		return auth.ErrBadCode
	}
	return nil
}

// Authenticate resolves a session cookie into a principal.
//
// It slides the idle expiry forward at most once a minute, so a busy session
// does not write to the database on every request.
func (s *Service) Authenticate(ctx context.Context, sessionToken string) (*Principal, error) {
	if sessionToken == "" {
		return nil, ErrNoSession
	}
	now := s.now()
	sess, err := s.store.Session(ctx, auth.HashTokenHex(sessionToken))
	if err != nil || !sess.Active(now) {
		return nil, ErrNoSession
	}
	if sess.MFAPending {
		// The password was right, the second factor has not been given yet.
		// Such a session carries no authority at all: only the MFA endpoints
		// accept it, through PendingMFA.
		return nil, ErrMFARequired
	}
	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, ErrNoSession
	}
	if user.Status == store.UserDisabled {
		_, _ = s.store.RevokeUserSessions(ctx, user.ID, "", now)
		return nil, ErrAccountDisabled
	}

	if now.Sub(sess.LastSeenAt) > time.Minute {
		expires := now.Add(s.cfg.Security.SessionIdle.Std())
		if expires.After(sess.AbsoluteExpiresAt) {
			expires = sess.AbsoluteExpiresAt
		}
		if err := s.store.TouchSession(ctx, sess.ID, now, expires); err != nil {
			return nil, err
		}
		sess.LastSeenAt, sess.ExpiresAt = now, expires
	}
	return &Principal{User: user, Session: sess}, nil
}

// PendingMFA reports whether a session has passed the password but not the
// second factor. Those sessions may only reach the MFA endpoints.
func (s *Service) PendingMFA(ctx context.Context, sessionToken string) (bool, error) {
	sess, err := s.store.Session(ctx, auth.HashTokenHex(sessionToken))
	if err != nil {
		return false, ErrNoSession
	}
	return sess.MFAPending && sess.Active(s.now()), nil
}

// CheckCSRF verifies the double-submit token of a session.
func (s *Service) CheckCSRF(p *Principal, token string) bool {
	if p == nil || token == "" {
		return false
	}
	return auth.EqualHashes(auth.HashToken(token), p.Session.CSRFHash)
}

// Logout ends the current session.
func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	return s.store.RevokeSession(ctx, auth.HashTokenHex(sessionToken), s.now())
}

// Sessions lists the live sessions of a user.
func (s *Service) Sessions(ctx context.Context, userID string) ([]store.Session, error) {
	return s.store.ListSessions(ctx, userID, s.now())
}

// RevokeSession ends one session of a user, by its identifier.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sess, err := s.store.Session(ctx, sessionID)
	if err != nil {
		return ErrNotFound
	}
	if sess.UserID != userID {
		return ErrForbidden
	}
	return s.store.RevokeSession(ctx, sessionID, s.now())
}

// RevokeOtherSessions signs the user out everywhere except here.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, keepSessionID string) (int64, error) {
	return s.store.RevokeUserSessions(ctx, userID, keepSessionID, s.now())
}

// ChangePassword replaces a password after checking the current one, and ends
// every other session.
func (s *Service) ChangePassword(ctx context.Context, p *Principal, current, next string) error {
	if p == nil {
		return ErrNoSession
	}
	if p.User.PasswordHash != "" {
		if err := auth.VerifyPassword(p.User.PasswordHash, current); err != nil {
			return ErrInvalidCredentials
		}
	}
	if strings.TrimSpace(next) == strings.TrimSpace(current) {
		return fmt.Errorf("%w: the new password must differ from the current one", auth.ErrWeakPassword)
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(ctx, p.User.ID, hash, false); err != nil {
		return err
	}
	_, err = s.store.RevokeUserSessions(ctx, p.User.ID, p.Session.ID, s.now())
	return err
}

// --- second factor enrolment -------------------------------------------------

// StartTOTP generates an enrolment and stores the seed, unconfirmed.
func (s *Service) StartTOTP(ctx context.Context, p *Principal, issuer string) (auth.TOTPEnrolment, error) {
	if p == nil {
		return auth.TOTPEnrolment{}, ErrNoSession
	}
	if s.cipher == nil {
		return auth.TOTPEnrolment{}, pcrypto.ErrNoMasterKey
	}
	enrolment, err := auth.NewTOTP(issuer, p.User.Email)
	if err != nil {
		return auth.TOTPEnrolment{}, err
	}
	sealed, err := s.cipher.SealString(pcrypto.PurposeTOTP, enrolment.Secret)
	if err != nil {
		return auth.TOTPEnrolment{}, err
	}
	if err := s.store.SetTOTPSecret(ctx, p.User.ID, sealed); err != nil {
		return auth.TOTPEnrolment{}, err
	}
	return enrolment, nil
}

// ConfirmTOTP validates the first code and issues recovery codes.
func (s *Service) ConfirmTOTP(ctx context.Context, p *Principal, code string) ([]string, error) {
	if p == nil {
		return nil, ErrNoSession
	}
	user, err := s.store.UserByID(ctx, p.User.ID)
	if err != nil {
		return nil, err
	}
	if len(user.TOTPSecretEnc) == 0 {
		return nil, ErrTOTPNotEnrolled
	}
	secret, err := s.cipher.OpenString(pcrypto.PurposeTOTP, user.TOTPSecretEnc)
	if err != nil {
		return nil, err
	}
	if err := auth.VerifyTOTP(secret, code, s.now()); err != nil {
		return nil, err
	}
	if err := s.store.ConfirmTOTP(ctx, user.ID, s.now()); err != nil {
		return nil, err
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, user.ID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableTOTP removes the second factor, after re-checking the password.
func (s *Service) DisableTOTP(ctx context.Context, p *Principal, password string) error {
	if p == nil {
		return ErrNoSession
	}
	if s.cfg.Security.RequireTOTP {
		return fmt.Errorf("%w: this instance requires a second factor", ErrForbidden)
	}
	if p.User.PasswordHash != "" {
		if err := auth.VerifyPassword(p.User.PasswordHash, password); err != nil {
			return ErrInvalidCredentials
		}
	}
	return s.store.DisableTOTP(ctx, p.User.ID)
}

// RegenerateRecoveryCodes issues a fresh set, invalidating the old one.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, p *Principal) ([]string, error) {
	if p == nil {
		return nil, ErrNoSession
	}
	if !p.User.HasTOTP() {
		return nil, ErrTOTPNotEnrolled
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, p.User.ID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// RemainingRecoveryCodes reports how many are left.
func (s *Service) RemainingRecoveryCodes(ctx context.Context, userID string) (int, error) {
	return s.store.CountRecoveryCodes(ctx, userID)
}
