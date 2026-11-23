package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/auth"
	"github.com/ShepaDesko/peek/internal/store"
)

// User management: creating the first administrator, inviting people,
// changing roles, and the password-reset path.

// InvitationTTL is how long an invitation link stays usable.
const InvitationTTL = 7 * 24 * time.Hour

// ResetTTL is how long a password-reset link stays usable. Short on purpose:
// it arrives by e-mail, which is the weakest channel in the picture.
const ResetTTL = time.Hour

// NeedsBootstrap reports whether the instance still has no account, which is
// what the setup link in peek admin create resolves.
func (s *Service) NeedsBootstrap(ctx context.Context, orgID string) (bool, error) {
	n, err := s.store.CountUsers(ctx, orgID)
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// Bootstrap creates the first administrator. It refuses once an account
// exists, so the path cannot be used to add a second one quietly.
func (s *Service) Bootstrap(ctx context.Context, orgID, email, password, displayName string) (store.User, error) {
	empty, err := s.NeedsBootstrap(ctx, orgID)
	if err != nil {
		return store.User{}, err
	}
	if !empty {
		return store.User{}, fmt.Errorf("%w: this instance already has accounts", ErrForbidden)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}
	return s.store.CreateUser(ctx, store.User{
		OrgID:        orgID,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  displayName,
		Role:         store.RoleAdmin,
		Status:       store.UserActive,
	})
}

// CreateUserInput is what a manager submits to add an account directly.
type CreateUserInput struct {
	Email       string
	DisplayName string
	Role        string
	Password    string // optional: empty means the account waits for an invitation
}

// CreateUser adds an account. Only a manager or above may call it.
func (s *Service) CreateUser(ctx context.Context, actor *Principal, in CreateUserInput) (store.User, error) {
	if err := s.requireManager(actor); err != nil {
		return store.User{}, err
	}
	if err := validRole(in.Role); err != nil {
		return store.User{}, err
	}
	if err := grantable(actor, in.Role); err != nil {
		return store.User{}, err
	}

	user := store.User{
		OrgID:       actor.User.OrgID,
		Email:       in.Email,
		DisplayName: in.DisplayName,
		Role:        in.Role,
		Status:      store.UserInvited,
	}
	if in.Password != "" {
		hash, err := auth.HashPassword(in.Password)
		if err != nil {
			return store.User{}, err
		}
		user.PasswordHash = hash
		user.Status = store.UserActive
		user.MustChangePassword = true
	}
	return s.store.CreateUser(ctx, user)
}

// Invitation is a pending invitation plus the link to send.
type Invitation struct {
	Record store.Invitation
	// Token is returned once: only its hash is stored.
	Token string
}

// Invite creates (or refreshes) an invitation for an address.
func (s *Service) Invite(ctx context.Context, actor *Principal, email, role string) (Invitation, error) {
	if err := s.requireManager(actor); err != nil {
		return Invitation{}, err
	}
	if err := validRole(role); err != nil {
		return Invitation{}, err
	}
	if err := grantable(actor, role); err != nil {
		return Invitation{}, err
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return Invitation{}, fmt.Errorf("%w: %q is not an e-mail address", ErrForbidden, email)
	}
	if err := s.checkRecipientDomain(email); err != nil {
		return Invitation{}, err
	}

	token, err := auth.NewToken()
	if err != nil {
		return Invitation{}, err
	}
	record, err := s.store.CreateInvitation(ctx, store.Invitation{
		OrgID:     actor.User.OrgID,
		Email:     email,
		Role:      role,
		TokenHash: auth.HashToken(token),
		InvitedBy: actor.User.ID,
		ExpiresAt: s.now().Add(InvitationTTL),
	})
	if err != nil {
		return Invitation{}, err
	}
	return Invitation{Record: record, Token: token}, nil
}

// checkRecipientDomain applies mail.allowed_recipient_domains, which exists so
// an instance cannot be used to mail arbitrary strangers.
func (s *Service) checkRecipientDomain(email string) error {
	allowed := s.cfg.Mail.AllowedDomains
	if len(allowed) == 0 {
		return nil
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return fmt.Errorf("%w: not an e-mail address", ErrForbidden)
	}
	domain := strings.ToLower(email[at+1:])
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), domain) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not an allowed recipient domain on this instance", ErrForbidden, domain)
}

// ListInvitations returns what is still pending.
func (s *Service) ListInvitations(ctx context.Context, actor *Principal) ([]store.Invitation, error) {
	if err := s.requireManager(actor); err != nil {
		return nil, err
	}
	return s.store.ListInvitations(ctx, actor.User.OrgID, s.now())
}

// RevokeInvitation withdraws a pending invitation.
func (s *Service) RevokeInvitation(ctx context.Context, actor *Principal, id string) error {
	if err := s.requireManager(actor); err != nil {
		return err
	}
	err := s.store.DeleteInvitation(ctx, actor.User.OrgID, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// InvitationPreview describes an invitation to the person opening the link,
// without revealing anything beyond what they already hold.
type InvitationPreview struct {
	Email string
	Role  string
	// NewAccount is false when the address already has an account, in which
	// case accepting only activates it.
	NewAccount bool
}

// PreviewInvitation resolves a token for the acceptance page.
func (s *Service) PreviewInvitation(ctx context.Context, token string) (InvitationPreview, error) {
	inv, err := s.store.InvitationByToken(ctx, auth.HashToken(token))
	if err != nil || !inv.Pending(s.now()) {
		return InvitationPreview{}, ErrNotFound
	}
	_, err = s.store.UserByEmail(ctx, inv.OrgID, inv.Email)
	return InvitationPreview{
		Email:      inv.Email,
		Role:       inv.Role,
		NewAccount: errors.Is(err, store.ErrNotFound),
	}, nil
}

// AcceptInvitation turns an invitation into a usable account.
func (s *Service) AcceptInvitation(ctx context.Context, token, password, displayName string) (store.User, error) {
	now := s.now()
	inv, err := s.store.InvitationByToken(ctx, auth.HashToken(token))
	if err != nil || !inv.Pending(now) {
		return store.User{}, ErrNotFound
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}

	user, err := s.store.UserByEmail(ctx, inv.OrgID, inv.Email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		user, err = s.store.CreateUser(ctx, store.User{
			OrgID:       inv.OrgID,
			Email:       inv.Email,
			DisplayName: strings.TrimSpace(displayName),
			Role:        inv.Role,
			Status:      store.UserActive,
		})
		if err != nil {
			return store.User{}, err
		}
	case err != nil:
		return store.User{}, err
	}

	if err := s.store.SetPassword(ctx, user.ID, hash, false); err != nil {
		return store.User{}, err
	}
	if err := s.store.UpdateUserProfile(ctx, user.ID, firstNonEmpty(displayName, user.DisplayName), inv.Role, store.UserActive); err != nil {
		return store.User{}, err
	}
	if err := s.store.AcceptInvitation(ctx, inv.ID, user.ID, now); err != nil {
		return store.User{}, err
	}
	return s.store.UserByID(ctx, user.ID)
}

// ListUsers returns the accounts of the organisation.
func (s *Service) ListUsers(ctx context.Context, actor *Principal) ([]store.User, error) {
	if actor == nil {
		return nil, ErrNoSession
	}
	if !actor.User.Can(store.RoleManager) && actor.User.Role != store.RoleAuditor {
		return nil, ErrForbidden
	}
	return s.store.ListUsers(ctx, actor.User.OrgID)
}

// UpdateUser changes someone's name, role or status.
func (s *Service) UpdateUser(ctx context.Context, actor *Principal, id, displayName, role, status string) error {
	if err := s.requireManager(actor); err != nil {
		return err
	}
	target, err := s.store.UserByID(ctx, id)
	if err != nil {
		return ErrNotFound
	}
	if target.OrgID != actor.User.OrgID {
		return ErrForbidden
	}
	if err := validRole(role); err != nil {
		return err
	}
	if err := grantable(actor, role); err != nil {
		return err
	}
	// And you cannot touch an account whose role is above your own, whatever
	// you are trying to set it to.
	if err := grantable(actor, target.Role); err != nil {
		return fmt.Errorf("%w (that account holds the %s role)", err, target.Role)
	}
	if target.ID == actor.User.ID && (role != actor.User.Role || status != store.UserActive) {
		// Removing your own powers locks everyone out of an instance with one
		// administrator, so it is refused rather than warned about.
		return fmt.Errorf("%w: change your own role or status from another administrator account", ErrForbidden)
	}
	if target.Role == store.RoleAdmin && role != store.RoleAdmin {
		if err := s.ensureAnotherAdmin(ctx, actor.User.OrgID, target.ID); err != nil {
			return err
		}
	}
	if err := s.store.UpdateUserProfile(ctx, id, displayName, role, status); err != nil {
		return err
	}
	if status == store.UserDisabled {
		_, err = s.store.RevokeUserSessions(ctx, id, "", s.now())
	}
	return err
}

// DeleteUser removes an account and every session with it.
func (s *Service) DeleteUser(ctx context.Context, actor *Principal, id string) error {
	if err := s.requireManager(actor); err != nil {
		return err
	}
	target, err := s.store.UserByID(ctx, id)
	if err != nil {
		return ErrNotFound
	}
	if target.OrgID != actor.User.OrgID {
		return ErrForbidden
	}
	if target.ID == actor.User.ID {
		return fmt.Errorf("%w: an account cannot delete itself", ErrForbidden)
	}
	if target.Role == store.RoleAdmin {
		if !actor.User.Can(store.RoleAdmin) {
			return fmt.Errorf("%w: only an administrator can remove an administrator", ErrForbidden)
		}
		if err := s.ensureAnotherAdmin(ctx, actor.User.OrgID, target.ID); err != nil {
			return err
		}
	}
	if _, err := s.store.RevokeUserSessions(ctx, id, "", s.now()); err != nil {
		return err
	}
	return s.store.DeleteUser(ctx, id)
}

// ensureAnotherAdmin refuses to leave an organisation without one.
func (s *Service) ensureAnotherAdmin(ctx context.Context, orgID, excluding string) error {
	users, err := s.store.ListUsers(ctx, orgID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.ID != excluding && u.Role == store.RoleAdmin && u.Status != store.UserDisabled {
			return nil
		}
	}
	return fmt.Errorf("%w: this is the last administrator of the instance", ErrForbidden)
}

// SetUserPassword lets a manager set a password directly, which the user must
// then change. It is the path for "the e-mail never arrived".
func (s *Service) SetUserPassword(ctx context.Context, actor *Principal, id, password string) error {
	if err := s.requireManager(actor); err != nil {
		return err
	}
	target, err := s.store.UserByID(ctx, id)
	if err != nil {
		return ErrNotFound
	}
	if target.OrgID != actor.User.OrgID {
		return ErrForbidden
	}
	if target.Role == store.RoleAdmin && !actor.User.Can(store.RoleAdmin) {
		return ErrForbidden
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(ctx, id, hash, true); err != nil {
		return err
	}
	_, err = s.store.RevokeUserSessions(ctx, id, "", s.now())
	return err
}

// --- password reset ----------------------------------------------------------

// StartPasswordReset issues a reset token for an address.
//
// It returns an empty token when the address is unknown, and the caller sends
// nothing: enumerating addresses through this endpoint must not be possible.
func (s *Service) StartPasswordReset(ctx context.Context, orgID, email string) (token string, user store.User, err error) {
	u, err := s.store.UserByEmail(ctx, orgID, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", store.User{}, nil
		}
		return "", store.User{}, err
	}
	if u.Status == store.UserDisabled {
		return "", store.User{}, nil
	}
	token, err = auth.NewToken()
	if err != nil {
		return "", store.User{}, err
	}
	if _, err := s.store.CreatePasswordReset(ctx, u.ID, auth.HashToken(token), s.now().Add(ResetTTL)); err != nil {
		return "", store.User{}, err
	}
	return token, u, nil
}

// CompletePasswordReset consumes a token and sets a new password.
func (s *Service) CompletePasswordReset(ctx context.Context, token, password string) error {
	userID, err := s.store.UsePasswordReset(ctx, auth.HashToken(token), s.now())
	if err != nil {
		return ErrNotFound
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(ctx, userID, hash, false); err != nil {
		return err
	}
	// A reset is a credential change: every existing session ends.
	_, err = s.store.RevokeUserSessions(ctx, userID, "", s.now())
	return err
}

// --- helpers -----------------------------------------------------------------

func (s *Service) requireManager(actor *Principal) error {
	if actor == nil {
		return ErrNoSession
	}
	if !actor.User.Can(store.RoleManager) {
		return ErrForbidden
	}
	return nil
}

// grantable refuses a role stronger than the actor's own.
//
// This replaced three checks that each named `admin` by hand. Adding
// platform_admin to the ladder turned every one of them into an escalation:
// an administrator would have passed `!Can(RoleAdmin)` and been allowed to
// grant the role above their own. A rule about the ladder belongs in one
// function that reads the ladder, not in a condition repeated per call site.
func grantable(actor *Principal, role string) error {
	if actor == nil {
		return ErrForbidden
	}
	if role == store.RoleAuditor {
		// auditor is outside the ladder: read-only, and a manager may grant
		// it. Can() would refuse it for everyone, including an administrator.
		if !actor.User.Can(store.RoleManager) {
			return ErrForbidden
		}
		return nil
	}
	if !actor.User.Can(role) {
		return fmt.Errorf("%w: you cannot grant the %s role, which is above your own (%s)",
			ErrForbidden, role, actor.User.Role)
	}
	return nil
}

func validRole(role string) error {
	switch role {
	case store.RoleAdmin, store.RoleManager, store.RoleMember, store.RoleAuditor,
		store.RolePlatformAdmin:
		return nil
	default:
		return fmt.Errorf("%w: unknown role %q", ErrForbidden, role)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
