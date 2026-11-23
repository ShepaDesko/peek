package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/oidc"
	"github.com/ShepaDesko/peek/internal/store"
)

// Signing in through an identity provider.
//
// The assertion has already been verified by the oidc package by the time any
// of this runs. What is left is the part that is Peek's policy rather than the
// protocol: which directory identities are allowed in, what account they get,
// and what role.

// SSO failures a caller distinguishes. Each one gets its own message in the
// interface, because "sign-in failed" after a successful sign-in at the
// provider is the most confusing error a product can show.
var (
	// ErrSSODomain means the address is outside sso.allowed_domains.
	ErrSSODomain = errors.New("accounts: that e-mail domain is not allowed to sign in here")
	// ErrSSONoAccount means provisioning is off and no account matches.
	ErrSSONoAccount = errors.New("accounts: no account here matches that directory identity")
	// ErrSSONoGroup means sso.require_group is set and none matched.
	ErrSSONoGroup = errors.New("accounts: that directory identity is in none of the mapped groups")
	// ErrSSONoEmail means the provider vouched for someone without an
	// address, which Peek cannot turn into a manageable account.
	ErrSSONoEmail = errors.New("accounts: the identity provider sent no e-mail address")
	// ErrSSOClaimed means another account already holds this identity.
	ErrSSOClaimed = errors.New("accounts: another account is already linked to that directory identity")
	// ErrSSORequired means a local credential was presented on an instance
	// that requires the identity provider.
	ErrSSORequired = errors.New("accounts: this instance requires single sign-on")
)

// SSOResult reports what happened, so the audit entry can say which.
type SSOResult struct {
	LoginResult
	// Provisioned is true when the account was created by this sign-in.
	Provisioned bool
	// Linked is true when an existing local account gained the directory
	// identity during this sign-in.
	Linked bool
	// RoleChanged names the new role when the directory mapping moved it.
	RoleChanged string
}

// SignInWithSSO turns a verified assertion into a session.
//
// The order matters and is the security of the whole feature:
//
//  1. the e-mail domain is checked before anything is created;
//  2. the account is found by (issuer, subject) first — the stable link;
//  3. only then by address, and linking an existing local account to a
//     directory identity requires that account to be unlinked;
//  4. provisioning happens last, and only if it is switched on.
func (s *Service) SignInWithSSO(ctx context.Context, claims *oidc.Claims, ip, userAgent string) (SSOResult, error) {
	sso := s.cfg.SSO
	now := s.now()

	email := store.NormalizeEmail(claims.Email)
	if email == "" || !strings.Contains(email, "@") {
		return SSOResult{}, ErrSSONoEmail
	}
	if !domainAllowed(email, sso.AllowedDomains) {
		return SSOResult{}, fmt.Errorf("%w (%s)", ErrSSODomain, domainOf(email))
	}

	role, mapped := mapRole(claims.Groups, sso)
	if sso.RequireGroup && !mapped {
		return SSOResult{}, ErrSSONoGroup
	}

	var out SSOResult

	user, err := s.store.UserBySSOSubject(ctx, claims.Issuer, claims.Subject)
	switch {
	case err == nil:
		// Known identity. The address may have changed at the provider; the
		// link is what identifies the person, so follow it.
	case errors.Is(err, store.ErrNotFound):
		user, out, err = s.resolveNewSSOIdentity(ctx, claims, email, role, out)
		if err != nil {
			return SSOResult{}, err
		}
	default:
		return SSOResult{}, err
	}

	if user.Status == store.UserDisabled {
		// A disabled account stays disabled whatever the directory says. This
		// is how an operator locks somebody out faster than the directory can
		// be updated.
		return SSOResult{}, ErrAccountDisabled
	}
	if user.Locked(now) {
		return SSOResult{}, ErrAccountLocked
	}

	// Keep the account in step with the directory. The display name always;
	// the role only when the operator asked for it, so a local promotion is
	// not undone at the next sign-in.
	refreshName := claims.Name != "" && claims.Name != user.DisplayName
	refreshRole := ""
	if sso.SyncRoleOnLogin && mapped && role != user.Role && !out.Provisioned {
		refreshRole, out.RoleChanged = role, role
	}
	if refreshName || refreshRole != "" {
		if err := s.store.UpdateUserIdentity(ctx, user.ID, claims.Name, refreshRole); err != nil {
			return SSOResult{}, err
		}
		if refreshName {
			user.DisplayName = claims.Name
		}
		if refreshRole != "" {
			user.Role = refreshRole
		}
	}
	// An address that changed at the provider follows the subject.
	if store.NormalizeEmail(user.Email) != email {
		if err := s.store.SetUserEmail(ctx, user.ID, claims.Email); err != nil {
			// Someone else already holds the new address: refuse rather than
			// sign the wrong person in.
			return SSOResult{}, fmt.Errorf("%w: the address %s is already in use here", ErrSSOClaimed, email)
		}
		user.Email = claims.Email
	}

	// A second factor on top of the provider's own authentication is the
	// operator's choice, and the provider is usually already enforcing one.
	// An account that enrolled TOTP here keeps being asked for it.
	mfaPending := user.HasTOTP()
	result, err := s.openSession(ctx, user, mfaPending, ip, userAgent, now)
	if err != nil {
		return SSOResult{}, err
	}
	result.MFARequired = mfaPending
	if !mfaPending {
		if err := s.store.RecordLogin(ctx, user.ID, now); err != nil {
			return SSOResult{}, err
		}
	}
	out.LoginResult = result
	return out, nil
}

// resolveNewSSOIdentity handles a subject nobody has seen before: either an
// existing local account by the same address, or a new one.
func (s *Service) resolveNewSSOIdentity(
	ctx context.Context, claims *oidc.Claims, email, role string, out SSOResult,
) (store.User, SSOResult, error) {
	sso := s.cfg.SSO

	existing, err := s.store.UserByEmail(ctx, store.DefaultOrgID, email)
	switch {
	case err == nil:
		// A local account with this address exists. Link it — this is how an
		// instance that started with local accounts moves to the directory
		// without everybody losing their secrets.
		//
		// It is only safe because the address came from a verified assertion
		// by the configured issuer. A provider that lets a user set an
		// arbitrary unverified address would make this an account takeover,
		// which is why an address the provider explicitly marks unverified is
		// refused below.
		if claims.EmailVerifiedPresent && !claims.EmailVerified {
			return store.User{}, out, fmt.Errorf(
				"%w: the provider says that address is not verified, so it cannot be linked to the existing account",
				ErrSSOClaimed)
		}
		if existing.FromDirectory() {
			return store.User{}, out, ErrSSOClaimed
		}
		linked, err := s.store.LinkSSO(ctx, existing.ID, claims.Issuer, claims.Subject)
		if err != nil {
			return store.User{}, out, err
		}
		if !linked {
			return store.User{}, out, ErrSSOClaimed
		}
		existing.SSOIssuer, existing.SSOSubject = claims.Issuer, claims.Subject
		out.Linked = true
		return existing, out, nil

	case errors.Is(err, store.ErrNotFound):
		if !sso.Provision {
			return store.User{}, out, ErrSSONoAccount
		}
		created, err := s.store.CreateUser(ctx, store.User{
			OrgID:       store.DefaultOrgID,
			Email:       claims.Email,
			DisplayName: orEmailLocalPart(claims.Name, email),
			Role:        role,
			Status:      store.UserActive,
			SSOIssuer:   claims.Issuer,
			SSOSubject:  claims.Subject,
			// No password hash at all: this account has no local credential
			// to guess, and ChangePassword refuses it with a clear message.
		})
		if err != nil {
			if errors.Is(err, store.ErrUserExists) {
				// Two sign-ins at once for the same new user. Read it back.
				again, rerr := s.store.UserBySSOSubject(ctx, claims.Issuer, claims.Subject)
				if rerr == nil {
					return again, out, nil
				}
			}
			return store.User{}, out, err
		}
		out.Provisioned = true
		return created, out, nil

	default:
		return store.User{}, out, err
	}
}

// mapRole picks the strongest role the directory groups grant.
//
// Strongest, not first: a user who is both a manager and an administrator is
// an administrator, and the answer must not depend on the order of the lists
// in the configuration file. auditor is outside the ladder, so it only applies
// when nothing stronger matched.
func mapRole(groups []string, sso config.SSO) (string, bool) {
	match := func(mapped []string) bool {
		for _, want := range mapped {
			for _, have := range groups {
				if strings.EqualFold(strings.TrimSpace(want), strings.TrimSpace(have)) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case match(sso.AdminGroups):
		return store.RoleAdmin, true
	case match(sso.ManagerGroups):
		return store.RoleManager, true
	case match(sso.MemberGroups):
		return store.RoleMember, true
	case match(sso.AuditorGroups):
		return store.RoleAuditor, true
	}
	role := sso.DefaultRole
	if role == "" {
		role = store.RoleMember
	}
	return role, false
}

// MapRole is the exported form, for peek doctor's dry run: an operator should
// be able to ask "what role would this group list get?" without signing in.
func MapRole(groups []string, sso config.SSO) (string, bool) { return mapRole(groups, sso) }

// requireSSO refuses a local credential when the instance requires the
// provider. It is called from every local sign-in path, so "required" is
// enforced by the server rather than by a hidden form.
func (s *Service) requireSSO(user store.User) error {
	if s.cfg.SSO.LocalSignInAllowed(user.Email) {
		return nil
	}
	return ErrSSORequired
}

func domainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := domainOf(email)
	for _, want := range allowed {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(want), "@"), domain) {
			return true
		}
	}
	return false
}

func domainOf(email string) string {
	_, domain, _ := strings.Cut(store.NormalizeEmail(email), "@")
	return domain
}

// orEmailLocalPart gives a provisioned account something readable to be called
// when the provider sent no name.
func orEmailLocalPart(name, email string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	local, _, _ := strings.Cut(email, "@")
	return local
}
