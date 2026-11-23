package accounts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/ShepaDesko/peek/internal/store"
)

// Passkeys (WebAuthn).
//
// A passkey is the one credential on this list that cannot be phished: the
// authenticator signs a challenge bound to the origin, so a convincing copy of
// the login page on another domain gets nothing.
//
// The challenge lives in the database for a minute rather than in a cookie, so
// a load balancer may send the two halves of a ceremony to different nodes.

const challengeTTL = 5 * time.Minute

const (
	challengeRegistration = "registration"
	challengeLogin        = "login"
)

// ErrPasskeysDisabled is returned when the instance does not allow them.
var ErrPasskeysDisabled = errors.New("accounts: passkeys are disabled on this instance")

// webAuthnUser adapts a Peek account to the library's interface.
type webAuthnUser struct {
	user        store.User
	credentials []webauthn.Credential
}

func (u webAuthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u webAuthnUser) WebAuthnName() string                       { return u.user.Email }
func (u webAuthnUser) WebAuthnDisplayName() string                { return displayOrEmail(u.user) }
func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func displayOrEmail(u store.User) string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Email
}

// webAuthn builds the library handle from the public URL.
//
// The relying party id is the registrable domain of public_url and the origin
// must match exactly: this is what ties a credential to this instance, so it
// is derived from configuration rather than from a request header.
func (s *Service) webAuthn() (*webauthn.WebAuthn, error) {
	if !s.cfg.Security.AllowPasskeys {
		return nil, ErrPasskeysDisabled
	}
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("accounts: public_url must be a valid URL to use passkeys")
	}
	origin := u.Scheme + "://" + u.Host
	return webauthn.New(&webauthn.Config{
		RPDisplayName: s.cfg.Branding.ServiceName,
		RPID:          u.Hostname(),
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
}

// PasskeySupported reports whether passkeys can be offered at all.
func (s *Service) PasskeySupported() bool {
	_, err := s.webAuthn()
	return err == nil
}

// StartPasskeyRegistration returns the options a browser needs to create a
// credential, plus the challenge id to hand back.
func (s *Service) StartPasskeyRegistration(ctx context.Context, p *Principal) (options any, challengeID string, err error) {
	if p == nil {
		return nil, "", ErrNoSession
	}
	w, err := s.webAuthn()
	if err != nil {
		return nil, "", err
	}
	existing, err := s.credentialsOf(ctx, p.User.ID)
	if err != nil {
		return nil, "", err
	}

	creation, session, err := w.BeginRegistration(
		webAuthnUser{user: p.User, credentials: existing},
		webauthn.WithExclusions(excludeList(existing)),
	)
	if err != nil {
		return nil, "", fmt.Errorf("accounts: begin passkey registration: %w", err)
	}
	id, err := s.saveChallenge(ctx, p.User.ID, challengeRegistration, session)
	if err != nil {
		return nil, "", err
	}
	return creation, id, nil
}

// FinishPasskeyRegistration stores the new credential.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, p *Principal, challengeID, name string, response []byte) (store.Passkey, error) {
	if p == nil {
		return store.Passkey{}, ErrNoSession
	}
	w, err := s.webAuthn()
	if err != nil {
		return store.Passkey{}, err
	}
	session, err := s.takeChallenge(ctx, challengeID, challengeRegistration, p.User.ID)
	if err != nil {
		return store.Passkey{}, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return store.Passkey{}, fmt.Errorf("accounts: malformed registration response: %w", err)
	}
	existing, err := s.credentialsOf(ctx, p.User.ID)
	if err != nil {
		return store.Passkey{}, err
	}
	credential, err := w.CreateCredential(webAuthnUser{user: p.User, credentials: existing}, *session, parsed)
	if err != nil {
		return store.Passkey{}, fmt.Errorf("accounts: registration refused: %w", err)
	}

	label := strings.TrimSpace(name)
	if label == "" {
		label = "Clé " + time.Now().Format("2006-01-02")
	}
	return s.store.CreatePasskey(ctx, store.Passkey{
		UserID:         p.User.ID,
		CredentialID:   credential.ID,
		PublicKey:      credential.PublicKey,
		Attestation:    credential.AttestationType,
		AAGUID:         credential.Authenticator.AAGUID,
		SignCount:      credential.Authenticator.SignCount,
		Transports:     joinTransports(credential.Transport),
		Name:           label,
		BackupEligible: credential.Flags.BackupEligible,
		BackedUp:       credential.Flags.BackupState,
	})
}

// StartPasskeyLogin begins a passwordless sign-in.
//
// It is deliberately discoverable (no user hint): the browser offers whichever
// credential it holds for this origin, and the response tells us who it is.
// Asking for an address first would leak which addresses have accounts.
func (s *Service) StartPasskeyLogin(ctx context.Context) (options any, challengeID string, err error) {
	w, err := s.webAuthn()
	if err != nil {
		return nil, "", err
	}
	assertion, session, err := w.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("accounts: begin passkey login: %w", err)
	}
	id, err := s.saveChallenge(ctx, "", challengeLogin, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, id, nil
}

// FinishPasskeyLogin verifies an assertion and opens a session.
func (s *Service) FinishPasskeyLogin(ctx context.Context, challengeID string, response []byte, ip, userAgent string) (LoginResult, error) {
	w, err := s.webAuthn()
	if err != nil {
		return LoginResult{}, err
	}
	session, err := s.takeChallenge(ctx, challengeID, challengeLogin, "")
	if err != nil {
		return LoginResult{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return LoginResult{}, fmt.Errorf("accounts: malformed assertion: %w", err)
	}

	now := s.now()
	var matched store.User

	credential, err := w.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := s.store.UserByID(ctx, string(userHandle))
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		if user.Status == store.UserDisabled {
			return nil, ErrAccountDisabled
		}
		// A passkey is a local credential, so sso.required applies to it too.
		if err := s.requireSSO(user); err != nil {
			return nil, err
		}
		credentials, err := s.credentialsOf(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		matched = user
		return webAuthnUser{user: user, credentials: credentials}, nil
	}, *session, parsed)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
	}

	stored, err := s.store.PasskeyByCredential(ctx, credential.ID)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	// A counter that goes backwards means the credential was cloned. The
	// specification says to treat it as a signal; we refuse the sign-in.
	if credential.Authenticator.CloneWarning {
		return LoginResult{}, fmt.Errorf("%w: this security key reported a cloning warning", ErrInvalidCredentials)
	}
	if err := s.store.UpdatePasskeyUsage(ctx, stored.ID, credential.Authenticator.SignCount, now); err != nil {
		return LoginResult{}, err
	}

	// A passkey is already two factors in one gesture (possession plus the
	// device's own user verification), so it does not ask for TOTP as well.
	result, err := s.openSession(ctx, matched, false, ip, userAgent, now)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.store.RecordLogin(ctx, matched.ID, now); err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

// ListPasskeys returns the credentials of an account.
func (s *Service) ListPasskeys(ctx context.Context, p *Principal) ([]store.Passkey, error) {
	if p == nil {
		return nil, ErrNoSession
	}
	return s.store.PasskeysForUser(ctx, p.User.ID)
}

// RenamePasskey relabels a credential.
func (s *Service) RenamePasskey(ctx context.Context, p *Principal, id, name string) error {
	if p == nil {
		return ErrNoSession
	}
	if err := s.store.RenamePasskey(ctx, p.User.ID, id, strings.TrimSpace(name)); err != nil {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a credential.
//
// It refuses to remove the last sign-in method: an account with no password
// and no passkey is an account nobody can reach.
func (s *Service) DeletePasskey(ctx context.Context, p *Principal, id string) error {
	if p == nil {
		return ErrNoSession
	}
	keys, err := s.store.PasskeysForUser(ctx, p.User.ID)
	if err != nil {
		return err
	}
	if len(keys) <= 1 && p.User.PasswordHash == "" {
		return fmt.Errorf("%w: this is the only way left to sign in to this account", ErrForbidden)
	}
	if err := s.store.DeletePasskey(ctx, p.User.ID, id); err != nil {
		return ErrNotFound
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

func (s *Service) credentialsOf(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	keys, err := s.store.PasskeysForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(keys))
	for _, k := range keys {
		out = append(out, webauthn.Credential{
			ID:              k.CredentialID,
			PublicKey:       k.PublicKey,
			AttestationType: k.Attestation,
			Transport:       splitTransports(k.Transports),
			Flags: webauthn.CredentialFlags{
				BackupEligible: k.BackupEligible,
				BackupState:    k.BackedUp,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    k.AAGUID,
				SignCount: k.SignCount,
			},
		})
	}
	return out, nil
}

func (s *Service) saveChallenge(ctx context.Context, userID, kind string, session *webauthn.SessionData) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	id, err := store.NewID()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveChallenge(ctx, id, userID, kind, string(payload), s.now().Add(challengeTTL)); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Service) takeChallenge(ctx context.Context, id, kind, expectUser string) (*webauthn.SessionData, error) {
	userID, payload, err := s.store.TakeChallenge(ctx, id, kind, s.now())
	if err != nil {
		return nil, fmt.Errorf("accounts: this attempt expired, start again")
	}
	if expectUser != "" && userID != expectUser {
		return nil, ErrForbidden
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(payload), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func excludeList(credentials []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, c := range credentials {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
			Transport:    c.Transport,
		})
	}
	return out
}

func joinTransports(transports []protocol.AuthenticatorTransport) string {
	parts := make([]string, 0, len(transports))
	for _, t := range transports {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ",")
}

func splitTransports(value string) []protocol.AuthenticatorTransport {
	if value == "" {
		return nil
	}
	var out []protocol.AuthenticatorTransport
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, protocol.AuthenticatorTransport(part))
		}
	}
	return out
}

// EncodeCredentialID renders a credential id for the interface.
func EncodeCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}
