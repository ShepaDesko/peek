package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Audit event names. Keep them stable: they end up in SIEM rules.
const (
	EventCreated        = "secret.created"
	EventPageViewed     = "secret.page_viewed"
	EventRevealed       = "secret.revealed"
	EventBadPassphrase  = "secret.bad_passphrase"
	EventBurned         = "secret.burned"
	EventDeleted        = "secret.deleted"
	EventExpired        = "secret.expired"
	EventPurged         = "secret.purged"
	EventLinkEmailed    = "secret.link_emailed"
	EventNotFound       = "secret.not_found"
	EventFileUploaded   = "secret.file_uploaded"
	EventFileDownloaded = "secret.file_downloaded"

	// Secret requests ("send me X"): the request itself, and each answer.
	EventRequestCreated   = "request.created"
	EventRequestOpened    = "request.opened"
	EventRequestDeposited = "request.deposited"
	EventRequestClosed    = "request.closed"
	EventRequestNotFound  = "request.not_found"

	// API tokens.
	EventTokenCreated    = "token.created"
	EventTokenRevoked    = "token.revoked"
	EventTokenBlocked    = "token.scope_refused"
	EventRateLimited     = "request.rate_limited"
	EventAdminBlocked    = "request.admin_blocked"
	EventConfigChanged   = "admin.config_changed"
	EventBrandingChanged = "admin.branding_changed"
	EventBrandingReset   = "admin.branding_reset"
	EventTestEmailSent   = "admin.test_email_sent"
	EventUpdateApplied   = "admin.update_applied"

	// Webhooks. The deliveries themselves are not audited — they would double
	// the trail they carry — but an operator poking the queue is.
	EventWebhookTested   = "admin.webhook_tested"
	EventWebhookRequeued = "admin.webhook_requeued"

	// Accounts and sessions.
	EventLogin                  = "auth.login"
	EventLoginFailed            = "auth.login_failed"
	EventLogout                 = "auth.logout"
	EventMFAFailed              = "auth.mfa_failed"
	EventPasswordChanged        = "auth.password_changed"
	EventPasswordResetRequested = "auth.password_reset_requested"
	EventPasswordReset          = "auth.password_reset"
	EventTOTPEnabled            = "auth.totp_enabled"
	EventTOTPDisabled           = "auth.totp_disabled"
	EventRecoveryCodesIssued    = "auth.recovery_codes_issued"
	EventSessionsRevoked        = "auth.sessions_revoked"
	EventPasskeyRegistered      = "auth.passkey_registered"
	EventPasskeyRemoved         = "auth.passkey_removed"
	EventPasskeyLogin           = "auth.passkey_login"
	// Single sign-on. A refusal carries a reason, never a token or a claim.
	EventSSOLogin    = "auth.sso_login"
	EventSSOFailed   = "auth.sso_failed"
	EventSSOUnlinked = "admin.sso_unlinked"

	// User management.
	EventUserCreated        = "admin.user_created"
	EventUserUpdated        = "admin.user_updated"
	EventUserDeleted        = "admin.user_deleted"
	EventInvitationSent     = "admin.invitation_sent"
	EventInvitationRevoked  = "admin.invitation_revoked"
	EventInvitationAccepted = "admin.invitation_accepted"
	EventUserPasswordSet    = "admin.user_password_set"
)

// AuditEvent is one append-only entry. The content of a secret, its key, its
// passphrase and any URL fragment are never part of it.
type AuditEvent struct {
	ID        int64             `json:"id"`
	OrgID     string            `json:"org_id"`
	SecretID  string            `json:"secret_id,omitempty"`
	UserID    string            `json:"user_id,omitempty"`
	Event     string            `json:"event"`
	At        time.Time         `json:"at"`
	IP        string            `json:"ip,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
}

// Append writes an audit entry.
func (s *Store) Append(ctx context.Context, e AuditEvent) error {
	var detail any
	if len(e.Detail) > 0 {
		buf, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = string(buf)
	}
	at := e.At
	if at.IsZero() {
		at = s.Now()
	}
	_, err := s.exec(ctx, `INSERT INTO audit_events (org_id, secret_id, user_id, event, at, ip, user_agent, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		orDefaultOrg(e.OrgID), nullString(e.SecretID), nullString(e.UserID), e.Event,
		unix(at), nullString(e.IP), nullString(truncate(e.UserAgent, 512)), detail)
	if err != nil {
		return fmt.Errorf("store: append audit event: %w", err)
	}
	return nil
}

// AuditFilter narrows a listing.
type AuditFilter struct {
	SecretID string
	Event    string
	Since    time.Time
	Until    time.Time
	Limit    int
	Offset   int
}

// ListAudit returns audit entries, most recent first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	q := `SELECT id, org_id, secret_id, user_id, event, at, ip, user_agent, detail FROM audit_events WHERE 1 = 1`
	var args []any
	if f.SecretID != "" {
		q += ` AND secret_id = ?`
		args = append(args, f.SecretID)
	}
	if f.Event != "" {
		q += ` AND event = ?`
		args = append(args, f.Event)
	}
	if !f.Since.IsZero() {
		q += ` AND at >= ?`
		args = append(args, unix(f.Since))
	}
	if !f.Until.IsZero() {
		q += ` AND at <= ?`
		args = append(args, unix(f.Until))
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q += ` ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, max(f.Offset, 0))

	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AuditEvent
	for rows.Next() {
		var (
			e                            AuditEvent
			secretID, userID, ip, ua, dt nullStr
			at                           int64
		)
		if err := rows.Scan(&e.ID, &e.OrgID, &secretID, &userID, &e.Event, &at, &ip, &ua, &dt); err != nil {
			return nil, err
		}
		e.SecretID, e.UserID, e.IP, e.UserAgent = secretID.String, userID.String, ip.String, ua.String
		e.At = fromUnix(at)
		if dt.String != "" {
			_ = json.Unmarshal([]byte(dt.String), &e.Detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeAudit drops entries older than the retention window and returns how
// many were removed. Zero retention means keep forever.
func (s *Store) PurgeAudit(ctx context.Context, retention time.Duration, now time.Time) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	res, err := s.exec(ctx, `DELETE FROM audit_events WHERE at < ?`, unix(now.Add(-retention)))
	if err != nil {
		return 0, fmt.Errorf("store: purge audit: %w", err)
	}
	return res.RowsAffected()
}

// AnonymizeIP keeps a /24 (IPv4) or /48 (IPv6) prefix, which is enough to spot
// abuse patterns while satisfying a GDPR data-minimisation requirement.
func AnonymizeIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IP{v4[0], v4[1], v4[2], 0}.String() + "/24"
	}
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

type nullStr struct{ String string }

// Scan implements sql.Scanner for optional text columns without dragging
// sql.NullString through the struct literals.
func (n *nullStr) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		n.String = ""
	case string:
		n.String = v
	case []byte:
		n.String = string(v)
	default:
		return fmt.Errorf("store: cannot scan %T as text", value)
	}
	return nil
}

// orDefaultOrg returns the organisation to use, falling back to the single
// organisation of a single-tenant instance.
func orDefaultOrg(orgID string) string {
	if orgID == "" {
		return DefaultOrgID
	}
	return orgID
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
