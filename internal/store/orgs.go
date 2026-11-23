package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Organisations and their domains.
//
// A single-tenant instance has exactly one row here, `default`, inserted by
// the first migration, and never looks at any of this. Multi-organisation mode
// turns one installation into several: each organisation has its own brand,
// its own users, its own secrets and its own audit trail, and a request says
// which one it belongs to by its Host header.
//
// A user belongs to one organisation, not several. The specification sketched
// a memberships table; this is the deliberate simplification. "One instance
// hosts several customers" does not mean one person works for two of them, and
// a membership table would put an org_id in every session, every token and
// every query that today takes it from the account — a lot of surface for a
// case nobody asked for. A person who genuinely needs both gets two accounts,
// which is also the honest audit trail.

// RolePlatformAdmin is the role above admin, for an instance hosting several
// organisations. It is the only role that may create one, and it only exists
// in the default organisation.
const RolePlatformAdmin = "platform_admin"

// Organisation statuses. A suspended organisation keeps its data and refuses
// every request: a customer who has not paid is not a customer whose secrets
// are deleted.
const (
	OrgActive    = "active"
	OrgSuspended = "suspended"
)

// Org is one tenant.
type Org struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Policies  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Active reports whether the organisation may be used.
func (o Org) Active() bool { return o.Status == "" || o.Status == OrgActive }

// Domain is one name pointed at this instance for an organisation.
type Domain struct {
	Domain     string     `json:"domain"`
	OrgID      string     `json:"org_id"`
	Token      string     `json:"verify_token"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Primary    bool       `json:"primary"`
	CreatedAt  time.Time  `json:"created_at"`
	CheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
}

// Verified reports whether the TXT record has been seen.
func (d Domain) Verified() bool { return d.VerifiedAt != nil }

// ErrOrgExists is returned when a slug or a domain is already taken.
var ErrOrgExists = errors.New("store: that organisation or domain already exists")

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

const orgColumns = `id, slug, name, status, policies, created_at, updated_at`

func scanOrg(row interface{ Scan(...any) error }) (Org, error) {
	var (
		o                Org
		created, updated int64
	)
	if err := row.Scan(&o.ID, &o.Slug, &o.Name, &o.Status, &o.Policies, &created, &updated); err != nil {
		return Org{}, err
	}
	o.CreatedAt = fromUnix(created)
	if updated > 0 {
		o.UpdatedAt = fromUnix(updated)
	}
	return o, nil
}

// CreateOrg inserts an organisation.
func (s *Store) CreateOrg(ctx context.Context, o Org) (Org, error) {
	if o.ID == "" {
		id, err := newID()
		if err != nil {
			return Org{}, err
		}
		o.ID = id
	}
	o.Slug = NormaliseSlug(o.Slug)
	if o.Slug == "" {
		return Org{}, errors.New("store: an organisation needs a slug")
	}
	if o.Name == "" {
		o.Name = o.Slug
	}
	if o.Status == "" {
		o.Status = OrgActive
	}
	if o.Policies == "" {
		o.Policies = "{}"
	}
	now := s.Now()
	o.CreatedAt, o.UpdatedAt = now, now

	_, err := s.exec(ctx, `INSERT INTO organizations (id, slug, name, policies, created_at, status, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.Slug, o.Name, o.Policies, unix(now), o.Status, unix(now))
	if err != nil {
		if isUniqueViolation(err) {
			return Org{}, ErrOrgExists
		}
		return Org{}, fmt.Errorf("store: create organisation: %w", err)
	}
	return o, nil
}

// OrgByID reads one organisation.
func (s *Store) OrgByID(ctx context.Context, id string) (Org, error) {
	o, err := scanOrg(s.queryRow(ctx, `SELECT `+orgColumns+` FROM organizations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	return o, err
}

// OrgBySlug reads one organisation by its slug.
func (s *Store) OrgBySlug(ctx context.Context, slug string) (Org, error) {
	o, err := scanOrg(s.queryRow(ctx, `SELECT `+orgColumns+` FROM organizations WHERE slug = ?`,
		NormaliseSlug(slug)))
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	return o, err
}

// ListOrgs returns every organisation, oldest first.
func (s *Store) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := s.query(ctx, `SELECT `+orgColumns+` FROM organizations ORDER BY created_at, slug`)
	if err != nil {
		return nil, fmt.Errorf("store: list organisations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Org
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// UpdateOrg changes the name or the status. Empty values are left alone.
func (s *Store) UpdateOrg(ctx context.Context, id, name, status string) error {
	q := `UPDATE organizations SET updated_at = ?`
	args := []any{unix(s.Now())}
	if name != "" {
		q += `, name = ?`
		args = append(args, name)
	}
	if status != "" {
		q += `, status = ?`
		args = append(args, status)
	}
	q += ` WHERE id = ?`
	args = append(args, id)
	if _, err := s.exec(ctx, q, args...); err != nil {
		return fmt.Errorf("store: update organisation: %w", err)
	}
	return nil
}

// OrgCounts is what a platform administrator wants on one line per customer.
type OrgCounts struct {
	Users   int `json:"users"`
	Secrets int `json:"secrets"`
	Domains int `json:"domains"`
}

// CountOrg returns the live counts for an organisation.
func (s *Store) CountOrg(ctx context.Context, orgID string) (OrgCounts, error) {
	var out OrgCounts
	err := s.queryRow(ctx, `SELECT
		(SELECT COUNT(*) FROM users WHERE org_id = ?),
		(SELECT COUNT(*) FROM secrets WHERE org_id = ?),
		(SELECT COUNT(*) FROM org_domains WHERE org_id = ?)`,
		orgID, orgID, orgID).Scan(&out.Users, &out.Secrets, &out.Domains)
	if err != nil {
		return out, fmt.Errorf("store: count organisation: %w", err)
	}
	return out, nil
}

// DeleteOrg removes an organisation and everything that cascades from it.
//
// It refuses the default organisation: that row is the single-tenant instance
// itself, and deleting it would leave every existing secret pointing at
// nothing.
func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	if id == DefaultOrgID {
		return errors.New("store: the default organisation cannot be deleted")
	}
	counts, err := s.CountOrg(ctx, id)
	if err != nil {
		return err
	}
	if counts.Users > 0 || counts.Secrets > 0 {
		return fmt.Errorf("store: organisation %s still has %d user(s) and %d secret(s)",
			id, counts.Users, counts.Secrets)
	}
	if _, err := s.exec(ctx, `DELETE FROM org_domains WHERE org_id = ?`, id); err != nil {
		return fmt.Errorf("store: delete organisation domains: %w", err)
	}
	if _, err := s.exec(ctx, `DELETE FROM branding WHERE org_id = ?`, id); err != nil {
		return fmt.Errorf("store: delete organisation branding: %w", err)
	}
	if _, err := s.exec(ctx, `DELETE FROM organizations WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete organisation: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

const domainColumns = `domain, org_id, verify_token, verified_at, is_primary, created_at,
	last_checked_at, last_error`

func scanDomain(row interface{ Scan(...any) error }) (Domain, error) {
	var (
		d                 Domain
		verified, checked sql.NullInt64
		primary           int
		created           int64
		lastError         nullStr
	)
	if err := row.Scan(&d.Domain, &d.OrgID, &d.Token, &verified, &primary, &created,
		&checked, &lastError); err != nil {
		return Domain{}, err
	}
	if verified.Valid {
		at := fromUnix(verified.Int64)
		d.VerifiedAt = &at
	}
	if checked.Valid {
		at := fromUnix(checked.Int64)
		d.CheckedAt = &at
	}
	d.Primary, d.CreatedAt, d.LastError = primary == 1, fromUnix(created), lastError.String
	return d, nil
}

// AddDomain declares a domain for an organisation, unverified, with a fresh
// token to publish.
func (s *Store) AddDomain(ctx context.Context, orgID, domain, token string) (Domain, error) {
	name := NormaliseDomain(domain)
	if name == "" {
		return Domain{}, errors.New("store: a domain cannot be empty")
	}
	now := s.Now()
	_, err := s.exec(ctx, `INSERT INTO org_domains (domain, org_id, verify_token, created_at)
		VALUES (?, ?, ?, ?)`, name, orgID, token, unix(now))
	if err != nil {
		if isUniqueViolation(err) {
			return Domain{}, ErrOrgExists
		}
		return Domain{}, fmt.Errorf("store: add domain: %w", err)
	}
	return Domain{Domain: name, OrgID: orgID, Token: token, CreatedAt: now}, nil
}

// DomainByName reads one domain, whether verified or not.
func (s *Store) DomainByName(ctx context.Context, domain string) (Domain, error) {
	d, err := scanDomain(s.queryRow(ctx, `SELECT `+domainColumns+` FROM org_domains WHERE domain = ?`,
		NormaliseDomain(domain)))
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	return d, err
}

// OrgByDomain resolves a Host header to an organisation.
//
// Only a verified domain resolves. An unverified one is a declaration, and
// honouring it would let anyone who can point a DNS name at this instance wear
// another customer's brand.
func (s *Store) OrgByDomain(ctx context.Context, domain string) (Org, error) {
	row := s.queryRow(ctx, `SELECT `+prefixed("o", orgColumns)+`
		FROM organizations o
		JOIN org_domains d ON d.org_id = o.id
		WHERE d.domain = ? AND d.verified_at IS NOT NULL`, NormaliseDomain(domain))
	o, err := scanOrg(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	return o, err
}

// ListDomains returns an organisation's domains, or every domain when orgID is
// empty.
func (s *Store) ListDomains(ctx context.Context, orgID string) ([]Domain, error) {
	q := `SELECT ` + domainColumns + ` FROM org_domains`
	var args []any
	if orgID != "" {
		q += ` WHERE org_id = ?`
		args = append(args, orgID)
	}
	q += ` ORDER BY is_primary DESC, domain`

	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list domains: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkDomainVerified records a successful check.
//
// The first domain an organisation verifies also becomes its primary one. The
// alternative is an organisation whose brand resolves on its own domain while
// its links point at the instance's address, which is a footgun nobody would
// choose deliberately. A later SetPrimaryDomain overrides it.
func (s *Store) MarkDomainVerified(ctx context.Context, domain string, now time.Time) error {
	name := NormaliseDomain(domain)
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID string
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT org_id FROM org_domains WHERE domain = ?`),
			name).Scan(&orgID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE org_domains
			SET verified_at = ?, last_checked_at = ?, last_error = NULL
			WHERE domain = ?`), unix(now), unix(now), name); err != nil {
			return fmt.Errorf("store: mark domain verified: %w", err)
		}
		var primaries int
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM org_domains
			WHERE org_id = ? AND is_primary = 1`), orgID).Scan(&primaries); err != nil {
			return err
		}
		if primaries > 0 {
			return nil
		}
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE org_domains SET is_primary = 1 WHERE domain = ?`), name)
		return err
	})
}

// MarkDomainFailed records a check that did not find the record.
//
// It does not clear verified_at. A domain that was proved once stays proved
// through a DNS outage: clearing it would take a customer's brand away because
// their resolver was slow.
func (s *Store) MarkDomainFailed(ctx context.Context, domain, reason string, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE org_domains
		SET last_checked_at = ?, last_error = ?
		WHERE domain = ?`, unix(now), truncate(reason, 300), NormaliseDomain(domain))
	if err != nil {
		return fmt.Errorf("store: mark domain failed: %w", err)
	}
	return nil
}

// SetPrimaryDomain moves the primary flag within an organisation, in one
// transaction: the partial unique index refuses two primaries, so clearing and
// setting must not be two round trips that could be interrupted between.
func (s *Store) SetPrimaryDomain(ctx context.Context, orgID, domain string) error {
	name := NormaliseDomain(domain)
	return s.tx(ctx, func(tx *sql.Tx) error {
		var verified sql.NullInt64
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT verified_at FROM org_domains
			WHERE domain = ? AND org_id = ?`), name, orgID).Scan(&verified)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !verified.Valid {
			return errors.New("store: an unverified domain cannot be the primary one")
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE org_domains SET is_primary = 0 WHERE org_id = ?`),
			orgID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE org_domains SET is_primary = 1 WHERE domain = ?`), name)
		return err
	})
}

// DeleteDomain removes a domain.
func (s *Store) DeleteDomain(ctx context.Context, orgID, domain string) error {
	_, err := s.exec(ctx, `DELETE FROM org_domains WHERE domain = ? AND org_id = ?`,
		NormaliseDomain(domain), orgID)
	if err != nil {
		return fmt.Errorf("store: delete domain: %w", err)
	}
	return nil
}

// PrimaryDomain returns the organisation's primary domain, if it has one.
func (s *Store) PrimaryDomain(ctx context.Context, orgID string) (Domain, error) {
	d, err := scanDomain(s.queryRow(ctx, `SELECT `+domainColumns+` FROM org_domains
		WHERE org_id = ? AND is_primary = 1`, orgID))
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	return d, err
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

// NormaliseSlug reduces a slug to lowercase letters, digits and hyphens.
func NormaliseSlug(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == ' ', r == '.':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// NormaliseDomain lowercases a host and drops a port, a trailing dot and a
// scheme if somebody pasted a URL.
//
// A Host header is attacker-controlled on a direct connection, so this is also
// the sanitiser: whatever arrives is reduced to something that can only be a
// hostname before it reaches a query.
func NormaliseDomain(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	// A scheme and a bare trailing slash are tolerated, because an operator
	// pasting an address from a browser bar is the common case. Anything else
	// after the host is refused rather than truncated: "evil.com/../acme.com"
	// is not a request to talk about evil.com.
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		if strings.Trim(host[slash:], "/") != "" {
			return ""
		}
		host = host[:slash]
	}
	// An IPv6 literal arrives bracketed; a port follows the bracket.
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			host = host[1:end]
		}
	} else if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	host = strings.TrimSuffix(host, ".")
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == ':':
		default:
			return ""
		}
	}
	return host
}

// prefixed qualifies a column list with a table alias, so a join can reuse it.
func prefixed(alias, columns string) string {
	parts := strings.Split(columns, ",")
	for i, part := range parts {
		parts[i] = alias + "." + strings.TrimSpace(part)
	}
	return strings.Join(parts, ", ")
}
