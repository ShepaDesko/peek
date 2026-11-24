package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Asset kinds. A brand has at most one of each.
const (
	AssetLogoLight  = "logo_light"
	AssetLogoDark   = "logo_dark"
	AssetFavicon    = "favicon"
	AssetOpenGraph  = "open_graph"
	AssetBackground = "background"
)

// AssetKinds lists the kinds an administrator may upload.
var AssetKinds = []string{AssetLogoLight, AssetLogoDark, AssetFavicon, AssetOpenGraph, AssetBackground}

// ValidAssetKind reports whether a kind is one we store.
func ValidAssetKind(kind string) bool {
	for _, k := range AssetKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Branding is the stored brand of an organisation.
//
// Every field may be empty: an empty value means "fall back to peek.toml",
// which is what a fresh install runs on. That is why nothing here is nullable
// — an empty string is a meaningful, explicit "not set".
type Branding struct {
	OrgID           string
	ServiceName     string
	PrimaryColor    string
	AccentColor     string
	BackgroundColor string
	CornerRadius    string
	Font            string
	ButtonStyle     string
	HidePoweredBy   bool
	SupportURL      string
	LegalURL        string
	PrivacyURL      string
	ContactEmail    string
	// Texts is JSON: language → key → value.
	Texts string
	// Palette is JSON: token → hex colour. It pins individual colours over
	// the ones derived from PrimaryColor and AccentColor; an empty object
	// means everything is derived, which is the usual case.
	Palette   string
	CustomCSS string
	Version   int
	UpdatedAt time.Time
	UpdatedBy string
}

// BrandingAsset is one stored image.
type BrandingAsset struct {
	OrgID       string
	Kind        string
	ContentType string
	Bytes       []byte
	SizeBytes   int64
	ETag        string
	UpdatedAt   time.Time
}

const brandingColumns = `org_id, service_name, primary_color, accent_color, background_color,
	corner_radius, font, button_style, hide_powered_by, support_url, legal_url, privacy_url,
	contact_email, texts, palette, custom_css, version, updated_at, updated_by`

// Branding returns the stored brand, or ErrNotFound when none was saved yet.
func (s *Store) Branding(ctx context.Context, orgID string) (Branding, error) {
	var (
		b         Branding
		hide      int
		updated   int64
		updatedBy nullStr
	)
	err := s.queryRow(ctx, `SELECT `+brandingColumns+` FROM branding WHERE org_id = ?`,
		orDefaultOrg(orgID)).Scan(
		&b.OrgID, &b.ServiceName, &b.PrimaryColor, &b.AccentColor, &b.BackgroundColor,
		&b.CornerRadius, &b.Font, &b.ButtonStyle, &hide, &b.SupportURL, &b.LegalURL, &b.PrivacyURL,
		&b.ContactEmail, &b.Texts, &b.Palette, &b.CustomCSS, &b.Version, &updated, &updatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Branding{}, ErrNotFound
	}
	if err != nil {
		return Branding{}, fmt.Errorf("store: read branding: %w", err)
	}
	b.HidePoweredBy = hide == 1
	b.UpdatedAt = fromUnix(updated)
	b.UpdatedBy = updatedBy.String
	return b, nil
}

// SaveBranding writes the brand, bumping its version.
//
// The version is what the interface and the stylesheet hang their cache on:
// every change produces a new ETag without hashing the whole record.
func (s *Store) SaveBranding(ctx context.Context, b Branding) (Branding, error) {
	if b.OrgID == "" {
		b.OrgID = DefaultOrgID
	}
	if b.Texts == "" {
		b.Texts = "{}"
	}
	if b.Palette == "" {
		b.Palette = "{}"
	}
	now := s.Now()
	b.UpdatedAt = now

	err := s.tx(ctx, func(tx *sql.Tx) error {
		var version int
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT version FROM branding WHERE org_id = ?`), b.OrgID).Scan(&version)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			version = 0
		case err != nil:
			return err
		}
		b.Version = version + 1

		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO branding
			(org_id, service_name, primary_color, accent_color, background_color, corner_radius,
			 font, button_style, hide_powered_by, support_url, legal_url, privacy_url,
			 contact_email, texts, palette, custom_css, version, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (org_id) DO UPDATE SET
				service_name = ?, primary_color = ?, accent_color = ?, background_color = ?,
				corner_radius = ?, font = ?, button_style = ?, hide_powered_by = ?,
				support_url = ?, legal_url = ?, privacy_url = ?, contact_email = ?,
				texts = ?, palette = ?, custom_css = ?, version = ?, updated_at = ?, updated_by = ?`),
			b.OrgID, b.ServiceName, b.PrimaryColor, b.AccentColor, b.BackgroundColor, b.CornerRadius,
			b.Font, b.ButtonStyle, boolToInt(b.HidePoweredBy), b.SupportURL, b.LegalURL, b.PrivacyURL,
			b.ContactEmail, b.Texts, b.Palette, b.CustomCSS, b.Version, unix(now), nullString(b.UpdatedBy),

			b.ServiceName, b.PrimaryColor, b.AccentColor, b.BackgroundColor,
			b.CornerRadius, b.Font, b.ButtonStyle, boolToInt(b.HidePoweredBy),
			b.SupportURL, b.LegalURL, b.PrivacyURL, b.ContactEmail,
			b.Texts, b.Palette, b.CustomCSS, b.Version, unix(now), nullString(b.UpdatedBy))
		return err
	})
	if err != nil {
		return Branding{}, fmt.Errorf("store: save branding: %w", err)
	}
	return b, nil
}

// ResetBranding removes the stored brand, so peek.toml takes over again.
func (s *Store) ResetBranding(ctx context.Context, orgID string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM branding WHERE org_id = ?`), orDefaultOrg(orgID)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM branding_assets WHERE org_id = ?`), orDefaultOrg(orgID))
		return err
	})
}

// --- assets ------------------------------------------------------------------

// SaveAsset stores or replaces one image.
func (s *Store) SaveAsset(ctx context.Context, a BrandingAsset) error {
	if a.OrgID == "" {
		a.OrgID = DefaultOrgID
	}
	if !ValidAssetKind(a.Kind) {
		return fmt.Errorf("store: unknown asset kind %q", a.Kind)
	}
	now := s.Now()
	_, err := s.exec(ctx, `INSERT INTO branding_assets (org_id, kind, content_type, bytes, size_bytes, etag, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (org_id, kind) DO UPDATE SET
			content_type = ?, bytes = ?, size_bytes = ?, etag = ?, updated_at = ?`,
		a.OrgID, a.Kind, a.ContentType, a.Bytes, int64(len(a.Bytes)), a.ETag, unix(now),
		a.ContentType, a.Bytes, int64(len(a.Bytes)), a.ETag, unix(now))
	if err != nil {
		return fmt.Errorf("store: save branding asset: %w", err)
	}
	return nil
}

// Asset returns one image.
func (s *Store) Asset(ctx context.Context, orgID, kind string) (BrandingAsset, error) {
	var (
		a       BrandingAsset
		updated int64
	)
	err := s.queryRow(ctx, `SELECT org_id, kind, content_type, bytes, size_bytes, etag, updated_at
		FROM branding_assets WHERE org_id = ? AND kind = ?`, orDefaultOrg(orgID), kind).Scan(
		&a.OrgID, &a.Kind, &a.ContentType, &a.Bytes, &a.SizeBytes, &a.ETag, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return BrandingAsset{}, ErrNotFound
	}
	if err != nil {
		return BrandingAsset{}, fmt.Errorf("store: read branding asset: %w", err)
	}
	a.UpdatedAt = fromUnix(updated)
	return a, nil
}

// ListAssets returns the metadata of every stored image, without the bytes.
func (s *Store) ListAssets(ctx context.Context, orgID string) ([]BrandingAsset, error) {
	rows, err := s.query(ctx, `SELECT kind, content_type, size_bytes, etag, updated_at
		FROM branding_assets WHERE org_id = ? ORDER BY kind`, orDefaultOrg(orgID))
	if err != nil {
		return nil, fmt.Errorf("store: list branding assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []BrandingAsset
	for rows.Next() {
		var (
			a       BrandingAsset
			updated int64
		)
		if err := rows.Scan(&a.Kind, &a.ContentType, &a.SizeBytes, &a.ETag, &updated); err != nil {
			return nil, err
		}
		a.OrgID = orDefaultOrg(orgID)
		a.UpdatedAt = fromUnix(updated)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAsset removes one image.
func (s *Store) DeleteAsset(ctx context.Context, orgID, kind string) error {
	res, err := s.exec(ctx, `DELETE FROM branding_assets WHERE org_id = ? AND kind = ?`, orDefaultOrg(orgID), kind)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
