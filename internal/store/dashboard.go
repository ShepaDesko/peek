package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SecretSummary is one line of the sender's dashboard.
//
// It is assembled from the live row when the secret still exists and from the
// tombstone once it is gone, so a sender keeps a history without the server
// keeping any content.
type SecretSummary struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Status         string    `json:"status"`
	ViewsUsed      int       `json:"views_used"`
	ViewsMax       int       `json:"views_max"`
	ViewsRemaining int       `json:"views_remaining"`
	HasPassphrase  bool      `json:"has_passphrase"`
	SizeBytes      int64     `json:"size_bytes"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	LastEventAt    time.Time `json:"last_event_at,omitzero"`
	// LabelEnc is the sender's private label, encrypted in their browser. The
	// server stores and returns it without ever being able to read it.
	LabelEnc []byte `json:"label_enc,omitempty"`
	GroupID  string `json:"group_id,omitempty"`
}

// DashboardFilter narrows a listing.
type DashboardFilter struct {
	OrgID     string
	CreatorID string
	// Status filters on the computed status; empty means every status.
	Status string
	Limit  int
	Offset int
}

// ListSecretsByCreator returns the secrets a user created, newest first.
func (s *Store) ListSecretsByCreator(ctx context.Context, f DashboardFilter, now time.Time) ([]SecretSummary, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	// Live secrets first, then the tombstones of the ones that are gone. Two
	// queries rather than a UNION: the two tables have different shapes and
	// the result is small enough that merging in Go is clearer.
	live, err := s.liveSummaries(ctx, f, now, limit, offset)
	if err != nil {
		return nil, err
	}
	closed, err := s.closedSummaries(ctx, f, limit, offset)
	if err != nil {
		return nil, err
	}

	out := make([]SecretSummary, 0, len(live)+len(closed))
	out = append(out, live...)
	out = append(out, closed...)
	sortSummaries(out)
	if f.Status != "" {
		filtered := out[:0]
		for _, item := range out {
			if item.Status == f.Status {
				filtered = append(filtered, item)
			}
		}
		out = filtered
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) liveSummaries(ctx context.Context, f DashboardFilter, now time.Time, limit, offset int) ([]SecretSummary, error) {
	rows, err := s.query(ctx, `SELECT id, kind, has_passphrase, views_max, views_remaining,
		size_bytes, created_at, expires_at, last_viewed_at, label_enc, group_id
		FROM secrets WHERE org_id = ? AND creator_id = ?
		ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		orDefaultOrg(f.OrgID), f.CreatorID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list dashboard secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SecretSummary
	for rows.Next() {
		var (
			item             SecretSummary
			hasPassphrase    int
			created, expires int64
			lastViewed       sql.NullInt64
			groupID          nullStr
		)
		if err := rows.Scan(&item.ID, &item.Kind, &hasPassphrase, &item.ViewsMax, &item.ViewsRemaining,
			&item.SizeBytes, &created, &expires, &lastViewed, &item.LabelEnc, &groupID); err != nil {
			return nil, err
		}
		item.HasPassphrase = hasPassphrase == 1
		item.ViewsUsed = item.ViewsMax - item.ViewsRemaining
		item.CreatedAt = fromUnix(created)
		item.ExpiresAt = fromUnix(expires)
		if lastViewed.Valid {
			item.LastEventAt = fromUnix(lastViewed.Int64)
		}
		item.GroupID = groupID.String
		item.Status = StatusActive
		if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(now) {
			item.Status = StatusExpired
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) closedSummaries(ctx context.Context, f DashboardFilter, limit, offset int) ([]SecretSummary, error) {
	rows, err := s.query(ctx, `SELECT id, status, views_used, views_max, created_at, closed_at, group_id
		FROM secret_tombstones WHERE org_id = ? AND creator_id = ?
		ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		orDefaultOrg(f.OrgID), f.CreatorID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list closed secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SecretSummary
	for rows.Next() {
		var (
			item            SecretSummary
			created, closed int64
			groupID         nullStr
		)
		if err := rows.Scan(&item.ID, &item.Status, &item.ViewsUsed, &item.ViewsMax,
			&created, &closed, &groupID); err != nil {
			return nil, err
		}
		item.CreatedAt = fromUnix(created)
		item.LastEventAt = fromUnix(closed)
		item.GroupID = groupID.String
		out = append(out, item)
	}
	return out, rows.Err()
}

// CountSecretsByCreator returns live and closed counts for the dashboard header.
func (s *Store) CountSecretsByCreator(ctx context.Context, orgID, creatorID string) (live, closed int, err error) {
	if err = s.queryRow(ctx, `SELECT COUNT(*) FROM secrets WHERE org_id = ? AND creator_id = ?`,
		orDefaultOrg(orgID), creatorID).Scan(&live); err != nil {
		return 0, 0, err
	}
	if err = s.queryRow(ctx, `SELECT COUNT(*) FROM secret_tombstones WHERE org_id = ? AND creator_id = ?`,
		orDefaultOrg(orgID), creatorID).Scan(&closed); err != nil {
		return 0, 0, err
	}
	return live, closed, nil
}

// BurnAsOwner destroys a secret the caller created, without needing the
// receipt token: the dashboard knows it is theirs from the creator column.
func (s *Store) BurnAsOwner(ctx context.Context, orgID, creatorID, secretID string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var (
			owner            nullStr
			org              string
			viewsMax, remain int
			createdAt        int64
			groupID          nullStr
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT creator_id, org_id, views_max, views_remaining, created_at, group_id
			FROM secrets WHERE id = ?`), secretID).Scan(&owner, &org, &viewsMax, &remain, &createdAt, &groupID)
		if err != nil {
			return ErrNotFound
		}
		if owner.String != creatorID || org != orDefaultOrg(orgID) {
			return ErrNotFound
		}
		return deleteSecretTx(ctx, s, tx, secretID, org, sql.NullString{String: creatorID, Valid: true},
			sql.NullString{String: groupID.String, Valid: groupID.String != ""},
			StatusBurned, viewsMax-remain, viewsMax, createdAt, now)
	})
}

// sortSummaries orders by creation time, newest first, with a stable tie-break
// on the identifier so paging does not shuffle.
func sortSummaries(items []SecretSummary) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			if items[j].CreatedAt.After(items[j-1].CreatedAt) ||
				(items[j].CreatedAt.Equal(items[j-1].CreatedAt) && items[j].ID < items[j-1].ID) {
				items[j], items[j-1] = items[j-1], items[j]
				continue
			}
			break
		}
	}
}
