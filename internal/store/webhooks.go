package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The webhook delivery queue.
//
// Events are enqueued on the request path — one small insert, the same cost as
// the audit row next to it — and delivered by the background job. Nothing in
// an HTTP handler waits on an outbound call.

// Delivery is one queued webhook call.
type Delivery struct {
	ID       string    `json:"id"`
	OrgID    string    `json:"org_id"`
	Endpoint string    `json:"endpoint"`
	Event    string    `json:"event"`
	Payload  string    `json:"-"`
	Attempts int       `json:"attempts"`
	NextAt   time.Time `json:"next_attempt_at"`
	Created  time.Time `json:"created_at"`

	Delivered  *time.Time `json:"delivered_at,omitempty"`
	Failed     *time.Time `json:"failed_at,omitempty"`
	LastStatus int        `json:"last_status,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
}

// Pending reports whether the delivery is still owed.
func (d Delivery) Pending() bool { return d.Delivered == nil && d.Failed == nil }

// EnqueueDelivery adds one call to the queue, due immediately.
func (s *Store) EnqueueDelivery(ctx context.Context, d Delivery) (string, error) {
	id := d.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return "", err
		}
	}
	now := d.Created
	if now.IsZero() {
		now = s.Now()
	}
	next := d.NextAt
	if next.IsZero() {
		next = now
	}
	_, err := s.exec(ctx, `INSERT INTO webhook_deliveries
		(id, org_id, endpoint, event, payload, attempts, next_attempt_at, created_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		id, orDefaultOrg(d.OrgID), d.Endpoint, d.Event, d.Payload, unix(next), unix(now))
	if err != nil {
		return "", fmt.Errorf("store: enqueue webhook delivery: %w", err)
	}
	return id, nil
}

// DueDeliveries returns the queued calls whose turn has come, oldest first.
//
// There is no per-row lease: the whole drain is claimed by the job lock, so
// one node at a time reads this and one node at a time writes the result back.
// A lease per row would buy nothing and could strand a delivery behind a node
// that died holding it.
func (s *Store) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.query(ctx, `SELECT id, org_id, endpoint, event, payload, attempts, next_attempt_at, created_at
		FROM webhook_deliveries
		WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= ?
		ORDER BY next_attempt_at, created_at
		LIMIT ?`, unix(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: due webhook deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Delivery
	for rows.Next() {
		var (
			d               Delivery
			nextAt, created int64
		)
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Endpoint, &d.Event, &d.Payload, &d.Attempts, &nextAt, &created); err != nil {
			return nil, err
		}
		d.NextAt, d.Created = fromUnix(nextAt), fromUnix(created)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliverySucceeded closes a row out as delivered.
func (s *Store) DeliverySucceeded(ctx context.Context, id string, status int, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE webhook_deliveries
		SET attempts = attempts + 1, delivered_at = ?, last_status = ?, last_error = NULL
		WHERE id = ? AND delivered_at IS NULL AND failed_at IS NULL`,
		unix(now), status, id)
	if err != nil {
		return fmt.Errorf("store: mark webhook delivered: %w", err)
	}
	return nil
}

// DeliveryFailed records an attempt that did not arrive.
//
// retryAt in the future reschedules; a zero retryAt gives up and stamps
// failed_at, which is what the operator's listing shows and what keeps the row
// out of the drain for ever.
func (s *Store) DeliveryFailed(ctx context.Context, id string, status int, reason string, retryAt, now time.Time) error {
	if retryAt.IsZero() {
		_, err := s.exec(ctx, `UPDATE webhook_deliveries
			SET attempts = attempts + 1, failed_at = ?, last_status = ?, last_error = ?
			WHERE id = ? AND delivered_at IS NULL AND failed_at IS NULL`,
			unix(now), nullInt(status), truncate(reason, 500), id)
		if err != nil {
			return fmt.Errorf("store: mark webhook failed: %w", err)
		}
		return nil
	}
	_, err := s.exec(ctx, `UPDATE webhook_deliveries
		SET attempts = attempts + 1, next_attempt_at = ?, last_status = ?, last_error = ?
		WHERE id = ? AND delivered_at IS NULL AND failed_at IS NULL`,
		unix(retryAt), nullInt(status), truncate(reason, 500), id)
	if err != nil {
		return fmt.Errorf("store: reschedule webhook: %w", err)
	}
	return nil
}

// RetryDelivery puts a failed row back in the queue, due now, with its attempt
// counter reset. This is what peek webhook retry calls after the operator has
// fixed the receiver.
func (s *Store) RetryDelivery(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.exec(ctx, `UPDATE webhook_deliveries
		SET attempts = 0, next_attempt_at = ?, failed_at = NULL, last_error = NULL
		WHERE id = ? AND failed_at IS NOT NULL`, unix(now), id)
	if err != nil {
		return false, fmt.Errorf("store: retry webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil //nolint:nilerr // a driver that cannot count: say nothing happened
	}
	return n > 0, nil
}

// RetryFailedDeliveries requeues every failed row, optionally for one endpoint.
func (s *Store) RetryFailedDeliveries(ctx context.Context, endpoint string, now time.Time) (int64, error) {
	q := `UPDATE webhook_deliveries
		SET attempts = 0, next_attempt_at = ?, failed_at = NULL, last_error = NULL
		WHERE failed_at IS NOT NULL`
	args := []any{unix(now)}
	if endpoint != "" {
		q += ` AND endpoint = ?`
		args = append(args, endpoint)
	}
	res, err := s.exec(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("store: retry failed webhooks: %w", err)
	}
	return res.RowsAffected()
}

// DeliveryFilter narrows a listing.
type DeliveryFilter struct {
	Endpoint string
	Event    string
	// State is pending, delivered, failed or empty for all.
	State string
	Limit int
}

// ListDeliveries returns deliveries, most recent first.
func (s *Store) ListDeliveries(ctx context.Context, f DeliveryFilter) ([]Delivery, error) {
	q := `SELECT id, org_id, endpoint, event, attempts, next_attempt_at, created_at,
		delivered_at, failed_at, last_status, last_error
		FROM webhook_deliveries WHERE 1 = 1`
	var args []any
	if f.Endpoint != "" {
		q += ` AND endpoint = ?`
		args = append(args, f.Endpoint)
	}
	if f.Event != "" {
		q += ` AND event = ?`
		args = append(args, f.Event)
	}
	switch f.State {
	case "pending":
		q += ` AND delivered_at IS NULL AND failed_at IS NULL`
	case "delivered":
		q += ` AND delivered_at IS NOT NULL`
	case "failed":
		q += ` AND failed_at IS NOT NULL`
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list webhook deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Delivery
	for rows.Next() {
		var (
			d                             Delivery
			nextAt, created               int64
			delivered, failed, lastStatus sql.NullInt64
			lastError                     nullStr
		)
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Endpoint, &d.Event, &d.Attempts,
			&nextAt, &created, &delivered, &failed, &lastStatus, &lastError); err != nil {
			return nil, err
		}
		d.NextAt, d.Created = fromUnix(nextAt), fromUnix(created)
		if delivered.Valid {
			at := fromUnix(delivered.Int64)
			d.Delivered = &at
		}
		if failed.Valid {
			at := fromUnix(failed.Int64)
			d.Failed = &at
		}
		d.LastStatus, d.LastError = int(lastStatus.Int64), lastError.String
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliveryCounts summarises the queue for peek doctor and the admin page.
type DeliveryCounts struct {
	Pending   int64 `json:"pending"`
	Delivered int64 `json:"delivered"`
	Failed    int64 `json:"failed"`
	// Oldest is the creation time of the oldest row still owed, zero if the
	// queue is empty. A queue that is not empty but not growing is fine; one
	// whose oldest row keeps ageing is a receiver that is down.
	Oldest time.Time `json:"oldest_pending,omitempty"`
}

// DeliveryStats counts the queue by state.
func (s *Store) DeliveryStats(ctx context.Context) (DeliveryCounts, error) {
	var (
		out    DeliveryCounts
		oldest sql.NullInt64
	)
	err := s.queryRow(ctx, `SELECT
		COUNT(CASE WHEN delivered_at IS NULL AND failed_at IS NULL THEN 1 END),
		COUNT(delivered_at),
		COUNT(failed_at),
		MIN(CASE WHEN delivered_at IS NULL AND failed_at IS NULL THEN created_at END)
		FROM webhook_deliveries`).Scan(&out.Pending, &out.Delivered, &out.Failed, &oldest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, fmt.Errorf("store: webhook queue stats: %w", err)
	}
	if oldest.Valid {
		out.Oldest = fromUnix(oldest.Int64)
	}
	return out, nil
}

// PurgeDeliveries drops finished rows older than the retention window. Failed
// rows are kept twice as long: they are the ones an operator comes looking for.
func (s *Store) PurgeDeliveries(ctx context.Context, retention time.Duration, now time.Time) (int64, error) {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	res, err := s.exec(ctx, `DELETE FROM webhook_deliveries
		WHERE (delivered_at IS NOT NULL AND delivered_at < ?)
		   OR (failed_at IS NOT NULL AND failed_at < ?)`,
		unix(now.Add(-retention)), unix(now.Add(-2*retention)))
	if err != nil {
		return 0, fmt.Errorf("store: purge webhook deliveries: %w", err)
	}
	return res.RowsAffected()
}

// nullInt keeps a zero status out of the column: a transport error has no HTTP
// status, and storing 0 would read as one.
func nullInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
