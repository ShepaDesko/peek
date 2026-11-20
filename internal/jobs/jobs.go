// Package jobs runs the periodic work: purging expired secrets and trimming
// the audit trail.
//
// There is no Redis and no external scheduler. In a multi-node deployment the
// database lock in Claim makes sure exactly one node runs a given tick.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
)

// Runner owns the background tickers.
type Runner struct {
	cfg     *config.Config
	log     *slog.Logger
	store   *store.Store
	secrets *secrets.Service

	// PurgeInterval defaults to one minute: an expired ciphertext should not
	// outlive its expiry by more than that.
	PurgeInterval time.Duration
	AuditInterval time.Duration
}

// New builds a Runner.
func New(cfg *config.Config, log *slog.Logger, st *store.Store, svc *secrets.Service) *Runner {
	return &Runner{
		cfg:           cfg,
		log:           log,
		store:         st,
		secrets:       svc,
		PurgeInterval: time.Minute,
		AuditInterval: time.Hour,
	}
}

// Run blocks until the context is cancelled.
func (r *Runner) Run(ctx context.Context) {
	purge := time.NewTicker(r.PurgeInterval)
	audit := time.NewTicker(r.AuditInterval)
	defer purge.Stop()
	defer audit.Stop()

	// Run once at start: a node that was down over an expiry window should not
	// wait a full tick before cleaning up.
	r.purgeOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			r.log.Info("background jobs stopped")
			return
		case <-purge.C:
			r.purgeOnce(ctx)
		case <-audit.C:
			r.trimAudit(ctx)
		}
	}
}

func (r *Runner) purgeOnce(ctx context.Context) {
	n, err := r.secrets.Purge(ctx)
	if err != nil {
		r.log.Error("purge expired secrets", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Info("purged expired secrets", "count", n)
		_ = r.store.Append(ctx, store.AuditEvent{
			OrgID: "default",
			Event: store.EventPurged,
			Detail: map[string]string{
				"count": itoa(n),
			},
		})
	}
}

func (r *Runner) trimAudit(ctx context.Context) {
	retention := r.cfg.Security.AuditRetention.Std()
	if retention <= 0 {
		return
	}
	n, err := r.store.PurgeAudit(ctx, retention, time.Now())
	if err != nil {
		r.log.Error("trim audit trail", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Info("trimmed audit trail", "removed", n, "retention", retention.String())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
