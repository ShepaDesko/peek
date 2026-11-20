// Package jobs runs the periodic work: purging expired secrets, trimming the
// audit trail, and the housekeeping that keeps shared tables small.
//
// There is no Redis and no external scheduler. Every tick is claimed through a
// lock in the database, so a cluster behind a load balancer does the work once
// rather than once per node.
package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
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

	// holder identifies this node in the lock table.
	holder string
}

// New builds a Runner.
func New(cfg *config.Config, log *slog.Logger, st *store.Store, svc *secrets.Service) *Runner {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "node"
	}
	return &Runner{
		cfg:           cfg,
		log:           log,
		store:         st,
		secrets:       svc,
		PurgeInterval: time.Minute,
		AuditInterval: time.Hour,
		holder:        host + "/" + strconv.Itoa(os.Getpid()),
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
			r.housekeeping(ctx)
		}
	}
}

// claim takes the lock for a job. The lease is deliberately shorter than the
// interval, so a node that dies mid-job delays the next run by one tick at
// most.
func (r *Runner) claim(ctx context.Context, name string, lease time.Duration) bool {
	ok, err := r.store.TryLock(ctx, name, r.holder, lease, time.Now())
	if err != nil {
		r.log.Error("cannot claim the job lock", "job", name, "error", err.Error())
		return false
	}
	return ok
}

func (r *Runner) purgeOnce(ctx context.Context) {
	if !r.claim(ctx, "purge-secrets", 45*time.Second) {
		return
	}
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
				"count": strconv.Itoa(n),
			},
		})
	}
}

// housekeeping trims the audit trail and the shared rate-limit table.
func (r *Runner) housekeeping(ctx context.Context) {
	if !r.claim(ctx, "housekeeping", 30*time.Minute) {
		return
	}
	r.trimAudit(ctx)
	r.trimRateLimits(ctx)
	r.trimSessions(ctx)
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

func (r *Runner) trimRateLimits(ctx context.Context) {
	n, err := r.store.PurgeRateLimits(ctx, 2*time.Hour, time.Now())
	if err != nil {
		r.log.Error("trim rate limits", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Debug("trimmed rate limit buckets", "removed", n)
	}
}

func (r *Runner) trimSessions(ctx context.Context) {
	n, err := r.store.PurgeExpiredSessions(ctx, time.Now())
	if err != nil {
		r.log.Error("trim sessions", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Info("removed expired sessions", "count", n)
	}
}

// Describe returns a line for the logs at startup.
func (r *Runner) Describe() string {
	return fmt.Sprintf("purge every %s, housekeeping every %s, as %s",
		r.PurgeInterval, r.AuditInterval, r.holder)
}
