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
	"github.com/ShepaDesko/peek/internal/requests"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/webhooks"
)

// Runner owns the background tickers.
type Runner struct {
	cfg      *config.Config
	log      *slog.Logger
	store    *store.Store
	secrets  *secrets.Service
	requests *requests.Service
	hooks    *webhooks.Deliverer

	// PurgeInterval defaults to one minute: an expired ciphertext should not
	// outlive its expiry by more than that.
	PurgeInterval time.Duration
	AuditInterval time.Duration
	// WebhookInterval is short: a notification that arrives a minute after the
	// reveal is a notification nobody trusts. The tick costs one indexed query
	// when the queue is empty.
	WebhookInterval time.Duration

	// holder identifies this node in the lock table.
	holder string
}

// New builds a Runner. The request service may be nil on a node that only
// serves secrets; the request purge is then skipped rather than crashing.
func New(cfg *config.Config, log *slog.Logger, st *store.Store, svc *secrets.Service, reqs *requests.Service, hooks *webhooks.Deliverer) *Runner {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "node"
	}
	return &Runner{
		cfg:             cfg,
		log:             log,
		store:           st,
		secrets:         svc,
		requests:        reqs,
		hooks:           hooks,
		PurgeInterval:   time.Minute,
		AuditInterval:   time.Hour,
		WebhookInterval: 10 * time.Second,
		holder:          host + "/" + strconv.Itoa(os.Getpid()),
	}
}

// Run blocks until the context is cancelled.
func (r *Runner) Run(ctx context.Context) {
	purge := time.NewTicker(r.PurgeInterval)
	audit := time.NewTicker(r.AuditInterval)
	defer purge.Stop()
	defer audit.Stop()

	hooks := newIdleTicker(r.WebhookInterval, r.hooks.Enabled())
	defer hooks.Stop()

	// Run once at start: a node that was down over an expiry window should not
	// wait a full tick before cleaning up.
	r.purgeOnce(ctx)
	r.deliverWebhooks(ctx)

	for {
		select {
		case <-ctx.Done():
			r.log.Info("background jobs stopped")
			return
		case <-purge.C:
			r.purgeOnce(ctx)
		case <-audit.C:
			r.housekeeping(ctx)
		case <-hooks.C:
			r.deliverWebhooks(ctx)
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

	r.purgeFiles(ctx)
	r.purgeRequests(ctx)
}

// purgeFiles removes blobs nothing references any more, then the storage
// objects no row points at. The second half is what catches a crash between
// writing the blob and recording it: the object would otherwise sit there for
// ever, taking space and telling an attacker how many secrets exist.
func (r *Runner) purgeFiles(ctx context.Context) {
	rows, orphans, err := r.secrets.PurgeFiles(ctx)
	if err != nil {
		r.log.Error("purge files", "error", err.Error())
	}
	if rows > 0 || orphans > 0 {
		r.log.Info("purged files", "rows", rows, "orphans", orphans)
	}
}

// purgeRequests removes secret requests that expired or filled up, once every
// deposit they received is gone. Closing the door never takes an unread answer
// with it.
func (r *Runner) purgeRequests(ctx context.Context) {
	if r.requests == nil {
		return
	}
	n, err := r.requests.Purge(ctx)
	if err != nil {
		r.log.Error("purge secret requests", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Info("purged secret requests", "count", n)
	}
}

// deliverWebhooks drains the delivery queue.
//
// The lease is shorter than the interval on purpose, as everywhere else here,
// but it is also longer than one attempt can take: a node that dies mid-drain
// must not leave the queue locked, and must not have two nodes sending the
// same row at once either.
func (r *Runner) deliverWebhooks(ctx context.Context) {
	if !r.hooks.Enabled() {
		return
	}
	if !r.claim(ctx, "webhooks", 2*time.Minute) {
		return
	}
	sent, retried, failed := r.hooks.Drain(ctx, time.Now())
	if sent > 0 || retried > 0 || failed > 0 {
		r.log.Info("webhook queue drained", "sent", sent, "retried", retried, "failed", failed)
	}
}

// newIdleTicker returns a ticker that never fires when the feature is off, so
// an instance with no webhooks does not wake up every ten seconds.
func newIdleTicker(every time.Duration, enabled bool) *time.Ticker {
	if !enabled || every <= 0 {
		t := time.NewTicker(time.Hour)
		t.Stop()
		return t
	}
	return time.NewTicker(every)
}

// housekeeping trims the audit trail and the shared rate-limit table.
func (r *Runner) housekeeping(ctx context.Context) {
	if !r.claim(ctx, "housekeeping", 30*time.Minute) {
		return
	}
	r.trimAudit(ctx)
	r.trimRateLimits(ctx)
	r.trimSessions(ctx)
	r.trimWebhookQueue(ctx)
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

func (r *Runner) trimWebhookQueue(ctx context.Context) {
	if !r.hooks.Enabled() {
		return
	}
	n, err := r.hooks.Purge(ctx, time.Now())
	if err != nil {
		r.log.Error("trim webhook queue", "error", err.Error())
		return
	}
	if n > 0 {
		r.log.Info("trimmed the webhook queue", "removed", n)
	}
}

// Describe returns a line for the logs at startup.
func (r *Runner) Describe() string {
	line := fmt.Sprintf("purge every %s, housekeeping every %s, as %s",
		r.PurgeInterval, r.AuditInterval, r.holder)
	if r.hooks.Enabled() {
		line += fmt.Sprintf(", webhooks every %s", r.WebhookInterval)
	}
	return line
}
