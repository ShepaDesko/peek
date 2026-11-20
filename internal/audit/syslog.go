// Package audit forwards the audit trail to a SIEM.
//
// The trail is always written to the database first: forwarding is an extra,
// and a SIEM that is down, slow or unreachable must never slow a request down
// or lose a secret. Delivery is therefore asynchronous and best-effort, with a
// bounded queue and a counter of what it had to drop.
package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// Forwarder sends audit events somewhere else.
type Forwarder interface {
	Forward(event store.AuditEvent)
	Close() error
}

// Nop is the forwarder of an instance with no SIEM.
type Nop struct{}

// Forward does nothing.
func (Nop) Forward(store.AuditEvent) {}

// Close does nothing.
func (Nop) Close() error { return nil }

// Syslog forwards events as RFC 5424 messages.
type Syslog struct {
	cfg      config.Syslog
	log      *slog.Logger
	hostname string

	queue  chan store.AuditEvent
	done   chan struct{}
	closed atomic.Bool
	once   sync.Once

	dropped atomic.Uint64
	sent    atomic.Uint64

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslog starts a forwarder. It does not connect yet: a SIEM that is not
// listening at boot must not stop Peek from starting.
func NewSyslog(cfg config.Syslog, log *slog.Logger) *Syslog {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "-"
	}
	s := &Syslog{
		cfg:      cfg,
		log:      log,
		hostname: host,
		queue:    make(chan store.AuditEvent, 1024),
		done:     make(chan struct{}),
	}
	go s.run()
	return s
}

// Forward queues an event. It never blocks: when the queue is full the event
// is counted as dropped and the database copy remains the record of truth.
func (s *Syslog) Forward(event store.AuditEvent) {
	if s == nil || s.closed.Load() {
		return
	}
	select {
	case s.queue <- event:
	default:
		if n := s.dropped.Add(1); n == 1 || n%1000 == 0 {
			s.log.Warn("syslog queue full, audit events are being dropped from the forwarder only",
				"dropped", n, "address", s.cfg.Address)
		}
	}
}

// Close drains what it can and releases the connection.
func (s *Syslog) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.queue)
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// Stats reports what the forwarder has done, for peek doctor.
func (s *Syslog) Stats() (sent, dropped uint64) {
	if s == nil {
		return 0, 0
	}
	return s.sent.Load(), s.dropped.Load()
}

func (s *Syslog) run() {
	defer close(s.done)
	for event := range s.queue {
		if err := s.write(event); err != nil {
			// One line per failure would flood the log when a SIEM is down,
			// so the connection is dropped and retried on the next event.
			s.dropConn()
			if n := s.dropped.Add(1); n == 1 || n%1000 == 0 {
				s.log.Warn("cannot forward audit event to syslog",
					"address", s.cfg.Address, "error", err.Error(), "dropped", n)
			}
			continue
		}
		s.sent.Add(1)
	}
}

func (s *Syslog) write(event store.AuditEvent) error {
	conn, err := s.connection()
	if err != nil {
		return err
	}
	msg := s.format(event)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(msg))
	return err
}

func (s *Syslog) connection() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn, nil
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var (
		conn net.Conn
		err  error
	)
	switch s.cfg.Protocol {
	case "tcp":
		conn, err = dialer.DialContext(context.Background(), "tcp", s.cfg.Address)
	case "tls":
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: s.cfg.SkipVerify, //nolint:gosec // opt-in, for an internal CA
			},
		}
		conn, err = tlsDialer.DialContext(context.Background(), "tcp", s.cfg.Address)
	default: // udp
		conn, err = dialer.DialContext(context.Background(), "udp", s.cfg.Address)
	}
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

func (s *Syslog) dropConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// severityOf maps an event to a syslog severity, so a SIEM can alert on the
// ones that matter without parsing the message.
func severityOf(event string) int {
	switch event {
	case store.EventLoginFailed, store.EventMFAFailed, store.EventBadPassphrase,
		store.EventAdminBlocked, store.EventRateLimited:
		return 4 // warning
	case store.EventCreated, store.EventRevealed, store.EventBurned, store.EventDeleted,
		store.EventPasswordChanged, store.EventPasswordReset, store.EventTOTPEnabled,
		store.EventTOTPDisabled, store.EventUserCreated, store.EventUserDeleted,
		store.EventUserUpdated, store.EventUpdateApplied, store.EventConfigChanged:
		return 5 // notice
	default:
		return 6 // informational
	}
}

// format renders one RFC 5424 message.
//
// The structured data carries the fields a SIEM wants to correlate on; the
// free-text part stays human readable. No secret content ever appears here,
// for the same reason it never appears in the database trail.
func (s *Syslog) format(e store.AuditEvent) string {
	facility := s.cfg.Facility
	if facility < 0 || facility > 23 {
		facility = 13 // local1
	}
	priority := facility*8 + severityOf(e.Event)

	at := e.At
	if at.IsZero() {
		at = time.Now()
	}
	app := s.cfg.AppName
	if app == "" {
		app = "peek"
	}

	var sd strings.Builder
	sd.WriteString("[peek@52913")
	writeParam(&sd, "event", e.Event)
	writeParam(&sd, "org", e.OrgID)
	if e.SecretID != "" {
		writeParam(&sd, "secret", e.SecretID)
	}
	if e.UserID != "" {
		writeParam(&sd, "user", e.UserID)
	}
	if e.IP != "" {
		writeParam(&sd, "ip", e.IP)
	}
	for k, v := range e.Detail {
		writeParam(&sd, "d_"+k, v)
	}
	sd.WriteString("]")

	message := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		priority,
		at.UTC().Format("2006-01-02T15:04:05.000Z"),
		s.hostname,
		app,
		e.Event,
		sd.String(),
		humanSummary(e),
	)
	if s.cfg.Protocol == "tcp" || s.cfg.Protocol == "tls" {
		// Octet counting is what RFC 6587 recommends over a stream.
		return fmt.Sprintf("%d %s", len(message), message)
	}
	return message
}

func writeParam(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, " %s=%q", key, escapeSD(value))
}

// escapeSD escapes the three characters RFC 5424 reserves inside structured
// data, and drops control characters so a crafted user agent cannot inject a
// line break into someone's SIEM.
func escapeSD(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '"' || r == '\\' || r == ']':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func humanSummary(e store.AuditEvent) string {
	switch {
	case e.SecretID != "" && e.UserID != "":
		return fmt.Sprintf("secret=%s user=%s", e.SecretID, e.UserID)
	case e.SecretID != "":
		return "secret=" + e.SecretID
	case e.UserID != "":
		return "user=" + e.UserID
	default:
		return "-"
	}
}

// New builds the forwarder the configuration asks for.
func New(cfg config.Syslog, log *slog.Logger) Forwarder {
	if !cfg.Enabled || cfg.Address == "" {
		return Nop{}
	}
	log.Info("forwarding the audit trail to syslog",
		"address", cfg.Address, "protocol", cfg.Protocol)
	return NewSyslog(cfg, log)
}
