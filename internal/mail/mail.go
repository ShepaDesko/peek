// Package mail sends the few messages Peek produces: an invitation, a
// password reset, a secret link, a notification.
//
// It never sends a passphrase, and never a decryption key: those travel with
// the person, not with the mail. A message carries a link and nothing that
// would open it on its own.
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// ErrNotConfigured is returned when no SMTP server is configured.
var ErrNotConfigured = errors.New("mail: no SMTP server configured")

// Message is what Sender takes.
type Message struct {
	To      []string
	Subject string
	// Text is required: a mail client that refuses HTML must still be usable.
	Text string
	// HTML is optional.
	HTML string
	// ReplyTo is optional.
	ReplyTo string
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, msg Message) error
	Configured() bool
}

// SMTPSender talks to an SMTP server.
type SMTPSender struct {
	cfg config.Mail
	log *slog.Logger
	// dialTimeout is short: a login must not hang because a relay is down.
	dialTimeout time.Duration
}

// New builds a Sender from the configuration.
func New(cfg config.Mail, log *slog.Logger) *SMTPSender {
	return &SMTPSender{cfg: cfg, log: log, dialTimeout: 10 * time.Second}
}

// Configured reports whether anything can be sent at all.
func (s *SMTPSender) Configured() bool { return s != nil && s.cfg.Host != "" }

// Send delivers one message.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	if len(msg.To) == 0 {
		return errors.New("mail: no recipient")
	}
	if err := s.checkRecipients(msg.To); err != nil {
		return err
	}

	body := s.render(msg)

	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprint(s.cfg.Port))
	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: connect to %s: %w", addr, err)
	}

	if s.cfg.Encryption == "tls" {
		conn = tls.Client(conn, s.tlsConfig())
	}
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: SMTP handshake with %s: %w", addr, err)
	}
	defer func() { _ = client.Quit() }()

	if s.cfg.Encryption == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("mail: %s does not offer STARTTLS, and mail.encryption is starttls", addr)
		}
		if err := client.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("mail: STARTTLS: %w", err)
		}
	}

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: authentication refused: %w", err)
		}
	}

	if err := client.Mail(s.cfg.FromAddress); err != nil {
		return fmt.Errorf("mail: sender refused: %w", err)
	}
	for _, to := range msg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("mail: recipient %s refused: %w", to, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         s.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.cfg.SkipVerify, //nolint:gosec // opt-in, for an internal relay with a private CA
	}
}

// checkRecipients applies mail.allowed_recipient_domains.
func (s *SMTPSender) checkRecipients(to []string) error {
	if len(s.cfg.AllowedDomains) == 0 {
		return nil
	}
	for _, address := range to {
		at := strings.LastIndex(address, "@")
		if at < 0 {
			return fmt.Errorf("mail: %q is not an address", address)
		}
		domain := strings.ToLower(address[at+1:])
		allowed := false
		for _, candidate := range s.cfg.AllowedDomains {
			if strings.EqualFold(strings.TrimSpace(candidate), domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("mail: %s is not an allowed recipient domain on this instance", domain)
		}
	}
	return nil
}

// render builds the RFC 5322 message, multipart when HTML is present.
func (s *SMTPSender) render(msg Message) []byte {
	var b bytes.Buffer
	from := s.cfg.FromAddress
	if s.cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("utf-8", s.cfg.FromName), s.cfg.FromAddress)
	}

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(msg.To, ", "))
	if msg.ReplyTo != "" {
		fmt.Fprintf(&b, "Reply-To: %s\r\n", msg.ReplyTo)
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%d.peek@%s>\r\n", time.Now().UnixNano(), s.cfg.Host)
	b.WriteString("MIME-Version: 1.0\r\n")
	// These messages are transactional and must not be filed as bulk, nor
	// auto-replied to by an out-of-office.
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("X-Auto-Response-Suppress: All\r\n")

	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(normalizeNewlines(msg.Text))
		return b.Bytes()
	}

	boundary := fmt.Sprintf("peek-%d", time.Now().UnixNano())
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(normalizeNewlines(msg.Text))
	fmt.Fprintf(&b, "\r\n--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(normalizeNewlines(msg.HTML))
	fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
	return b.Bytes()
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// Discard is a Sender that drops everything, for instances without SMTP.
type Discard struct{ Log *slog.Logger }

// Send records that a message could not be sent and returns ErrNotConfigured.
func (d Discard) Send(_ context.Context, msg Message) error {
	if d.Log != nil {
		d.Log.Warn("e-mail not sent: no SMTP server is configured",
			"subject", msg.Subject, "recipients", len(msg.To))
	}
	return ErrNotConfigured
}

// Configured always reports false.
func (d Discard) Configured() bool { return false }
