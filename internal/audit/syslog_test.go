package audit_test

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/audit"
	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// TestSyslogDeliversRFC5424 starts a TCP listener and checks what actually
// arrives on the wire, which is the only way to know a SIEM will parse it.
func TestSyslogDeliversRFC5424(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	received := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		for {
			// Octet counting: "<length> <message>".
			lengthField, err := reader.ReadString(' ')
			if err != nil {
				return
			}
			var length int
			for _, c := range strings.TrimSpace(lengthField) {
				if c < '0' || c > '9' {
					return
				}
				length = length*10 + int(c-'0')
			}
			buf := make([]byte, length)
			if _, err := io.ReadFull(reader, buf); err != nil {
				return
			}
			received <- string(buf)
		}
	}()

	forwarder := audit.NewSyslog(config.Syslog{
		Enabled:  true,
		Address:  ln.Addr().String(),
		Protocol: "tcp",
		Facility: 13,
		AppName:  "peek",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = forwarder.Close() }()

	forwarder.Forward(store.AuditEvent{
		OrgID:     "default",
		SecretID:  "AbCdEfGhIjKlMnOpQrStUv",
		UserID:    "user-1",
		Event:     store.EventRevealed,
		At:        time.Date(2026, 11, 20, 15, 4, 5, 0, time.UTC),
		IP:        "203.0.113.5",
		UserAgent: "Mozilla/5.0",
		Detail:    map[string]string{"destroyed": "true"},
	})

	select {
	case msg := <-received:
		// Priority: facility 13 * 8 + notice (5) = 109.
		if !strings.HasPrefix(msg, "<109>1 2026-11-20T15:04:05.000Z ") {
			t.Fatalf("unexpected header: %q", msg)
		}
		for _, want := range []string{
			"peek", "secret.revealed",
			`event="secret.revealed"`,
			`secret="AbCdEfGhIjKlMnOpQrStUv"`,
			`user="user-1"`,
			`ip="203.0.113.5"`,
			`d_destroyed="true"`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("message is missing %q:\n%s", want, msg)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived on the syslog listener")
	}
}

// TestSyslogEscapesStructuredData makes sure a crafted value cannot break out
// of the structured-data block or inject a line into a SIEM.
func TestSyslogEscapesStructuredData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err == nil {
			received <- string(buf[:n])
		}
	}()

	forwarder := audit.NewSyslog(config.Syslog{
		Enabled: true, Address: ln.Addr().String(), Protocol: "tcp", Facility: 13,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = forwarder.Close() }()

	forwarder.Forward(store.AuditEvent{
		OrgID: "default",
		Event: store.EventLoginFailed,
		At:    time.Now(),
		Detail: map[string]string{
			"email": "attacker\"]\n<13>1 injected message here [x@1 a=\"b",
		},
	})

	select {
	case msg := <-received:
		if strings.Count(msg, "\n") > 0 {
			t.Fatalf("a newline survived into the message:\n%q", msg)
		}
		if strings.Contains(msg, `"]`+"\n") || strings.Contains(msg, "injected message here [x@1") &&
			!strings.Contains(msg, `\]`) {
			t.Fatalf("structured data was not escaped:\n%s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived")
	}
}

// TestSyslogNeverBlocks checks the queue drops rather than waits when nobody
// is listening: an unreachable SIEM must not slow a request down.
func TestSyslogNeverBlocks(t *testing.T) {
	forwarder := audit.NewSyslog(config.Syslog{
		Enabled: true,
		// A port nothing listens on, so every write fails.
		Address:  "127.0.0.1:9",
		Protocol: "tcp",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = forwarder.Close() }()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			forwarder.Forward(store.AuditEvent{Event: store.EventPageViewed, At: time.Now()})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("forwarding blocked when the SIEM was unreachable")
	}
}

func TestNopForwarder(t *testing.T) {
	var f audit.Forwarder = audit.Nop{}
	f.Forward(store.AuditEvent{Event: "anything"})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := audit.New(config.Syslog{Enabled: false}, slog.Default()).(audit.Nop); !ok {
		t.Fatal("a disabled configuration did not produce the no-op forwarder")
	}
}
