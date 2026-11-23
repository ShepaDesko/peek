package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
)

// TestLoadErrorNeverEchoesTheFile is a regression test for a real leak.
//
// go-toml renders a friendly excerpt of the surrounding document for a decode
// failure, and that is the obvious thing to put in the error. On a file whose
// typo sits next to mail.password — or an S3 key, a backup passphrase, a
// client secret, a webhook secret — the excerpt carries the credential into
// the message, which goes to the terminal and, when the service is in a
// restart loop at boot, to journald.
//
// It was found on a real host: a configuration the running binary did not
// understand printed the webhook secret into the journal, four times a second.
func TestLoadErrorNeverEchoesTheFile(t *testing.T) {
	const secret = "s3cr3t-value-that-must-not-appear"
	file := filepath.Join(t.TempDir(), "peek.toml")
	// The unknown setting sits directly between two credentials, which is
	// where a copy-pasted example usually puts it.
	body := `
public_url = "https://secrets.example.com"

[mail]
host = "smtp.example.com"
from_address = "peek@example.com"
password = "` + secret + `"
this_setting_does_not_exist = true

[backup]
passphrase = "` + secret + `"
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(file, false)
	if err == nil {
		t.Fatal("an unknown setting was accepted; a typo must not silently disable a protection")
	}
	message := err.Error()
	if strings.Contains(message, secret) {
		t.Fatalf("the error message carries a credential:\n%s", message)
	}
	// It still has to be useful: the name of the setting and its line.
	if !strings.Contains(message, "this_setting_does_not_exist") {
		t.Errorf("the error does not name the unknown setting:\n%s", message)
	}
	if !strings.Contains(message, "line 8") {
		t.Errorf("the error does not say where it is:\n%s", message)
	}
}

// TestLoadSyntaxErrorNeverEchoesTheFile covers the other decoder path: a file
// that is not valid TOML at all, rather than one with an unknown key.
func TestLoadSyntaxErrorNeverEchoesTheFile(t *testing.T) {
	const secret = "another-secret-value-9f2a"
	file := filepath.Join(t.TempDir(), "peek.toml")
	body := `
[mail]
password = "` + secret + `"
host = not a string at all
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(file, false)
	if err == nil {
		t.Fatal("invalid TOML was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error message carries a credential:\n%s", err.Error())
	}
}

// TestRedactedHidesEverySecret: peek config show prints this, and an operator
// pastes it into a ticket.
func TestRedactedHidesEverySecret(t *testing.T) {
	cfg := config.Default()
	const secret = "a-value-nobody-should-see"
	cfg.Mail.Password = secret
	cfg.Storage.S3SecretKey = secret
	cfg.Backup.Passphrase = secret
	cfg.SSO.ClientSecret = secret
	cfg.Webhooks = []config.Webhook{
		{Name: "siem", URL: "https://hooks.example.com/x", Secret: secret},
		{Name: "chat", URL: "https://chat.example.com/x", Secret: secret},
	}

	redacted := cfg.Redacted()
	buf, err := redacted.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(buf), secret) {
		t.Errorf("a secret survived redaction:\n%s", buf)
	}
	// And redaction must not have mutated the original: the caller still has
	// a working configuration afterwards.
	if cfg.Webhooks[0].Secret != secret || cfg.Mail.Password != secret {
		t.Error("Redacted modified the configuration it was called on")
	}
}

func TestValidateRefusesDangerousCombinations(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(*config.Config)
		want  string
	}{
		{
			name:  "an unsigned webhook",
			tweak: func(c *config.Config) { c.Webhooks = []config.Webhook{{Name: "x", URL: "https://a.test/h"}} },
			want:  "secret",
		},
		{
			name: "two webhooks with the same name",
			tweak: func(c *config.Config) {
				c.Webhooks = []config.Webhook{
					{Name: "x", URL: "https://a.test/h", Secret: "0123456789abcdef"},
					{Name: "x", URL: "https://b.test/h", Secret: "0123456789abcdef"},
				}
			},
			want: "declared twice",
		},
		{
			name: "a plain-HTTP issuer",
			tweak: func(c *config.Config) {
				c.SSO = config.SSO{Enabled: true, Issuer: "http://idp.test", ClientID: "a", ClientSecret: "b", Discovery: true}
			},
			want: "https",
		},
		{
			name: "require_group with nothing mapped",
			tweak: func(c *config.Config) {
				c.SSO = config.SSO{
					Enabled: true, Issuer: "https://idp.test", ClientID: "a", ClientSecret: "b",
					Discovery: true, RequireGroup: true,
				}
			},
			want: "nobody could sign in",
		},
		{
			name: "discovery off with no endpoints",
			tweak: func(c *config.Config) {
				c.SSO = config.SSO{Enabled: true, Issuer: "https://idp.test", ClientID: "a", ClientSecret: "b"}
			},
			want: "sso.discovery is false",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			tc.tweak(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the message does not mention %q:\n%s", tc.want, err.Error())
			}
		})
	}
}

func TestLocalSignInAllowed(t *testing.T) {
	sso := config.SSO{Enabled: true, Required: true, PasswordExempt: []string{"Ops@ACME.test"}}
	if !sso.LocalSignInAllowed("ops@acme.test") {
		t.Error("the exempt account is refused; the comparison must ignore case")
	}
	if sso.LocalSignInAllowed("someone@acme.test") {
		t.Error("a non-exempt account may sign in locally while sso.required is set")
	}
	// With required off, everyone may — including when the list is empty.
	sso.Required = false
	if !sso.LocalSignInAllowed("someone@acme.test") {
		t.Error("local sign-in is refused with sso.required off")
	}
}

// TestACMEHostProblem is the rule itself, in the one place that holds it.
// peek config check, peek doctor and the server all read this function, which
// is the point: doctor's own copy used to be missing the address case, so it
// reported OK for a host the server then refused to start with.
func TestACMEHostProblem(t *testing.T) {
	for host, shouldRefuse := range map[string]bool{
		"secrets.acme.com":     false,
		"peek.sub.acme.co.uk":  false,
		"xn--bcher-kva.com":    false, // a punycode name is a public name
		"":                     true,
		"192.0.2.10":           true,
		"2001:db8::1":          true,
		"localhost":            true,
		"peek.localhost":       true,
		"peek.local":           true,
		"peek.internal":        true,
		"secrets.acme.test":    true,
		"secrets":              true,
		"https://acme.com":     true,
		"secrets.acme.com:443": true,
		"secrets acme.com":     true,
	} {
		problem := config.ACMEHostProblem(host)
		if shouldRefuse && problem == "" {
			t.Errorf("%q was accepted; no public authority would sign it", host)
		}
		if !shouldRefuse && problem != "" {
			t.Errorf("%q was refused: %s", host, problem)
		}
	}
}

func TestWebhookBackoffIsBounded(t *testing.T) {
	// Attempt 0 and a huge attempt must both return something sane rather
	// than panic on a slice index.
	for _, attempt := range []int{-1, 0, 1, 5, 6, 1000} {
		if d := config.WebhookBackoff(attempt); d <= 0 {
			t.Errorf("backoff for attempt %d is %s", attempt, d)
		}
	}
	if config.WebhookBackoff(1) >= config.WebhookBackoff(2) {
		t.Error("the backoff does not grow")
	}
}

// TestRedactDSNHidesThePassword: peek config check, peek config show and
// peek restore all print the DSN, and those are the three outputs somebody
// pastes into a ticket when they are asking for help.
func TestRedactDSNHidesThePassword(t *testing.T) {
	const password = "a-database-password"
	for dsn, want := range map[string]string{
		"postgres://peek:" + password + "@db:5432/peek":              "postgres://peek:***@db:5432/peek",
		"postgresql://peek:" + password + "@db/peek?sslmode=require": "postgresql://peek:***@db/peek?sslmode=require",
		// No password: nothing to hide, and the DSN stays readable.
		"postgres://peek@db:5432/peek": "postgres://peek@db:5432/peek",
		// The key/value form.
		"host=db user=peek password=" + password + " dbname=peek": "host=db user=peek password=*** dbname=peek",
		"host=db user=peek dbname=peek":                           "host=db user=peek dbname=peek",
		// A SQLite path is not a DSN with a password.
		"/var/lib/peek/peek.db": "/var/lib/peek/peek.db",
		"":                      "",
	} {
		got := config.RedactDSN(dsn)
		if got != want {
			t.Errorf("RedactDSN(%q)\n got: %q\nwant: %q", dsn, got, want)
		}
		if strings.Contains(got, password) {
			t.Errorf("RedactDSN(%q) still carries the password", dsn)
		}
	}
}
