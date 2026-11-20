// Command peek-cli pushes and reads secrets from a terminal.
//
// It performs the same encryption as the browser — same format, same test
// vectors — so a secret created here opens in a browser and the other way
// round. The server it talks to never receives a key or a passphrase.
//
//	peek-cli push --server https://secrets.example.com --views 1 --ttl 24h
//	echo -n "s3cret" | peek-cli push --server https://secrets.example.com
//	peek-cli get "https://secrets.example.com/s/<id>#v1.<key>"
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

var version = "dev"

// main holds no deferred work: run owns the signal context and returns the
// exit code, so os.Exit cannot skip a cleanup.
func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		return 2
	}

	var err error
	switch os.Args[1] {
	case "push":
		err = push(ctx, os.Args[2:])
	case "get":
		err = get(ctx, os.Args[2:])
	case "version":
		fmt.Printf("peek-cli %s (format %s)\n", version, pcrypto.Version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "peek-cli: unknown command %q\n\n", os.Args[1])
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "peek-cli:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Println(`peek-cli — share secrets from the command line.

Usage:
  peek-cli push [options] [TEXT]     encrypt and upload (reads stdin if TEXT is omitted)
  peek-cli get URL [options]         fetch and decrypt a secret link
  peek-cli version

Push options:
  --server URL        Peek instance (or set PEEK_SERVER)
  --views N           number of reads (default 1)
  --ttl DURATION      expiry, e.g. 30m, 24h, 7d (default 24h)
  --passphrase P      extra passphrase (prompted with --ask-passphrase)
  --ask-passphrase    prompt for the passphrase instead of passing it on the command line
  --no-retrieval      disable the click-to-reveal step
  --deletable         let the recipient delete the secret

Get options:
  --passphrase P      passphrase (prompted when the secret needs one)
  --quiet             print the secret and nothing else`)
}

func push(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	server := fs.String("server", os.Getenv("PEEK_SERVER"), "Peek instance URL")
	views := fs.Int("views", 1, "number of reads")
	ttl := fs.Duration("ttl", 24*time.Hour, "expiry")
	passphrase := fs.String("passphrase", "", "passphrase")
	askPass := fs.Bool("ask-passphrase", false, "prompt for the passphrase")
	noRetrieval := fs.Bool("no-retrieval", false, "disable the click-to-reveal step")
	deletable := fs.Bool("deletable", false, "let the recipient delete the secret")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if *server == "" {
		return errors.New("no server: pass --server or set PEEK_SERVER")
	}
	base := strings.TrimRight(*server, "/")

	plaintext := strings.Join(positional, " ")
	if plaintext == "" {
		buf, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		plaintext = strings.TrimRight(string(buf), "\r\n")
	}
	if plaintext == "" {
		return errors.New("nothing to send")
	}

	pass := *passphrase
	if *askPass {
		if pass, err = promptSecret("Passphrase: "); err != nil {
			return err
		}
	}

	// Everything below mirrors what the browser does, step for step.
	id, err := pcrypto.NewID()
	if err != nil {
		return err
	}
	contentKey, err := pcrypto.NewContentKey()
	if err != nil {
		return err
	}
	kdf, err := pcrypto.DefaultKDFParams()
	if err != nil {
		return err
	}
	keys, err := pcrypto.DeriveKeys(contentKey, pass, kdf)
	if err != nil {
		return err
	}
	payload, err := pcrypto.Payload{Kind: pcrypto.KindText, Text: plaintext}.Marshal()
	if err != nil {
		return err
	}
	sealed, err := pcrypto.Seal(keys.Enc, pcrypto.AAD(id), payload)
	if err != nil {
		return err
	}
	receiptToken, err := pcrypto.NewContentKey()
	if err != nil {
		return err
	}

	body := map[string]any{
		"id":                 id,
		"kind":               pcrypto.KindText,
		"ciphertext":         pcrypto.B64.EncodeToString(sealed),
		"read_token_hash":    pcrypto.B64.EncodeToString(keys.ReadTokenHash),
		"receipt_token_hash": pcrypto.B64.EncodeToString(pcrypto.HashReadToken(receiptToken)),
		"kdf": map[string]any{
			"salt":        pcrypto.B64.EncodeToString(kdf.Salt),
			"memory_kib":  kdf.MemoryKiB,
			"iterations":  kdf.Iterations,
			"parallelism": kdf.Parallelism,
		},
		"has_passphrase":         pass != "",
		"ttl_seconds":            int(ttl.Seconds()),
		"views":                  *views,
		"retrieval_step":         !*noRetrieval,
		"deletable_by_recipient": *deletable,
	}

	var created struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
		ViewsMax  int       `json:"views_max"`
	}
	if err := call(ctx, http.MethodPost, base+"/api/v1/secrets", body, "", &created); err != nil {
		return err
	}

	fmt.Printf("%s/s/%s#%s\n", base, created.ID, pcrypto.EncodeFragment(contentKey))
	fmt.Fprintf(os.Stderr, "receipt: %s/r/%s#%s~%s\n", base, created.ID,
		pcrypto.B64.EncodeToString(contentKey), pcrypto.B64.EncodeToString(receiptToken))
	fmt.Fprintf(os.Stderr, "expires %s, %d read(s)\n", created.ExpiresAt.Local().Format(time.RFC1123), created.ViewsMax)
	return nil
}

func get(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "passphrase")
	quiet := fs.Bool("quiet", false, "print the secret only")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: peek-cli get URL [--passphrase P]")
	}

	link, err := url.Parse(positional[0])
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if link.Fragment == "" {
		return errors.New("this link carries no key: copy it in full, including everything after the #")
	}
	contentKey, err := pcrypto.DecodeFragment(link.Fragment)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.Trim(link.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "s" {
		return errors.New("this is not a secret link (expected /s/<id>#<key>)")
	}
	id := parts[1]
	base := link.Scheme + "://" + link.Host

	var meta struct {
		HasPassphrase bool `json:"has_passphrase"`
		AttemptsLeft  int  `json:"attempts_left"`
		KDF           struct {
			Salt        string `json:"salt"`
			MemoryKiB   uint32 `json:"memory_kib"`
			Iterations  uint32 `json:"iterations"`
			Parallelism uint8  `json:"parallelism"`
		} `json:"kdf"`
	}
	if err := call(ctx, http.MethodGet, base+"/api/v1/secrets/"+id, nil, "", &meta); err != nil {
		return err
	}

	pass := *passphrase
	if meta.HasPassphrase && pass == "" {
		if pass, err = promptSecret("Passphrase: "); err != nil {
			return err
		}
	}

	salt, err := pcrypto.B64.DecodeString(meta.KDF.Salt)
	if err != nil {
		return fmt.Errorf("malformed server metadata: %w", err)
	}
	keys, err := pcrypto.DeriveKeys(contentKey, pass, pcrypto.KDFParams{
		Salt:        salt,
		MemoryKiB:   meta.KDF.MemoryKiB,
		Iterations:  meta.KDF.Iterations,
		Parallelism: meta.KDF.Parallelism,
	})
	if err != nil {
		return err
	}

	var revealed struct {
		Ciphertext     string `json:"ciphertext"`
		ViewsRemaining int    `json:"views_remaining"`
		Destroyed      bool   `json:"destroyed"`
	}
	err = call(ctx, http.MethodPost, base+"/api/v1/secrets/"+id+"/reveal",
		map[string]string{"read_token": pcrypto.B64.EncodeToString(keys.ReadToken)}, "", &revealed)
	if err != nil {
		return err
	}

	sealed, err := pcrypto.B64.DecodeString(revealed.Ciphertext)
	if err != nil {
		return err
	}
	plain, err := pcrypto.Open(keys.Enc, pcrypto.AAD(id), sealed)
	if err != nil {
		return err
	}
	payload, err := pcrypto.UnmarshalPayload(plain)
	if err != nil {
		return err
	}

	text := payload.Text
	if payload.Kind == pcrypto.KindURL {
		text = payload.URL
	}
	fmt.Println(text)
	if !*quiet {
		if payload.Message != "" {
			fmt.Fprintf(os.Stderr, "message: %s\n", payload.Message)
		}
		if revealed.Destroyed {
			fmt.Fprintln(os.Stderr, "this was the last read: the secret has been destroyed")
		} else {
			fmt.Fprintf(os.Stderr, "%d read(s) left\n", revealed.ViewsRemaining)
		}
	}
	return nil
}

// parseInterleaved parses flags that appear before or after the positional
// arguments. The standard flag package stops at the first non-flag word, which
// would silently ignore "peek-cli get URL --passphrase x".
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

// call performs one JSON request and maps API errors to readable messages.
func call(ctx context.Context, method, target string, body any, token string, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	// The target is built from the server the operator passed on the command
	// line, which is the whole point of this tool.
	req, err := http.NewRequestWithContext(ctx, method, target, reader) //nolint:gosec // operator-supplied endpoint
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Peek-Token", token)
	}
	req.Header.Set("User-Agent", "peek-cli/"+version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // G704: the endpoint is the server the operator passed on the command line
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error struct {
				Code         string `json:"code"`
				Message      string `json:"message"`
				AttemptsLeft *int   `json:"attempts_left"`
			} `json:"error"`
		}
		if json.Unmarshal(payload, &apiErr) == nil && apiErr.Error.Message != "" {
			if apiErr.Error.AttemptsLeft != nil {
				return fmt.Errorf("%s (%d attempt(s) left)", apiErr.Error.Message, *apiErr.Error.AttemptsLeft)
			}
			return errors.New(apiErr.Error.Message)
		}
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, target)
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	return json.Unmarshal(payload, out)
}

// promptSecret reads a passphrase without echoing it.
func promptSecret(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	// os.Stdin.Fd is portable; syscall.Stdin is an int on unix and a Handle on
	// Windows, which makes a direct conversion either redundant or wrong.
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal available to read the passphrase; use --passphrase")
	}
	buf, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}
