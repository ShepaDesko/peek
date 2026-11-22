package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

// requester is what the browser of someone asking for a secret holds: an ECDH
// key pair whose private half never leaves their own link, and a symmetric
// request key that the deposit link carries so a depositor can read the prompt
// and prove possession.
type requester struct {
	id      string
	key     pcrypto.RequestKey
	request []byte // the symmetric request key, from the deposit link
	kdf     pcrypto.KDFParams
	keys    pcrypto.Keys
	receipt []byte
	prompt  string
}

func newRequester(t *testing.T, prompt string) *requester {
	t.Helper()
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pcrypto.NewRequestKey()
	if err != nil {
		t.Fatal(err)
	}
	reqKey, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	kdf, err := pcrypto.DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	kdf.MemoryKiB, kdf.Iterations = 8192, 1
	keys, err := pcrypto.DeriveKeys(reqKey, "", kdf)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	return &requester{id: id, key: pair, request: reqKey, kdf: kdf, keys: keys, receipt: receipt, prompt: prompt}
}

func (q *requester) createBody(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	sealed, err := pcrypto.Seal(q.keys.Enc, pcrypto.AAD(q.id), []byte(q.prompt))
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"id":                 q.id,
		"public_key":         pcrypto.B64.EncodeToString(q.key.Pub),
		"read_token_hash":    pcrypto.B64.EncodeToString(q.keys.ReadTokenHash),
		"receipt_token_hash": pcrypto.B64.EncodeToString(pcrypto.HashReadToken(q.receipt)),
		"prompt_enc":         pcrypto.B64.EncodeToString(sealed),
		"kdf": map[string]any{
			"salt":        pcrypto.B64.EncodeToString(q.kdf.Salt),
			"memory_kib":  q.kdf.MemoryKiB,
			"iterations":  q.kdf.Iterations,
			"parallelism": q.kdf.Parallelism,
		},
		"ttl_seconds":  3600,
		"max_deposits": 1,
	}
	if mutate != nil {
		mutate(body)
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// depositBody builds what a depositor sends: an ordinary secret, plus its
// content key wrapped to the requester's public key.
func depositBody(t *testing.T, q *requester, dep *client, readToken []byte, pub []byte) []byte {
	t.Helper()
	var secret map[string]any
	if err := json.Unmarshal(dep.createBody(t, nil), &secret); err != nil {
		t.Fatal(err)
	}
	box, err := pcrypto.SealToRequest(pub, q.id, dep.contentKey)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := json.Marshal(map[string]any{
		"read_token":  pcrypto.B64.EncodeToString(readToken),
		"wrapped_key": pcrypto.B64.EncodeToString(box),
		"secret":      secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func (h *harness) createRequest(t *testing.T, q *requester, mutate func(map[string]any)) map[string]any {
	t.Helper()
	rec := do(t, h.internal, http.MethodPost, "/api/v1/requests", q.createBody(t, mutate), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create request returned %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody(t, rec)
}

// TestSecretRequestJourney is the whole inverted flow: ask, deposit, read.
// At no point does the server hold anything it could decrypt.
func TestSecretRequestJourney(t *testing.T) {
	h := newHarness(t, nil)
	q := newRequester(t, "Mot de passe du compte SAP, merci")
	created := h.createRequest(t, q, nil)
	if created["url"] == "" {
		t.Error("the created request has no deposit URL")
	}

	// A depositor follows the link: metadata, then the prompt, proving they
	// hold the request key from the fragment.
	rec := do(t, h.public, http.MethodGet, "/api/v1/requests/"+q.id, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("request metadata returned %d: %s", rec.Code, rec.Body.String())
	}

	openBody, _ := json.Marshal(map[string]string{
		"read_token": pcrypto.B64.EncodeToString(q.keys.ReadToken),
	})
	rec = do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/open", openBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("open returned %d: %s", rec.Code, rec.Body.String())
	}
	promptEnc, err := pcrypto.B64.DecodeString(decodeBody(t, rec)["prompt_enc"].(string))
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := pcrypto.Open(q.keys.Enc, pcrypto.AAD(q.id), promptEnc)
	if err != nil {
		t.Fatalf("the prompt does not decrypt: %v", err)
	}
	if string(prompt) != q.prompt {
		t.Errorf("prompt = %q", prompt)
	}

	// The deposit. The depositor seals a normal secret and wraps its content
	// key to the public key that came out of the link, not out of the server.
	dep := newClient(t, "", "hunter2-for-SAP")
	rec = do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, dep, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deposit returned %d: %s", rec.Code, rec.Body.String())
	}

	// The requester opens their own receipt link and unwraps the answer.
	receiptBody, _ := json.Marshal(map[string]string{
		"receipt_token": pcrypto.B64.EncodeToString(q.receipt),
	})
	rec = do(t, h.internal, http.MethodPost, "/api/v1/requests/"+q.id+"/receipt", receiptBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("request receipt returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	deposits, ok := body["deposits"].([]any)
	if !ok || len(deposits) != 1 {
		t.Fatalf("expected one deposit, got %v", body["deposits"])
	}
	d := deposits[0].(map[string]any)
	wrapped, err := pcrypto.B64.DecodeString(d["wrapped_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	contentKey, err := q.key.Open(q.id, wrapped)
	if err != nil {
		t.Fatalf("the requester cannot unwrap the content key: %v", err)
	}
	if !bytes.Equal(contentKey, dep.contentKey) {
		t.Fatal("the unwrapped key is not the depositor's content key")
	}

	// With the content key, the deposit is an ordinary secret.
	kdfBlock := d["kdf"].(map[string]any)
	salt, err := pcrypto.B64.DecodeString(kdfBlock["salt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pcrypto.DeriveKeys(contentKey, "", pcrypto.KDFParams{
		Salt:        salt,
		MemoryKiB:   uint32(kdfBlock["memory_kib"].(float64)),
		Iterations:  uint32(kdfBlock["iterations"].(float64)),
		Parallelism: uint8(kdfBlock["parallelism"].(float64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = h.reveal(t, h.internal, dep, keys.ReadToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("revealing the deposit returned %d: %s", rec.Code, rec.Body.String())
	}
	sealed, err := pcrypto.B64.DecodeString(decodeBody(t, rec)["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := pcrypto.Open(keys.Enc, pcrypto.AAD(dep.id), sealed)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := pcrypto.UnmarshalPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Text != "hunter2-for-SAP" {
		t.Errorf("the requester read %q", payload.Text)
	}
}

func TestSecretRequestIsSingleUseByDefault(t *testing.T) {
	h := newHarness(t, nil)
	q := newRequester(t, "once only")
	h.createRequest(t, q, nil)

	first := newClient(t, "", "answer one")
	rec := do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, first, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first deposit returned %d: %s", rec.Code, rec.Body.String())
	}

	second := newClient(t, "", "answer two")
	rec = do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, second, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusGone {
		t.Fatalf("second deposit returned %d, want 410: %s", rec.Code, rec.Body.String())
	}

	// And the page itself stops offering: a filled request is as good as gone.
	if rec := do(t, h.public, http.MethodGet, "/api/v1/requests/"+q.id, nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("metadata of a filled request returned %d", rec.Code)
	}
}

func TestSecretRequestAcceptsSeveralWhenAllowed(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.MaxDeposits = 3 })
	q := newRequester(t, "several answers welcome")
	h.createRequest(t, q, func(b map[string]any) { b["max_deposits"] = 3 })

	for i := 0; i < 3; i++ {
		dep := newClient(t, "", "answer")
		rec := do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
			depositBody(t, q, dep, q.keys.ReadToken, q.key.Pub), nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("deposit %d returned %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	dep := newClient(t, "", "one too many")
	rec := do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, dep, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusGone {
		t.Errorf("the fourth deposit returned %d, want 410", rec.Code)
	}
}

func TestSecretRequestRefusesOverThePolicyLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.MaxDeposits = 2 })
	q := newRequester(t, "too many")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/requests",
		q.createBody(t, func(b map[string]any) { b["max_deposits"] = 50 }), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("asking for 50 deposits with a limit of 2 returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSecretRequestRejectsBadKeyAndToken(t *testing.T) {
	h := newHarness(t, nil)

	// A public key that is not a point on P-256 would be an attack on the
	// depositor's own key exchange, so it never gets stored.
	bad := newRequester(t, "bent key")
	broken := append([]byte{}, bad.key.Pub...)
	broken[len(broken)-1] ^= 0x01
	rec := do(t, h.internal, http.MethodPost, "/api/v1/requests",
		bad.createBody(t, func(b map[string]any) {
			b["public_key"] = pcrypto.B64.EncodeToString(broken)
		}), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an off-curve public key returned %d: %s", rec.Code, rec.Body.String())
	}

	q := newRequester(t, "normal")
	h.createRequest(t, q, nil)

	wrongToken := bytes.Repeat([]byte{4}, 32)
	openBody, _ := json.Marshal(map[string]string{
		"read_token": pcrypto.B64.EncodeToString(wrongToken),
	})
	if rec := do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/open", openBody, nil); rec.Code != http.StatusForbidden {
		t.Errorf("open with a wrong token returned %d", rec.Code)
	}

	dep := newClient(t, "", "nope")
	rec = do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, dep, wrongToken, q.key.Pub), nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("deposit with a wrong token returned %d", rec.Code)
	}
	// A refused deposit must not have counted against the request.
	if rec := do(t, h.public, http.MethodGet, "/api/v1/requests/"+q.id, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("the request was closed by a failed deposit (%d)", rec.Code)
	}
}

func TestCreatingARequestIsInternalOnly(t *testing.T) {
	h := newHarness(t, nil)
	q := newRequester(t, "x")
	rec := do(t, h.public, http.MethodPost, "/api/v1/requests", q.createBody(t, nil), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("creating a request on the public listener returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestClosingARequestLeavesTheDepositAlone(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.MaxDeposits = 2 })
	q := newRequester(t, "close me")
	h.createRequest(t, q, func(b map[string]any) { b["max_deposits"] = 2 })

	dep := newClient(t, "", "already answered")
	rec := do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, dep, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deposit returned %d: %s", rec.Code, rec.Body.String())
	}

	closeBody, _ := json.Marshal(map[string]string{
		"receipt_token": pcrypto.B64.EncodeToString(q.receipt),
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/requests/"+q.id, bytes.NewReader(closeBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:54321"
	w := httptest.NewRecorder()
	h.internal.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("closing the request returned %d: %s", w.Code, w.Body.String())
	}

	// The deposit is a secret of its own: closing the door does not burn it.
	if rec := do(t, h.internal, http.MethodGet, "/api/v1/secrets/"+dep.id, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("the deposited secret disappeared with the request (%d)", rec.Code)
	}
	// But no new deposit can arrive.
	other := newClient(t, "", "late")
	rec = do(t, h.public, http.MethodPost, "/api/v1/requests/"+q.id+"/deposit",
		depositBody(t, q, other, q.keys.ReadToken, q.key.Pub), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("a deposit on a closed request returned %d", rec.Code)
	}
}
