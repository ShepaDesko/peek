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

// upload sends an encrypted blob the way the browser does and returns the id
// and the claim token.
func (h *harness) upload(t *testing.T, stream []byte) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", bytes.NewReader(stream))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(stream))
	req.RemoteAddr = "192.0.2.10:54321"
	rec := httptest.NewRecorder()
	h.internal.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	return body["id"].(string), body["token"].(string)
}

// sealedFile returns a plaintext and the encrypted stream for it.
func sealedFile(t *testing.T, size int) (fileKey, plain, stream []byte) {
	t.Helper()
	fileKey, err := pcrypto.NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	plain = make([]byte, size)
	for i := range plain {
		plain[i] = byte(i * 7)
	}
	stream, err = pcrypto.SealFile(fileKey, pcrypto.MinChunkSize, plain)
	if err != nil {
		t.Fatal(err)
	}
	return fileKey, plain, stream
}

func (h *harness) download(t *testing.T, handler http.Handler, fileID, grant string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if grant != "" {
		headers["X-Peek-Download"] = grant
	}
	return do(t, handler, http.MethodGet, "/api/v1/files/"+fileID, nil, headers)
}

// TestFileJourney is the whole attachment path: encrypt, upload, attach,
// reveal, download with the grant, decrypt. The server never holds a key at
// any point of it.
func TestFileJourney(t *testing.T) {
	h := newHarness(t, nil)
	fileKey, plain, stream := sealedFile(t, 3*pcrypto.MinChunkSize+11)
	fileID, claim := h.upload(t, stream)

	c := newClient(t, "", "see attachment")
	h.create(t, c, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileID, "token": claim}}
	})

	rec := h.reveal(t, h.public, c, c.keys.ReadToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("reveal returned %d: %s", rec.Code, rec.Body.String())
	}
	revealed := decodeBody(t, rec)
	grant, _ := revealed["download_token"].(string)
	if grant == "" {
		t.Fatal("reveal did not hand out a download grant")
	}

	// The secret was a one-view secret, so its row is already gone. The grant
	// is what keeps the attachment reachable, which is the entire point.
	if revealed["destroyed"] != true {
		t.Error("a one-view secret should be destroyed after the reveal")
	}

	dl := h.download(t, h.public, fileID, grant)
	if dl.Code != http.StatusOK {
		t.Fatalf("download returned %d: %s", dl.Code, dl.Body.String())
	}
	if ct := dl.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q", ct)
	}
	got, err := pcrypto.OpenFile(fileKey, dl.Body.Bytes())
	if err != nil {
		t.Fatalf("the downloaded stream does not decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the decrypted file does not match what was uploaded")
	}
}

func TestFileDownloadNeedsAGrant(t *testing.T) {
	h := newHarness(t, nil)
	_, _, stream := sealedFile(t, 128)
	fileID, claim := h.upload(t, stream)

	c := newClient(t, "", "attachment")
	h.create(t, c, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileID, "token": claim}}
	})

	// No grant at all, and a well-formed but unknown one: both answer 404,
	// not 401 or 403. The difference would tell a prober that the blob exists.
	if rec := h.download(t, h.public, fileID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("download without a grant returned %d", rec.Code)
	}
	bogus := pcrypto.B64.EncodeToString(make([]byte, 32))
	if rec := h.download(t, h.public, fileID, bogus); rec.Code != http.StatusNotFound {
		t.Errorf("download with an unknown grant returned %d", rec.Code)
	}
}

func TestFileGrantIsScopedToItsBundle(t *testing.T) {
	h := newHarness(t, nil)
	_, _, streamA := sealedFile(t, 64)
	_, _, streamB := sealedFile(t, 64)
	fileA, claimA := h.upload(t, streamA)
	fileB, claimB := h.upload(t, streamB)

	a := newClient(t, "", "first")
	h.create(t, a, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileA, "token": claimA}}
	})
	b := newClient(t, "", "second")
	h.create(t, b, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileB, "token": claimB}}
	})

	grant := decodeBody(t, h.reveal(t, h.public, a, a.keys.ReadToken))["download_token"].(string)
	if rec := h.download(t, h.public, fileA, grant); rec.Code != http.StatusOK {
		t.Fatalf("own file returned %d", rec.Code)
	}
	// Revealing one secret must not open another sender's attachment.
	if rec := h.download(t, h.public, fileB, grant); rec.Code != http.StatusNotFound {
		t.Errorf("a grant for one bundle opened another bundle's file (%d)", rec.Code)
	}
}

func TestFileClaimNeedsTheUploadToken(t *testing.T) {
	h := newHarness(t, nil)
	_, _, stream := sealedFile(t, 64)
	fileID, claim := h.upload(t, stream)

	wrong := pcrypto.B64.EncodeToString(bytes.Repeat([]byte{9}, 32))
	c := newClient(t, "", "x")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets",
		c.createBody(t, func(body map[string]any) {
			body["kind"] = "file"
			body["files"] = []map[string]string{{"id": fileID, "token": wrong}}
		}), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("claiming with the wrong token returned %d: %s", rec.Code, rec.Body.String())
	}

	// And the blob is still claimable by whoever actually uploaded it.
	ok := newClient(t, "", "x")
	h.create(t, ok, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileID, "token": claim}}
	})

	// Claiming it a second time must fail: one blob, one bundle.
	again := newClient(t, "", "x")
	rec = do(t, h.internal, http.MethodPost, "/api/v1/secrets",
		again.createBody(t, func(body map[string]any) {
			body["kind"] = "file"
			body["files"] = []map[string]string{{"id": fileID, "token": claim}}
		}), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("claiming an attached blob twice returned %d", rec.Code)
	}
}

func TestUploadRefusesOversizedFiles(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.MaxFileBytes = 1024 })
	_, _, stream := sealedFile(t, 8*1024)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", bytes.NewReader(stream))
	req.ContentLength = int64(len(stream))
	req.RemoteAddr = "192.0.2.10:54321"
	rec := httptest.NewRecorder()
	h.internal.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload returned %d: %s", rec.Code, rec.Body.String())
	}
	// Nothing should have been written.
	keys, err := h.blobs.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("a refused upload left %d blobs behind", len(keys))
	}
}

func TestUploadIsInternalOnly(t *testing.T) {
	h := newHarness(t, nil)
	_, _, stream := sealedFile(t, 64)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", bytes.NewReader(stream))
	req.ContentLength = int64(len(stream))
	req.RemoteAddr = "192.0.2.10:54321"
	rec := httptest.NewRecorder()
	h.public.ServeHTTP(rec, req)
	// Out there the route must not even admit it exists.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("uploading on the public listener returned %d: %s", rec.Code, rec.Body.String())
	}
}

// TestMultiRecipientBundle is the other half of M7: N links, one upload, each
// link with its own key, views and lifecycle.
func TestMultiRecipientBundle(t *testing.T) {
	h := newHarness(t, nil)
	fileKey, plain, stream := sealedFile(t, 2048)
	fileID, claim := h.upload(t, stream)

	alice := newClient(t, "", "for alice")
	bob := newClient(t, "", "for bob")
	carol := newClient(t, "", "for carol")

	recipients := make([]map[string]any, 0, 3)
	for _, c := range []*client{alice, bob, carol} {
		var block map[string]any
		if err := json.Unmarshal(c.createBody(t, func(b map[string]any) {
			b["kind"] = "file"
		}), &block); err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, block)
	}
	// Bob gets two views; the others get one. Per-recipient settings are the
	// point of the feature.
	recipients[1]["views"] = 2

	body, err := json.Marshal(map[string]any{
		"recipients": recipients,
		"files":      []map[string]string{{"id": fileID, "token": claim}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bundle creation returned %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	list, ok := out["secrets"].([]any)
	if !ok || len(list) != 3 {
		t.Fatalf("expected three links, got %v", out["secrets"])
	}
	if out["bundle_id"] != alice.id {
		t.Errorf("bundle_id = %v, want the first link's id", out["bundle_id"])
	}

	// Each recipient reveals with their own key, and each gets the same file.
	for _, c := range []*client{alice, bob, carol} {
		r := h.reveal(t, h.public, c, c.keys.ReadToken)
		if r.Code != http.StatusOK {
			t.Fatalf("reveal for %s returned %d: %s", c.id, r.Code, r.Body.String())
		}
		grant := decodeBody(t, r)["download_token"].(string)
		dl := h.download(t, h.public, fileID, grant)
		if dl.Code != http.StatusOK {
			t.Fatalf("download for %s returned %d", c.id, dl.Code)
		}
		got, err := pcrypto.OpenFile(fileKey, dl.Body.Bytes())
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("recipient %s got the wrong bytes (%v)", c.id, err)
		}
	}

	// Alice and Carol are spent; Bob had two views and still has one.
	if r := h.reveal(t, h.public, alice, alice.keys.ReadToken); r.Code != http.StatusNotFound {
		t.Errorf("alice's second reveal returned %d", r.Code)
	}
	if r := h.reveal(t, h.public, bob, bob.keys.ReadToken); r.Code != http.StatusOK {
		t.Errorf("bob's second reveal returned %d", r.Code)
	}

	// One recipient's key must not open another recipient's link.
	if r := h.reveal(t, h.public, carol, bob.keys.ReadToken); r.Code == http.StatusOK {
		t.Error("bob's token opened carol's link")
	}
}

func TestBundleRefusesTooManyRecipients(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.MaxRecipients = 2 })

	recipients := []map[string]any{}
	for i := 0; i < 3; i++ {
		var block map[string]any
		if err := json.Unmarshal(newClient(t, "", "x").createBody(t, nil), &block); err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, block)
	}
	body, _ := json.Marshal(map[string]any{"recipients": recipients})
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", body, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("three recipients with a limit of two returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBundleRefusesBothForms(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "x")
	var single map[string]any
	if err := json.Unmarshal(c.createBody(t, nil), &single); err != nil {
		t.Fatal(err)
	}
	var other map[string]any
	if err := json.Unmarshal(newClient(t, "", "y").createBody(t, nil), &other); err != nil {
		t.Fatal(err)
	}
	single["recipients"] = []map[string]any{other}
	body, _ := json.Marshal(single)
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mixing the two forms returned %d: %s", rec.Code, rec.Body.String())
	}
}

// TestFilePurgeFollowsTheSecret checks the promise of section 5.2: the blob
// disappears with the secret, and an upload nobody claimed does not linger.
func TestFilePurgeFollowsTheSecret(t *testing.T) {
	h := newHarness(t, nil)
	ctx := t.Context()
	svc := h.srv.Secrets()

	_, _, stream := sealedFile(t, 256)
	fileID, claim := h.upload(t, stream)

	c := newClient(t, "", "attached")
	h.create(t, c, func(body map[string]any) {
		body["kind"] = "file"
		body["files"] = []map[string]string{{"id": fileID, "token": claim}}
	})

	// While the secret is alive and unread, the blob stays.
	if rows, orphans, err := svc.PurgeFiles(ctx); err != nil || rows != 0 || orphans != 0 {
		t.Fatalf("purge removed %d rows and %d orphans from a live bundle (%v)", rows, orphans, err)
	}
	if _, err := h.blobs.Size(ctx, fileID); err != nil {
		t.Fatalf("the blob of a live secret is gone: %v", err)
	}

	// The sender burns it. The secret row goes immediately; the blob goes on
	// the next purge, because no grant is outstanding.
	burn, _ := json.Marshal(map[string]string{
		"receipt_token": pcrypto.B64.EncodeToString(c.receiptToken),
	})
	if rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets/"+c.id+"/burn", burn, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("burn returned %d: %s", rec.Code, rec.Body.String())
	}
	rows, _, err := svc.PurgeFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("purge removed %d rows after the burn, want 1", rows)
	}
	if _, err := h.blobs.Size(ctx, fileID); err == nil {
		t.Error("the blob outlived the burned secret")
	}
}

// TestOrphanBlobsAreCollected covers the crash between writing the object and
// recording it: nothing points at the object, so nothing would ever delete it.
func TestOrphanBlobsAreCollected(t *testing.T) {
	h := newHarness(t, nil)
	ctx := t.Context()

	orphan := "ZZZZZZZZZZZZZZZZZZZZZZ"
	if err := h.blobs.Put(ctx, orphan, 4, bytes.NewReader([]byte("junk"))); err != nil {
		t.Fatal(err)
	}
	_, orphans, err := h.srv.Secrets().PurgeFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if orphans != 1 {
		t.Errorf("purge collected %d orphans, want 1", orphans)
	}
	if _, err := h.blobs.Size(ctx, orphan); err == nil {
		t.Error("the orphan blob is still there")
	}
}
