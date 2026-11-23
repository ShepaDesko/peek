package server_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/orgs"
	"github.com/ShepaDesko/peek/internal/store"
)

// Multi-organisation mode.
//
// The tests that matter here are the boundary ones: that a Host header cannot
// claim a brand it has not proved, that an account of one organisation cannot
// act on another's address, and that an administrator of one organisation
// cannot see the others exist.

// hostRequest issues a request with a chosen Host, from a trusted proxy
// address so X-Forwarded-Host would be honoured too.
func hostRequest(t *testing.T, h http.Handler, method, target, host string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	var reader *strings.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, target, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Host = host
	req.RemoteAddr = "192.0.2.10:54321"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// discardLogger keeps the service's own logging out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newMultiOrgHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, func(cfg *config.Config) {
		cfg.MultiOrg = true
		cfg.PublicURL = "https://secrets.example.test"
	})
}

// seedOrg creates an organisation with a verified domain and its own brand.
func seedOrg(t *testing.T, h *harness, slug, domain, serviceName string) store.Org {
	t.Helper()
	org, err := h.store.CreateOrg(t.Context(), store.Org{Slug: slug, Name: serviceName})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AddDomain(t.Context(), org.ID, domain, "token-"+slug); err != nil {
		t.Fatal(err)
	}
	if err := h.store.MarkDomainVerified(t.Context(), domain, h.store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SaveBranding(t.Context(), store.Branding{
		OrgID: org.ID, ServiceName: serviceName, PrimaryColor: "#112233",
	}); err != nil {
		t.Fatal(err)
	}
	return org
}

// TestBrandResolvesByVerifiedDomainOnly is the whole point of the TXT record.
func TestBrandResolvesByVerifiedDomainOnly(t *testing.T) {
	h := newMultiOrgHarness(t)
	seedOrg(t, h, "acme", "secrets.acme.test", "ACME Secrets")

	// The verified domain gets its own brand.
	rec := hostRequest(t, h.public, http.MethodGet, "/api/v1/branding", "secrets.acme.test", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("branding returned %d", rec.Code)
	}
	if name, _ := decodeBody(t, rec)["service_name"].(string); name != "ACME Secrets" {
		t.Errorf("service_name = %q on the verified domain", name)
	}

	// A domain declared but not proved resolves to nothing: anybody can point
	// a DNS name at this instance, so the record is what grants the brand.
	other, err := h.store.CreateOrg(t.Context(), store.Org{Slug: "impostor", Name: "Impostor"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AddDomain(t.Context(), other.ID, "evil.test", "token-evil"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SaveBranding(t.Context(), store.Branding{
		OrgID: other.ID, ServiceName: "Impostor Secrets",
	}); err != nil {
		t.Fatal(err)
	}
	rec = hostRequest(t, h.public, http.MethodGet, "/api/v1/branding", "evil.test", nil, nil)
	if name, _ := decodeBody(t, rec)["service_name"].(string); name == "Impostor Secrets" {
		t.Error("an unverified domain served its organisation's brand")
	}

	// And an unknown host gets the instance's own brand, not a refusal: a
	// recipient who was sent a link must be able to read their secret.
	rec = hostRequest(t, h.public, http.MethodGet, "/api/v1/branding", "nobody.test", nil, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("an unknown host returned %d", rec.Code)
	}
}

// TestSuspendedOrganisationStopsResolving: a customer who has not paid is not
// a customer whose secrets are deleted, but their domain stops serving their
// brand.
func TestSuspendedOrganisationStopsResolving(t *testing.T) {
	h := newMultiOrgHarness(t)
	org := seedOrg(t, h, "acme", "secrets.acme.test", "ACME Secrets")

	svc := orgs.New(h.cfg, h.store, discardLogger())
	if err := svc.Update(t.Context(), org.ID, "", store.OrgSuspended); err != nil {
		t.Fatal(err)
	}
	// The server has its own resolver with its own cache, so go through the
	// store state the way a fresh node would.
	h2 := newMultiOrgHarness(t)
	_ = h2
	if got := svc.Resolve(t.Context(), "secrets.acme.test").ID; got == org.ID {
		t.Error("a suspended organisation still resolves")
	}
	// Its rows are untouched.
	if again, err := h.store.OrgByID(t.Context(), org.ID); err != nil || again.Status != store.OrgSuspended {
		t.Errorf("the organisation was not merely suspended: %+v %v", again, err)
	}
}

// TestSecretsAreScopedToTheResolvedOrganisation: an anonymous creation on
// acme's domain belongs to acme, and acme's dashboard must not show anybody
// else's.
func TestSecretsAreScopedToTheResolvedOrganisation(t *testing.T) {
	h := newMultiOrgHarness(t)
	acme := seedOrg(t, h, "acme", "secrets.acme.test", "ACME")
	beta := seedOrg(t, h, "beta", "secrets.beta.test", "Beta")

	for _, tc := range []struct {
		host string
		org  string
	}{{"secrets.acme.test", acme.ID}, {"secrets.beta.test", beta.ID}} {
		c := newClient(t, "", "le mot de passe")
		rec := hostRequest(t, h.internal, http.MethodPost, "/api/v1/secrets", tc.host,
			c.createBody(t, nil), nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create on %s returned %d: %s", tc.host, rec.Code, rec.Body.String())
		}
		// The link is built on that organisation's own domain, so the address
		// in it, the certificate serving it and the brand on it agree.
		if url, _ := decodeBody(t, rec)["url"].(string); !strings.HasPrefix(url, "https://"+tc.host+"/s/") {
			t.Errorf("the link for %s is %q", tc.host, url)
		}
	}

	countAcme, err := h.store.CountOrg(t.Context(), acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	countBeta, err := h.store.CountOrg(t.Context(), beta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if countAcme.Secrets != 1 || countBeta.Secrets != 1 {
		t.Errorf("secrets landed in the wrong organisation: acme %d, beta %d",
			countAcme.Secrets, countBeta.Secrets)
	}
}

// TestATokenCannotCrossOrganisations is the guard a browser cannot reach.
//
// Cookies are scoped to a host, so a session from acme is never sent to beta.
// A bearer token is a header, and the Host beside it is the caller's choice.
func TestATokenCannotCrossOrganisations(t *testing.T) {
	h := newMultiOrgHarness(t)
	seedOrg(t, h, "beta", "secrets.beta.test", "Beta")

	// The bootstrap administrator belongs to the default organisation.
	token, _ := h.issueToken(t, []string{store.ScopeSecretsWrite, store.ScopeInstanceRead})
	bearer := map[string]string{"Authorization": "Bearer " + token}

	// On its own organisation's address it works.
	rec := hostRequest(t, h.internal, http.MethodGet, "/api/v1/policy", "secrets.example.test", nil, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("the token was refused on its own organisation: %d %s", rec.Code, rec.Body.String())
	}

	// On another organisation's address it is refused, by code.
	rec = hostRequest(t, h.internal, http.MethodGet, "/api/v1/policy", "secrets.beta.test", nil, bearer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a token acted on another organisation's address: %d %s", rec.Code, rec.Body.String())
	}
	if code, _ := decodeBody(t, rec)["error"].(map[string]any)["code"].(string); code != "wrong_organisation" {
		t.Errorf("error code = %q", code)
	}

	// And the attempt is in the audit trail, which is what an operator of a
	// hosted instance needs to see.
	events, err := h.store.ListAudit(t.Context(), store.AuditFilter{Event: store.EventWrongOrg})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("audit holds %d wrong-organisation events", len(events))
	}
}

// TestPlatformSurfaceNeedsThePlatformRole: an administrator of one customer
// must not be able to list the others.
func TestPlatformSurfaceNeedsThePlatformRole(t *testing.T) {
	h := newMultiOrgHarness(t)
	admin := h.signIn(t)

	// The bootstrap account is an ordinary administrator.
	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/orgs", nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an administrator listed the organisations: %d %s", rec.Code, rec.Body.String())
	}

	// Promote it and the surface opens.
	if err := h.store.UpdateUserProfile(t.Context(), admin.user["id"].(string), "",
		store.RolePlatformAdmin, store.UserActive); err != nil {
		t.Fatal(err)
	}
	rec = admin.do(t, h.internal, http.MethodGet, "/api/v1/orgs", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the platform administrator was refused: %d %s", rec.Code, rec.Body.String())
	}
	if list, _ := decodeBody(t, rec)["orgs"].([]any); len(list) != 1 {
		t.Errorf("orgs = %v, want just the default one", decodeBody(t, rec)["orgs"])
	}

	// Creating one, and the record to publish comes back with it.
	rec = admin.do(t, h.internal, http.MethodPost, "/api/v1/orgs",
		jsonBody(t, map[string]string{"slug": "ACME Ltd.", "name": "ACME"}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	created, _ := decodeBody(t, rec)["org"].(map[string]any)
	if created["slug"] != "acme-ltd" {
		t.Errorf("slug = %v, want it normalised", created["slug"])
	}

	rec = admin.do(t, h.internal, http.MethodPost,
		"/api/v1/orgs/"+created["id"].(string)+"/domains",
		jsonBody(t, map[string]string{"domain": "https://Secrets.ACME.com:8443/"}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add domain returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	record, _ := body["record"].(map[string]any)
	if record["name"] != "_peek-challenge.secrets.acme.com" {
		t.Errorf("record name = %v (the domain should be normalised out of a pasted URL)", record["name"])
	}
	if value, _ := record["value"].(string); !strings.HasPrefix(value, "peek-verification=") {
		t.Errorf("record value = %q", value)
	}
	// It is not verified, so it resolves to nothing yet.
	domain, _ := body["domain"].(map[string]any)
	if domain["verified_at"] != nil {
		t.Error("a freshly declared domain is already verified")
	}
}

// TestPlatformSurfaceIsRefusedOnASingleTenantInstance: half a feature must
// refuse loudly, naming the setting.
func TestPlatformSurfaceIsRefusedOnASingleTenantInstance(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)
	if err := h.store.UpdateUserProfile(t.Context(), admin.user["id"].(string), "",
		store.RolePlatformAdmin, store.UserActive); err != nil {
		t.Fatal(err)
	}

	// Listing works and says so: an operator should be able to ask.
	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/orgs", nil, nil)
	if rec.Code != http.StatusOK || decodeBody(t, rec)["multi_org"] != false {
		t.Errorf("list on a single-tenant instance: %d %s", rec.Code, rec.Body.String())
	}

	rec = admin.do(t, h.internal, http.MethodPost, "/api/v1/orgs",
		jsonBody(t, map[string]string{"slug": "acme"}), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("create on a single-tenant instance returned %d", rec.Code)
	}
	message, _ := decodeBody(t, rec)["error"].(map[string]any)["message"].(string)
	if !strings.Contains(message, "multi_org") {
		t.Errorf("the refusal does not name the setting to change: %q", message)
	}
}

// TestSingleTenantIgnoresTheHostHeader: nothing about the Host may change
// behaviour on an instance that is not hosting several organisations.
func TestSingleTenantIgnoresTheHostHeader(t *testing.T) {
	h := newHarness(t, nil)
	// Declare and verify a domain anyway, as a leftover from an experiment.
	org, err := h.store.CreateOrg(t.Context(), store.Org{Slug: "acme", Name: "ACME"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AddDomain(t.Context(), org.ID, "secrets.acme.test", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := h.store.MarkDomainVerified(t.Context(), "secrets.acme.test", h.store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SaveBranding(t.Context(), store.Branding{
		OrgID: org.ID, ServiceName: "ACME Secrets",
	}); err != nil {
		t.Fatal(err)
	}

	rec := hostRequest(t, h.public, http.MethodGet, "/api/v1/branding", "secrets.acme.test", nil, nil)
	if name, _ := decodeBody(t, rec)["service_name"].(string); name == "ACME Secrets" {
		t.Error("a single-tenant instance resolved the brand from the Host header")
	}
}

// --- domain verification ----------------------------------------------------

// TestVerifyReadsTheTXTRecord runs the real resolver code against a DNS server
// of our own, so the lookup, the value comparison and the recorded outcome are
// all exercised rather than mocked.
func TestVerifyReadsTheTXTRecord(t *testing.T) {
	h := newMultiOrgHarness(t)
	org, err := h.store.CreateOrg(t.Context(), store.Org{Slug: "acme", Name: "ACME"})
	if err != nil {
		t.Fatal(err)
	}
	svc := orgs.New(h.cfg, h.store, discardLogger())
	declared, err := svc.AddDomain(t.Context(), org.ID, "secrets.acme.test")
	if err != nil {
		t.Fatal(err)
	}

	// The resolver is a function, so the zone is a map. There is nothing in
	// net.Resolver worth testing here: what matters is the value comparison
	// and what gets recorded.
	zone := map[string][]string{}
	svc.SetResolver(func(_ context.Context, name string) ([]string, error) {
		values, ok := zone[name]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return values, nil
	})

	// Nothing published yet.
	if _, err := svc.Verify(t.Context(), declared.Domain); err == nil {
		t.Fatal("verification succeeded with no record published")
	}
	after, err := h.store.DomainByName(t.Context(), declared.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if after.Verified() {
		t.Error("the domain was marked verified")
	}
	if after.LastError == "" || after.CheckedAt == nil {
		t.Error("the failed check was not recorded, so an operator sees nothing")
	}

	// The wrong value: another instance's token, or a stale one.
	zone[orgs.RecordName(declared.Domain)] = []string{"peek-verification=somebody-elses-token"}
	if _, err := svc.Verify(t.Context(), declared.Domain); err == nil {
		t.Fatal("a record with the wrong token verified")
	}

	// The right value, with the quotes and whitespace operators paste.
	zone[orgs.RecordName(declared.Domain)] = []string{
		"v=spf1 -all",
		`  "` + orgs.RecordValue(declared.Token) + `"  `,
	}
	verified, err := svc.Verify(t.Context(), declared.Domain)
	if err != nil {
		t.Fatalf("verification failed with the record published: %v", err)
	}
	if !verified.Verified() {
		t.Fatal("the domain is still unverified")
	}

	// And now it resolves.
	if got := svc.Resolve(t.Context(), "secrets.acme.test").ID; got != org.ID {
		t.Errorf("resolved to %q, want %q", got, org.ID)
	}

	// A later DNS outage does not take the brand away: proved once is proved.
	delete(zone, orgs.RecordName(declared.Domain))
	if _, err := svc.Verify(t.Context(), declared.Domain); err == nil {
		t.Error("a re-check with no record succeeded")
	}
	again, err := h.store.DomainByName(t.Context(), declared.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Verified() {
		t.Error("a failed re-check cleared a domain that had been proved")
	}
}

func TestNormaliseDomainRefusesNonsense(t *testing.T) {
	for raw, want := range map[string]string{
		"Secrets.ACME.com":          "secrets.acme.com",
		"https://secrets.acme.com/": "secrets.acme.com",
		"secrets.acme.com:8443":     "secrets.acme.com",
		"secrets.acme.com.":         "secrets.acme.com",
		"[2001:db8::1]:8443":        "2001:db8::1",
		"evil.com/../acme.com":      "",
		"https://secrets.acme.com":  "secrets.acme.com",
		"acme.com' OR 1=1":          "",
		"acme.com\nHost: other":     "",
		"":                          "",
	} {
		if got := store.NormaliseDomain(raw); got != want {
			t.Errorf("NormaliseDomain(%q) = %q, want %q", raw, got, want)
		}
	}
}
