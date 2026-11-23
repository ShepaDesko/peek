// Package orgs resolves which organisation a request belongs to, and proves
// that a domain may claim one.
//
// A single-tenant instance never uses any of it: Resolve returns the default
// organisation without touching the database, which is also what keeps the
// hot path free of a lookup nobody needs.
//
// In multi-organisation mode the Host header decides, and a Host header is
// attacker-controlled on a direct connection. Two things make it safe to act
// on. It is only read from a source Peek was told to trust — the same rule the
// real-client-IP code follows — and a domain only resolves once a DNS TXT
// record has proved that whoever controls the name asked for it. Without that
// proof, anybody able to point a name at this instance could wear another
// customer's brand, and a recipient would see the right logo above the wrong
// organisation's page.
package orgs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// ChallengePrefix is the label the TXT record goes under. A dedicated
// subdomain rather than the apex: an apex TXT record is shared with SPF, DMARC
// and half a dozen verification tokens, and operators delete each other's.
const ChallengePrefix = "_peek-challenge"

// TokenPrefix marks the record value, so an operator reading a zone file can
// tell what it is for. It is a label in a public DNS record, not a credential:
// the secret half is the token after it.
const TokenPrefix = "peek-verification=" //nolint:gosec // G101: a public record prefix

// resolveTTL is how long a Host-to-organisation answer is reused.
//
// Short enough that adding a domain takes effect while the operator is still
// looking at the screen; long enough that a flood of requests to one domain is
// one query, not one per request.
const resolveTTL = 30 * time.Second

// negativeTTL caches "this host belongs to nobody". It is shorter than the
// positive one on purpose: the usual cause is a domain that was just added and
// is about to be verified.
const negativeTTL = 10 * time.Second

// dnsTimeout bounds one verification. A resolver that hangs must not hold an
// administrator's request open.
const dnsTimeout = 10 * time.Second

// ErrNotMultiOrg is returned by the operations that only make sense on an
// instance hosting several organisations.
var ErrNotMultiOrg = errors.New("orgs: this instance is single-tenant; set multi_org = true in peek.toml")

// ErrUnverified is returned when a domain's TXT record was not found.
var ErrUnverified = errors.New("orgs: the verification record was not found")

// Service resolves and manages organisations.
type Service struct {
	cfg   *config.Config
	store *store.Store
	log   *slog.Logger
	// lookupTXT is the resolver, as a function so a test can answer without
	// a DNS server and so an operator's resolver is the system one in
	// production. Peek ships no DNS client: a host that needs a particular
	// resolver configures the host.
	lookupTXT func(ctx context.Context, name string) ([]string, error)

	mu    sync.RWMutex
	cache map[string]cached
}

type cached struct {
	org   store.Org
	found bool
	until time.Time
}

// New builds the service. The resolver is the system one: Peek does not ship a
// DNS client, and an operator who needs a specific resolver configures the
// host's.
func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Service {
	return &Service{
		cfg:       cfg,
		store:     st,
		log:       log,
		lookupTXT: net.DefaultResolver.LookupTXT,
		cache:     map[string]cached{},
	}
}

// SetResolver replaces the TXT lookup, for the tests.
func (s *Service) SetResolver(lookup func(ctx context.Context, name string) ([]string, error)) {
	s.lookupTXT = lookup
}

// MultiOrg reports whether this instance hosts several organisations.
func (s *Service) MultiOrg() bool { return s != nil && s.cfg.MultiOrg }

// Resolve maps a Host header to an organisation.
//
// On a single-tenant instance it returns the default organisation and makes no
// query at all. In multi-organisation mode an unknown or unverified host also
// gets the default one: the alternative is refusing the request, and a
// recipient who was sent a link must be able to read their secret even when
// the operator has not finished setting the brand up. What they get is the
// instance's own brand, not somebody else's.
func (s *Service) Resolve(ctx context.Context, host string) store.Org {
	fallback := store.Org{ID: store.DefaultOrgID, Slug: "default", Name: s.cfg.Branding.ServiceName, Status: store.OrgActive}
	if !s.MultiOrg() {
		return fallback
	}
	domain := store.NormaliseDomain(host)
	if domain == "" {
		return fallback
	}

	now := time.Now()
	s.mu.RLock()
	entry, ok := s.cache[domain]
	s.mu.RUnlock()
	if ok && now.Before(entry.until) {
		if entry.found {
			return entry.org
		}
		return fallback
	}

	org, err := s.store.OrgByDomain(ctx, domain)
	switch {
	case err == nil && org.Active():
		s.remember(domain, org, true, now.Add(resolveTTL))
		return org
	case err == nil:
		// Suspended: the organisation exists but is not serving. Fall back to
		// the instance brand rather than show a half-configured page.
		s.remember(domain, store.Org{}, false, now.Add(resolveTTL))
		return fallback
	case errors.Is(err, store.ErrNotFound):
		s.remember(domain, store.Org{}, false, now.Add(negativeTTL))
		return fallback
	default:
		// A database that cannot be read is not a reason to refuse a
		// recipient: log it and serve the instance brand.
		s.log.Error("cannot resolve the host to an organisation", "error", err.Error())
		return fallback
	}
}

func (s *Service) remember(domain string, org store.Org, found bool, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A cache keyed by an attacker-controlled header must not grow without
	// bound. A thousand entries is far more than any instance has domains,
	// and clearing it wholesale is cheaper than tracking an eviction order
	// for something that refills in thirty seconds.
	if len(s.cache) > 1000 {
		s.cache = map[string]cached{}
	}
	s.cache[domain] = cached{org: org, found: found, until: until}
}

// Forget drops a domain from the cache, so a change takes effect at once on
// this node. Other nodes pick it up within resolveTTL, which is why that is
// thirty seconds and not thirty minutes.
func (s *Service) Forget(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, store.NormaliseDomain(domain))
}

// ---------------------------------------------------------------------------
// Managing organisations
// ---------------------------------------------------------------------------

// Create adds an organisation.
func (s *Service) Create(ctx context.Context, slug, name string) (store.Org, error) {
	if !s.MultiOrg() {
		return store.Org{}, ErrNotMultiOrg
	}
	slug = store.NormaliseSlug(slug)
	if slug == "" {
		return store.Org{}, errors.New("orgs: a slug is required, such as acme")
	}
	if slug == store.DefaultOrgID {
		return store.Org{}, errors.New("orgs: default is the instance's own organisation")
	}
	return s.store.CreateOrg(ctx, store.Org{Slug: slug, Name: name})
}

// List returns every organisation with its counts.
type Listed struct {
	store.Org
	Counts  store.OrgCounts `json:"counts"`
	Domains []store.Domain  `json:"domains,omitempty"`
}

// List returns the organisations of the instance.
func (s *Service) List(ctx context.Context) ([]Listed, error) {
	all, err := s.store.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	domains, err := s.store.ListDomains(ctx, "")
	if err != nil {
		return nil, err
	}
	byOrg := map[string][]store.Domain{}
	for _, d := range domains {
		byOrg[d.OrgID] = append(byOrg[d.OrgID], d)
	}

	out := make([]Listed, 0, len(all))
	for _, org := range all {
		counts, err := s.store.CountOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, Listed{Org: org, Counts: counts, Domains: byOrg[org.ID]})
	}
	return out, nil
}

// Update changes an organisation's name or status.
func (s *Service) Update(ctx context.Context, id, name, status string) error {
	if !s.MultiOrg() {
		return ErrNotMultiOrg
	}
	switch status {
	case "", store.OrgActive, store.OrgSuspended:
	default:
		return fmt.Errorf("orgs: status must be %s or %s", store.OrgActive, store.OrgSuspended)
	}
	if err := s.store.UpdateOrg(ctx, id, name, status); err != nil {
		return err
	}
	// The resolution cache holds this organisation under each of its domains.
	s.forgetOrg(ctx, id)
	return nil
}

// Delete removes an empty organisation.
func (s *Service) Delete(ctx context.Context, id string) error {
	if !s.MultiOrg() {
		return ErrNotMultiOrg
	}
	s.forgetOrg(ctx, id)
	return s.store.DeleteOrg(ctx, id)
}

func (s *Service) forgetOrg(ctx context.Context, id string) {
	domains, err := s.store.ListDomains(ctx, id)
	if err != nil {
		// Worst case the cache is stale for resolveTTL.
		return
	}
	for _, d := range domains {
		s.Forget(d.Domain)
	}
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

// AddDomain declares a domain and returns the record to publish.
func (s *Service) AddDomain(ctx context.Context, orgID, domain string) (store.Domain, error) {
	if !s.MultiOrg() {
		return store.Domain{}, ErrNotMultiOrg
	}
	name := store.NormaliseDomain(domain)
	if name == "" || !strings.Contains(name, ".") {
		return store.Domain{}, fmt.Errorf("orgs: %q is not a domain name", domain)
	}
	token, err := newToken()
	if err != nil {
		return store.Domain{}, err
	}
	return s.store.AddDomain(ctx, orgID, name, token)
}

// RecordName returns the DNS name the TXT record goes under.
func RecordName(domain string) string {
	return ChallengePrefix + "." + store.NormaliseDomain(domain)
}

// RecordValue returns what the TXT record must contain.
func RecordValue(token string) string { return TokenPrefix + token }

// Verify looks the TXT record up and records the outcome.
//
// This is the one place in Peek that makes a DNS query, and it only happens
// when an administrator asks for it: it is not a background job, and nothing
// is resolved on the request path. An air-gapped instance simply never calls
// it, and single-tenant mode has no reason to.
func (s *Service) Verify(ctx context.Context, domain string) (store.Domain, error) {
	if !s.MultiOrg() {
		return store.Domain{}, ErrNotMultiOrg
	}
	record, err := s.store.DomainByName(ctx, domain)
	if err != nil {
		return store.Domain{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	name := RecordName(record.Domain)
	values, lookupErr := s.lookupTXT(ctx, name)
	now := time.Now()

	if lookupErr != nil {
		reason := dnsReason(lookupErr)
		if markErr := s.store.MarkDomainFailed(ctx, record.Domain, reason, now); markErr != nil {
			s.log.Error("cannot record a domain check", "error", markErr.Error())
		}
		return record, fmt.Errorf("%w: looking up TXT %s: %s", ErrUnverified, name, reason)
	}

	want := RecordValue(record.Token)
	for _, value := range values {
		// A resolver may split a long record into chunks, and operators
		// paste the value with the quotes and the spaces their zone file had.
		// The order matters: trimming quotes first does nothing to a value
		// that starts with a space.
		if trimRecord(value) == want {
			if err := s.store.MarkDomainVerified(ctx, record.Domain, now); err != nil {
				return record, err
			}
			s.Forget(record.Domain)
			s.log.Info("domain verified", "domain", record.Domain, "org", record.OrgID)
			return s.store.DomainByName(ctx, record.Domain)
		}
	}

	reason := fmt.Sprintf("%d TXT record(s) found at %s, none of them %s", len(values), name, want)
	if err := s.store.MarkDomainFailed(ctx, record.Domain, reason, now); err != nil {
		s.log.Error("cannot record a domain check", "error", err.Error())
	}
	return record, fmt.Errorf("%w: %s", ErrUnverified, reason)
}

// SetPrimary chooses the domain links are built with.
func (s *Service) SetPrimary(ctx context.Context, orgID, domain string) error {
	if !s.MultiOrg() {
		return ErrNotMultiOrg
	}
	return s.store.SetPrimaryDomain(ctx, orgID, domain)
}

// RemoveDomain deletes a domain.
func (s *Service) RemoveDomain(ctx context.Context, orgID, domain string) error {
	if !s.MultiOrg() {
		return ErrNotMultiOrg
	}
	if err := s.store.DeleteDomain(ctx, orgID, domain); err != nil {
		return err
	}
	s.Forget(domain)
	return nil
}

// ListDomains returns an organisation's domains.
func (s *Service) ListDomains(ctx context.Context, orgID string) ([]store.Domain, error) {
	return s.store.ListDomains(ctx, orgID)
}

// PublicURL returns the base URL for an organisation's links.
//
// A multi-organisation instance builds a recipient link on that
// organisation's own primary domain, so the brand, the certificate and the
// address in the link all agree. Without one, it falls back to the instance's
// public_url.
func (s *Service) PublicURL(ctx context.Context, orgID string) string {
	base := strings.TrimRight(s.cfg.PublicURL, "/")
	if !s.MultiOrg() || orgID == "" || orgID == store.DefaultOrgID {
		return base
	}
	domain, err := s.store.PrimaryDomain(ctx, orgID)
	if err != nil || !domain.Verified() {
		return base
	}
	scheme := "https"
	if strings.HasPrefix(base, "http://") {
		// An instance served over plain HTTP is a LAN deployment; its
		// organisations are on plain HTTP too.
		scheme = "http"
	}
	return scheme + "://" + domain.Domain
}

// trimRecord strips what a zone file and a copy-paste add around a value.
func trimRecord(value string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"`))
}

func newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// dnsReason turns a resolver error into something an operator can act on.
func dnsReason(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "no such record (the name does not exist yet, or has not propagated)"
		case dnsErr.IsTimeout:
			return "the resolver timed out"
		case dnsErr.IsTemporary:
			return "a temporary resolver failure"
		}
		return dnsErr.Err
	}
	return err.Error()
}
