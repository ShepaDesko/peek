-- Domains, for the optional multi-organisation mode.
--
-- One instance, several customers: each organisation has its own brand, its
-- own users and its own policies, and the way a request says which one it
-- belongs to is the Host header. That header is only trustworthy when it comes
-- from a proxy Peek was told to trust or from a direct connection, which is
-- the same rule the real-client-IP code already follows.
--
-- A domain must be proved before it resolves. Without that, anyone who can
-- point a DNS name at this instance could claim another customer's brand, and
-- a recipient would see the right logo on the wrong organisation's page. The
-- proof is a TXT record holding a token this table hands out; until it checks
-- out, verified_at stays NULL and the domain resolves to nothing.
CREATE TABLE org_domains (
    -- The domain is the key: it must be unique across the whole instance, not
    -- merely within an organisation.
    domain TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- The value the operator publishes as a TXT record. Random, 128 bits, and
    -- kept after verification so a re-check can be run at any time.
    verify_token TEXT NOT NULL,
    -- NULL until the TXT record has been seen. A domain in this state is
    -- declared, not active.
    verified_at INTEGER,
    -- The primary domain is the one links are built with for this
    -- organisation. Exactly one per organisation, enforced below.
    is_primary INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    -- What the last check saw, so an operator is not left guessing between
    -- "no record", "wrong value" and "DNS is down".
    last_checked_at INTEGER,
    last_error      TEXT
);

CREATE INDEX idx_org_domains_org ON org_domains (org_id);

-- One primary per organisation. A partial unique index rather than a trigger:
-- the database refuses the second one instead of the code remembering to.
CREATE UNIQUE INDEX idx_org_domains_primary ON org_domains (org_id)
WHERE is_primary = 1;

-- Organisations gain the fields a hosted instance needs: whether they are
-- live, and when they were last touched.
ALTER TABLE organizations
ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

ALTER TABLE organizations
ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
