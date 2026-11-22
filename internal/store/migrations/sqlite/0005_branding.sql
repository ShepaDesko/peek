-- White-label branding (milestone M6).
--
-- The brand lives in the database rather than in peek.toml so that an
-- administrator can change it from the interface, with a preview, and without
-- editing a file and restarting the service. peek.toml keeps the defaults a
-- fresh install starts from.

CREATE TABLE branding (
    org_id           TEXT PRIMARY KEY REFERENCES organizations (id),
    service_name     TEXT NOT NULL DEFAULT '',
    primary_color    TEXT NOT NULL DEFAULT '',
    accent_color     TEXT NOT NULL DEFAULT '',
    background_color TEXT NOT NULL DEFAULT '',
    corner_radius    TEXT NOT NULL DEFAULT '',
    font             TEXT NOT NULL DEFAULT '',
    button_style     TEXT NOT NULL DEFAULT '',
    hide_powered_by  INTEGER NOT NULL DEFAULT 0,
    support_url      TEXT NOT NULL DEFAULT '',
    legal_url        TEXT NOT NULL DEFAULT '',
    privacy_url      TEXT NOT NULL DEFAULT '',
    contact_email    TEXT NOT NULL DEFAULT '',
    -- Per-language texts, as JSON: {"fr": {"home.title": "…"}, "en": {…}}
    texts            TEXT NOT NULL DEFAULT '{}',
    -- Administrator CSS, checked when it is stored and served from our own
    -- origin, so the CSP needs no inline style.
    custom_css       TEXT NOT NULL DEFAULT '',
    version          INTEGER NOT NULL DEFAULT 1,
    updated_at       INTEGER NOT NULL,
    updated_by       TEXT
);

-- Logos, favicon and the Open Graph image.
--
-- They are rows rather than files so that a restore brings the brand back with
-- the data, and so that several nodes serve the same bytes without a shared
-- filesystem.
CREATE TABLE branding_assets (
    org_id       TEXT NOT NULL REFERENCES organizations (id),
    kind         TEXT NOT NULL,
    content_type TEXT NOT NULL,
    bytes        BLOB NOT NULL,
    size_bytes   INTEGER NOT NULL,
    -- Short digest, used as the cache-busting part of the asset URL.
    etag         TEXT NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (org_id, kind)
);
