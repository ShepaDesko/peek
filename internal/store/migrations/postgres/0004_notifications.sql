-- Sender notifications (section 3.2 of the brief), PostgreSQL dialect.

ALTER TABLE secrets ADD COLUMN notify_email_enc BYTEA;
ALTER TABLE secrets ADD COLUMN notify_on_view INTEGER NOT NULL DEFAULT 0;

ALTER TABLE secret_tombstones ADD COLUMN notify_email_enc BYTEA;
