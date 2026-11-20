-- Sender notifications (section 3.2 of the brief).
--
-- The address is encrypted with the server master key: the server has to be
-- able to send to it, so it cannot be client-encrypted, but it must not sit
-- in plaintext in a stolen database file either.

ALTER TABLE secrets ADD COLUMN notify_email_enc BLOB;
ALTER TABLE secrets ADD COLUMN notify_on_view INTEGER NOT NULL DEFAULT 0;

ALTER TABLE secret_tombstones ADD COLUMN notify_email_enc BLOB;
