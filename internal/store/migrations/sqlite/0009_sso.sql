-- Linking a local account to a directory identity.
--
-- The link is (issuer, subject), not the e-mail address. An address is a
-- label: people marry, departments rename, an administrator fixes a typo, and
-- at a provider the same mailbox can be reassigned to a new human. The subject
-- is the directory's own stable identifier for a person and never changes while the
-- account exists, which is exactly the property an authentication link needs.
--
-- The issuer is stored beside it so that pointing the instance at a different
-- tenant does not silently match the old subjects: a subject is only unique
-- within its issuer.
ALTER TABLE users
ADD COLUMN sso_issuer TEXT;

ALTER TABLE users
ADD COLUMN sso_subject TEXT;

-- One directory identity, one account. The partial index leaves local-only
-- accounts alone: several may have no subject at all.
CREATE UNIQUE INDEX idx_users_sso ON users (sso_issuer, sso_subject)
WHERE sso_subject IS NOT NULL;
