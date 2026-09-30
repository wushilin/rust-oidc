-- Case-insensitive identity is done in the application (util::fold), not by
-- collation, so SQLite, Postgres and MySQL agree. Each case-insensitive column
-- gets a folded twin with a plain unique index; the display column keeps the
-- original casing.
-- SQLite's lower() only folds ASCII; rows holding non-ASCII UPNs/domains/names
-- are re-folded by the application on next write, and lookups of such rows
-- created before this migration are the only place the two can differ.
-- The columns stay nullable because SQLite cannot add NOT NULL without a
-- default; the application always writes them.

-- GROUPS is a reserved word in MySQL 8.0.2+; rename so no engine needs quoting.
ALTER TABLE groups RENAME TO user_groups;

ALTER TABLE users ADD COLUMN upn_folded TEXT;
UPDATE users SET upn_folded = lower(upn);
CREATE UNIQUE INDEX users_tenant_upn_folded ON users(tenant_id, upn_folded);

ALTER TABLE tenant_domains ADD COLUMN domain_folded TEXT;
UPDATE tenant_domains SET domain_folded = lower(domain);
CREATE UNIQUE INDEX tenant_domains_folded ON tenant_domains(domain_folded);

ALTER TABLE user_groups ADD COLUMN name_folded TEXT;
UPDATE user_groups SET name_folded = lower(name);
CREATE UNIQUE INDEX user_groups_tenant_name_folded ON user_groups(tenant_id, name_folded);
