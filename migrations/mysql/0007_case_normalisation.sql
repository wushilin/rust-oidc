-- Case-insensitive identity is done in the application (util::fold), not by
-- collation, so SQLite, Postgres and MySQL agree. Each case-insensitive column
-- gets a folded twin with a plain unique index; the display column keeps the
-- original casing.
--
-- The folded columns are VARCHAR (MySQL cannot index TEXT without a prefix
-- length) and utf8mb4_bin: under the table's _ai_ci default, `e` and `é` would
-- compare equal and two different accounts would collide.

-- NOTE: the lower() backfill below is only the cheap initial fill. It is exact
-- for ASCII, but not for non-ASCII. db::reconcile_folded recomputes every
-- folded column with util::fold at startup and is what makes the data exact.
-- Keep both: dropping the Rust pass locks out users with non-ASCII identifiers.

-- The legacy constraints (UNIQUE(tenant_id, upn), UNIQUE(tenant_id, name), the
-- tenant_domains primary key) sit on columns at the table default
-- utf8mb4_unicode_ci, which is accent-insensitive: `jose@x` would be refused as
-- a duplicate of `josé@x` before the folded index is consulted. The folded
-- column is the identity authority, so the legacy constraint must be
-- byte-exact and never reject a pair the folded index considers distinct.
-- MODIFY restates the 0001 definitions exactly, changing only the collation.
-- None of these columns is referenced by a foreign key.
ALTER TABLE users          MODIFY upn    VARCHAR(320) COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE tenant_domains MODIFY domain VARCHAR(320) COLLATE utf8mb4_bin NOT NULL;

-- GROUPS is a reserved word in MySQL 8.0.2+; rename so no statement needs backticks.
RENAME TABLE `groups` TO user_groups;
-- (after the rename, hence its position)
ALTER TABLE user_groups    MODIFY name   VARCHAR(255) COLLATE utf8mb4_bin NOT NULL;

ALTER TABLE users ADD COLUMN upn_folded VARCHAR(320) COLLATE utf8mb4_bin;
UPDATE users SET upn_folded = LOWER(upn);
CREATE UNIQUE INDEX users_tenant_upn_folded ON users(tenant_id, upn_folded);

ALTER TABLE tenant_domains ADD COLUMN domain_folded VARCHAR(320) COLLATE utf8mb4_bin;
UPDATE tenant_domains SET domain_folded = LOWER(domain);
CREATE UNIQUE INDEX tenant_domains_folded ON tenant_domains(domain_folded);

ALTER TABLE user_groups ADD COLUMN name_folded VARCHAR(255) COLLATE utf8mb4_bin;
UPDATE user_groups SET name_folded = LOWER(name);
CREATE UNIQUE INDEX user_groups_tenant_name_folded ON user_groups(tenant_id, name_folded);
