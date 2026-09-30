-- Case-insensitive identity is done in the application (util::fold), not by
-- collation, so SQLite, Postgres and MySQL agree. Each case-insensitive column
-- gets a folded twin with a plain unique index; the display column keeps the
-- original casing.
--
-- The folded columns are VARCHAR (MySQL cannot index TEXT without a prefix
-- length) and utf8mb4_bin: under the table's _ai_ci default, `e` and `é` would
-- compare equal and two different accounts would collide.

-- GROUPS is a reserved word in MySQL 8.0.2+; rename so no statement needs backticks.
RENAME TABLE `groups` TO user_groups;

ALTER TABLE users ADD COLUMN upn_folded VARCHAR(320) COLLATE utf8mb4_bin;
UPDATE users SET upn_folded = LOWER(upn);
CREATE UNIQUE INDEX users_tenant_upn_folded ON users(tenant_id, upn_folded);

ALTER TABLE tenant_domains ADD COLUMN domain_folded VARCHAR(320) COLLATE utf8mb4_bin;
UPDATE tenant_domains SET domain_folded = LOWER(domain);
CREATE UNIQUE INDEX tenant_domains_folded ON tenant_domains(domain_folded);

ALTER TABLE user_groups ADD COLUMN name_folded VARCHAR(255) COLLATE utf8mb4_bin;
UPDATE user_groups SET name_folded = LOWER(name);
CREATE UNIQUE INDEX user_groups_tenant_name_folded ON user_groups(tenant_id, name_folded);
