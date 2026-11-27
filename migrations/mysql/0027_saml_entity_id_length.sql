-- SAML allows an Entity ID of 1024 characters (SAML Metadata 2.3.2), and the
-- column held 512. As utf8mb4, 1024 characters are more than InnoDB's
-- 3072-byte key limit, so the keys hold a SHA-256 digest of the identifier
-- instead of the identifier: the primary key, and the tenant-wide unique index
-- a request's Issuer must be unique under. Queries still compare the full
-- identifier, helped by a prefix index. One statement, so the table always has
-- a primary key (`sql_require_primary_key`).
ALTER TABLE app_saml_identifiers
    DROP PRIMARY KEY,
    DROP INDEX tenant_id,
    MODIFY entity_id VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
    ADD COLUMN entity_id_digest BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(entity_id, 256))) STORED NOT NULL,
    ADD PRIMARY KEY (application_id, entity_id_digest),
    ADD UNIQUE INDEX app_saml_identifiers_tenant_entity (tenant_id, entity_id_digest),
    ADD INDEX app_saml_identifiers_tenant (tenant_id, entity_id(256));
