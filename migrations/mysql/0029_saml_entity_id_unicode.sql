-- An Entity ID may again hold any characters, as it could before 0027 made the
-- column ASCII: up to 1024 of them (SAML Metadata 2.3.2), which as utf8mb4 is
-- more than InnoDB's 3072-byte key limit. So the keys hold a SHA-256 digest of
-- the identifier instead of the identifier: the primary key, and the
-- tenant-wide unique index a request's Issuer must be unique under. Queries
-- still compare the full identifier, helped by a prefix index.
ALTER TABLE app_saml_identifiers
    DROP PRIMARY KEY,
    DROP INDEX tenant_id,
    MODIFY entity_id VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
    ADD COLUMN entity_id_digest BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(entity_id, 256))) STORED NOT NULL,
    ADD PRIMARY KEY (application_id, entity_id_digest),
    ADD UNIQUE INDEX app_saml_identifiers_tenant_entity (tenant_id, entity_id_digest),
    ADD INDEX app_saml_identifiers_tenant (tenant_id, entity_id(256));
