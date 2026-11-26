-- Preserve utf8mb4 Entity IDs while allowing the SAML limit of 1024
-- characters. The digest keeps the tenant-wide unique key within InnoDB's
-- key length. Queries still compare the full identifier.
ALTER TABLE app_saml_identifiers
    ADD INDEX app_saml_identifiers_application (application_id),
    ADD INDEX app_saml_identifiers_tenant (tenant_id, entity_id(256));

ALTER TABLE app_saml_identifiers
    DROP PRIMARY KEY,
    DROP INDEX tenant_id,
    MODIFY entity_id VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
    ADD COLUMN entity_id_digest BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(entity_id, 256))) STORED,
    ADD UNIQUE INDEX app_saml_identifiers_tenant_entity (tenant_id, entity_id_digest);
