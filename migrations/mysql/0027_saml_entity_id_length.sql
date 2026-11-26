-- SAML allows an Entity ID of 1024 characters (SAML Metadata 2.3.2), and the
-- column held 512. Identifiers are ASCII (the storage layer refuses others, as
-- a URI is ASCII), so the column becomes ASCII: 1024 bytes keeps the primary
-- key and the tenant-wide unique index within InnoDB's 3072-byte key limit,
-- which 1024 utf8mb4 characters would not.
ALTER TABLE app_saml_identifiers MODIFY entity_id VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
