-- SAML allows an Entity ID of 1024 characters (SAML Metadata 2.3.2). The
-- column is TEXT here, so nothing changes; MySQL widens its column in this
-- migration. Identifiers are ASCII, so an index entry stays at 1024 bytes.
SELECT 1;
