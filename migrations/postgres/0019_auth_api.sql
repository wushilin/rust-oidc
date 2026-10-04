-- The built-in Auth API (src/auth_api.rs): which applications an administrator
-- has granted one of its application permissions, e.g. Credentials.Verify.
-- The Auth API is not a registered application, so a grant names the client's
-- service principal and the permission by its value (AuthApiPermission::as_str).

CREATE TABLE auth_api_grants (
    client_sp_id    TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    permission      TEXT NOT NULL,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at      BIGINT NOT NULL,
    PRIMARY KEY (client_sp_id, permission)
);
