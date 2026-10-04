-- The built-in Auth API (src/auth_api.rs): which applications an administrator
-- has granted one of its application permissions, e.g. Credentials.Verify.
-- The Auth API is not a registered application, so a grant names the client's
-- service principal and the permission by its value (AuthApiPermission::as_str).

CREATE TABLE auth_api_grants (
    client_sp_id    VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    permission      VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    tenant_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    created_at      BIGINT NOT NULL,
    PRIMARY KEY (client_sp_id, permission),
    FOREIGN KEY (client_sp_id) REFERENCES service_principals(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
