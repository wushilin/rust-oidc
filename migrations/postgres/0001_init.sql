-- Phase 1 schema. Modelled on the Entra ID directory: tenants own users, groups,
-- application registrations and service principals. All timestamps are unix seconds.

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,                -- tenant id (tid), GUID
    name        TEXT NOT NULL,
    is_root     BOOLEAN NOT NULL DEFAULT FALSE,      -- the platform (system) tenant
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    settings    TEXT NOT NULL DEFAULT '{}',      -- JSON TenantSettings
    created_at  BIGINT NOT NULL,
    deleted_at  BIGINT
);
CREATE UNIQUE INDEX tenants_single_root ON tenants(is_root) WHERE is_root;

-- Verified domains. Like Entra, a domain belongs to exactly one tenant, which is
-- what makes UPN-based home realm discovery possible later.
CREATE TABLE tenant_domains (
    domain      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  BIGINT NOT NULL
);
CREATE INDEX tenant_domains_tenant ON tenant_domains(tenant_id);

CREATE TABLE users (
    id              TEXT PRIMARY KEY,            -- object id (oid)
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    upn             TEXT NOT NULL,
    email           TEXT,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    display_name    TEXT,
    given_name      TEXT,
    family_name     TEXT,
    password_hash   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL,
    UNIQUE (tenant_id, upn)
);

CREATE TABLE groups (
    id            TEXT PRIMARY KEY,              -- object id
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,  -- emitted in the `groups` claim
    description   TEXT,
    created_at    BIGINT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE group_members (
    group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

-- Built-in directory roles (Global Administrator, ...). role_template_id is
-- Microsoft's well-known template GUID; emitted in the `wids` claim.
CREATE TABLE directory_role_assignments (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_template_id  TEXT NOT NULL,
    principal_id      TEXT NOT NULL,
    principal_type    TEXT NOT NULL CHECK (principal_type IN ('User', 'Group', 'ServicePrincipal')),
    created_at        BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, role_template_id, principal_id)
);

-- Application registration (Entra "App registrations"). Owned by its home tenant.
CREATE TABLE applications (
    id                TEXT PRIMARY KEY,          -- application object id
    app_id            TEXT NOT NULL UNIQUE,      -- client_id, GUID
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name      TEXT NOT NULL,
    sign_in_audience  TEXT NOT NULL DEFAULT 'AzureADMyOrg',
    created_at        BIGINT NOT NULL,
    deleted_at        BIGINT
);

CREATE TABLE app_identifier_uris (
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL,
    uri             TEXT NOT NULL,
    PRIMARY KEY (tenant_id, uri)
);

CREATE TABLE app_redirect_uris (
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL CHECK (platform IN ('web', 'spa', 'publicClient')),
    uri             TEXT NOT NULL,
    PRIMARY KEY (application_id, platform, uri)
);

-- Client secrets (Entra "passwordCredentials"). Secrets are high-entropy random
-- strings, so a SHA-256 hash is sufficient; only the hint is kept in clear.
CREATE TABLE app_secrets (
    key_id          TEXT PRIMARY KEY,
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    display_name    TEXT,
    hint            TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    start_at        BIGINT NOT NULL,
    end_at          BIGINT NOT NULL,
    created_at      BIGINT NOT NULL
);

CREATE TABLE app_roles (
    id                    TEXT PRIMARY KEY,
    application_id        TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    value                 TEXT NOT NULL,         -- emitted in the `roles` claim
    display_name          TEXT NOT NULL,
    description           TEXT,
    allowed_member_types  TEXT NOT NULL,         -- JSON array: ["User"], ["Application"] or both
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (application_id, value)
);

CREATE TABLE app_scopes (
    id              TEXT PRIMARY KEY,
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    value           TEXT NOT NULL,               -- emitted in the `scp` claim
    display_name    TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'User' CHECK (type IN ('User', 'Admin')),
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (application_id, value)
);

-- The application's identity inside a tenant (Entra "Enterprise applications").
-- Today there is exactly one, in the home tenant; multi-tenant apps add more.
CREATE TABLE service_principals (
    id                            TEXT PRIMARY KEY,   -- oid of app-only tokens
    tenant_id                     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id                        TEXT NOT NULL REFERENCES applications(app_id) ON DELETE CASCADE,
    app_role_assignment_required  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled                       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                    BIGINT NOT NULL,
    UNIQUE (tenant_id, app_id)
);

CREATE TABLE app_role_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    app_role_id     TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    principal_id    TEXT NOT NULL,
    principal_type  TEXT NOT NULL CHECK (principal_type IN ('User', 'Group', 'ServicePrincipal')),
    created_at      BIGINT NOT NULL,
    UNIQUE (resource_id, app_role_id, principal_id)
);
CREATE INDEX app_role_assignments_principal ON app_role_assignments(principal_id);

-- Token signing keys, shared by all tenants (as in Entra). Each RSA key is
-- wrapped in a self-signed certificate so the JWKS can carry x5c; kid = x5t.
CREATE TABLE signing_keys (
    kid              TEXT PRIMARY KEY,
    private_key_pem  TEXT NOT NULL,
    cert_der         BYTEA NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('next', 'active', 'retired')),
    created_at       BIGINT NOT NULL,
    retired_at       BIGINT,
    not_after        BIGINT NOT NULL
);
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys(status) WHERE status = 'active';

CREATE TABLE audit_log (
    id          BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    tenant_id   TEXT,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    details     TEXT,
    created_at  BIGINT NOT NULL
);
