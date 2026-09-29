-- Phase 1 schema. Modelled on the Entra ID directory: tenants own users, groups,
-- application registrations and service principals. All timestamps are unix seconds.

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,                -- tenant id (tid), GUID
    name        TEXT NOT NULL,
    is_root     INTEGER NOT NULL DEFAULT 0,      -- the platform (system) tenant
    enabled     INTEGER NOT NULL DEFAULT 1,
    settings    TEXT NOT NULL DEFAULT '{}',      -- JSON TenantSettings
    created_at  INTEGER NOT NULL,
    deleted_at  INTEGER
);
CREATE UNIQUE INDEX tenants_single_root ON tenants(is_root) WHERE is_root = 1;

-- Verified domains. Like Entra, a domain belongs to exactly one tenant, which is
-- what makes UPN-based home realm discovery possible later.
CREATE TABLE tenant_domains (
    domain      TEXT PRIMARY KEY COLLATE NOCASE,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX tenant_domains_tenant ON tenant_domains(tenant_id);

CREATE TABLE users (
    id              TEXT PRIMARY KEY,            -- object id (oid)
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    upn             TEXT NOT NULL COLLATE NOCASE,
    email           TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    display_name    TEXT,
    given_name      TEXT,
    family_name     TEXT,
    password_hash   TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (tenant_id, upn)
);

CREATE TABLE groups (
    id            TEXT PRIMARY KEY,              -- object id
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL COLLATE NOCASE,  -- emitted in the `groups` claim
    description   TEXT,
    created_at    INTEGER NOT NULL,
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
    created_at        INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, role_template_id, principal_id)
);

-- Application registration (Entra "App registrations"). Owned by its home tenant.
CREATE TABLE applications (
    id                TEXT PRIMARY KEY,          -- application object id
    app_id            TEXT NOT NULL UNIQUE,      -- client_id, GUID
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name      TEXT NOT NULL,
    sign_in_audience  TEXT NOT NULL DEFAULT 'AzureADMyOrg',
    created_at        INTEGER NOT NULL,
    deleted_at        INTEGER
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
    start_at        INTEGER NOT NULL,
    end_at          INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE app_roles (
    id                    TEXT PRIMARY KEY,
    application_id        TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    value                 TEXT NOT NULL,         -- emitted in the `roles` claim
    display_name          TEXT NOT NULL,
    description           TEXT,
    allowed_member_types  TEXT NOT NULL,         -- JSON array: ["User"], ["Application"] or both
    enabled               INTEGER NOT NULL DEFAULT 1,
    UNIQUE (application_id, value)
);

CREATE TABLE app_scopes (
    id              TEXT PRIMARY KEY,
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    value           TEXT NOT NULL,               -- emitted in the `scp` claim
    display_name    TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'User' CHECK (type IN ('User', 'Admin')),
    enabled         INTEGER NOT NULL DEFAULT 1,
    UNIQUE (application_id, value)
);

-- The application's identity inside a tenant (Entra "Enterprise applications").
-- Today there is exactly one, in the home tenant; multi-tenant apps add more.
CREATE TABLE service_principals (
    id                            TEXT PRIMARY KEY,   -- oid of app-only tokens
    tenant_id                     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id                        TEXT NOT NULL REFERENCES applications(app_id) ON DELETE CASCADE,
    app_role_assignment_required  INTEGER NOT NULL DEFAULT 0,
    enabled                       INTEGER NOT NULL DEFAULT 1,
    created_at                    INTEGER NOT NULL,
    UNIQUE (tenant_id, app_id)
);

CREATE TABLE app_role_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    app_role_id     TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    principal_id    TEXT NOT NULL,
    principal_type  TEXT NOT NULL CHECK (principal_type IN ('User', 'Group', 'ServicePrincipal')),
    created_at      INTEGER NOT NULL,
    UNIQUE (resource_id, app_role_id, principal_id)
);
CREATE INDEX app_role_assignments_principal ON app_role_assignments(principal_id);

-- Token signing keys, shared by all tenants (as in Entra). Each RSA key is
-- wrapped in a self-signed certificate so the JWKS can carry x5c; kid = x5t.
CREATE TABLE signing_keys (
    kid              TEXT PRIMARY KEY,
    private_key_pem  TEXT NOT NULL,
    cert_der         BLOB NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('next', 'active', 'retired')),
    created_at       INTEGER NOT NULL,
    retired_at       INTEGER,
    not_after        INTEGER NOT NULL
);
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys(status) WHERE status = 'active';

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    details     TEXT,
    created_at  INTEGER NOT NULL
);
