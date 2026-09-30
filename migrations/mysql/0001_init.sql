-- Phase 1 schema, MySQL dialect. Modelled on the Entra ID directory: tenants own
-- users, groups, application registrations and service principals. All
-- timestamps are unix seconds.
--
-- Dialect notes: every column that is keyed, indexed or referenced is a bounded
-- VARCHAR (ids are GUID strings: VARCHAR(64); hashes VARCHAR(128); UPNs and
-- domains VARCHAR(320)). Free-form columns stay TEXT. MySQL has no partial
-- indexes, so "at most one row where X" is a unique index over a generated
-- column that is NULL for every other row. Booleans are TINYINT(1). MySQL string
-- comparison is case-insensitive under its default collation, so NOCASE is dropped.
-- `groups` is a reserved word in MySQL 8, hence the backticks.

CREATE TABLE tenants (
    id          VARCHAR(64) PRIMARY KEY,         -- tenant id (tid), GUID
    name        TEXT NOT NULL,
    is_root     TINYINT(1) NOT NULL DEFAULT 0,   -- the platform (system) tenant
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    settings    TEXT NOT NULL DEFAULT ('{}'),    -- JSON TenantSettings
    created_at  BIGINT NOT NULL,
    deleted_at  BIGINT,
    single_root TINYINT GENERATED ALWAYS AS (CASE WHEN is_root = 1 THEN 1 END) STORED
);
CREATE UNIQUE INDEX tenants_single_root ON tenants(single_root);

-- Verified domains. Like Entra, a domain belongs to exactly one tenant, which is
-- what makes UPN-based home realm discovery possible later.
CREATE TABLE tenant_domains (
    domain      VARCHAR(320) PRIMARY KEY,
    tenant_id   VARCHAR(64) NOT NULL,
    is_default  TINYINT(1) NOT NULL DEFAULT 0,
    created_at  BIGINT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX tenant_domains_tenant ON tenant_domains(tenant_id);

CREATE TABLE users (
    id              VARCHAR(64) PRIMARY KEY,     -- object id (oid)
    tenant_id       VARCHAR(64) NOT NULL,
    upn             VARCHAR(320) NOT NULL,
    email           TEXT,
    email_verified  TINYINT(1) NOT NULL DEFAULT 0,
    display_name    TEXT,
    given_name      TEXT,
    family_name     TEXT,
    password_hash   TEXT,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL,
    UNIQUE (tenant_id, upn),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE `groups` (
    id            VARCHAR(64) PRIMARY KEY,       -- object id
    tenant_id     VARCHAR(64) NOT NULL,
    name          VARCHAR(255) NOT NULL,         -- emitted in the `groups` claim
    description   TEXT,
    created_at    BIGINT NOT NULL,
    UNIQUE (tenant_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE group_members (
    group_id    VARCHAR(64) NOT NULL,
    user_id     VARCHAR(64) NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Built-in directory roles (Global Administrator, ...). role_template_id is
-- Microsoft's well-known template GUID; emitted in the `wids` claim.
CREATE TABLE directory_role_assignments (
    tenant_id         VARCHAR(64) NOT NULL,
    role_template_id  VARCHAR(64) NOT NULL,
    principal_id      VARCHAR(64) NOT NULL,
    principal_type    VARCHAR(32) NOT NULL,
    created_at        BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, role_template_id, principal_id),
    CHECK (principal_type IN ('User', 'Group', 'ServicePrincipal')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Application registration (Entra "App registrations"). Owned by its home tenant.
CREATE TABLE applications (
    id                VARCHAR(64) PRIMARY KEY,   -- application object id
    app_id            VARCHAR(64) NOT NULL UNIQUE, -- client_id, GUID
    tenant_id         VARCHAR(64) NOT NULL,
    display_name      TEXT NOT NULL,
    sign_in_audience  VARCHAR(64) NOT NULL DEFAULT 'AzureADMyOrg',
    created_at        BIGINT NOT NULL,
    deleted_at        BIGINT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE app_identifier_uris (
    application_id  VARCHAR(64) NOT NULL,
    tenant_id       VARCHAR(64) NOT NULL,
    uri             VARCHAR(512) NOT NULL,
    PRIMARY KEY (tenant_id, uri),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

CREATE TABLE app_redirect_uris (
    application_id  VARCHAR(64) NOT NULL,
    platform        VARCHAR(32) NOT NULL,
    uri             VARCHAR(512) NOT NULL,
    PRIMARY KEY (application_id, platform, uri),
    CHECK (platform IN ('web', 'spa', 'publicClient')),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Client secrets (Entra "passwordCredentials"). Secrets are high-entropy random
-- strings, so a SHA-256 hash is sufficient; only the hint is kept in clear.
CREATE TABLE app_secrets (
    key_id          VARCHAR(64) PRIMARY KEY,
    application_id  VARCHAR(64) NOT NULL,
    display_name    TEXT,
    hint            TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    start_at        BIGINT NOT NULL,
    end_at          BIGINT NOT NULL,
    created_at      BIGINT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

CREATE TABLE app_roles (
    id                    VARCHAR(64) PRIMARY KEY,
    application_id        VARCHAR(64) NOT NULL,
    value                 VARCHAR(255) NOT NULL, -- emitted in the `roles` claim
    display_name          TEXT NOT NULL,
    description           TEXT,
    allowed_member_types  TEXT NOT NULL,         -- JSON array: ["User"], ["Application"] or both
    enabled               TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE (application_id, value),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

CREATE TABLE app_scopes (
    id              VARCHAR(64) PRIMARY KEY,
    application_id  VARCHAR(64) NOT NULL,
    value           VARCHAR(255) NOT NULL,       -- emitted in the `scp` claim
    display_name    TEXT NOT NULL,
    type            VARCHAR(16) NOT NULL DEFAULT 'User',
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE (application_id, value),
    CHECK (type IN ('User', 'Admin')),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- The application's identity inside a tenant (Entra "Enterprise applications").
-- Today there is exactly one, in the home tenant; multi-tenant apps add more.
CREATE TABLE service_principals (
    id                            VARCHAR(64) PRIMARY KEY, -- oid of app-only tokens
    tenant_id                     VARCHAR(64) NOT NULL,
    app_id                        VARCHAR(64) NOT NULL,
    app_role_assignment_required  TINYINT(1) NOT NULL DEFAULT 0,
    enabled                       TINYINT(1) NOT NULL DEFAULT 1,
    created_at                    BIGINT NOT NULL,
    UNIQUE (tenant_id, app_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES applications(app_id) ON DELETE CASCADE
);

CREATE TABLE app_role_assignments (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    resource_id     VARCHAR(64) NOT NULL,
    app_role_id     VARCHAR(64) NOT NULL,
    principal_id    VARCHAR(64) NOT NULL,
    principal_type  VARCHAR(32) NOT NULL,
    created_at      BIGINT NOT NULL,
    UNIQUE (resource_id, app_role_id, principal_id),
    CHECK (principal_type IN ('User', 'Group', 'ServicePrincipal')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES service_principals(id) ON DELETE CASCADE,
    FOREIGN KEY (app_role_id) REFERENCES app_roles(id) ON DELETE CASCADE
);
CREATE INDEX app_role_assignments_principal ON app_role_assignments(principal_id);

-- Token signing keys, shared by all tenants (as in Entra). Each RSA key is
-- wrapped in a self-signed certificate so the JWKS can carry x5c; kid = x5t.
CREATE TABLE signing_keys (
    kid              VARCHAR(64) PRIMARY KEY,
    private_key_pem  TEXT NOT NULL,
    cert_der         LONGBLOB NOT NULL,
    status           VARCHAR(16) NOT NULL,
    created_at       BIGINT NOT NULL,
    retired_at       BIGINT,
    not_after        BIGINT NOT NULL,
    single_active    TINYINT GENERATED ALWAYS AS (CASE WHEN status = 'active' THEN 1 END) STORED,
    CHECK (status IN ('next', 'active', 'retired'))
);
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys(single_active);

CREATE TABLE audit_log (
    id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tenant_id   VARCHAR(64),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    details     TEXT,
    created_at  BIGINT NOT NULL
);
