-- Phase 2: interactive user sign-in. MySQL dialect.

-- Entra-style smart lockout.
ALTER TABLE users ADD COLUMN failed_logins BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until BIGINT;

-- Server-wide secrets (e.g. the pairwise subject key). Generated on first use.
CREATE TABLE server_secrets (
    name        VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
    value       LONGBLOB NOT NULL,
    created_at  BIGINT NOT NULL
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Browser sign-in sessions. One browser cookie can hold a session in several
-- tenants, like Entra's ESTSAUTH cookie. Only a hash of the cookie is stored.
CREATE TABLE sessions (
    cookie_hash   VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    tenant_id     VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    user_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    auth_time     BIGINT NOT NULL,
    amr           TEXT NOT NULL,                -- JSON array, e.g. ["pwd"]
    created_at    BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL,
    PRIMARY KEY (cookie_hash, tenant_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE auth_codes (
    code_hash              VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id              VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    client_app_id          TEXT COLLATE utf8mb4_bin NOT NULL,
    redirect_uri           TEXT COLLATE utf8mb4_bin NOT NULL,
    platform               TEXT COLLATE utf8mb4_bin NOT NULL,       -- web | spa | publicClient
    user_id                VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    scope                  TEXT NOT NULL,       -- normalized requested scope string
    nonce                  TEXT,
    code_challenge         TEXT,
    code_challenge_method  TEXT,
    auth_time              BIGINT NOT NULL,
    amr                    TEXT NOT NULL,
    created_at             BIGINT NOT NULL,
    expires_at             BIGINT NOT NULL,
    redeemed_at            BIGINT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Opaque refresh tokens, rotated on every use. `family_id` groups a chain of
-- rotations; replaying a rotated token revokes the whole family.
CREATE TABLE refresh_tokens (
    token_hash      VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    family_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    code_hash       TEXT COLLATE utf8mb4_bin,                       -- the code that started the family
    tenant_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    client_app_id   TEXT COLLATE utf8mb4_bin NOT NULL,
    platform        TEXT COLLATE utf8mb4_bin NOT NULL,
    user_id         VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    scope           TEXT NOT NULL,
    auth_time       BIGINT NOT NULL,
    amr             TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    used_at         BIGINT,
    revoked_at      BIGINT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens(user_id);
