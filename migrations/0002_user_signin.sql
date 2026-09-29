-- Phase 2: interactive user sign-in.

-- Entra-style smart lockout.
ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until INTEGER;

-- Server-wide secrets (e.g. the pairwise subject key). Generated on first use.
CREATE TABLE server_secrets (
    name        TEXT PRIMARY KEY,
    value       BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

-- Browser sign-in sessions. One browser cookie can hold a session in several
-- tenants, like Entra's ESTSAUTH cookie. Only a hash of the cookie is stored.
CREATE TABLE sessions (
    cookie_hash   TEXT NOT NULL,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time     INTEGER NOT NULL,
    amr           TEXT NOT NULL,                -- JSON array, e.g. ["pwd"]
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    PRIMARY KEY (cookie_hash, tenant_id)
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE auth_codes (
    code_hash              TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_app_id          TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    platform               TEXT NOT NULL,       -- web | spa | publicClient
    user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope                  TEXT NOT NULL,       -- normalized requested scope string
    nonce                  TEXT,
    code_challenge         TEXT,
    code_challenge_method  TEXT,
    auth_time              INTEGER NOT NULL,
    amr                    TEXT NOT NULL,
    created_at             INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    redeemed_at            INTEGER
);

-- Opaque refresh tokens, rotated on every use. `family_id` groups a chain of
-- rotations; replaying a rotated token revokes the whole family.
CREATE TABLE refresh_tokens (
    token_hash      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    code_hash       TEXT,                       -- the code that started the family
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_app_id   TEXT NOT NULL,
    platform        TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT NOT NULL,
    auth_time       INTEGER NOT NULL,
    amr             TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    revoked_at      INTEGER
);
CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens(user_id);
