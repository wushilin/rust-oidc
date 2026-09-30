-- Certificate credentials for confidential clients (private_key_jwt).
--
-- The client signs a short-lived JWT assertion with the private key; we hold
-- only the certificate. `key_id` is the Entra-style thumbprint,
-- base64url(SHA-1(cert DER)), which the assertion carries as `x5t` (or `kid`).
CREATE TABLE app_key_credentials (
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    key_id         TEXT NOT NULL,
    display_name   TEXT,
    cert_der       BYTEA NOT NULL,
    public_n       BYTEA NOT NULL,
    public_e       BYTEA NOT NULL,
    created_at     BIGINT NOT NULL,
    not_before     BIGINT NOT NULL,
    not_after      BIGINT NOT NULL,
    PRIMARY KEY (application_id, key_id)
);

-- Replay protection for client assertions: a `jti` may be presented once while
-- the assertion is still within its lifetime. Rows are pruned once expired.
CREATE TABLE client_assertion_jti (
    jti           TEXT NOT NULL,
    client_app_id TEXT NOT NULL,
    expires_at    BIGINT NOT NULL,
    PRIMARY KEY (jti, client_app_id)
);
CREATE INDEX client_assertion_jti_expires ON client_assertion_jti(expires_at);
