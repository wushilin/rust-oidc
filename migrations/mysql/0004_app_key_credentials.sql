-- Certificate credentials for confidential clients (private_key_jwt). MySQL dialect.
--
-- The client signs a short-lived JWT assertion with the private key; we hold
-- only the certificate. `key_id` is the Entra-style thumbprint,
-- base64url(SHA-1(cert DER)), which the assertion carries as `x5t` (or `kid`).
CREATE TABLE app_key_credentials (
    application_id VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    key_id         VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    display_name   TEXT,
    cert_der       LONGBLOB NOT NULL,
    public_n       LONGBLOB NOT NULL,
    public_e       LONGBLOB NOT NULL,
    created_at     BIGINT NOT NULL,
    not_before     BIGINT NOT NULL,
    not_after      BIGINT NOT NULL,
    PRIMARY KEY (application_id, key_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Replay protection for client assertions: a `jti` may be presented once while
-- the assertion is still within its lifetime. Rows are pruned once expired.
CREATE TABLE client_assertion_jti (
    jti           VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
    client_app_id VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    expires_at    BIGINT NOT NULL,
    PRIMARY KEY (jti, client_app_id)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE INDEX client_assertion_jti_expires ON client_assertion_jti(expires_at);
