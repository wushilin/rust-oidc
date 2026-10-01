-- The admin console's flow tester: one row per authorize request it has sent and
-- has not yet seen come back. MySQL dialect.
--
-- The row exists so the callback can *check* the response rather than believe it:
-- the `state` it generated, the `nonce` it asked for, and the PKCE verifier it
-- must present at the token endpoint. All three are request secrets, so the row
-- is keyed by the hash of the state (as auth_codes and device_codes are keyed by
-- the hash of their code) and is deleted the moment the callback uses it or it
-- expires. Nothing that comes back -- no code, no token -- is ever stored.
--
-- `admin_session` is the console session that started the flow, so one
-- administrator's session cannot complete, or read the result of, a flow test
-- started by another. The cascade means signing out discards the pending rows.
CREATE TABLE flow_tests (
    state_hash     VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id      VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    client_app_id  TEXT COLLATE utf8mb4_bin NOT NULL,
    admin_session  VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    response_type  TEXT COLLATE utf8mb4_bin NOT NULL,              -- ResponseType
    response_mode  TEXT COLLATE utf8mb4_bin NOT NULL,              -- ResponseMode
    scope          TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    nonce          TEXT COLLATE utf8mb4_bin NOT NULL,
    code_verifier  TEXT COLLATE utf8mb4_bin,
    authorize_url  TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (admin_session) REFERENCES admin_sessions(cookie_hash) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX flow_tests_expires ON flow_tests(expires_at);

-- The client the console registers on request so that a flow can be exercised
-- without touching a real app registration. One per tenant; it is an ordinary
-- application object, visible and removable in the applications section, and this
-- table is only how the console recognises it again.
CREATE TABLE flow_test_clients (
    tenant_id  VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    app_id     TEXT COLLATE utf8mb4_bin NOT NULL,
    created_at BIGINT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
