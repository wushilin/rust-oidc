-- The admin console's flow tester: one row per authorize request it has sent and
-- has not yet seen come back.
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
    state_hash     TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_app_id  TEXT NOT NULL,
    admin_session  TEXT NOT NULL REFERENCES admin_sessions(cookie_hash) ON DELETE CASCADE,
    response_type  TEXT NOT NULL,              -- ResponseType
    response_mode  TEXT NOT NULL,              -- ResponseMode
    scope          TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    code_verifier  TEXT,
    authorize_url  TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL
);
CREATE INDEX flow_tests_expires ON flow_tests(expires_at);

-- The client the console registers on request so that a flow can be exercised
-- without touching a real app registration. One per tenant; it is an ordinary
-- application object, visible and removable in the applications section, and this
-- table is only how the console recognises it again.
CREATE TABLE flow_test_clients (
    tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
