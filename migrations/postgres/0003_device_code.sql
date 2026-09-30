-- Device authorization grant (RFC 8628), in Entra's shape.
--
-- The device polls with `device_code` while the user approves in a browser
-- using the short, human-readable `user_code`. Only the hash of the device
-- code is stored, as for auth codes and refresh tokens.
CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_app_id    TEXT NOT NULL,
    scope            TEXT NOT NULL,
    status           TEXT NOT NULL,             -- DeviceStatus: pending | approved | denied
    user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
    auth_time        BIGINT,
    amr              TEXT,
    interval_secs    BIGINT NOT NULL,
    created_at       BIGINT NOT NULL,
    expires_at       BIGINT NOT NULL,
    last_polled_at   BIGINT,
    redeemed_at      BIGINT
);
CREATE INDEX device_codes_user_code ON device_codes(user_code);
CREATE INDEX device_codes_expires ON device_codes(expires_at);
