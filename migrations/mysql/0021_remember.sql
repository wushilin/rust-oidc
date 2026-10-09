-- "Keep me signed in" and "Don't ask again on this device". Both are off until a
-- tenant turns them on (TenantSettings::allow_keep_signed_in, allow_remember_mfa).

-- A session the user asked to keep lasts TenantSettings::KEEP_SIGNED_IN_SECS
-- instead of the tenant's session lifetime. Recorded so that turning the
-- tenant's switch off can cut kept sessions back at once.
ALTER TABLE sessions ADD COLUMN keep_signed_in SMALLINT NOT NULL DEFAULT 0;

-- The choice travels with a sign-in waiting at its second step, so the session
-- made after the code is the kind the user asked for on the password page.
ALTER TABLE mfa_pending ADD COLUMN keep_signed_in SMALLINT NOT NULL DEFAULT 0;

-- A browser on which a user's second factor need not be asked for again until
-- expires_at. The browser holds a random value in a cookie; only its hash is
-- stored. tenant_id is the user's home tenant, whose switch allows it. Sign-in
-- state, like sessions: ended with them (users::revoke_access).
CREATE TABLE mfa_remembered_devices (
    device_hash VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    user_id     VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    tenant_id   VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (device_hash, user_id)
);
CREATE INDEX mfa_remembered_devices_user ON mfa_remembered_devices(user_id);
CREATE INDEX mfa_remembered_devices_tenant ON mfa_remembered_devices(tenant_id);
