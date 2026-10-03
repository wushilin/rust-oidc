-- Multi-factor authentication with an authenticator app (TOTP, RFC 6238).

-- Whether a user must use MFA: NULL follows the tenant, otherwise 'Required' or
-- 'NotRequired' (MfaPolicy::as_str).
ALTER TABLE users ADD COLUMN mfa_policy TEXT;

-- An application that requires MFA of everyone signing in to it, on top of the
-- user's and the tenant's own setting.
ALTER TABLE service_principals ADD COLUMN mfa_required BOOLEAN NOT NULL DEFAULT FALSE;

-- A user's authenticator: the shared secret, as is (the database is the thing to
-- protect), and the last 30-second step a code was accepted for, so the same code
-- is not accepted twice.
CREATE TABLE user_totp (
    user_id     TEXT PRIMARY KEY,
    secret      TEXT NOT NULL,
    enrolled_at BIGINT NOT NULL,
    last_step   BIGINT NOT NULL DEFAULT 0
);

-- One-time recovery codes, hashed: the server only ever compares them.
CREATE TABLE user_recovery_codes (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    used_at     BIGINT
);
CREATE INDEX user_recovery_codes_user ON user_recovery_codes(user_id);

-- A sign-in that has passed its password and waits for its second factor, or for
-- an authenticator to be set up. The ticket travels in the page's form; only its
-- hash is stored. An enrolment carries the secret being set up, so the code shown
-- in the authenticator stays the same across a mistyped attempt.
CREATE TABLE mfa_pending (
    ticket_hash   TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    enroll_secret TEXT,
    attempts      BIGINT NOT NULL DEFAULT 0,
    created_at    BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL
);
