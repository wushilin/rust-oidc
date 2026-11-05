-- "Set up an authenticator?" at sign-in, with "Not now" (TenantSettings::
-- suggest_mfa_setup). An account that answered "Not now" is not asked again
-- until snoozed_until. Sign-in state, like remembered browsers: written at
-- sign-in (mfa::snooze_setup), not by a transaction.
CREATE TABLE mfa_setup_snoozed (
    user_id       TEXT PRIMARY KEY,
    snoozed_until INTEGER NOT NULL
);
