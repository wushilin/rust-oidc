-- Resource owner password credentials (ROPC) is opt-in per application.
--
-- The grant hands the user's password to the client, cannot do MFA and defeats
-- conditional access, so it is off unless an administrator turns it on.
ALTER TABLE applications ADD COLUMN allow_password_grant INTEGER NOT NULL DEFAULT 0;
