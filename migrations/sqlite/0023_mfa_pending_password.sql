-- A sign-in waiting for its code whose password was wrong (decision 55). The
-- code page is shown anyway, so a sign-in never says which of the password and
-- the code was wrong, and the attempt counts toward lockout only when exactly
-- one of them is right. Every other pending step had a right password.
ALTER TABLE mfa_pending ADD COLUMN password_right INTEGER NOT NULL DEFAULT 1;
