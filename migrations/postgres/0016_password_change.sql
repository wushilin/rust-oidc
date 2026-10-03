-- "Must change password at next sign-in", and the passwords a user has had.

-- Set by an administrator's reset (and a new account made in the console): the
-- user chooses their own password before anything is issued to them.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Argon2 hashes of the passwords a user has had, newest first by created_at, so a
-- new one can be refused for being one of the last few (a tenant setting).
CREATE TABLE password_history (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    BIGINT NOT NULL
);
CREATE INDEX password_history_user ON password_history(user_id, created_at);
