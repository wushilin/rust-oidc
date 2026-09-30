-- Single-row mutex for keys::rotate. Locking the active signing key itself is
-- not enough: once a rotation commits, that row is no longer "active", so a
-- waiting rotation would re-run its UPDATE, match nothing, and hold no lock.
-- This row always exists, so the UPDATE always locks it.
CREATE TABLE key_rotation_lock (id INTEGER PRIMARY KEY, held_at BIGINT NOT NULL);
INSERT INTO key_rotation_lock (id, held_at) VALUES (1, 0);
