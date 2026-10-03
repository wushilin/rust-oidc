-- Named locks for the transaction engine (src/txn).
--
-- A rule that spans many rows -- somebody must remain a Global Administrator --
-- cannot be protected by locking one of the rows it reads. Every transaction
-- that can affect it locks the named row here first (SELECT ... FOR UPDATE), so
-- such transactions run one at a time. On SQLite a transaction holds the whole
-- database from its start, so the row is only read there.

CREATE TABLE txn_locks (
    name TEXT PRIMARY KEY
);

INSERT INTO txn_locks (name) VALUES ('administrators');
