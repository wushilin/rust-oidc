-- What a deleted group was, so its id still says something in the audit log and
-- in Find by id. A group is deleted outright (its name is free for reuse at
-- once), and this row is all that is left of it.
CREATE TABLE deleted_groups (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    deleted_at  INTEGER NOT NULL
);
CREATE INDEX deleted_groups_tenant ON deleted_groups(tenant_id);
