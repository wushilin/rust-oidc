-- What a deleted group was, so its id still says something in the audit log and
-- in Find by id. A group is deleted outright (its name is free for reuse at
-- once), and this row is all that is left of it.
CREATE TABLE deleted_groups (
    id          VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id   VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    name        VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
    description TEXT,
    deleted_at  BIGINT NOT NULL
);
CREATE INDEX deleted_groups_tenant ON deleted_groups(tenant_id);
