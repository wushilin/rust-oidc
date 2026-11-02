-- Which groups an application's tokens carry, and groups inside groups.

-- Entra's `groupMembershipClaims` (GroupMembershipClaims::as_str): 'None' (no
-- `groups` claim), 'All' (every group the user is in, nested ones included) or
-- 'ApplicationGroup' (only groups assigned to the application).
ALTER TABLE applications ADD COLUMN group_membership_claims VARCHAR(32) COLLATE utf8mb4_bin NOT NULL DEFAULT 'None';

-- One row per "parent directly contains child": what an administrator did, and
-- the source of truth for nesting. Both groups are of the same tenant. MySQL
-- refuses a CHECK on a column with a cascading foreign key, so "not inside
-- itself" is enforced by the storage layer alone here (src/groups.rs).
CREATE TABLE group_nesting (
    parent_id   VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    child_id    VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    tenant_id   VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (parent_id, child_id),
    FOREIGN KEY (parent_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (child_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX group_nesting_child ON group_nesting(child_id);
CREATE INDEX group_nesting_tenant ON group_nesting(tenant_id);

-- Every group above every group, computed from group_nesting and rebuilt in the
-- same transaction as any change to it; never edited row by row. `depth` is the
-- longest chain of links from ancestor down to descendant. Each group is its own
-- ancestor at depth 0.
CREATE TABLE group_closure (
    ancestor_id    VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    descendant_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    tenant_id      VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    depth          BIGINT NOT NULL,
    PRIMARY KEY (ancestor_id, descendant_id),
    FOREIGN KEY (ancestor_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (descendant_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX group_closure_descendant ON group_closure(descendant_id);

INSERT INTO group_closure (ancestor_id, descendant_id, tenant_id, depth)
SELECT id, id, tenant_id, 0 FROM user_groups;
