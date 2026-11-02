-- Which groups an application's tokens carry, and groups inside groups.

-- Entra's `groupMembershipClaims` (GroupMembershipClaims::as_str): 'None' (no
-- `groups` claim), 'All' (every group the user is in, nested ones included) or
-- 'ApplicationGroup' (only groups assigned to the application).
ALTER TABLE applications ADD COLUMN group_membership_claims TEXT NOT NULL DEFAULT 'None';

-- One row per "parent directly contains child": what an administrator did, and
-- the source of truth for nesting. Both groups are of the same tenant.
CREATE TABLE group_nesting (
    parent_id   TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    child_id    TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (parent_id, child_id),
    CHECK (parent_id <> child_id)
);
CREATE INDEX group_nesting_child ON group_nesting(child_id);
CREATE INDEX group_nesting_tenant ON group_nesting(tenant_id);

-- Every group above every group, computed from group_nesting and rebuilt in the
-- same transaction as any change to it; never edited row by row. `depth` is the
-- longest chain of links from ancestor down to descendant. Each group is its own
-- ancestor at depth 0.
CREATE TABLE group_closure (
    ancestor_id    TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    descendant_id  TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    depth          INTEGER NOT NULL,
    PRIMARY KEY (ancestor_id, descendant_id)
);
CREATE INDEX group_closure_descendant ON group_closure(descendant_id);

INSERT INTO group_closure (ancestor_id, descendant_id, tenant_id, depth)
SELECT id, id, tenant_id, 0 FROM user_groups;
