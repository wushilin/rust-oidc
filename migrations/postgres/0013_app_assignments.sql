-- Who is assigned to an application, apart from which of its roles they hold.
--
-- Until now a user or group was "assigned" by holding at least one app role, so
-- an application with no roles could have nobody assigned to it. An assignment
-- is now its own row; app_role_assignments keeps the roles an assigned principal
-- was given (and, as before, the roles granted to client applications).
CREATE TABLE app_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    principal_id    TEXT NOT NULL,
    principal_type  TEXT NOT NULL CHECK (principal_type IN ('User', 'Group')),
    created_at      BIGINT NOT NULL,
    UNIQUE (resource_id, principal_id)
);
CREATE INDEX app_assignments_principal ON app_assignments(principal_id);

-- Everyone who holds a role is assigned. One row per principal and application;
-- the id is taken from one of their role rows, which needs no id generator and so
-- reads the same on every engine.
INSERT INTO app_assignments (id, tenant_id, resource_id, principal_id, principal_type, created_at)
SELECT MIN(id), MIN(tenant_id), resource_id, principal_id, MIN(principal_type), MIN(created_at)
FROM app_role_assignments
WHERE principal_type IN ('User', 'Group')
GROUP BY resource_id, principal_id;
