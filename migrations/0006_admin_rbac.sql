-- Admin console RBAC: a role carries actions, a binding carries the scope.

CREATE TABLE role_bindings (
    id             TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,              -- PrincipalType: User | Group
    principal_id   TEXT NOT NULL,
    role_id        TEXT NOT NULL,              -- RoleId::as_str
    scope_kind     TEXT NOT NULL,              -- ScopeKind: all | tenants
    created_at     INTEGER NOT NULL,
    created_by     TEXT
);
CREATE INDEX role_bindings_principal ON role_bindings(principal_type, principal_id);

CREATE TABLE role_binding_tenants (
    binding_id TEXT NOT NULL REFERENCES role_bindings(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    PRIMARY KEY (binding_id, tenant_id)
);

-- Carry existing directory role assignments across as tenant-scoped bindings.
-- Only User and Group principals: a service principal cannot use the console.
INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
SELECT lower(hex(randomblob(16))), principal_type, principal_id,
       CASE role_template_id
           WHEN '62e90394-69f5-4237-9190-012177145e10' THEN 'GlobalAdministrator'
           WHEN 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' THEN 'GlobalReader'
           WHEN 'fe930be7-5e62-47db-91af-98c3a49a38b1' THEN 'UserAdministrator'
           WHEN 'fdd7a751-b60b-444a-984c-02652fe8fa1c' THEN 'GroupsAdministrator'
           WHEN '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' THEN 'ApplicationAdministrator'
           WHEN '158c047a-c907-4556-b7ef-446551a6b5f7' THEN 'CloudApplicationAdministrator'
           WHEN 'e8611ab8-c189-46e8-94e1-60213ab1f814' THEN 'PrivilegedRoleAdministrator'
       END,
       'tenants', created_at, 'migration'
FROM directory_role_assignments
WHERE principal_type IN ('User', 'Group')
  AND role_template_id IN (
      '62e90394-69f5-4237-9190-012177145e10','f2ef992c-3afb-46b9-b7cf-a126ee74c451',
      'fe930be7-5e62-47db-91af-98c3a49a38b1','fdd7a751-b60b-444a-984c-02652fe8fa1c',
      '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7',
      'e8611ab8-c189-46e8-94e1-60213ab1f814');

-- A binding collects only the tenants of the assignment that produced it: the
-- join key includes the role, or a principal holding different roles in
-- different tenants would gain every tenant on every role.
INSERT INTO role_binding_tenants (binding_id, tenant_id)
SELECT b.id, d.tenant_id
FROM role_bindings b
JOIN directory_role_assignments d
  ON  d.principal_id   = b.principal_id
  AND d.principal_type = b.principal_type
  AND b.role_id = CASE d.role_template_id
        WHEN '62e90394-69f5-4237-9190-012177145e10' THEN 'GlobalAdministrator'
        WHEN 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' THEN 'GlobalReader'
        WHEN 'fe930be7-5e62-47db-91af-98c3a49a38b1' THEN 'UserAdministrator'
        WHEN 'fdd7a751-b60b-444a-984c-02652fe8fa1c' THEN 'GroupsAdministrator'
        WHEN '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' THEN 'ApplicationAdministrator'
        WHEN '158c047a-c907-4556-b7ef-446551a6b5f7' THEN 'CloudApplicationAdministrator'
        WHEN 'e8611ab8-c189-46e8-94e1-60213ab1f814' THEN 'PrivilegedRoleAdministrator'
      END
WHERE b.created_by = 'migration';

-- The platform administrators are the Global Administrators of the root tenant.
-- Nothing else can create a binding on a migrated deployment, so without this
-- nobody could create or assume a tenant.
INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
SELECT DISTINCT lower(hex(randomblob(16))), d.principal_type, d.principal_id,
       'PlatformAdministrator', 'all', d.created_at, 'migration'
FROM directory_role_assignments d
JOIN tenants t ON t.id = d.tenant_id AND t.is_root = 1
WHERE d.principal_type IN ('User', 'Group')
  AND d.role_template_id = '62e90394-69f5-4237-9190-012177145e10';

DROP TABLE directory_role_assignments;

-- The console's own session: not tenant-scoped, and records any assumed tenant.
CREATE TABLE admin_sessions (
    cookie_hash   TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    home_tenant   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    acting_tenant TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX admin_sessions_expires ON admin_sessions(expires_at);

-- Soft delete for users, mirroring applications.deleted_at.
ALTER TABLE users ADD COLUMN deleted_at INTEGER;
