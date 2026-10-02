-- Console roles, redefined: one Global Administrator role that is everything, and
-- tenant roles (administrator or viewer of the tenant, or of its users, groups or
-- applications) that apply to the tenant their holder belongs to.
--
-- Existing bindings are carried across in place. The statements are the same on
-- every engine; a subquery on the table being changed goes through a derived
-- table, which MySQL requires.

-- A tenant-scoped platform role granted nothing.
DELETE FROM role_binding_tenants WHERE binding_id IN
    (SELECT id FROM role_bindings WHERE role_id = 'PlatformAdministrator' AND scope_kind = 'tenants');
DELETE FROM role_bindings WHERE role_id = 'PlatformAdministrator' AND scope_kind = 'tenants';

-- The platform role is folded into Global Administrator. Whoever held both keeps one.
DELETE FROM role_bindings
WHERE role_id = 'PlatformAdministrator' AND scope_kind = 'all'
  AND principal_id IN (SELECT principal_id FROM
        (SELECT principal_id FROM role_bindings
         WHERE role_id = 'GlobalAdministrator' AND scope_kind = 'all') held);
UPDATE role_bindings SET role_id = 'GlobalAdministrator'
WHERE role_id = 'PlatformAdministrator' AND scope_kind = 'all';

-- Global Administrator of named tenants was a tenant's administrator.
UPDATE role_bindings SET role_id = 'TenantAdministrator'
WHERE role_id = 'GlobalAdministrator' AND scope_kind = 'tenants';
-- Whoever could grant roles in a tenant could already grant themselves all of it.
UPDATE role_bindings SET role_id = 'TenantAdministrator' WHERE role_id = 'PrivilegedRoleAdministrator';
UPDATE role_bindings SET role_id = 'ApplicationAdministrator' WHERE role_id = 'CloudApplicationAdministrator';
UPDATE role_bindings SET role_id = 'TenantViewer' WHERE role_id = 'GlobalReader';

-- Every role but Global Administrator now applies to its holder's own tenant.
-- Drop the tenants that are not the holder's own ...
DELETE FROM role_binding_tenants
WHERE NOT EXISTS (
    SELECT 1 FROM role_bindings b
    LEFT JOIN users u ON b.principal_type = 'User' AND u.id = b.principal_id
    LEFT JOIN user_groups g ON b.principal_type = 'Group' AND g.id = b.principal_id
    WHERE b.id = role_binding_tenants.binding_id
      AND COALESCE(u.tenant_id, g.tenant_id) = role_binding_tenants.tenant_id);
-- ... turn "every tenant" into the holder's own ...
INSERT INTO role_binding_tenants (binding_id, tenant_id)
SELECT b.id, COALESCE(u.tenant_id, g.tenant_id)
FROM role_bindings b
LEFT JOIN users u ON b.principal_type = 'User' AND u.id = b.principal_id
LEFT JOIN user_groups g ON b.principal_type = 'Group' AND g.id = b.principal_id
WHERE b.scope_kind = 'all' AND b.role_id <> 'GlobalAdministrator'
  AND COALESCE(u.tenant_id, g.tenant_id) IS NOT NULL;
UPDATE role_bindings SET scope_kind = 'tenants'
WHERE scope_kind = 'all' AND role_id <> 'GlobalAdministrator';
-- ... and remove what is left applying to nothing.
DELETE FROM role_bindings
WHERE scope_kind = 'tenants'
  AND NOT EXISTS (SELECT 1 FROM role_binding_tenants r WHERE r.binding_id = role_bindings.id);
