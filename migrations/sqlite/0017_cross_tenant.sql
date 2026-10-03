-- Signing in to an application of another tenant.
--
-- An application may accept accounts of other tenants, as long as each is
-- assigned to it (directly, or through an assigned group of their tenant). The
-- account's own tenant decides whether its accounts may do that at all: a
-- tenant default (in the tenant's settings) and a per-user override here.

ALTER TABLE service_principals ADD COLUMN accept_other_tenants INTEGER NOT NULL DEFAULT 0;

-- NULL follows the tenant's default; otherwise 'Allow' or 'Disallow'
-- (CrossTenantPolicy::as_str).
ALTER TABLE users ADD COLUMN cross_tenant_policy TEXT;
