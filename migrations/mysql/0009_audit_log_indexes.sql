-- audit_log is append-only and unbounded, and had no index in any engine. The
-- admin console reads it by tenant and time, and a user's own history by target.
-- Indexing now is far cheaper than indexing a large table later.
--
-- MySQL cannot index a TEXT column without a prefix length, so the three columns
-- that are indexed here get a definite width first. They hold identifiers and
-- event names, never prose. utf8mb4_bin because every use is an equality match:
-- the default utf8mb4_unicode_ci would make 'cli' and 'CLI' the same actor.
ALTER TABLE audit_log MODIFY actor  VARCHAR(255) COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE audit_log MODIFY action VARCHAR(128) COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE audit_log MODIFY target VARCHAR(255) COLLATE utf8mb4_bin;

CREATE INDEX audit_log_tenant_created ON audit_log(tenant_id, created_at);
CREATE INDEX audit_log_tenant_action_created ON audit_log(tenant_id, action, created_at);
CREATE INDEX audit_log_target ON audit_log(target);
