-- audit_log is append-only and unbounded, and had no index in any engine. The
-- admin console reads it by tenant and time, and a user's own history by target.
-- Indexing now is far cheaper than indexing a large table later.
CREATE INDEX audit_log_tenant_created ON audit_log(tenant_id, created_at);
CREATE INDEX audit_log_tenant_action_created ON audit_log(tenant_id, action, created_at);
CREATE INDEX audit_log_target ON audit_log(target);
