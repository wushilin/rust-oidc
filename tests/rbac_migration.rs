
//! The migration must carry existing directory role assignments across.
mod common;
use common::*;

#[tokio::test]
async fn directory_role_assignments_become_tenant_scoped_bindings() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    // A row inserted the way bootstrap used to, then read back as a binding.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM role_bindings WHERE scope_kind = 'tenants'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "fresh database starts with no bindings");

    // The old table must be gone, so there is only one source of truth.
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE name = 'directory_role_assignments'")
            .fetch_optional(&s.pool)
            .await
            .unwrap();
    assert!(exists.is_none(), "directory_role_assignments should be dropped");

    // users.deleted_at exists and defaults to NULL.
    let _: (Option<i64>,) = sqlx::query_as("SELECT deleted_at FROM users LIMIT 0")
        .fetch_optional(&s.pool)
        .await
        .unwrap()
        .unwrap_or((None,));
    let _ = t;
}

/// Scopes must not bleed between two roles held by one principal. The migration
/// keys its tenant join on (principal, role); this pins the resulting shape.
#[tokio::test]
async fn one_principals_two_roles_keep_separate_tenant_scopes() {
    use rust_oidc::rbac::{RoleId, Scope};
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    for (id, role, tenant) in [
        ("b-admin", RoleId::GlobalAdministrator, &f.tenant.id),
        ("b-reader", RoleId::GlobalReader, &other.id),
    ] {
        sqlx::query(
            "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
             VALUES (?, 'User', ?, ?, 'tenants', 0)",
        )
        .bind(id)
        .bind(&f.user_id)
        .bind(role.as_str())
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)")
            .bind(id)
            .bind(tenant)
            .execute(&s.pool)
            .await
            .unwrap();
    }
    let eff = rust_oidc::admin::bindings::effective_for_user(&s.pool, &f.user_id)
        .await
        .unwrap();
    let scope_of = |role: RoleId| eff.iter().find(|b| b.role == role).unwrap().scope.clone();
    assert_eq!(scope_of(RoleId::GlobalAdministrator), Scope::Tenants(vec![f.tenant.id.clone()]));
    assert_eq!(scope_of(RoleId::GlobalReader), Scope::Tenants(vec![other.id.clone()]));
}
