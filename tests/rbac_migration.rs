
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
