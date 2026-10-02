//! The migration must carry existing directory role assignments across.
//!
//! DELIBERATELY SQLite-ONLY, not an oversight. The tests named `sqlite_*` test
//! migration MECHANICS: they apply `migrations/sqlite/*.sql` by `include_str!`
//! and inspect `sqlite_master`. Both are engine-specific. The postgres and mysql
//! sets are kept in step by `migration_drift.rs` (role arms) and by the
//! per-engine suite run; a per-engine copy of these tests is not worth the
//! maintenance. `effective_bindings_*` is engine-neutral behaviour.
mod common;
use common::*;

#[tokio::test]
async fn sqlite_fresh_database_has_the_new_schema_and_no_old_table() {
    let s = TestServer::start().await;
    if rust_oidc::db::engine_of(&s.pool) != rust_oidc::db::Engine::Sqlite {
        // The other engines' schema is covered by tests/db_migrations.rs.
        eprintln!("skipping: this test inspects sqlite_master");
        return;
    }
    let f = user_fixture(&s).await;

    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_bindings")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "fresh database starts with no bindings");

    // Absence must fail: query sqlite_master for each table by name.
    for table in ["role_bindings", "role_binding_tenants", "admin_sessions"] {
        let found: Option<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master WHERE name = ?")
            .bind(table)
            .fetch_optional(&s.pool)
            .await
            .unwrap();
        assert!(found.is_some(), "{table} should exist");
    }

    // The old table must be gone, so there is only one source of truth.
    let old: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE name = 'directory_role_assignments'")
            .fetch_optional(&s.pool)
            .await
            .unwrap();
    assert!(old.is_none(), "directory_role_assignments should be dropped");

    // users.deleted_at exists (the query errors if not) and defaults to NULL.
    let (deleted_at,): (Option<i64>,) = sqlx::query_as("SELECT deleted_at FROM users WHERE id = ?")
        .bind(&f.user_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(deleted_at, None);
}

/// Storage-shape test, not a migration test: bindings inserted by hand for one
/// principal must expand through `effective_for_user` with separate scopes.
/// The migration itself is covered by the seeded test below.
#[tokio::test]
async fn effective_bindings_keep_two_roles_scopes_separate() {
    use rust_oidc::rbac::{RoleId, Scope};
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    for (id, role, tenant) in [
        ("b-admin", RoleId::GlobalAdministrator, &f.tenant.id),
        ("b-reader", RoleId::GlobalReader, &other.id),
    ] {
        let e = rust_oidc::db::engine_of(&s.pool);
        sqlx::query(rust_oidc::db::sql_stmt(
            e,
            "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
             VALUES (?, 'User', ?, ?, 'tenants', 0)",
        ))
        .bind(id)
        .bind(&f.user_id)
        .bind(role.as_str())
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query(rust_oidc::db::sql_stmt(
            e,
            "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)",
        ))
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
    assert_eq!(
        scope_of(RoleId::GlobalAdministrator),
        Scope::Tenants(vec![f.tenant.id.clone()])
    );
    assert_eq!(scope_of(RoleId::GlobalReader), Scope::Tenants(vec![other.id.clone()]));
}

const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";

/// Runs the real migration SQL over real rows: 0001..0005 by hand, seed the old
/// schema, then 0006. The normal migrator is deliberately not used.
#[tokio::test]
async fn sqlite_migration_keeps_each_role_scoped_to_its_own_tenant_and_promotes_root_admins() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let opts = SqliteConnectOptions::new()
        .filename(dir.path().join("m.db"))
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();

    for sql in [
        include_str!("../migrations/sqlite/0001_init.sql"),
        include_str!("../migrations/sqlite/0002_user_signin.sql"),
        include_str!("../migrations/sqlite/0003_device_code.sql"),
        include_str!("../migrations/sqlite/0004_app_key_credentials.sql"),
        include_str!("../migrations/sqlite/0005_password_grant.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }

    for (id, root) in [("root", 1), ("t1", 0), ("t2", 0), ("t3", 0)] {
        sqlx::query("INSERT INTO tenants (id, name, is_root, created_at) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(id)
            .bind(root)
            .execute(&pool)
            .await
            .unwrap();
    }
    // multi: two roles in two tenants (the escalation case). single: one
    // assignment. rootadmin: Global Admin in the root tenant. tenantadmin:
    // Global Admin in a non-root tenant.
    for (tenant, role, principal) in [
        ("t1", GLOBAL_ADMIN, "multi"),
        ("t2", USER_ADMIN, "multi"),
        ("t3", USER_ADMIN, "single"),
        ("root", GLOBAL_ADMIN, "rootadmin"),
        ("t1", GLOBAL_ADMIN, "tenantadmin"),
        ("t1", GLOBAL_ADMIN, "samerole"),
        ("t2", GLOBAL_ADMIN, "samerole"),
    ] {
        sqlx::query(
            "INSERT INTO directory_role_assignments
             (tenant_id, role_template_id, principal_id, principal_type, created_at)
             VALUES (?, ?, ?, 'User', 0)",
        )
        .bind(tenant)
        .bind(role)
        .bind(principal)
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::raw_sql(include_str!("../migrations/sqlite/0006_admin_rbac.sql"))
        .execute(&pool)
        .await
        .unwrap();

    // (role, scope_kind, sorted tenants) for one principal.
    let shape = |principal: &'static str| {
        let pool = pool.clone();
        async move {
            let rows: Vec<(String, String, String)> = sqlx::query_as(
                "SELECT id, role_id, scope_kind FROM role_bindings WHERE principal_id = ? ORDER BY role_id",
            )
            .bind(principal)
            .fetch_all(&pool)
            .await
            .unwrap();
            let mut out = Vec::new();
            for (id, role, kind) in rows {
                let tenants: Vec<(String,)> = sqlx::query_as(
                    "SELECT tenant_id FROM role_binding_tenants WHERE binding_id = ? ORDER BY tenant_id",
                )
                .bind(id)
                .fetch_all(&pool)
                .await
                .unwrap();
                out.push((role, kind, tenants.into_iter().map(|t| t.0).collect::<Vec<_>>()));
            }
            out
        }
    };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

    assert_eq!(
        shape("multi").await,
        vec![
            ("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["t1"])),
            ("UserAdministrator".to_string(), "tenants".to_string(), s(&["t2"])),
        ],
        "each role keeps only its own tenant"
    );
    assert_eq!(
        shape("single").await,
        vec![("UserAdministrator".to_string(), "tenants".to_string(), s(&["t3"]))]
    );
    assert_eq!(
        shape("rootadmin").await,
        vec![
            ("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["root"])),
            ("PlatformAdministrator".to_string(), "all".to_string(), s(&[])),
        ],
        "a root-tenant Global Administrator is also a platform administrator"
    );
    assert_eq!(
        shape("tenantadmin").await,
        vec![("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["t1"]))],
        "a non-root Global Administrator is not"
    );
    // The same role held in two tenants is ONE binding covering both.
    assert_eq!(
        shape("samerole").await,
        vec![(
            "GlobalAdministrator".to_string(),
            "tenants".to_string(),
            s(&["t1", "t2"])
        )],
        "one binding per (principal, role), holding exactly that pair's tenants"
    );
    let (duplicated,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM (
             SELECT principal_id, role_id FROM role_bindings
             GROUP BY principal_id, role_id HAVING COUNT(*) > 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        duplicated, 0,
        "no (principal, role) pair may have more than one binding"
    );
}
