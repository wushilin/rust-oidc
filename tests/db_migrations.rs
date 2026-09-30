//! Migration behaviour on every configured engine. These run the real per-engine
//! SQL files over real rows; the normal migrator is deliberately not used.
mod common;

use rust_oidc::db::{Engine, engine_of, is_unique_violation, sql_stmt};

const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";

/// `migrations/<engine>/000N_*.sql` for N in 1..=5, then 0006 separately.
fn before_0006(engine: Engine) -> [&'static str; 5] {
    match engine {
        Engine::Sqlite => [
            include_str!("../migrations/sqlite/0001_init.sql"),
            include_str!("../migrations/sqlite/0002_user_signin.sql"),
            include_str!("../migrations/sqlite/0003_device_code.sql"),
            include_str!("../migrations/sqlite/0004_app_key_credentials.sql"),
            include_str!("../migrations/sqlite/0005_password_grant.sql"),
        ],
        Engine::Postgres => [
            include_str!("../migrations/postgres/0001_init.sql"),
            include_str!("../migrations/postgres/0002_user_signin.sql"),
            include_str!("../migrations/postgres/0003_device_code.sql"),
            include_str!("../migrations/postgres/0004_app_key_credentials.sql"),
            include_str!("../migrations/postgres/0005_password_grant.sql"),
        ],
        Engine::MySql => [
            include_str!("../migrations/mysql/0001_init.sql"),
            include_str!("../migrations/mysql/0002_user_signin.sql"),
            include_str!("../migrations/mysql/0003_device_code.sql"),
            include_str!("../migrations/mysql/0004_app_key_credentials.sql"),
            include_str!("../migrations/mysql/0005_password_grant.sql"),
        ],
    }
}

fn migration_0006(engine: Engine) -> &'static str {
    match engine {
        Engine::Sqlite => include_str!("../migrations/sqlite/0006_admin_rbac.sql"),
        Engine::Postgres => include_str!("../migrations/postgres/0006_admin_rbac.sql"),
        Engine::MySql => include_str!("../migrations/mysql/0006_admin_rbac.sql"),
    }
}

/// The cross-tenant privilege escalation guard in 0006: the join is keyed by role,
/// so a principal holding different roles in different tenants must not gain every
/// tenant on every role.
#[tokio::test]
async fn migration_0006_keeps_each_role_scoped_to_its_own_tenant_and_promotes_root_admins() {
    for engine in Engine::ALL {
        let Some(pool) = common::blank_pool_for(*engine).await else {
            eprintln!("skipping {}: not configured", engine.as_str());
            continue;
        };
        let e = engine_of(&pool);
        assert_eq!(e, *engine);
        for sql in before_0006(e) {
            sqlx::raw_sql(sql)
                .execute(&*pool)
                .await
                .unwrap_or_else(|err| panic!("{}: {err}", e.as_str()));
        }
        for (id, root) in [("root", true), ("t1", false), ("t2", false), ("t3", false)] {
            sqlx::query(sql_stmt(
                e,
                "INSERT INTO tenants (id, name, is_root, created_at) VALUES (?, ?, ?, 0)",
            ))
            .bind(id)
            .bind(id)
            .bind(root)
            .execute(&*pool)
            .await
            .unwrap();
        }
        for (tenant, role, principal) in [
            ("t1", GLOBAL_ADMIN, "multi"),
            ("t2", USER_ADMIN, "multi"),
            ("t3", USER_ADMIN, "single"),
            ("root", GLOBAL_ADMIN, "rootadmin"),
            ("t1", GLOBAL_ADMIN, "tenantadmin"),
            ("t1", GLOBAL_ADMIN, "samerole"),
            ("t2", GLOBAL_ADMIN, "samerole"),
        ] {
            sqlx::query(sql_stmt(
                e,
                "INSERT INTO directory_role_assignments
                 (tenant_id, role_template_id, principal_id, principal_type, created_at)
                 VALUES (?, ?, ?, 'User', 0)",
            ))
            .bind(tenant)
            .bind(role)
            .bind(principal)
            .execute(&*pool)
            .await
            .unwrap();
        }

        sqlx::raw_sql(migration_0006(e))
            .execute(&*pool)
            .await
            .unwrap_or_else(|err| panic!("{}: 0006 failed: {err}", e.as_str()));

        let shape = |principal: &'static str| {
            let pool = (*pool).clone();
            async move {
                let rows: Vec<(String, String, String)> = sqlx::query_as(sql_stmt(
                    e,
                    "SELECT id, role_id, scope_kind FROM role_bindings WHERE principal_id = ? ORDER BY role_id",
                ))
                .bind(principal)
                .fetch_all(&pool)
                .await
                .unwrap();
                let mut out = Vec::new();
                for (id, role, kind) in rows {
                    let tenants: Vec<(String,)> = sqlx::query_as(sql_stmt(
                        e,
                        "SELECT tenant_id FROM role_binding_tenants WHERE binding_id = ? ORDER BY tenant_id",
                    ))
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
        let name = e.as_str();

        assert_eq!(
            shape("multi").await,
            vec![
                ("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["t1"])),
                ("UserAdministrator".to_string(), "tenants".to_string(), s(&["t2"])),
            ],
            "{name}: each role keeps only its own tenant"
        );
        assert_eq!(
            shape("single").await,
            vec![("UserAdministrator".to_string(), "tenants".to_string(), s(&["t3"]))],
            "{name}"
        );
        assert_eq!(
            shape("rootadmin").await,
            vec![
                ("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["root"])),
                ("PlatformAdministrator".to_string(), "all".to_string(), s(&[])),
            ],
            "{name}: a root-tenant Global Administrator is also a platform administrator"
        );
        assert_eq!(
            shape("tenantadmin").await,
            vec![("GlobalAdministrator".to_string(), "tenants".to_string(), s(&["t1"]))],
            "{name}: a non-root Global Administrator is not"
        );
        assert_eq!(
            shape("samerole").await,
            vec![(
                "GlobalAdministrator".to_string(),
                "tenants".to_string(),
                s(&["t1", "t2"])
            )],
            "{name}: one binding per (principal, role), holding exactly that pair's tenants"
        );
        let (duplicated,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM (
                 SELECT principal_id, role_id FROM role_bindings
                 GROUP BY principal_id, role_id HAVING COUNT(*) > 1) AS d",
        )
        .fetch_one(&*pool)
        .await
        .unwrap();
        assert_eq!(
            duplicated, 0,
            "{name}: no (principal, role) pair may have more than one binding"
        );
    }
}

async fn insert_tenant(pool: &rust_oidc::db::DbPool, id: &str, root: bool) -> Result<(), sqlx::Error> {
    sqlx::query(sql_stmt(
        engine_of(pool),
        "INSERT INTO tenants (id, name, is_root, enabled, settings, created_at) VALUES (?, ?, ?, ?, '{}', 0)",
    ))
    .bind(id)
    .bind(id)
    .bind(root)
    .bind(true)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Postgres partial index / MySQL STORED generated column: exactly one root
/// tenant, unlimited non-root tenants.
#[tokio::test]
async fn exactly_one_root_tenant_but_any_number_of_others() {
    for pool in common::all_engine_pools().await {
        let name = engine_of(&pool).as_str();
        insert_tenant(&pool, "root-1", true).await.unwrap();
        for i in 0..5 {
            insert_tenant(&pool, &format!("plain-{i}"), false)
                .await
                .unwrap_or_else(|e| panic!("{name}: non-root tenant {i} refused: {e}"));
        }
        let err = insert_tenant(&pool, "root-2", true)
            .await
            .expect_err("second root must be refused");
        assert!(
            is_unique_violation(&err),
            "{name}: expected a unique violation, got {err:?}"
        );
    }
}

/// Exactly one active signing key, unlimited next/retired ones.
#[tokio::test]
async fn exactly_one_active_signing_key_but_any_number_of_others() {
    async fn insert_key(pool: &rust_oidc::db::DbPool, kid: &str, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query(sql_stmt(
            engine_of(pool),
            "INSERT INTO signing_keys (kid, private_key_pem, cert_der, status, created_at, not_after)
             VALUES (?, 'pem', ?, ?, 0, 0)",
        ))
        .bind(kid)
        .bind(vec![1u8, 2, 3])
        .bind(status)
        .execute(pool)
        .await
        .map(|_| ())
    }
    for pool in common::all_engine_pools().await {
        let name = engine_of(&pool).as_str();
        // `keys::ensure` is deliberately not called: start from an empty table.
        insert_key(&pool, "a1", "active").await.unwrap();
        for i in 0..4 {
            insert_key(&pool, &format!("r{i}"), "retired")
                .await
                .unwrap_or_else(|e| panic!("{name}: retired key {i} refused: {e}"));
            insert_key(&pool, &format!("n{i}"), "next")
                .await
                .unwrap_or_else(|e| panic!("{name}: next key {i} refused: {e}"));
        }
        let err = insert_key(&pool, "a2", "active")
            .await
            .expect_err("second active key must be refused");
        assert!(
            is_unique_violation(&err),
            "{name}: expected a unique violation, got {err:?}"
        );
        // The rotation path retires the active key and promotes another in one go.
        rust_oidc::keys::rotate(&pool)
            .await
            .unwrap_or_else(|e| panic!("{name}: rotate: {e}"));
    }
}

/// A duplicate primary key / unique index surfaces as `is_unique_violation` and
/// a different failure (NOT NULL) does not.
#[tokio::test]
async fn unique_violations_are_recognised_and_other_errors_are_not() {
    for pool in common::all_engine_pools().await {
        let name = engine_of(&pool).as_str();
        insert_tenant(&pool, "dup", false).await.unwrap();
        let dup = insert_tenant(&pool, "dup", false).await.unwrap_err();
        assert!(is_unique_violation(&dup), "{name}: duplicate PK: {dup:?}");

        let null = sqlx::query(sql_stmt(
            engine_of(&pool),
            "INSERT INTO tenants (id, name, created_at) VALUES (?, NULL, 0)",
        ))
        .bind("nn")
        .execute(&*pool)
        .await
        .unwrap_err();
        assert!(
            !is_unique_violation(&null),
            "{name}: NOT NULL misreported as unique: {null:?}"
        );
    }
}

/// `DEFAULT ('{}')` (MySQL 8.0.13+ expression default) and the other column
/// defaults apply when the column is omitted.
#[tokio::test]
async fn column_defaults_apply() {
    for pool in common::all_engine_pools().await {
        let e = engine_of(&pool);
        sqlx::query(sql_stmt(
            e,
            "INSERT INTO tenants (id, name, created_at) VALUES (?, ?, 0)",
        ))
        .bind("d1")
        .bind("d1")
        .execute(&*pool)
        .await
        .unwrap();
        let (settings, enabled, root): (String, rust_oidc::db::Flag, rust_oidc::db::Flag) = sqlx::query_as(sql_stmt(
            e,
            "SELECT settings, enabled, is_root FROM tenants WHERE id = ?",
        ))
        .bind("d1")
        .fetch_one(&*pool)
        .await
        .unwrap();
        assert_eq!(settings, "{}", "{}", e.as_str());
        assert!(bool::from(enabled), "{}: enabled defaults to true", e.as_str());
        assert!(!bool::from(root), "{}: is_root defaults to false", e.as_str());
    }
}

/// Non-ASCII accents must not collapse: the legacy unique constraints and the
/// folded ones are both byte-exact, so `jose` and `josé` are two accounts.
#[tokio::test]
async fn accented_and_plain_identities_are_distinct_on_every_engine() {
    use rust_oidc::users::{NewUser, create};
    for pool in common::all_engine_pools().await {
        let name = engine_of(&pool).as_str();
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false)
            .await
            .unwrap();
        for upn in ["jose@contoso.test", "josé@contoso.test"] {
            create(
                &pool,
                &t,
                NewUser {
                    upn,
                    email: None,
                    display_name: None,
                    given_name: None,
                    family_name: None,
                    password: "Correct-Horse-9",
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{name}: {upn}: {e}"));
        }
        rust_oidc::groups::create(&pool, &t, "Équipe", None).await.unwrap();
        rust_oidc::groups::create(&pool, &t, "Equipe", None)
            .await
            .unwrap_or_else(|e| panic!("{name}: Equipe vs Équipe: {e}"));
    }
}
