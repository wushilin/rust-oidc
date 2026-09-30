mod common;
use rust_oidc::db::Engine;

#[test]
fn the_engine_is_recognised_from_the_url() {
    assert_eq!(Engine::from_url("sqlite://x.db"), Some(Engine::Sqlite));
    assert_eq!(Engine::from_url("postgres://u@h/db"), Some(Engine::Postgres));
    assert_eq!(Engine::from_url("postgresql://u@h/db"), Some(Engine::Postgres));
    assert_eq!(Engine::from_url("mysql://u@h/db"), Some(Engine::MySql));
    assert_eq!(Engine::from_url("mariadb://u@h/db"), Some(Engine::MySql));
    assert_eq!(Engine::from_url("oracle://nope"), None);
    assert_eq!(Engine::from_url("sqlite:x.db"), Some(Engine::Sqlite));
    assert_eq!(Engine::from_url("sqlite:/abs/path.db"), Some(Engine::Sqlite));
    assert_eq!(Engine::from_url("sqlite://rel/path.db"), Some(Engine::Sqlite));
    assert_eq!(Engine::from_url("just-a-path.db"), None);
}

#[test]
fn engine_names_round_trip() {
    for e in Engine::ALL {
        assert_eq!(Engine::parse(e.as_str()), Some(*e));
    }
}

#[tokio::test]
async fn a_sqlite_url_still_connects_and_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("t.db").display());
    let pool = rust_oidc::db::connect(&url).await.unwrap();
    assert_eq!(rust_oidc::db::engine_of(&pool), Engine::Sqlite);
}

/// The schema relies on ON DELETE CASCADE (a deleted tenant's role bindings must
/// grant nothing). SQLite enforces it only with `PRAGMA foreign_keys = ON`, which
/// `db::connect` sets on every connection; Postgres and MySQL always enforce it.
#[tokio::test]
async fn foreign_key_cascades_fire_on_every_engine() {
    use rust_oidc::db::{engine_of, sql_stmt};
    for pool in common::all_engine_pools().await {
        let e = engine_of(&pool);
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.com", false).await.unwrap();
        sqlx::query(sql_stmt(
            e,
            "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
             VALUES ('b1', 'User', 'u1', 'GlobalReader', 'tenants', 0)",
        ))
        .execute(&*pool)
        .await
        .unwrap();
        sqlx::query(sql_stmt(e, "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES ('b1', ?)"))
            .bind(&t.id)
            .execute(&*pool)
            .await
            .unwrap();
        sqlx::query(sql_stmt(e, "DELETE FROM tenants WHERE id = ?"))
            .bind(&t.id)
            .execute(&*pool)
            .await
            .unwrap();
        let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_binding_tenants")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(left.0, 0, "{}: cascade did not fire", e.as_str());
    }
}

#[tokio::test]
async fn a_directory_named_mode_does_not_suppress_create() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("mode=foo");
    std::fs::create_dir(&sub).unwrap();
    let url = format!("sqlite:{}", sub.join("t.db").display());
    let pool = rust_oidc::db::connect(&url).await.unwrap();
    assert_eq!(rust_oidc::db::engine_of(&pool), Engine::Sqlite);
}

/// Review Focus 5: boolean columns must read back identically.
#[tokio::test]
async fn booleans_round_trip_on_every_available_engine() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        let id = rust_oidc::users::create(&pool, &t, rust_oidc::users::NewUser {
            upn: "alice@contoso.test", password: "Correct-Horse-9",
            display_name: None, given_name: None, family_name: None,
            email: Some("a@example.org"),
        }).await.unwrap();
        let u = rust_oidc::users::find(&pool, &t.id, &id).await.unwrap().unwrap();
        assert!(u.enabled, "enabled must read back true");
        assert!(!u.email_verified, "email_verified must read back false");
    }
}
