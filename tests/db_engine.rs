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
/// `db::connect` sets on every connection.
#[tokio::test]
async fn foreign_key_cascades_fire_on_sqlite() {
    let s = common::TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    sqlx::query(
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
         VALUES ('b1', 'User', 'u1', 'GlobalReader', 'tenants', 0)",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES ('b1', ?)")
        .bind(&t.id)
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenants WHERE id = ?")
        .bind(&t.id)
        .execute(&s.pool)
        .await
        .unwrap();
    let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_binding_tenants")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(left.0, 0, "cascade did not fire: foreign_keys pragma is off");
}
