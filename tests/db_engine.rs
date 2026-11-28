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

#[cfg(unix)]
#[tokio::test]
async fn sqlite_creates_private_database_and_sidecar_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("private directory");
    let db = sub.join("store?.db");
    let encoded = db.display().to_string().replace(' ', "%20").replace('?', "%3F");
    let pool = rust_oidc::db::connect(&format!("sqlite://{encoded}")).await.unwrap();
    assert_eq!(sub.metadata().unwrap().permissions().mode() & 0o077, 0);
    for file in ["store?.db", "store?.db-wal", "store?.db-shm"] {
        let mode = sub.join(file).metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{file} can be accessed by other accounts");
    }
    pool.close().await;
    let absent = dir.path().join("absent.db");
    assert!(
        rust_oidc::db::connect(&format!("sqlite://{}?mode=rw", absent.display()))
            .await
            .is_err()
    );
    assert!(!absent.exists(), "mode=rw should require an existing file");
}

#[tokio::test]
async fn saml_cleanup_prunes_expired_state_in_bounded_batches() {
    let fixture = common::pool_for(Engine::Sqlite).await.unwrap();
    sqlx::raw_sql(
        "INSERT INTO tenants (id, name, created_at) VALUES ('t', 'Fixture', 1);
         INSERT INTO applications (id, app_id, tenant_id, display_name, created_at)
            VALUES ('a', 'client', 't', 'Fixture app', 1);
         CREATE TEMP TABLE expiry_fixture (id TEXT, expires_at INTEGER);
         WITH RECURSIVE seq(i) AS (VALUES (1) UNION ALL SELECT i + 1 FROM seq WHERE i < 258)
         INSERT INTO expiry_fixture SELECT CAST(i AS TEXT), CASE WHEN i < 258 THEN 1 ELSE 3 END FROM seq;
         INSERT INTO saml_session_participants (session_index, session_hash, tenant_id, application_id, user_id,
                                                name_id, name_id_key, name_id_format, created_at, expires_at)
         SELECT id, id, 't', 'a', 'u', id, id, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                1, expires_at FROM expiry_fixture;
         INSERT INTO saml_launch_tickets (ticket_hash, tenant_id, application_id, user_id, expires_at)
            SELECT id, 't', 'a', 'u', expires_at FROM expiry_fixture;
         INSERT INTO saml_seen_messages (application_id, message_id, expires_at)
            SELECT 'a', id, expires_at FROM expiry_fixture;
         INSERT INTO saml_logout_state (request_id, tenant_id, pending_app, browser_hash, remaining, finish, expires_at)
            SELECT id, 't', 'a', 'b', '[]', '{}', expires_at FROM expiry_fixture;",
    )
    .execute(&*fixture)
    .await
    .unwrap();
    assert_eq!(rust_oidc::saml::prune_expired(&*fixture, 2).await.unwrap(), 4 * 256);
    assert_eq!(rust_oidc::saml::prune_expired(&*fixture, 2).await.unwrap(), 4);
    assert_eq!(rust_oidc::saml::prune_expired(&*fixture, 2).await.unwrap(), 0);
    assert_eq!(rust_oidc::saml::prune_expired(&*fixture, 3).await.unwrap(), 4);
}

/// The schema relies on ON DELETE CASCADE (a deleted tenant's role bindings must
/// grant nothing). SQLite enforces it only with `PRAGMA foreign_keys = ON`, which
/// `db::connect` sets on every connection; Postgres and MySQL always enforce it.
#[tokio::test]
async fn foreign_key_cascades_fire_on_every_engine() {
    use rust_oidc::db::{engine_of, sql_stmt};
    for pool in common::all_engine_pools().await {
        let e = engine_of(&pool);
        let t = rust_oidc::tenant::create(&*pool, "Contoso", "contoso.com", false)
            .await
            .unwrap();
        sqlx::query(sql_stmt(
            e,
            "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
             VALUES ('b1', 'User', 'u1', 'GlobalReader', 'tenants', 0)",
        ))
        .execute(&*pool)
        .await
        .unwrap();
        sqlx::query(sql_stmt(
            e,
            "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES ('b1', ?)",
        ))
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
        let t = rust_oidc::tenant::create(&*pool, "Contoso", "contoso.test", false)
            .await
            .unwrap();
        let id = rust_oidc::users::create(
            &pool,
            &t,
            rust_oidc::users::NewUser {
                upn: "alice@contoso.test",
                password: "Correct-Horse-9",
                display_name: None,
                given_name: None,
                family_name: None,
                email: Some("a@example.org"),
            },
        )
        .await
        .unwrap();
        let u = rust_oidc::users::find(&*pool, &t.id, &id).await.unwrap().unwrap();
        assert!(u.enabled, "enabled must read back true");
        assert!(!u.email_verified, "email_verified must read back false");
    }
}
