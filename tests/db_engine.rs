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
