mod common;

use common::TestServer;
use rust_oidc::keys::{self, KeyStore};

async fn kids(store: &KeyStore) -> Vec<(String, String)> {
    store
        .published()
        .await
        .unwrap()
        .iter()
        .map(|k| (k.kid.clone(), k.status.clone()))
        .collect()
}

#[tokio::test]
async fn rotation_promotes_prepublished_key_and_keeps_old_one() {
    let s = TestServer::start().await;
    let before = kids(&KeyStore::new(s.pool.clone())).await;
    let active = before.iter().find(|(_, st)| st == "active").unwrap().0.clone();
    let next = before.iter().find(|(_, st)| st == "next").unwrap().0.clone();

    keys::rotate(&s.pool).await.unwrap();

    let store = KeyStore::new(s.pool.clone());
    let after = kids(&store).await;
    assert_eq!(after.len(), 3);
    assert!(
        after.contains(&(next.clone(), "active".into())),
        "next key became active"
    );
    assert!(
        after.contains(&(active.clone(), "retired".into())),
        "old key still published"
    );

    let token = store.sign(&serde_json::json!({ "x": 1 })).await.unwrap();
    assert_eq!(jsonwebtoken::decode_header(&token).unwrap().kid.unwrap(), next);

    // Pruning only removes keys retired long enough ago.
    assert_eq!(keys::prune(&s.pool, 3600).await.unwrap(), 0);
    assert_eq!(keys::prune(&s.pool, -1).await.unwrap(), 1);
}

/// The exact `retired == 4` count is only meaningful on Postgres and MySQL, where
/// a broken lock lets rotations merge; SQLite serializes writers anyway.
#[tokio::test]
async fn concurrent_rotations_leave_exactly_one_active_key_and_do_not_error() {
    let s = TestServer::start().await;
    let results = futures::future::join_all((0..4).map(|_| keys::rotate(&s.pool))).await;
    for r in &results {
        assert!(r.is_ok(), "rotation failed: {r:?}");
    }
    let all = kids(&KeyStore::new(s.pool.clone())).await;
    let count = |st: &str| all.iter().filter(|(_, s)| s == st).count();
    assert_eq!(count("active"), 1, "{all:?}");
    assert!(count("next") >= 1, "a next key stays published: {all:?}");
    assert_eq!(count("retired"), 4, "each rotation retired one key: {all:?}");
}
