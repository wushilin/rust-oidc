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
