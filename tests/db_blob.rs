mod common;

use sha1::{Digest, Sha1};

fn sha1_of(bytes: &[u8]) -> Vec<u8> {
    Sha1::digest(bytes).to_vec()
}

/// Review Focus 4: BYTEA and BLOB must round-trip byte-identically.
#[tokio::test]
async fn blobs_round_trip_byte_identically() {
    for pool in common::all_engine_pools().await {
        rust_oidc::keys::ensure(&pool).await.unwrap();
        let store = rust_oidc::keys::KeyStore::new((*pool).clone());
        let published = store.published().await.unwrap();
        assert!(!published.is_empty(), "a signing key must exist");
        for k in published.iter() {
            assert!(!k.cert_der.is_empty(), "certificate DER must not come back empty");
            assert_eq!(
                k.kid,
                rust_oidc::util::b64url(&sha1_of(&k.cert_der)),
                "kid is the SHA-1 of the DER, so a corrupted blob changes it"
            );
        }
    }
}

/// Every byte value, a leading zero, and a size past typical row-inline limits.
#[tokio::test]
async fn arbitrary_binary_survives_a_blob_column() {
    use rust_oidc::db::{engine_of, sql_stmt};
    let mut payload: Vec<u8> = vec![0, 0, 1];
    payload.extend((0..=255u8).cycle().take(70_000));
    for pool in common::all_engine_pools().await {
        let e = engine_of(&pool);
        sqlx::query(sql_stmt(
            e,
            "INSERT INTO server_secrets (name, value, created_at) VALUES (?, ?, 0)",
        ))
        .bind("blob-test")
        .bind(&payload)
        .execute(&*pool)
        .await
        .unwrap();
        let (back,): (Vec<u8>,) = sqlx::query_as(sql_stmt(e, "SELECT value FROM server_secrets WHERE name = ?"))
            .bind("blob-test")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(back.len(), payload.len(), "{}: length", e.as_str());
        assert!(back == payload, "{}: bytes differ", e.as_str());
    }
}
