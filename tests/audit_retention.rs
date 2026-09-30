//! `audit_log` is append-only and unauthenticated callers can append to it (a
//! failed client authentication is an event), so retention has to work -- on
//! every engine, since migration 0009 changes column types on MySQL to make the
//! table indexable.

mod common;

use rust_oidc::db;
use rust_oidc::util::now;

async fn insert_at(pool: &db::DbPool, tenant: &str, action: &str, created_at: i64) {
    sqlx::query(db::q(
        pool,
        "INSERT INTO audit_log (tenant_id, actor, action, target, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(tenant)
    .bind("cli")
    .bind(action)
    .bind(Some("target-1"))
    .bind("{}")
    .bind(created_at)
    .execute(pool)
    .await
    .unwrap();
}

async fn count(pool: &db::DbPool, tenant: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(db::q(pool, "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?"))
        .bind(tenant)
        .fetch_one(pool)
        .await
        .unwrap();
    n
}

#[tokio::test]
async fn prune_deletes_only_rows_older_than_the_cutoff() {
    for pool in common::all_engine_pools().await {
        let tenant = format!("t-{}", uuid::Uuid::new_v4());
        let ts = now();
        let day = 86_400;
        insert_at(&pool, &tenant, "auth.sign_in", ts - 100 * day).await;
        insert_at(&pool, &tenant, "auth.sign_in", ts - 91 * day).await;
        // Straddles the boundary from the other side, so an off-by-one in the
        // comparison shows up as a deleted row that should have been kept.
        insert_at(&pool, &tenant, "token.issued", ts - 89 * day).await;
        insert_at(&pool, &tenant, "token.issued", ts).await;
        assert_eq!(count(&pool, &tenant).await, 4);

        let deleted = db::prune_audit(&pool, 90 * day).await.unwrap();
        assert_eq!(deleted, 2, "only the two rows past the cutoff");
        assert_eq!(count(&pool, &tenant).await, 2);

        // Idempotent: a second run has nothing left to do.
        assert_eq!(db::prune_audit(&pool, 90 * day).await.unwrap(), 0);
        assert_eq!(count(&pool, &tenant).await, 2);
    }
}

/// MySQL's 0009 narrows `actor`/`action`/`target` to VARCHAR with utf8mb4_bin.
/// The binary collation is the point: with the table's default
/// utf8mb4_unicode_ci, `cli` and `CLI` would be the same actor, and an audit
/// trail that folds case cannot distinguish two principals.
#[tokio::test]
async fn indexed_columns_are_matched_case_sensitively() {
    for pool in common::all_engine_pools().await {
        let tenant = format!("t-{}", uuid::Uuid::new_v4());
        let ts = now();
        insert_at(&pool, &tenant, "auth.sign_in", ts).await;

        let pool: &db::DbPool = &pool;
        let (n,): (i64,) = sqlx::query_as(db::q(
            pool,
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND action = ?",
        ))
        .bind(&tenant)
        .bind("AUTH.SIGN_IN")
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(n, 0, "action must not fold case on {:?}", db::engine_of(pool));
    }
}
