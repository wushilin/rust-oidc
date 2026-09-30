//! `FoldPolicy` split: a folding collision is tolerated only under `ReportOnly`;
//! any other reconcile failure propagates under both policies. SQLite only: the
//! policy logic is engine-independent.

use anyhow::anyhow;
use rust_oidc::db::{self, FoldConflict, FoldPolicy, apply_fold_policy};

fn conflict() -> anyhow::Result<()> {
    Err(FoldConflict("two rows fold to one".into()).into())
}

#[test]
fn policy_matrix_on_outcomes() {
    assert!(apply_fold_policy(FoldPolicy::FailClosed, Ok(())).is_ok());
    assert!(apply_fold_policy(FoldPolicy::ReportOnly, Ok(())).is_ok());
    assert!(apply_fold_policy(FoldPolicy::FailClosed, conflict()).is_err());
    assert!(apply_fold_policy(FoldPolicy::ReportOnly, conflict()).is_ok());
    let other = || Err(anyhow!("connection reset"));
    assert!(apply_fold_policy(FoldPolicy::FailClosed, other()).is_err());
    let err = apply_fold_policy(FoldPolicy::ReportOnly, other()).unwrap_err();
    assert!(err.to_string().contains("connection reset"));
}

async fn url_with(setup: impl AsyncFnOnce(&db::DbPool)) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("t.db").display());
    let pool = db::connect(&url).await.unwrap();
    setup(&pool).await;
    pool.close().await;
    (dir, url)
}

#[tokio::test]
async fn connect_with_a_real_collision_fails_closed_but_report_only_opens() {
    let (_dir, url) = url_with(async |pool| {
        let t = rust_oidc::tenant::create(pool, "Contoso", "contoso.test", false)
            .await
            .unwrap();
        for (id, upn, folded) in [
            ("u-1", "ÉLODIE@contoso.test", "Élodie@contoso.test"),
            ("u-2", "élodie@contoso.test", "élodie@contoso.test"),
        ] {
            sqlx::query(db::q(pool, "INSERT INTO users (id, tenant_id, upn, upn_folded, enabled, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0)"))
                .bind(id).bind(&t.id).bind(upn).bind(folded).bind(true).bind(false)
                .execute(pool).await.unwrap();
        }
    })
    .await;

    let err = db::connect_with(&url, FoldPolicy::FailClosed).await.unwrap_err();
    assert!(err.is::<FoldConflict>(), "serve must fail closed on a collision: {err}");
    db::connect_with(&url, FoldPolicy::ReportOnly)
        .await
        .unwrap()
        .close()
        .await;
}

#[tokio::test]
async fn connect_with_a_non_collision_failure_errors_under_both_policies() {
    // Dropping a table after migrations ran makes reconcile hit a genuine database error.
    let (_dir, url) = url_with(async |pool| {
        sqlx::query("DROP TABLE users").execute(pool).await.unwrap();
    })
    .await;
    for policy in [FoldPolicy::FailClosed, FoldPolicy::ReportOnly] {
        let err = db::connect_with(&url, policy).await.unwrap_err();
        assert!(!err.is::<FoldConflict>(), "{policy:?}: {err}");
    }
}
