mod common;

/// Identity must fold case identically on every engine.
#[tokio::test]
async fn a_upn_differing_only_by_case_is_the_same_account() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        let new = |upn| rust_oidc::users::NewUser {
            upn, password: "Correct-Horse-9",
            display_name: None, given_name: None, family_name: None, email: None,
        };
        rust_oidc::users::create(&pool, &t, new("alice@contoso.test")).await.unwrap();

        for attempt in ["alice@contoso.test", "Alice@Contoso.Test", "ALICE@CONTOSO.TEST"] {
            let outcome = rust_oidc::users::authenticate(&pool, &t, attempt, "Correct-Horse-9")
                .await.unwrap();
            assert!(matches!(outcome, rust_oidc::users::AuthResult::Ok(_)), "{attempt}");
        }

        let dup = rust_oidc::users::create(&pool, &t, new("Alice@Contoso.Test")).await;
        assert!(dup.is_err(), "a case-variant duplicate must be refused");
    }
}

#[tokio::test]
async fn tenant_domains_and_group_names_fold_case_too() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        assert!(rust_oidc::tenant::resolve(&pool, "CONTOSO.TEST").await.unwrap().is_some());
        assert!(rust_oidc::tenant::add_domain(&pool, &t.id, "Contoso.Test").await.is_err());
        rust_oidc::groups::create(&pool, &t, "Admins", None).await.unwrap();
        assert!(rust_oidc::groups::create(&pool, &t, "admins", None).await.is_err());
    }
}

#[test]
fn fold_is_full_unicode_and_trims() {
    assert_eq!(rust_oidc::util::fold("  Ünï@X.Test "), "ünï@x.test");
}

/// The migration's SQL lower() is ASCII-only on SQLite; the Rust pass must repair it.
#[tokio::test]
async fn reconcile_repairs_non_ascii_folded_columns_and_is_idempotent() {
    use rust_oidc::db::{engine_of, reconcile_folded, sql_stmt};
    for pool in common::all_engine_pools().await {
        let e = engine_of(&pool);
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        let hash = rust_oidc::users::hash_password("Correct-Horse-9").unwrap();
        // Folded value as ASCII-only lower() would leave it: the É untouched.
        sqlx::query(sql_stmt(e, "INSERT INTO users (id, tenant_id, upn, upn_folded, password_hash, enabled, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)"))
            .bind("u-1").bind(&t.id).bind("Élodie@contoso.test").bind("École@x".to_string()).bind(&hash).bind(true).bind(false)
            .execute(&*pool).await.unwrap();
        sqlx::query(sql_stmt(e, "INSERT INTO user_groups (id, tenant_id, name, name_folded, created_at) VALUES (?, ?, ?, ?, 0)"))
            .bind("g-1").bind(&t.id).bind("ÉQUIPE").bind("wrong").execute(&*pool).await.unwrap();
        sqlx::query(sql_stmt(e, "UPDATE tenant_domains SET domain_folded = ? WHERE tenant_id = ?"))
            .bind("wrong").bind(&t.id).execute(&*pool).await.unwrap();

        let miss = rust_oidc::users::authenticate(&pool, &t, "ÉLODIE@Contoso.Test", "Correct-Horse-9").await.unwrap();
        assert!(!matches!(miss, rust_oidc::users::AuthResult::Ok(_)), "precondition: broken before repair");

        assert_eq!(reconcile_folded(&pool).await.unwrap(), 3);
        let folded: (String,) = sqlx::query_as(sql_stmt(e, "SELECT upn_folded FROM users WHERE id = ?"))
            .bind("u-1").fetch_one(&*pool).await.unwrap();
        assert_eq!(folded.0, rust_oidc::util::fold("Élodie@contoso.test"));
        assert_eq!(folded.0, "élodie@contoso.test");
        let g: (String,) = sqlx::query_as(sql_stmt(e, "SELECT name_folded FROM user_groups WHERE id = ?"))
            .bind("g-1").fetch_one(&*pool).await.unwrap();
        assert_eq!(g.0, "équipe");
        assert!(rust_oidc::tenant::resolve(&pool, "CONTOSO.TEST").await.unwrap().is_some());

        let ok = rust_oidc::users::authenticate(&pool, &t, "ÉLODIE@Contoso.Test", "Correct-Horse-9").await.unwrap();
        assert!(matches!(ok, rust_oidc::users::AuthResult::Ok(_)));

        assert_eq!(reconcile_folded(&pool).await.unwrap(), 0, "second run changes nothing");
    }
}

async fn raw_user(pool: &rust_oidc::db::DbPool, id: &str, tenant: &str, upn: &str, folded: &str) {
    use rust_oidc::db::{engine_of, sql_stmt};
    sqlx::query(sql_stmt(engine_of(pool), "INSERT INTO users (id, tenant_id, upn, upn_folded, enabled, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0)"))
        .bind(id).bind(tenant).bind(upn).bind(folded).bind(true).bind(false).execute(pool).await.unwrap();
}

async fn folded_snapshot(pool: &rust_oidc::db::DbPool) -> Vec<(String, Option<String>)> {
    use rust_oidc::db::{engine_of, sql_stmt};
    sqlx::query_as(sql_stmt(engine_of(pool), "SELECT id, upn_folded FROM users ORDER BY id"))
        .fetch_all(pool).await.unwrap()
}

/// Two rows that only collide under Unicode folding must stop startup with an
/// actionable message, and must leave the data untouched.
#[tokio::test]
async fn reconcile_refuses_collisions_names_every_conflict_and_writes_nothing() {
    use rust_oidc::db::reconcile_folded;
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        // ASCII-only lower() left the É alone, so these do not collide yet.
        raw_user(&pool, "u-1", &t.id, "ÉLODIE@contoso.test", "Élodie@contoso.test").await;
        raw_user(&pool, "u-2", &t.id, "élodie@contoso.test", "élodie@contoso.test").await;
        // A second, distinct conflict, plus an innocent row needing repair.
        raw_user(&pool, "u-3", &t.id, "ÀNDRÉ@contoso.test", "Àndré@contoso.test").await;
        raw_user(&pool, "u-4", &t.id, "àndré@contoso.test", "àndré@contoso.test").await;
        raw_user(&pool, "u-5", &t.id, "ÖZ@contoso.test", "Öz@contoso.test").await;
        let before = folded_snapshot(&pool).await;

        let err = reconcile_folded(&pool).await.unwrap_err().to_string();
        for needle in [
            "users", "élodie@contoso.test", "ÉLODIE@contoso.test", "u-1", "u-2",
            "àndré@contoso.test", "ÀNDRÉ@contoso.test", "u-3", "u-4", "2 case-insensitive",
            "Rename or remove", &t.id,
        ] {
            assert!(err.contains(needle), "missing {needle:?} in: {err}");
        }
        assert!(!err.contains("u-5"), "non-conflicting row must not be listed: {err}");
        assert_eq!(folded_snapshot(&pool).await, before, "nothing may be written");
        // A retry behaves the same until the operator repairs the data.
        assert!(reconcile_folded(&pool).await.is_err());
    }
}
