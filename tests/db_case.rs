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
        sqlx::query(sql_stmt(e, "INSERT INTO users (id, tenant_id, upn, upn_folded, password_hash, enabled, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 0, 0, 0)"))
            .bind("u-1").bind(&t.id).bind("Élodie@contoso.test").bind("École@x".to_string()).bind(&hash)
            .execute(&pool).await.unwrap();
        sqlx::query(sql_stmt(e, "INSERT INTO user_groups (id, tenant_id, name, name_folded, created_at) VALUES (?, ?, ?, ?, 0)"))
            .bind("g-1").bind(&t.id).bind("ÉQUIPE").bind("wrong").execute(&pool).await.unwrap();
        sqlx::query(sql_stmt(e, "UPDATE tenant_domains SET domain_folded = ? WHERE tenant_id = ?"))
            .bind("wrong").bind(&t.id).execute(&pool).await.unwrap();

        let miss = rust_oidc::users::authenticate(&pool, &t, "ÉLODIE@Contoso.Test", "Correct-Horse-9").await.unwrap();
        assert!(!matches!(miss, rust_oidc::users::AuthResult::Ok(_)), "precondition: broken before repair");

        assert_eq!(reconcile_folded(&pool).await.unwrap(), 3);
        let folded: (String,) = sqlx::query_as(sql_stmt(e, "SELECT upn_folded FROM users WHERE id = ?"))
            .bind("u-1").fetch_one(&pool).await.unwrap();
        assert_eq!(folded.0, rust_oidc::util::fold("Élodie@contoso.test"));
        assert_eq!(folded.0, "élodie@contoso.test");
        let g: (String,) = sqlx::query_as(sql_stmt(e, "SELECT name_folded FROM user_groups WHERE id = ?"))
            .bind("g-1").fetch_one(&pool).await.unwrap();
        assert_eq!(g.0, "équipe");
        assert!(rust_oidc::tenant::resolve(&pool, "CONTOSO.TEST").await.unwrap().is_some());

        let ok = rust_oidc::users::authenticate(&pool, &t, "ÉLODIE@Contoso.Test", "Correct-Horse-9").await.unwrap();
        assert!(matches!(ok, rust_oidc::users::AuthResult::Ok(_)));

        assert_eq!(reconcile_folded(&pool).await.unwrap(), 0, "second run changes nothing");
    }
}
