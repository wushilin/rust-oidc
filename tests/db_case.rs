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
