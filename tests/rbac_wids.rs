mod common;
use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{RoleId, Scope};

#[tokio::test]
async fn a_tenant_scoped_binding_appears_in_wids_for_that_tenant_only() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();

    let here = rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id)
        .await
        .unwrap();
    assert_eq!(
        here,
        vec![RoleId::GlobalAdministrator.template_id().unwrap().to_string()]
    );
    let there = rust_oidc::directory::wids_for_user(&s.pool, &other.id, &f.user_id)
        .await
        .unwrap();
    assert!(there.is_empty(), "the binding does not cover that tenant");
}

#[tokio::test]
async fn an_all_scope_binding_appears_in_every_tenants_wids() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    for tid in [&f.tenant.id, &other.id] {
        let wids = rust_oidc::directory::wids_for_user(&s.pool, tid, &f.user_id)
            .await
            .unwrap();
        assert!(
            wids.contains(&RoleId::GlobalAdministrator.template_id().unwrap().to_string()),
            "{tid}"
        );
    }
}

#[tokio::test]
async fn platform_administrator_never_appears_in_wids() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let wids = rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id)
        .await
        .unwrap();
    assert!(wids.is_empty(), "it has no Entra template id, so it is not a wid");
}
