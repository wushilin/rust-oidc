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
        RoleId::TenantAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();

    let here = rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id)
        .await
        .unwrap();
    assert_eq!(here, vec![rust_oidc::directory::GLOBAL_ADMINISTRATOR.to_string()]);
    let there = rust_oidc::directory::wids_for_user(&s.pool, &other.id, &f.user_id)
        .await
        .unwrap();
    assert!(there.is_empty(), "the binding does not cover that tenant");
}

#[tokio::test]
async fn an_all_scope_binding_appears_in_every_tenants_wids() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
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

/// A tenant's administrator is that directory's Global Administrator in Entra's
/// terms, and its viewer the Global Reader. A role Entra has no counterpart of
/// is not a wid.
#[tokio::test]
async fn tenant_roles_appear_as_their_entra_counterparts_or_not_at_all() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let wids = || rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id);
    bind_in_own_tenant(&s, &f, RoleId::UserViewer).await;
    assert!(wids().await.unwrap().is_empty(), "it has no Entra template id");
    bind_in_own_tenant(&s, &f, RoleId::TenantViewer).await;
    assert_eq!(wids().await.unwrap(), [rust_oidc::directory::GLOBAL_READER]);
}
