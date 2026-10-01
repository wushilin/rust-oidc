//! Assuming a tenant: who may, what it changes, and what it records.
mod common;
use common::*;

use rust_oidc::db::Event;

#[tokio::test]
async fn a_platform_admin_can_assume_a_tenant_and_leave_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.post(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let page = b.get(&s.url("/admin/tenants")).await;
    assert!(
        page.body.contains("Acting in") && page.body.contains("Fabrikam"),
        "the banner names the assumed tenant: {}",
        page.body
    );

    let page = b.post(&s.url("/admin/leave"), &[]).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let page = b.get(&s.url("/admin/tenants")).await;
    assert!(!page.body.contains("Acting in"), "the banner is gone: {}", page.body);
}

#[tokio::test]
async fn a_tenant_admin_cannot_assume() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.post(&s.url(&format!("/admin/assume/{}", other.id)), &[]).await;
    assert_eq!(page.status, 403, "{}", page.body);
    // Not even their own tenant: assume is a platform action, and a tenant admin
    // is already acting in the tenants they hold.
    let own = b.post(&s.url(&format!("/admin/assume/{}", f.tenant.id)), &[]).await;
    assert_eq!(own.status, 403, "{}", own.body);
}

#[tokio::test]
async fn the_console_offers_assume_only_to_those_who_may() {
    let s = TestServer::start().await;
    let platform = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &platform).await;
    assert!(b.get(&s.url("/admin/tenants")).await.body.contains("Assume"));

    let s2 = TestServer::start().await;
    let delegated = tenant_admin_fixture(&s2).await;
    let b2 = signed_in_admin(&s2, &delegated).await;
    let page = b2.get(&s2.url("/admin/tenants")).await;
    assert!(
        !page.body.contains("Assume"),
        "a tenant admin is not offered it: {}",
        page.body
    );
}

/// Review Focus 4: a disabled and a non-existent tenant must look identical, so
/// the console is not an oracle for which tenants exist.
#[tokio::test]
async fn assuming_a_disabled_or_unknown_tenant_is_the_same_404() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let disabled = s.tenant("Gone", "gone.test").await;
    sqlx::query(rust_oidc::db::q(&s.pool, "UPDATE tenants SET enabled = ? WHERE id = ?"))
        .bind(false)
        .bind(&disabled.id)
        .execute(&s.pool)
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let a = b.post(&s.url(&format!("/admin/assume/{}", disabled.id)), &[]).await;
    let c = b
        .post(&s.url("/admin/assume/11111111-1111-1111-1111-111111111111"), &[])
        .await;
    assert_eq!(a.status, 404, "{}", a.body);
    assert_eq!(c.status, 404, "{}", c.body);
    assert_eq!(a.body, c.body, "the console must not reveal which tenants exist");
}

#[tokio::test]
async fn an_assume_is_audited_against_the_real_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    b.post(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;

    let rows = audit_rows(&s, Event::AdminTenantAssume.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id, "the person, not a tenant-local identity");
    assert_eq!(rows[0].1.as_deref(), Some(target.id.as_str()));
    assert_eq!(
        rows[0].2.as_deref(),
        Some(target.id.as_str()),
        "recorded in the assumed tenant"
    );
}

/// Work done while assuming stays attributable to the administrator personally.
#[tokio::test]
async fn work_done_while_assuming_is_still_recorded_as_the_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    b.post(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;

    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/new", target.id)),
            &[
                ("upn", "newbie@fabrikam.test"),
                ("password", "Correct-Horse-9"),
                ("display_name", "Newbie"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let rows = audit_rows(&s, Event::AdminUserCreate.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id, "the actor is the real administrator");
    assert_eq!(rows[0].2.as_deref(), Some(target.id.as_str()));
}

/// Assuming is a convenience, not a grant: it cannot reach a tenant the
/// administrator's bindings do not already cover.
#[tokio::test]
async fn assuming_does_not_widen_what_is_permitted() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    // Platform administrator can assume, but holds no user-administration role.
    bind(
        &s,
        &f.user_id,
        rust_oidc::rbac::RoleId::PlatformAdministrator,
        rust_oidc::rbac::Scope::All,
    )
    .await;
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(
        b.post(&s.url(&format!("/admin/assume/{}", other.id)), &[]).await.status,
        303
    );
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", other.id))).await;
    assert_eq!(page.status, 403, "assuming grants nothing new: {}", page.body);
}

/// The platform's actions are platform-wide, so holding the platform role at a
/// *tenant* scope must grant nothing at all. Without this, only the role half of
/// the rule is tested and the scope half can be removed unnoticed — the same hole
/// the lock-out rule had.
#[tokio::test]
async fn a_tenant_scoped_platform_binding_cannot_assume() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    bind(
        &s,
        &f.user_id,
        rust_oidc::rbac::RoleId::PlatformAdministrator,
        rust_oidc::rbac::Scope::Tenants(vec![f.tenant.id.clone(), other.id.clone()]),
    )
    .await;
    let b = signed_in_admin(&s, &f).await;
    for target in [&f.tenant.id, &other.id] {
        let page = b.post(&s.url(&format!("/admin/assume/{target}")), &[]).await;
        assert_eq!(
            page.status, 403,
            "a tenant-scoped platform binding assumed {target}: {}",
            page.body
        );
    }
    let session: (Option<String>,) = sqlx::query_as("SELECT acting_tenant FROM admin_sessions")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(session.0, None, "and no tenant was entered");
}
