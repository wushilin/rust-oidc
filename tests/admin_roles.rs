//! Granting and revoking console roles through the console, including the two
//! rules that make delegation safe: no widening, and no locking the platform out.
mod common;
use common::*;

use rust_oidc::admin::bindings::effective_for_user;
use rust_oidc::db::Event;
use rust_oidc::rbac::{Action, Resource, RoleId, Scope, Verb, allowed};

fn roles_url(s: &TestServer, tenant_id: &str) -> String {
    s.url(&format!("/admin/tenants/{tenant_id}/roles"))
}

#[tokio::test]
async fn a_platform_admin_can_grant_a_tenant_scoped_role() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let helper = user_fixture_in(&s, f.tenant.clone(), "helper@contoso.com").await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helper@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::UserAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let eff = effective_for_user(&s.pool, &helper.user_id).await.unwrap();
    assert!(allowed(&eff, Action::new(Resource::User, Verb::Write), &f.tenant.id));
    // And the grantee can now use the console.
    let theirs = signed_in_admin(&s, &helper).await;
    assert_eq!(
        theirs
            .get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id)))
            .await
            .status,
        200
    );

    let rows = audit_rows(&s, Event::AdminRoleGrant.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id, "the actor is the granting admin");
}

#[tokio::test]
async fn a_grant_can_be_revoked_again() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let helper = user_fixture_in(&s, f.tenant.clone(), "helper@contoso.com").await;
    let id = bind(
        &s,
        &helper.user_id,
        RoleId::UserAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[("op", "revoke"), ("binding", id.as_str())],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(effective_for_user(&s.pool, &helper.user_id).await.unwrap().is_empty());
    assert_eq!(audit_rows(&s, Event::AdminRoleRevoke.as_str()).await.len(), 1);
}

/// The no-widening rule, through the UI: a tenant admin may grant inside their own
/// tenant but must not be able to mint an `all`-scope binding.
#[tokio::test]
async fn a_tenant_admin_cannot_grant_at_every_tenant() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let helper = user_fixture_in(&s, f.tenant.clone(), "helper@contoso.com").await;
    let b = signed_in_admin(&s, &f).await;

    // Their own tenant: allowed.
    let own = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helper@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::UserAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(own.status, 303, "{}", own.body);

    // Every tenant: refused, and nothing written.
    let wide = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helper@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::GlobalAdministrator.as_str()),
                ("scope", "all"),
            ],
        )
        .await;
    assert_eq!(wide.status, 403, "{}", wide.body);
    let eff = effective_for_user(&s.pool, &helper.user_id).await.unwrap();
    assert_eq!(eff.len(), 1, "only the tenant-scoped grant exists: {eff:?}");
    assert!(matches!(eff[0].scope, Scope::Tenants(_)));
    // The form does not even offer it.
    let page = b.get(&roles_url(&s, &f.tenant.id)).await;
    assert!(!page.body.contains("Every tenant"), "{}", page.body);
}

/// Nor may they reach into another tenant's roles page at all.
#[tokio::test]
async fn a_tenant_admin_cannot_touch_another_tenants_roles() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let victim = user_fixture_in(&s, other.clone(), "mole@fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    assert_eq!(b.get(&roles_url(&s, &other.id)).await.status, 403);
    let page = b
        .post(
            &roles_url(&s, &other.id),
            &[
                ("op", "grant"),
                ("principal", "mole@fabrikam.test"),
                ("principal_type", "User"),
                ("role", RoleId::GlobalAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert!(effective_for_user(&s.pool, &victim.user_id).await.unwrap().is_empty());
}

/// A tenant admin must not be able to revoke a binding that is wider than their
/// own reach, even by naming its id directly.
#[tokio::test]
async fn a_tenant_admin_cannot_revoke_a_wider_binding() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    // Reach over every tenant is held from the root tenant, never from this one.
    let root = rust_oidc::tenant::create(&s.pool, "System", "system.test", true)
        .await
        .unwrap();
    let platform = user_fixture_in(&s, root, "boss@system.test").await;
    let wide = bind(&s, &platform.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[("op", "revoke"), ("binding", wide.as_str())],
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert_eq!(
        effective_for_user(&s.pool, &platform.user_id).await.unwrap().len(),
        1,
        "the wider binding survives"
    );
}

/// The lock-out rule, through the UI: the last platform binding cannot be revoked,
/// and the console says why rather than failing silently.
#[tokio::test]
async fn revoking_the_last_platform_binding_is_refused_with_a_reason() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let platform: (String,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT id FROM role_bindings WHERE role_id = ? AND scope_kind = ?",
    ))
    .bind(RoleId::PlatformAdministrator.as_str())
    .bind("all")
    .fetch_one(&s.pool)
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[("op", "revoke"), ("binding", platform.0.as_str())],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(
        page.body.to_lowercase().contains("last binding"),
        "the page says why: {}",
        page.body
    );
    // Still there, and the console still works.
    assert!(
        b.post(&s.url(&format!("/admin/assume/{}", f.tenant.id)), &[])
            .await
            .status
            == 303
    );
}

#[tokio::test]
async fn granting_to_an_unknown_principal_says_so_and_writes_nothing() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_bindings")
        .fetch_one(&s.pool)
        .await
        .unwrap();

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "ghost@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::UserAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("No user named"), "{}", page.body);
    let after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_bindings")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(before.0, after.0);
}

#[tokio::test]
async fn a_group_can_hold_a_role() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let member = user_fixture_in(&s, f.tenant.clone(), "member@contoso.com").await;
    rust_oidc::groups::create(&s.pool, &f.tenant, "Helpdesk", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&s.pool, &f.tenant, "Helpdesk", "member@contoso.com")
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helpdesk"),
                ("principal_type", "Group"),
                ("role", RoleId::UserAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let eff = effective_for_user(&s.pool, &member.user_id).await.unwrap();
    assert!(allowed(&eff, Action::new(Resource::User, Verb::Write), &f.tenant.id));
}

#[tokio::test]
async fn a_reader_sees_the_roles_but_is_offered_no_form() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&roles_url(&s, &f.tenant.id)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(!page.body.contains("Grant a role"), "{}", page.body);
    assert!(!page.body.contains("Revoke"), "{}", page.body);

    let post = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", f.upn.as_str()),
                ("principal_type", "User"),
                ("role", RoleId::GlobalAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(post.status, 403, "{}", post.body);
}

/// A user administrator can manage people but holds no role over roles, so the
/// page is closed to them entirely.
#[tokio::test]
async fn a_user_administrator_cannot_see_the_roles_page() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind(
        &s,
        &f.user_id,
        RoleId::UserAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(b.get(&roles_url(&s, &f.tenant.id)).await.status, 403);
}

/// A delegated administrator's roles page must not name the platform's
/// administrators, who may be accounts in tenants this one cannot see, nor the ids
/// of other tenants a binding happens to cover.
#[tokio::test]
async fn a_tenant_admin_is_not_shown_the_platform_administrators() {
    let s = TestServer::start().await;
    let platform = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let delegated = user_fixture_in(&s, other.clone(), "boss@fabrikam.test").await;
    bind(
        &s,
        &delegated.user_id,
        RoleId::GlobalAdministrator,
        Scope::Tenants(vec![other.id.clone()]),
    )
    .await;
    // A binding that covers this tenant *and* another one.
    // Only a root-tenant account can hold one.
    let shared = user_fixture_in(&s, platform.tenant.clone(), "shared@contoso.com").await;
    bind(
        &s,
        &shared.user_id,
        RoleId::GlobalReader,
        Scope::Tenants(vec![other.id.clone(), platform.tenant.id.clone()]),
    )
    .await;

    let b = signed_in_admin(&s, &delegated).await;
    let page = b.get(&roles_url(&s, &other.id)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("boss@fabrikam.test"), "their own: {}", page.body);
    assert!(
        !page.body.contains(&platform.upn),
        "the platform administrator is not named: {}",
        page.body
    );
    assert!(
        !page.body.contains(RoleId::PlatformAdministrator.display_name()),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains(&platform.tenant.id),
        "another tenant's id is not theirs to know: {}",
        page.body
    );
    assert!(
        page.body.contains("1 other tenant"),
        "summarised instead: {}",
        page.body
    );
}

/// A tenant-scoped `PlatformAdministrator` binding grants nothing, so the console
/// refuses to create one rather than storing a role that only looks like power.
#[tokio::test]
async fn the_platform_role_cannot_be_granted_to_one_tenant() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let helper = user_fixture_in(&s, f.tenant.clone(), "helper@contoso.com").await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helper@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::PlatformAdministrator.as_str()),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("every-tenant scope"), "{}", page.body);
    assert!(effective_for_user(&s.pool, &helper.user_id).await.unwrap().is_empty());

    // At every-tenant scope it is accepted, because there it means something.
    let wide = b
        .post(
            &roles_url(&s, &f.tenant.id),
            &[
                ("op", "grant"),
                ("principal", "helper@contoso.com"),
                ("principal_type", "User"),
                ("role", RoleId::PlatformAdministrator.as_str()),
                ("scope", "all"),
            ],
        )
        .await;
    assert_eq!(wide.status, 303, "{}", wide.body);
    let eff = effective_for_user(&s.pool, &helper.user_id).await.unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].scope, Scope::All);
}

/// And a tenant admin, who cannot grant at every-tenant scope, is not even shown
/// the platform role in the form.
#[tokio::test]
async fn a_tenant_admin_is_not_offered_the_platform_role() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&roles_url(&s, &f.tenant.id)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Grant a role"), "{}", page.body);
    assert!(
        !page.body.contains(RoleId::PlatformAdministrator.as_str()),
        "{}",
        page.body
    );
}
