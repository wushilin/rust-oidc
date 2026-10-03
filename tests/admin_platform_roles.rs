//! The page of every role: granting and revoking, Global Administrator included,
//! and where an administrator lands after signing in.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::db::Event;
use rust_oidc::rbac::{RoleId, Scope};

const PAGE: &str = "/admin/bindings";

async fn scopes_of(s: &TestServer, user_id: &str, role: RoleId) -> Vec<Scope> {
    bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.principal_id == user_id && b.role == role)
        .map(|b| b.scope)
        .collect()
}

/// A second account in the fixture tenant, holding nothing yet.
async fn another_user(s: &TestServer, f: &UserFixture, upn: &str) -> String {
    rust_oidc::users::create(
        &s.pool,
        &f.tenant,
        rust_oidc::users::NewUser {
            upn,
            password: "Another-Passw0rd!",
            display_name: Some("Another Person"),
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn global_administrator_is_granted_and_revoked_again() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let other = another_user(&s, &f, "bea@contoso.com").await;

    let page = b.get(&s.url(PAGE)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("Make somebody a Global Administrator"),
        "{}",
        page.body
    );

    let granted = b
        .post(
            &s.url(PAGE),
            &[
                ("op", "grant"),
                ("account", "bea@contoso.com"),
                ("role", RoleId::GlobalAdministrator.as_str()),
            ],
        )
        .await;
    assert_eq!(granted.status, 303, "{}", granted.body);
    assert_eq!(scopes_of(&s, &other, RoleId::GlobalAdministrator).await, [Scope::All]);
    assert_eq!(audit_rows(&s, Event::AdminRoleGrant.as_str()).await.len(), 1);

    // It is listed, by name, with where it applies in words.
    let page = b.get(&s.url(PAGE)).await;
    assert!(page.body.contains("bea@contoso.com"), "{}", page.body);
    assert!(page.body.contains("<td>Global Administrator</td>"), "{}", page.body);

    let id = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.principal_id == other)
        .unwrap()
        .id;
    let revoked = b.post(&s.url(PAGE), &[("op", "revoke"), ("binding", &id)]).await;
    assert_eq!(revoked.status, 303, "{}", revoked.body);
    assert!(scopes_of(&s, &other, RoleId::GlobalAdministrator).await.is_empty());
    assert_eq!(audit_rows(&s, Event::AdminRoleRevoke.as_str()).await.len(), 1);
}

/// Only what is not bound to a tenant is here: a tenant's roles are neither
/// listed nor granted on this page, whatever the form is made to say.
#[tokio::test]
async fn tenant_roles_are_neither_listed_nor_granted_here() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    let theirs = user_fixture_in(&s, fabrikam.clone(), "zed@fabrikam.test").await;
    bind_in_own_tenant(&s, &theirs, RoleId::TenantAdministrator).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.get(&s.url(PAGE)).await;
    assert!(page.body.contains(&f.upn), "the Global Administrator: {}", page.body);
    assert!(!page.body.contains("zed@fabrikam.test"), "{}", page.body);
    assert!(!page.body.contains("Tenant Administrator"), "{}", page.body);

    let refused = b
        .post(
            &s.url(PAGE),
            &[
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", RoleId::UserAdministrator.as_str()),
                // Fields of the form this page used to have change nothing.
                ("scope", "all"),
                ("tenant", f.tenant.id.as_str()),
            ],
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.body.contains("that tenant's Roles tab"), "{}", refused.body);
    assert!(
        scopes_of(&s, &theirs.user_id, RoleId::UserAdministrator)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn what_cannot_be_granted_is_refused_with_a_reason() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    user_fixture_in(&s, fabrikam, "zed@fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let before = bindings::list_all(&s.pool).await.unwrap().len();

    for (form, why) in [
        (
            vec![("op", "grant"), ("account", "nobody@contoso.com")],
            "no account named",
        ),
        (
            vec![
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", "GlobalAdministrator"),
            ],
            "Only accounts and groups in the root tenant",
        ),
    ] {
        let page = b.post(&s.url(PAGE), &form).await;
        assert_eq!(page.status, 400, "{why}: {}", page.body);
        assert!(page.body.contains(why), "{why}: {}", page.body);
    }
    assert_eq!(
        bindings::list_all(&s.pool).await.unwrap().len(),
        before,
        "nothing was written"
    );
}

/// The page is the platform's. Somebody whose roles are all inside one tenant can
/// neither read it nor post to it, whatever the form says.
#[tokio::test]
async fn a_tenant_admin_cannot_read_or_grant_platform_roles() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(b.get(&s.url(PAGE)).await.status, 403);

    let before = bindings::list_all(&s.pool).await.unwrap().len();
    let page = b
        .post(
            &s.url(PAGE),
            &[
                ("op", "grant"),
                ("account", f.upn.as_str()),
                ("role", RoleId::GlobalAdministrator.as_str()),
            ],
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert_eq!(
        bindings::list_all(&s.pool).await.unwrap().len(),
        before,
        "no self-promotion"
    );
}

/// The last binding that can administer the platform cannot be revoked from here.
#[tokio::test]
async fn the_last_platform_binding_cannot_be_revoked() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let platform = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.role == RoleId::GlobalAdministrator)
        .unwrap();
    let page = b
        .post(&s.url(PAGE), &[("op", "revoke"), ("binding", &platform.id)])
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("last Global Administrator"), "{}", page.body);
    assert_eq!(
        scopes_of(&s, &f.user_id, RoleId::GlobalAdministrator).await,
        [Scope::All]
    );
}

/// After signing in, a platform administrator starts with no tenant in view; an
/// administrator of one tenant starts inside it.
#[tokio::test]
async fn where_an_administrator_lands_depends_on_their_reach() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let home = b.get(&s.url("/admin/home")).await;
    assert_eq!(home.status, 303);
    assert!(home.location.unwrap().ends_with("/admin/tenants"), "the platform view");
    let page = b.get(&s.url("/admin/tenants")).await;
    assert!(page.body.contains("No tenant selected"), "{}", page.body);
    // Only the platform's own tabs: nothing for a tenant nobody opened.
    for tab in [
        ">Users<",
        ">Groups<",
        ">Applications<",
        ">Roles<",
        ">Flow tester<",
        ">Audit log<",
    ] {
        assert!(
            !page.body.contains(tab),
            "{tab} is offered with no tenant in view: {}",
            page.body
        );
    }
    for tab in [">Tenants<", ">Signing keys<", ">Global roles<", ">Configuration<"] {
        assert!(page.body.contains(tab), "{tab} missing: {}", page.body);
    }

    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let home = b.get(&s.url("/admin/home")).await;
    assert_eq!(home.status, 303);
    assert!(
        home.location
            .unwrap()
            .ends_with(&format!("/admin/tenants/{}/users", f.tenant.id)),
        "their own tenant"
    );
}

/// A group of the root tenant can be made Global Administrator, named by its name
/// alone; a user by the part before the @, the root domain being implied.
#[tokio::test]
async fn global_administrator_is_granted_to_a_group_or_by_short_user_name() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let tenant = rust_oidc::tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let ops = rust_oidc::groups::create(&s.pool, &tenant, "Operators", None)
        .await
        .unwrap();
    let bea = another_user(&s, &f, "bea@contoso.com").await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    rust_oidc::groups::create(&s.pool, &fabrikam, "Outsiders", None)
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let page = b.get(&s.url(PAGE)).await;
    assert!(page.body.contains(r#"value="Group" class="is-group""#), "{}", page.body);
    assert!(page.body.contains("@ <strong>contoso.com</strong>"), "{}", page.body);

    let group = b
        .post(
            &s.url(PAGE),
            &[("op", "grant"), ("principal_type", "Group"), ("group", "operators")],
        )
        .await;
    assert_eq!(group.status, 303, "{}", group.body);
    let user = b
        .post(
            &s.url(PAGE),
            &[("op", "grant"), ("principal_type", "User"), ("account", "bea")],
        )
        .await;
    assert_eq!(user.status, 303, "{}", user.body);
    let held: Vec<(String, Scope)> = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.principal_id == ops || b.principal_id == bea)
        .map(|b| (b.principal_id, b.scope))
        .collect();
    assert_eq!(held.len(), 2, "{held:?}");
    assert!(held.iter().all(|(_, scope)| *scope == Scope::All));

    // The page lists the group, and a group of another tenant is not found.
    let page = b.get(&s.url(PAGE)).await;
    assert!(page.body.contains("<td>Operators</td>"), "{}", page.body);
    let outsider = b
        .post(
            &s.url(PAGE),
            &[("op", "grant"), ("principal_type", "Group"), ("group", "Outsiders")],
        )
        .await;
    assert_eq!(outsider.status, 400);
    assert!(outsider.body.contains("no group named"), "{}", outsider.body);
}
