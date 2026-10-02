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
    assert!(page.body.contains("Grant a role"), "{}", page.body);
    // Every role is explained where it is granted.
    for role in RoleId::ALL {
        assert!(page.body.contains(role.display_name()), "{role:?}: {}", page.body);
    }

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
    assert!(page.body.contains(">everything<"), "{}", page.body);

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

/// No tenant is ever picked: a tenant role applies to the account's own tenant,
/// whatever the form is made to say.
#[tokio::test]
async fn a_tenant_role_applies_to_the_accounts_own_tenant() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    let theirs = user_fixture_in(&s, fabrikam.clone(), "zed@fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let granted = b
        .post(
            &s.url(PAGE),
            &[
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", RoleId::UserAdministrator.as_str()),
                // Stale or forged fields from the old form change nothing.
                ("scope", "all"),
                ("tenant", f.tenant.id.as_str()),
            ],
        )
        .await;
    assert_eq!(granted.status, 303, "{}", granted.body);
    assert_eq!(
        scopes_of(&s, &theirs.user_id, RoleId::UserAdministrator).await,
        [Scope::Tenants(vec![fabrikam.id.clone()])]
    );

    // The page names the tenant rather than printing its id.
    let page = b.get(&s.url(PAGE)).await;
    assert!(
        page.body.contains(r#"<span class="pill">Fabrikam</span>"#),
        "{}",
        page.body
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
            vec![
                ("op", "grant"),
                ("account", "nobody@contoso.com"),
                ("role", "TenantViewer"),
            ],
            "no account named",
        ),
        (
            vec![
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", "PlatformAdministrator"),
            ],
            "Choose a role",
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
    for tab in [">Tenants<", ">Signing keys<", ">All roles<"] {
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
