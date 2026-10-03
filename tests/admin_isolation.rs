//! A tenant admin must be confined to the tenants they are bound to, and must not
//! be able to widen that. The point of the whole design, so these tests are
//! written as attacks rather than as features.
mod common;
use common::*;

use rust_oidc::admin::authz::may_write_binding;
use rust_oidc::rbac::Scope;
use rust_oidc::users::{self, NewUser};

async fn victim_in(s: &TestServer, tenant: &rust_oidc::tenant::Tenant, upn: &str) -> String {
    users::create(
        &s.pool,
        tenant,
        NewUser {
            upn,
            password: "Correct-Horse-9",
            display_name: Some("Victim"),
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap()
}

/// Every tenant-scoped route, for an admin bound only to their own tenant, aimed
/// at another one.
#[tokio::test]
async fn a_tenant_admin_is_refused_on_another_tenant() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let victim = victim_in(&s, &other, "target@fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let gets = [
        format!("/admin/tenants/{}/users", other.id),
        format!("/admin/tenants/{}/users/{victim}", other.id),
        format!("/admin/tenants/{}/users/new", other.id),
    ];
    for path in gets {
        let page = b.get(&s.url(&path)).await;
        assert!(
            page.status == 403 || page.status == 404,
            "GET {path} leaked with {}: {}",
            page.status,
            page.body
        );
    }
    let posts: [(String, Vec<(&str, &str)>); 3] = [
        (
            format!("/admin/tenants/{}/users/new", other.id),
            vec![("upn", "mole@fabrikam.test"), ("password", "Correct-Horse-9")],
        ),
        (
            format!("/admin/tenants/{}/users/{victim}", other.id),
            vec![("op", "disable")],
        ),
        (
            format!("/admin/tenants/{}/users/{victim}", other.id),
            vec![("op", "reset"), ("password", "Taken-Over-9")],
        ),
    ];
    for (path, form) in posts {
        let page = b.post(&s.url(&path), &form).await;
        assert!(
            page.status == 403 || page.status == 404,
            "POST {path} leaked with {}: {}",
            page.status,
            page.body
        );
    }

    // And the other tenant is untouched.
    let still = users::find(&s.pool, &other.id, &victim).await.unwrap().unwrap();
    assert!(still.enabled, "the victim is still enabled");
    assert!(
        users::list(&s.pool, &other.id, Some("mole"), 10, 0)
            .await
            .unwrap()
            .is_empty(),
        "nothing was created in the other tenant"
    );
    let outcome = users::authenticate(&s.pool, &other, "target@fabrikam.test", "Correct-Horse-9")
        .await
        .unwrap();
    assert!(
        matches!(outcome, users::AuthResult::Ok(_)),
        "the victim's password was not reset"
    );
}

/// The tenant list must not be a directory of every tenant on the deployment.
#[tokio::test]
async fn a_tenant_admin_does_not_see_other_tenants_listed() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Contoso"), "their own tenant: {}", page.body);
    assert!(!page.body.contains("Fabrikam"), "and nobody else's: {}", page.body);
    assert!(!page.body.contains(&other.id), "{}", page.body);
}

/// A tenant may be addressed by a verified domain instead of its GUID. The scope
/// check compares canonical ids, so the alias form must not bypass it.
#[tokio::test]
async fn the_domain_alias_form_does_not_bypass_scope() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let _other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants/fabrikam.test/users")).await;
    assert!(
        page.status == 403 || page.status == 404,
        "{} {}",
        page.status,
        page.body
    );
    // The alias of their own tenant still works, so the check is on identity and
    // not on the form of the URL.
    let own = b.get(&s.url("/admin/tenants/contoso.com/users")).await;
    assert_eq!(own.status, 200, "{}", own.body);
}

/// The platform roles page is platform-wide, so a tenant admin must not see it —
/// it would otherwise list every tenant id on the deployment.
#[tokio::test]
async fn a_tenant_admin_cannot_read_the_platform_roles() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/bindings")).await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert!(!page.body.contains(&f.tenant.id), "{}", page.body);
}

#[tokio::test]
async fn a_tenant_admin_cannot_grant_themselves_another_tenant() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let eff = rust_oidc::admin::bindings::effective_for_user(&s.pool, &f.user_id)
        .await
        .unwrap();

    assert!(may_write_binding(&eff, &Scope::Tenants(vec![f.tenant.id.clone()])));
    assert!(!may_write_binding(&eff, &Scope::Tenants(vec![other.id.clone()])));
    assert!(!may_write_binding(
        &eff,
        &Scope::Tenants(vec![f.tenant.id.clone(), other.id.clone()])
    ));
    assert!(!may_write_binding(&eff, &Scope::All));
}

#[tokio::test]
async fn a_reader_can_look_but_not_touch() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let list = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert_eq!(list.status, 200, "{}", list.body);
    for form in [
        vec![("op", "disable")],
        vec![("op", "delete")],
        vec![("op", "attributes"), ("display_name", "Hacked")],
    ] {
        let write = b
            .post(
                &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
                &form,
            )
            .await;
        assert_eq!(write.status, 403, "{form:?}: {}", write.body);
    }
    let user = users::find(&s.pool, &f.tenant.id, &f.user_id).await.unwrap().unwrap();
    assert!(user.enabled);
    assert_eq!(user.display_name.as_deref(), Some("Alice Smith"));
}

#[tokio::test]
async fn the_nav_offers_only_permitted_actions() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert!(
        !page.body.contains("users/new"),
        "a reader is not offered create: {}",
        page.body
    );
    assert!(!page.body.contains("Disable sign-in"), "{}", page.body);
    assert!(!page.body.contains("Reset password"), "{}", page.body);
}

/// A role that is narrow by *action* rather than by scope must also be confined:
/// a user administrator can manage people but must not be able to read
/// tenants.
#[tokio::test]
async fn a_user_administrator_holds_only_the_user_pages() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind(
        &s,
        &f.user_id,
        rust_oidc::rbac::RoleId::UserAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let _other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    assert_eq!(
        b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id)))
            .await
            .status,
        200
    );
    assert_eq!(b.get(&s.url("/admin/bindings")).await.status, 403);
    let tenants = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(tenants.status, 200);
    assert!(
        !tenants.body.contains("Fabrikam") && !tenants.body.contains("Contoso"),
        "a user administrator has no Tenant:Read at all: {}",
        tenants.body
    );
}
