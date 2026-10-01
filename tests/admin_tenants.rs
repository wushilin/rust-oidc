//! The console's tenants section, through HTTP.
//!
//! Every write here is platform-scope, so the isolation test is a different shape
//! from the other sections': there is no `{tenant}` segment to aim at another
//! tenant, and the attack is a *tenant* administrator — who holds `Tenant:Write`
//! within their own tenant — trying to use these routes at all.
//!
//! Two lock-outs are tested as the refusals they are, because neither has a way
//! back from the console: disabling the root tenant, and withdrawing a domain that
//! an account still signs in with.

mod common;

use common::*;
use rust_oidc::tenant::{self, Tenant};
use rust_oidc::users::{self, NewUser};

/// The tenant with this name, resolved the way an administrator would: by a form
/// field, so a disabled one is found too.
async fn by_domain(s: &TestServer, domain: &str) -> Tenant {
    tenant::find_for_admin(&s.pool, domain)
        .await
        .unwrap_or_else(|e| panic!("tenant '{domain}' not found: {e}"))
}

#[tokio::test]
async fn a_tenant_is_created_renamed_disabled_and_re_enabled() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");

    let created = b
        .post(
            &url,
            &[("op", "create"), ("name", "Northwind"), ("domain", "northwind.test")],
        )
        .await;
    assert_eq!(created.status, 303, "{}", created.body);
    let made = by_domain(&s, "northwind.test").await;
    assert_eq!(made.name, "Northwind");
    assert!(made.enabled);
    assert!(
        !made.is_root,
        "a tenant created from the console is never a root tenant"
    );
    assert_eq!(
        tenant::domains(&s.pool, &made.id).await.unwrap(),
        vec!["northwind.test".to_string()]
    );
    // It starts on the default lifetimes, as `tenant::create` writes them.
    assert_eq!(made.settings.access_token_lifetime_secs, 3599);
    assert_eq!(made.settings.session_lifetime_secs, 86_400);

    // Rename: the display name only, so the id and the domains still resolve.
    let renamed = b
        .post(
            &url,
            &[("op", "rename"), ("tenant", &made.id), ("name", "Northwind Traders")],
        )
        .await;
    assert_eq!(renamed.status, 303, "{}", renamed.body);
    assert_eq!(by_domain(&s, "northwind.test").await.name, "Northwind Traders");

    // Disabling it takes it out of `resolve`, which is what stops every OIDC
    // endpoint and every tenant-scoped console page answering for it.
    let disabled = b.post(&url, &[("op", "disable"), ("tenant", &made.id)]).await;
    assert_eq!(disabled.status, 303, "{}", disabled.body);
    assert!(
        tenant::resolve(&s.pool, &made.id).await.unwrap().is_none(),
        "a disabled tenant must not resolve"
    );
    assert!(!by_domain(&s, "northwind.test").await.enabled);

    // And back. This is why the route carries no `{tenant}` segment: a disabled
    // tenant could never be addressed by one.
    let enabled = b.post(&url, &[("op", "enable"), ("tenant", &made.id)]).await;
    assert_eq!(enabled.status, 303, "{}", enabled.body);
    assert!(tenant::resolve(&s.pool, &made.id).await.unwrap().is_some());

    for action in [
        "admin.tenant.create",
        "admin.tenant.rename",
        "admin.tenant.disable",
        "admin.tenant.enable",
    ] {
        let rows = audit_rows(&s, action).await;
        assert_eq!(rows.len(), 1, "{action} was not recorded exactly once");
        assert_eq!(rows[0].0, f.user_id, "{action} named the wrong actor");
        assert_eq!(
            rows[0].2.as_deref(),
            Some(made.id.as_str()),
            "{action} was recorded against the wrong tenant"
        );
    }
}

#[tokio::test]
async fn a_verified_domain_is_added_and_withdrawn() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");

    let added = b
        .post(
            &url,
            &[
                ("op", "domain_add"),
                ("tenant", &f.tenant.id),
                ("domain", "contoso.example"),
            ],
        )
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    let domains = tenant::domains(&s.pool, &f.tenant.id).await.unwrap();
    assert!(domains.contains(&"contoso.example".to_string()), "{domains:?}");
    // A verified domain is an alias for the tenant everywhere, including in URLs.
    assert_eq!(
        tenant::resolve(&s.pool, "contoso.example").await.unwrap().unwrap().id,
        f.tenant.id
    );

    let removed = b
        .post(
            &url,
            &[
                ("op", "domain_remove"),
                ("tenant", &f.tenant.id),
                ("domain", "contoso.example"),
            ],
        )
        .await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert!(
        !tenant::domains(&s.pool, &f.tenant.id)
            .await
            .unwrap()
            .contains(&"contoso.example".to_string())
    );
    assert!(tenant::resolve(&s.pool, "contoso.example").await.unwrap().is_none());

    // A domain another tenant holds is not available.
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let taken = b
        .post(
            &url,
            &[
                ("op", "domain_add"),
                ("tenant", &f.tenant.id),
                ("domain", "fabrikam.test"),
            ],
        )
        .await;
    assert_eq!(taken.status, 400, "{}", taken.body);
    assert_eq!(
        tenant::resolve(&s.pool, "fabrikam.test").await.unwrap().unwrap().id,
        other.id,
        "the domain still belongs to the tenant that had it"
    );
}

/// Both refusals that stop a domain withdrawal stranding an identity.
#[tokio::test]
async fn a_domain_still_in_use_or_the_only_one_cannot_be_withdrawn() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");

    // The tenant's only domain, which every one of its accounts signs in with.
    let only = b
        .post(
            &url,
            &[
                ("op", "domain_remove"),
                ("tenant", &f.tenant.id),
                ("domain", "contoso.com"),
            ],
        )
        .await;
    assert_eq!(only.status, 400, "{}", only.body);
    assert!(only.body.contains("at least one"), "{}", only.body);
    assert!(
        tenant::domains(&s.pool, &f.tenant.id)
            .await
            .unwrap()
            .contains(&"contoso.com".to_string())
    );

    // A second domain, with an account whose user name uses it.
    tenant::add_domain(&s.pool, &f.tenant.id, "contoso.example")
        .await
        .unwrap();
    let tenant = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    users::create(
        &s.pool,
        &tenant,
        NewUser {
            upn: "bob@contoso.example",
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();

    let in_use = b
        .post(
            &url,
            &[
                ("op", "domain_remove"),
                ("tenant", &f.tenant.id),
                ("domain", "contoso.example"),
            ],
        )
        .await;
    assert_eq!(in_use.status, 400, "{}", in_use.body);
    assert!(in_use.body.contains("still use"), "{}", in_use.body);
    assert!(
        tenant::resolve(&s.pool, "contoso.example").await.unwrap().is_some(),
        "the domain bob signs in with is still verified"
    );
}

/// The root tenant holds the administrators who would have to undo it, and the
/// console is the only admin surface, so disabling it would be unrecoverable.
#[tokio::test]
async fn the_root_tenant_cannot_be_disabled_and_no_second_one_can_be_created() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");
    let root = tenant::create(&s.pool, "System", "system.test", true).await.unwrap();

    let refused = b.post(&url, &[("op", "disable"), ("tenant", &root.id)]).await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(
        refused.body.contains("root tenant cannot be disabled"),
        "{}",
        refused.body
    );
    assert!(
        tenant::resolve(&s.pool, &root.id).await.unwrap().is_some(),
        "the root tenant still resolves"
    );
    assert!(audit_rows(&s, "admin.tenant.disable").await.is_empty());

    // The page does not offer the button either.
    let page = b.get(&url).await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("system.test"),
        "the root tenant is listed: {}",
        page.body
    );
    let row = page
        .body
        .split("<tr>")
        .find(|row| row.contains("system.test"))
        .expect("the root tenant's row");
    assert!(
        !row.contains(r#"value="disable""#),
        "the root tenant is offered a disable button: {row}"
    );

    // Creating a tenant can never mint a second root: the console asks for
    // `is_root = false`, and the schema's unique index would refuse one anyway.
    let created = b
        .post(&url, &[("op", "create"), ("name", "Second"), ("domain", "second.test")])
        .await;
    assert_eq!(created.status, 303, "{}", created.body);
    assert!(!by_domain(&s, "second.test").await.is_root);
    assert_eq!(
        tenant::root(&s.pool).await.unwrap().map(|t| t.id),
        Some(root.id),
        "the root tenant is still the only one"
    );
}

/// The isolation test for this section. A tenant administrator holds
/// `Tenant:Write` — but only within their own tenant, and these routes require it
/// at platform scope, so every one of them is refused, including against their own
/// tenant.
#[tokio::test]
async fn a_tenant_admin_cannot_use_the_platform_tenant_routes() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");

    let posts: Vec<Vec<(&str, &str)>> = vec![
        vec![("op", "create"), ("name", "Mole"), ("domain", "mole.test")],
        vec![("op", "rename"), ("tenant", &other.id), ("name", "Taken over")],
        vec![("op", "disable"), ("tenant", &other.id)],
        vec![("op", "domain_add"), ("tenant", &other.id), ("domain", "mole.test")],
        vec![
            ("op", "domain_remove"),
            ("tenant", &other.id),
            ("domain", "fabrikam.test"),
        ],
        // Their own tenant too: these routes are platform-scope, not "any tenant
        // you administer".
        vec![("op", "rename"), ("tenant", &f.tenant.id), ("name", "Renamed")],
        vec![("op", "domain_add"), ("tenant", &f.tenant.id), ("domain", "mole.test")],
    ];
    for form in posts {
        let page = b.post(&url, &form).await;
        assert_eq!(page.status, 403, "{form:?} was allowed: {}", page.body);
    }

    // Nothing moved.
    assert_eq!(by_domain(&s, "fabrikam.test").await.name, "Fabrikam");
    assert!(by_domain(&s, "fabrikam.test").await.enabled);
    assert_eq!(by_domain(&s, "contoso.com").await.name, "Contoso");
    assert!(tenant::find_for_admin(&s.pool, "mole.test").await.is_err());
    assert_eq!(
        tenant::domains(&s.pool, &other.id).await.unwrap(),
        vec!["fabrikam.test".to_string()]
    );

    // The page offers them none of it, and does not list the other tenant.
    let page = b.get(&url).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Contoso"), "their own tenant is listed");
    assert!(!page.body.contains("Fabrikam"), "and nobody else's: {}", page.body);
    assert!(!page.body.contains(&other.id), "{}", page.body);
    for offered in ["Create a tenant", r#"value="rename""#, r#"value="domain_add""#] {
        assert!(!page.body.contains(offered), "{offered} is offered: {}", page.body);
    }
}

/// Each tenant row on the Tenants page links straight to that tenant's flow
/// tester, so testing a sign-in does not start with hunting through the menu.
#[tokio::test]
async fn each_tenant_row_links_to_its_flow_tester() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let link = format!("/admin/tenants/{}/flow\"", f.tenant.id);
    assert!(
        page.body.contains(&link),
        "no flow tester link for the tenant: {}",
        page.body
    );
    // And the link leads somewhere real.
    let flow = b.get(&s.url(&format!("/admin/tenants/{}/flow", f.tenant.id))).await;
    assert_eq!(flow.status, 200, "{}", flow.body);
}
