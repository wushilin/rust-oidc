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

/// A second domain put there by hand, as a tenant from before "one domain" has.
async fn legacy_second_domain(s: &TestServer, tenant_id: &str, domain: &str) {
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO tenant_domains (domain, domain_folded, tenant_id, is_default, created_at) VALUES (?, ?, ?, ?, 0)",
    ))
    .bind(domain)
    .bind(domain)
    .bind(tenant_id)
    .bind(false)
    .execute(&s.pool)
    .await
    .unwrap();
}

async fn upns(s: &TestServer, tenant_id: &str) -> Vec<(String, Option<String>)> {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT upn, email FROM users WHERE tenant_id = ? ORDER BY upn_folded",
    ))
    .bind(tenant_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

/// A tenant has one domain. Changing it renames every account in the same step,
/// and nothing else about them moves.
#[tokio::test]
async fn changing_the_domain_renames_every_account_with_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await; // alice@contoso.com, a Global Administrator
    let tenant = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    for (upn, email) in [
        ("bob@contoso.com", Some("bob@contoso.com")), // the default: follows the name
        ("carol@contoso.com", Some("carol@personal.example")), // a real address: left alone
        ("Dave@Contoso.com", None),
    ] {
        users::create(
            &s.pool,
            &tenant,
            NewUser {
                upn,
                password: "Correct-Horse-9",
                display_name: None,
                given_name: None,
                family_name: None,
                email,
            },
        )
        .await
        .unwrap();
    }
    let group = rust_oidc::groups::create(&s.pool, &tenant, "Staff", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&s.pool, &tenant, "Staff", "bob@contoso.com")
        .await
        .unwrap();
    let ids_before: Vec<(String,)> = sqlx::query_as("SELECT id FROM users ORDER BY id")
        .fetch_all(&s.pool)
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");

    // The Settings page says what the domain is and offers to change it, not to add one.
    let settings = b.get(&s.url(&format!("/admin/tenants/{}/settings", f.tenant.id))).await;
    assert!(
        settings.body.contains("<strong>@contoso.com</strong>"),
        "{}",
        settings.body
    );
    assert!(settings.body.contains(r#"value="domain_change""#), "{}", settings.body);
    for gone in [r#"value="domain_add""#, r#"value="domain_remove""#] {
        assert!(!settings.body.contains(gone), "{gone}: {}", settings.body);
    }

    let changed = b
        .post(
            &url,
            &[
                ("op", "domain_change"),
                ("tenant", &f.tenant.id),
                ("domain", "Contoso.Example"),
            ],
        )
        .await;
    assert_eq!(changed.status, 303, "{}", changed.body);

    assert_eq!(
        tenant::domains(&s.pool, &f.tenant.id).await.unwrap(),
        ["contoso.example"]
    );
    assert!(
        tenant::resolve(&s.pool, "contoso.com").await.unwrap().is_none(),
        "the old one is released"
    );
    assert_eq!(
        tenant::resolve(&s.pool, "contoso.example").await.unwrap().unwrap().id,
        f.tenant.id
    );
    let after = upns(&s, &f.tenant.id).await;
    let names: Vec<&str> = after.iter().map(|(u, _)| u.as_str()).collect();
    assert_eq!(
        names,
        [
            "alice@contoso.example",
            "bob@contoso.example",
            "carol@contoso.example",
            "Dave@contoso.example"
        ]
    );
    let email_of = |upn: &str| after.iter().find(|(u, _)| u == upn).unwrap().1.clone();
    assert_eq!(email_of("bob@contoso.example").as_deref(), Some("bob@contoso.example"));
    assert_eq!(
        email_of("carol@contoso.example").as_deref(),
        Some("carol@personal.example")
    );
    assert_eq!(email_of("Dave@contoso.example"), None);

    // The same people: ids, group membership and roles are untouched.
    let ids_after: Vec<(String,)> = sqlx::query_as("SELECT id FROM users ORDER BY id")
        .fetch_all(&s.pool)
        .await
        .unwrap();
    assert_eq!(ids_after, ids_before);
    let members = rust_oidc::groups::members(&s.pool, &group).await.unwrap();
    assert_eq!(members.len(), 1);
    // The administrator who did it is still signed in, and signs in next time
    // with the new name and the same password.
    assert_eq!(b.get(&url).await.status, 200);
    let renamed = UserFixture {
        upn: "alice@contoso.example".into(),
        ..f
    };
    let again = signed_in_admin(&s, &renamed).await;
    assert_eq!(again.get(&url).await.status, 200);
    // New accounts go on the new domain, the old one is refused.
    let tenant = tenant::find_for_admin(&s.pool, &renamed.tenant.id).await.unwrap();
    assert!(users::validate_upn(&s.pool, &tenant, "eve@contoso.com").await.is_err());
    assert!(
        users::validate_upn(&s.pool, &tenant, "eve@contoso.example")
            .await
            .is_ok()
    );

    // One audit row, saying from what to what and how many were renamed.
    let rows = audit_rows(&s, rust_oidc::db::Event::AdminTenantDomainChange.as_str()).await;
    assert_eq!(rows.len(), 1);
    let (details,): (String,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ?",
    ))
    .bind(rust_oidc::db::Event::AdminTenantDomainChange.as_str())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(
        details.contains("contoso.example") && details.contains("contoso.com") && details.contains("\"renamed\":4"),
        "{details}"
    );
}

#[tokio::test]
async fn a_domain_change_that_cannot_be_made_changes_nothing() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");
    let before = upns(&s, &f.tenant.id).await;

    for (domain, why) in [
        ("fabrikam.test", "already registered"), // another tenant's
        ("contoso.com", "already this tenant"),  // its own
        ("not a domain", "invalid domain"),
        ("", "invalid domain"),
    ] {
        let page = b
            .post(
                &url,
                &[("op", "domain_change"), ("tenant", &f.tenant.id), ("domain", domain)],
            )
            .await;
        assert_eq!(page.status, 400, "{domain}: {}", page.body);
        assert!(page.body.contains(why), "{domain}: {}", page.body);
    }
    assert_eq!(tenant::domains(&s.pool, &f.tenant.id).await.unwrap(), ["contoso.com"]);
    assert_eq!(upns(&s, &f.tenant.id).await, before);
    assert_eq!(
        tenant::resolve(&s.pool, "fabrikam.test").await.unwrap().unwrap().id,
        other.id,
        "the domain still belongs to the tenant that had it"
    );
}

/// A tenant that still has several domains, from before a tenant had one. The
/// surplus ones can be withdrawn when nobody uses them, and changing the domain
/// brings everyone onto one -- unless two accounts would get the same name, in
/// which case nothing at all is changed.
#[tokio::test]
async fn a_tenant_with_several_domains_is_brought_down_to_one() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");
    let remove = |domain: &'static str| {
        let (b, url, id) = (&b, &url, f.tenant.id.clone());
        async move {
            b.post(url, &[("op", "domain_remove"), ("tenant", &id), ("domain", domain)])
                .await
        }
    };

    // The only domain cannot be withdrawn.
    let only = remove("contoso.com").await;
    assert_eq!(only.status, 400, "{}", only.body);
    assert!(only.body.contains("at least one"), "{}", only.body);

    legacy_second_domain(&s, &f.tenant.id, "contoso.example").await;
    legacy_second_domain(&s, &f.tenant.id, "unused.example").await;
    let tenant = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    for upn in ["bob@contoso.example", "alice@contoso.example"] {
        users::create(
            &s.pool,
            &tenant,
            NewUser {
                upn,
                password: "Correct-Horse-9",
                display_name: None,
                given_name: None,
                family_name: None,
                email: None,
            },
        )
        .await
        .unwrap();
    }
    // The page lists them, with a way to withdraw each.
    let settings = b.get(&s.url(&format!("/admin/tenants/{}/settings", f.tenant.id))).await;
    assert!(settings.body.contains("more than one domain"), "{}", settings.body);
    assert!(settings.body.contains(r#"value="domain_remove""#), "{}", settings.body);

    // One in use stays; one nobody uses goes.
    let in_use = remove("contoso.example").await;
    assert_eq!(in_use.status, 400, "{}", in_use.body);
    assert!(in_use.body.contains("still use"), "{}", in_use.body);
    assert_eq!(remove("unused.example").await.status, 303);

    // alice@contoso.com and alice@contoso.example cannot both become alice@new.
    let before = upns(&s, &f.tenant.id).await;
    let clash = b
        .post(
            &url,
            &[
                ("op", "domain_change"),
                ("tenant", &f.tenant.id),
                ("domain", "new.example"),
            ],
        )
        .await;
    assert_eq!(clash.status, 400, "{}", clash.body);
    assert!(
        clash.body.contains("alice@new.example"),
        "it names the clash: {}",
        clash.body
    );
    assert_eq!(upns(&s, &f.tenant.id).await, before, "nobody was renamed");
    assert_eq!(tenant::domains(&s.pool, &f.tenant.id).await.unwrap().len(), 2);

    // With the clash out of the way, everyone lands on the one domain -- which
    // may be one the tenant already had.
    sqlx::query(rust_oidc::db::q(&s.pool, "DELETE FROM users WHERE upn_folded = ?"))
        .bind("alice@contoso.example")
        .execute(&s.pool)
        .await
        .unwrap();
    let merged = b
        .post(
            &url,
            &[
                ("op", "domain_change"),
                ("tenant", &f.tenant.id),
                ("domain", "contoso.example"),
            ],
        )
        .await;
    assert_eq!(merged.status, 303, "{}", merged.body);
    assert_eq!(
        tenant::domains(&s.pool, &f.tenant.id).await.unwrap(),
        ["contoso.example"]
    );
    let names: Vec<String> = upns(&s, &f.tenant.id).await.into_iter().map(|(u, _)| u).collect();
    assert_eq!(names, ["alice@contoso.example", "bob@contoso.example"]);
}

/// The root tenant holds the administrators who would have to undo it, and the
/// console is the only admin surface, so disabling it would be unrecoverable.
#[tokio::test]
async fn the_root_tenant_cannot_be_disabled_and_no_second_one_can_be_created() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/tenants");
    // The administrator's own tenant is the root tenant: only its accounts can
    // hold an every-tenant role, and there is exactly one root.
    let root = f.tenant.clone();
    assert!(root.is_root);

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
        page.body.contains("contoso.com"),
        "the root tenant is listed: {}",
        page.body
    );
    let row = page
        .body
        .split("<tr>")
        .find(|row| row.contains("contoso.com"))
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
        vec![("op", "domain_change"), ("tenant", &other.id), ("domain", "mole.test")],
        vec![
            ("op", "domain_remove"),
            ("tenant", &other.id),
            ("domain", "fabrikam.test"),
        ],
        // Their own tenant too: these routes are platform-scope, not "any tenant
        // you administer".
        vec![("op", "rename"), ("tenant", &f.tenant.id), ("name", "Renamed")],
        vec![
            ("op", "domain_change"),
            ("tenant", &f.tenant.id),
            ("domain", "mole.test"),
        ],
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
    for offered in ["Create a tenant", r#"value="rename""#, r#"value="domain_change""#] {
        assert!(!page.body.contains(offered), "{offered} is offered: {}", page.body);
    }
}

/// The list is a list: a tenant's name opens it, and what can be done inside it
/// is on its own tabs rather than repeated on every row.
#[tokio::test]
async fn a_tenant_row_opens_the_tenant_whose_tabs_include_the_flow_tester() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    // The name is the link, to the first section these roles reach.
    let opened = format!(r#"/admin/tenants/{}/users">"#, f.tenant.id);
    assert!(
        page.body.contains(&opened),
        "the tenant name opens the tenant: {}",
        page.body
    );
    // No tenant is in view on the list, so no tenant tab is offered there.
    assert!(page.body.contains("No tenant selected"), "{}", page.body);
    assert!(
        !page.body.contains(&format!("/admin/tenants/{}/flow", f.tenant.id)),
        "{}",
        page.body
    );

    // Inside the tenant its name is in the corner and its tabs are shown.
    let inside = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert_eq!(inside.status, 200, "{}", inside.body);
    assert!(
        inside.body.contains(&format!(
            r#"<span class="tenant">Tenant <strong>{}</strong></span>"#,
            f.tenant.name
        )),
        "{}",
        inside.body
    );
    assert!(
        inside.body.contains(&format!("/admin/tenants/{}/flow\"", f.tenant.id)),
        "{}",
        inside.body
    );
    assert!(
        inside.body.contains(r#"class="active" aria-current="page""#),
        "{}",
        inside.body
    );
    let flow = b.get(&s.url(&format!("/admin/tenants/{}/flow", f.tenant.id))).await;
    assert_eq!(flow.status, 200, "{}", flow.body);
}
