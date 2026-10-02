//! Find by id, names in the audit log, and the new-user form.

mod common;

use common::*;
use rust_oidc::{apps, groups, users};

fn find(s: &TestServer, id: &str) -> String {
    s.url(&format!("/admin/find?id={id}"))
}

#[tokio::test]
async fn an_id_is_identified_as_what_it_is() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let group = groups::create(&s.pool, &f.tenant, "Engineering", None).await.unwrap();
    let api = apps::find(&s.pool, &f.api.app_id).await.unwrap().unwrap();
    let role = apps::roles(&s.pool, &api).await.unwrap().remove(0);
    let scope = apps::scopes(&s.pool, &api).await.unwrap().remove(0);

    for (id, kind, name) in [
        (f.user_id.clone(), "User", f.upn.clone()),
        (group, "Group", "Engineering".to_string()),
        (f.api.app_id.clone(), "Application", api.display_name.clone()),
        (api.id.clone(), "Application", api.display_name.clone()),
        (f.api.sp_id.clone(), "Service principal", api.display_name.clone()),
        (role.id.clone(), "App role", role.value.clone()),
        (scope.id.clone(), "Scope", scope.value.clone()),
        (f.tenant.id.clone(), "Tenant", f.tenant.name.clone()),
    ] {
        let page = b.get(&find(&s, &id)).await;
        assert_eq!(page.status, 200, "{kind}: {}", page.body);
        assert!(
            page.body.contains(&format!("<td>{kind}</td>")),
            "{id} should be a {kind}: {}",
            page.body
        );
        assert!(
            page.body.contains(&name),
            "{kind} {id} should be named {name}: {}",
            page.body
        );
    }
    // Upper case finds it too: ids are compared the way they are stored.
    let page = b.get(&find(&s, &f.user_id.to_uppercase())).await;
    assert!(page.body.contains("<td>User</td>"), "{}", page.body);

    let page = b.get(&find(&s, "11111111-2222-3333-4444-555555555555")).await;
    assert!(page.body.contains("Nothing with the id"), "{}", page.body);
}

/// The search is not a way around the tenant boundary: an object in a tenant the
/// administrator cannot read gets the same answer as one that does not exist.
#[tokio::test]
async fn an_id_in_another_tenant_is_reported_as_nothing() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let outsider = users::create(
        &s.pool,
        &other,
        users::NewUser {
            upn: "zed@fabrikam.test",
            password: "Another-Passw0rd!",
            display_name: Some("Zed Outsider"),
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    let their_app = s.app(&other, "fabrikam-api").await;
    let b = signed_in_admin(&s, &f).await;

    // Their own tenant's objects are found...
    assert!(b.get(&find(&s, &f.user_id)).await.body.contains("<td>User</td>"));
    // ...the other tenant's are not, and nothing about them is said.
    for id in [
        outsider.as_str(),
        their_app.app_id.as_str(),
        their_app.sp_id.as_str(),
        other.id.as_str(),
    ] {
        let page = b.get(&find(&s, id)).await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains("Nothing with the id"), "{id} leaked: {}", page.body);
        for leak in ["zed@fabrikam.test", "Zed Outsider", "fabrikam-api", "Fabrikam"] {
            assert!(
                !page.body.contains(leak),
                "{leak} is visible across the tenant boundary: {}",
                page.body
            );
        }
    }
}

/// The audit log names who did something, when the reader may know who that is.
#[tokio::test]
async fn the_audit_log_names_actors_the_reader_may_see_and_no_others() {
    let s = TestServer::start().await;
    // A tenant administrator, and a platform administrator from another tenant.
    let f = tenant_admin_fixture(&s).await;
    let root = s.tenant("Operations", "ops.test").await;
    let platform_user = users::create(
        &s.pool,
        &root,
        users::NewUser {
            upn: "root-op@ops.test",
            password: "Another-Passw0rd!",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    // Two entries in the tenant's log: one by its own administrator, one by the outsider.
    for actor in [f.user_id.as_str(), platform_user.as_str()] {
        rust_oidc::db::audit(
            &s.pool,
            Some(&f.tenant.id),
            rust_oidc::db::Actor::Id(actor),
            rust_oidc::db::Event::AdminUserUpdate,
            Some(&f.user_id),
            serde_json::json!({}),
        )
        .await
        .unwrap();
    }
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/audit", f.tenant.id))).await;
    assert_eq!(page.status, 200, "{}", page.body);
    // Their own account is named, with the id kept as the tooltip.
    assert!(
        page.body.contains(&format!(r#"title="{}">{}</a>"#, f.user_id, f.upn)),
        "{}",
        page.body
    );
    // The outsider stays an id: this page must not say who that is.
    assert!(page.body.contains(&platform_user), "{}", page.body);
    assert!(!page.body.contains("root-op@ops.test"), "{}", page.body);
}

#[tokio::test]
async fn a_new_user_is_named_by_the_part_before_the_at_and_a_picked_domain() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let new = s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id));

    // The form offers the tenant's verified domains to pick from.
    let page = b.get(&new).await;
    assert!(page.body.contains(r#"<option value="contoso.com""#), "{}", page.body);

    // The part before the @, plus the picked domain. The email is left empty and
    // becomes the user name.
    let made = b
        .post(
            &new,
            &[
                ("upn", "dana"),
                ("upn_domain", "contoso.com"),
                ("password", "A-Long-Passw0rd!"),
            ],
        )
        .await;
    assert_eq!(made.status, 303, "{}", made.body);
    let dana = users::find_by_upn(&s.pool, &f.tenant.id, "dana@contoso.com")
        .await
        .unwrap()
        .expect("dana@contoso.com exists");
    assert_eq!(dana.email.as_deref(), Some("dana@contoso.com"));

    // A whole name typed in is used as typed; the picked domain is ignored. An
    // email given is kept as given.
    let made = b
        .post(
            &new,
            &[
                ("upn", "erin@contoso.com"),
                ("upn_domain", "ignored.example"),
                ("password", "A-Long-Passw0rd!"),
                ("email", "erin.personal@example.org"),
            ],
        )
        .await;
    assert_eq!(made.status, 303, "{}", made.body);
    let erin = users::find_by_upn(&s.pool, &f.tenant.id, "erin@contoso.com")
        .await
        .unwrap()
        .expect("erin@contoso.com exists");
    assert_eq!(erin.email.as_deref(), Some("erin.personal@example.org"));

    // The picker is a convenience, not a check: a domain this tenant has not
    // verified is refused whichever way it arrives.
    for form in [
        vec![
            ("upn", "mallory"),
            ("upn_domain", "evil.example"),
            ("password", "A-Long-Passw0rd!"),
        ],
        vec![
            ("upn", "mallory@evil.example"),
            ("upn_domain", "contoso.com"),
            ("password", "A-Long-Passw0rd!"),
        ],
    ] {
        let refused = b.post(&new, &form).await;
        assert_eq!(refused.status, 400, "{}", refused.body);
    }
    assert!(
        users::find_by_upn(&s.pool, &f.tenant.id, "mallory@evil.example")
            .await
            .unwrap()
            .is_none()
    );
}

/// Assuming a tenant goes into it.
#[tokio::test]
async fn assuming_a_tenant_lands_inside_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.post(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(
        page.location
            .unwrap()
            .ends_with(&format!("/admin/tenants/{}/users", target.id)),
        "assume enters the tenant"
    );
}
