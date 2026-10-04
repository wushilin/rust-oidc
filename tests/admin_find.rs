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
async fn a_new_user_is_named_by_the_part_before_the_at_and_the_tenants_domain() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let new = s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id));

    // The form shows the tenant's domain beside the name. There is one, so
    // there is nothing to pick.
    let page = b.get(&new).await;
    assert!(page.body.contains("@ <strong>contoso.com</strong>"), "{}", page.body);
    assert!(
        page.body.contains(r#"name="upn_domain" value="contoso.com""#),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<select name=\"upn_domain\""), "{}", page.body);

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

/// A deleted user, application or group is still found, marked as deleted and
/// read-only, so an id in an old audit entry still says something. A deleted
/// user can be restored from there.
#[tokio::test]
async fn deleted_objects_are_found_read_only_and_a_user_can_be_restored() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let tenant = rust_oidc::tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let gone = user_fixture_in(&s, f.tenant.clone(), "gone@contoso.com").await;
    let group = rust_oidc::groups::create(&s.pool, &tenant, "Old team", None)
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(
        b.post(
            &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, gone.user_id)),
            &[("op", "delete")]
        )
        .await
        .status,
        303
    );
    assert!(rust_oidc::groups::delete(&s.pool, &f.tenant.id, &group).await.unwrap());

    let page = b.get(&s.url(&format!("/admin/find?id={}", gone.user_id))).await;
    assert!(page.body.contains("gone@contoso.com"), "{}", page.body);
    assert!(page.body.contains("deleted "), "{}", page.body);
    assert!(
        !page.body.contains(&format!(
            r#"href="{}"#,
            s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, gone.user_id))
        )),
        "no link to a page it no longer has: {}",
        page.body
    );
    assert!(page.body.contains(r#"value="restore""#), "{}", page.body);

    let page = b.get(&s.url(&format!("/admin/find?id={group}"))).await;
    assert!(page.body.contains("Old team"), "{}", page.body);
    assert!(page.body.contains("deleted "), "{}", page.body);
    assert!(
        !page.body.contains(r#"value="restore""#),
        "a group is not restored: {}",
        page.body
    );
    // Its name is free again at once.
    rust_oidc::groups::create(&s.pool, &tenant, "Old team", None)
        .await
        .unwrap();

    // The audit log names them, as deleted, rather than printing bare ids.
    let audit = b.get(&s.url(&format!("/admin/tenants/{}/audit", f.tenant.id))).await;
    assert!(audit.body.contains("gone@contoso.com (deleted)"), "{}", audit.body);

    // Restore: the account is back, enabled, at its own page.
    let restored = b
        .post(
            &s.url("/admin/find"),
            &[
                ("op", "restore"),
                ("id", gone.user_id.as_str()),
                ("tenant", f.tenant.id.as_str()),
            ],
        )
        .await;
    assert_eq!(restored.status, 303, "{}", restored.body);
    assert!(
        restored
            .location
            .unwrap()
            .ends_with(&format!("/users/{}", gone.user_id))
    );
    let back = rust_oidc::users::find(&s.pool, &f.tenant.id, &gone.user_id)
        .await
        .unwrap()
        .expect("restored");
    assert!(back.enabled);
    // Restoring needs what deleting needed: a viewer is refused.
    let s2 = TestServer::start().await;
    let v = reader_fixture(&s2).await;
    let vb = signed_in_admin(&s2, &v).await;
    let refused = vb
        .post(
            &s2.url("/admin/find"),
            &[
                ("op", "restore"),
                ("id", v.user_id.as_str()),
                ("tenant", v.tenant.id.as_str()),
            ],
        )
        .await;
    assert_eq!(refused.status, 403);
}

/// The built-in APIs' fixed ids name no row, yet appear in tokens and the audit
/// log: Find by id says what they are, for anyone who may use the console.
#[tokio::test]
async fn built_in_ids_are_identified() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let cases = [
        (
            rust_oidc::auth_api::AUTH_API_APP_ID,
            "Built-in API",
            "Auth API",
            "api://auth-api",
        ),
        (
            rust_oidc::scopes::GRAPH_APP_ID,
            "Built-in API",
            "Microsoft Graph",
            "UserInfo",
        ),
        (
            rust_oidc::auth_api::AuthApiPermission::CredentialsVerify.id(),
            "Built-in permission",
            "Credentials.Verify",
            "Auth API",
        ),
    ];
    for (id, kind, name, detail) in cases {
        let page = b.get(&find(&s, id)).await;
        assert_eq!(page.status, 200);
        for want in [kind, name, detail, "Every tenant"] {
            assert!(page.body.contains(want), "{id}: {want} in {}", page.body);
        }
        // Upper case is the same id.
        assert!(b.get(&find(&s, &id.to_uppercase())).await.body.contains(name));
    }
}

/// A token issued for the Auth API is recorded with the API as its target, and
/// the audit page names it rather than printing the id.
#[tokio::test]
async fn the_audit_log_names_the_auth_api() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let (status, body) = s
        .client_credentials(&f.tenant.id, &f.web, "api://auth-api/.default")
        .await;
    assert_eq!(status, 200, "{body}");
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/audit", f.tenant.id))).await;
    assert!(page.body.contains("Auth API (built-in)"), "{}", page.body);
    assert!(
        page.body
            .contains(&format!(r#"title="{}""#, rust_oidc::auth_api::AUTH_API_APP_ID)),
        "the id stays as the tooltip: {}",
        page.body
    );
}
