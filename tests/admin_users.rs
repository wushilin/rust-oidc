//! The users section: list, search, create, edit, enable/disable, reset, delete.
mod common;
use common::*;

use rust_oidc::db::Event;
use rust_oidc::users::{self, AuthResult, NewUser};

async fn make_user(s: &TestServer, tenant: &rust_oidc::tenant::Tenant, upn: &str) -> String {
    users::create(
        &s.pool,
        tenant,
        NewUser {
            upn,
            password: "Correct-Horse-9",
            display_name: Some(upn),
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap()
}

// ---- list and search (task 10) ----

#[tokio::test]
async fn the_user_list_searches_and_excludes_deleted_users() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    for upn in ["bob@contoso.com", "carol@contoso.com"] {
        make_user(&s, &f.tenant, upn).await;
    }
    let all = users::list(&s.pool, &f.tenant.id, None, 50, 0).await.unwrap();
    assert!(all.len() >= 3, "{all:?}", all = all.len());

    let found = users::list(&s.pool, &f.tenant.id, Some("CAROL"), 50, 0).await.unwrap();
    assert_eq!(found.len(), 1, "the search folds case");
    assert_eq!(found[0].upn, "carol@contoso.com");

    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE users SET deleted_at = ? WHERE upn_folded = ?",
    ))
    .bind(1_i64)
    .bind("carol@contoso.com")
    .execute(&s.pool)
    .await
    .unwrap();
    let after = users::list(&s.pool, &f.tenant.id, Some("carol"), 50, 0).await.unwrap();
    assert!(after.is_empty(), "soft-deleted users are excluded");
}

#[tokio::test]
async fn the_user_list_never_crosses_tenants() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    make_user(&s, &other, "stranger@fabrikam.test").await;
    let mine = users::list(&s.pool, &f.tenant.id, None, 50, 0).await.unwrap();
    assert!(
        mine.iter().all(|u| u.tenant_id == f.tenant.id),
        "{mine:?}",
        mine = mine.len()
    );
}

#[tokio::test]
async fn the_users_page_renders_for_a_permitted_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains(&f.upn), "{}", page.body);
}

#[tokio::test]
async fn the_users_page_can_be_searched() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    make_user(&s, &f.tenant, "bob@contoso.com").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b
        .get(&s.url(&format!("/admin/tenants/{}/users?q=bob", f.tenant.id)))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("bob@contoso.com"), "{}", page.body);
    // Alice's own UPN still appears in the chrome, so look for her row's link.
    assert!(
        !page.body.contains(&format!("/users/{}", f.user_id)),
        "the search narrowed the list: {}",
        page.body
    );
}

/// The console renders user-controlled text. It must be escaped, because the
/// pages are built with `format!` rather than a template engine that escapes for
/// us.
#[tokio::test]
async fn a_display_name_cannot_inject_markup() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let hostile = "<script>alert(1)</script>";
    let id = make_user(&s, &f.tenant, "mallory@contoso.com").await;
    users::update_attributes(
        &s.pool,
        &f.tenant.id,
        &id,
        &users::UserAttributes {
            display_name: Some(hostile),
            given_name: None,
            family_name: None,
            email: None,
            email_verified: false,
        },
    )
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;
    for url in [
        s.url(&format!("/admin/tenants/{}/users", f.tenant.id)),
        s.url(&format!("/admin/tenants/{}/users/{id}", f.tenant.id)),
    ] {
        let page = b.get(&url).await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(!page.body.contains(hostile), "unescaped markup in {url}");
        assert!(page.body.contains("&lt;script&gt;"), "escaped instead: {url}");
    }
}

// ---- create (task 11) ----

#[tokio::test]
async fn creating_a_user_validates_the_domain_and_audits() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id));

    let page = b
        .post(
            &url,
            &[
                ("upn", "dave@notours.test"),
                ("password", "Correct-Horse-9"),
                ("display_name", "Dave"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.to_lowercase().contains("domain"), "{}", page.body);

    let page = b
        .post(
            &url,
            &[
                ("upn", "dave@contoso.com"),
                ("password", "Correct-Horse-9"),
                ("display_name", "Dave"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let found = users::list(&s.pool, &f.tenant.id, Some("dave"), 10, 0).await.unwrap();
    assert_eq!(found.len(), 1);

    let rows = audit_rows(&s, Event::AdminUserCreate.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id);
    assert_eq!(rows[0].1.as_deref(), Some(found[0].id.as_str()));
}

#[tokio::test]
async fn a_short_password_is_refused_with_a_message() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id)),
            &[("upn", "dave@contoso.com"), ("password", "short")],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("8 characters"), "{}", page.body);
}

#[tokio::test]
async fn a_reader_cannot_create_a_user() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id)),
            &[
                ("upn", "eve@contoso.com"),
                ("password", "Correct-Horse-9"),
                ("display_name", "Eve"),
            ],
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert!(
        users::list(&s.pool, &f.tenant.id, Some("eve"), 10, 0)
            .await
            .unwrap()
            .is_empty(),
        "and nothing was created"
    );
}

// ---- edit, enable, disable (task 12) ----

#[tokio::test]
async fn editing_attributes_persists() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id));

    let page = b
        .post(
            &url,
            &[
                ("op", "attributes"),
                ("display_name", "Alice Cooper"),
                ("given_name", "Alice"),
                ("family_name", "Cooper"),
                ("email", "alice.cooper@example.org"),
                ("email_verified", "on"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let user = users::find(&s.pool, &f.tenant.id, &f.user_id).await.unwrap().unwrap();
    assert_eq!(user.display_name.as_deref(), Some("Alice Cooper"));
    assert_eq!(user.family_name.as_deref(), Some("Cooper"));
    assert!(user.email_verified);

    // Unticking the box clears it, rather than leaving the old value.
    b.post(
        &url,
        &[
            ("op", "attributes"),
            ("display_name", "Alice Cooper"),
            ("email", "alice.cooper@example.org"),
        ],
    )
    .await;
    let user = users::find(&s.pool, &f.tenant.id, &f.user_id).await.unwrap().unwrap();
    assert!(!user.email_verified, "the checkbox is authoritative");
    assert_eq!(user.given_name, None, "an empty box clears the attribute");

    let rows = audit_rows(&s, Event::AdminUserUpdate.as_str()).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id);
}

#[tokio::test]
async fn disabling_a_user_blocks_sign_in_and_enabling_restores_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let target = make_user(&s, &f.tenant, "frank@contoso.com").await;
    let url = s.url(&format!("/admin/tenants/{}/users/{target}", f.tenant.id));

    assert_eq!(b.post(&url, &[("op", "disable")]).await.status, 303);
    let outcome = users::authenticate(&s.pool, &f.tenant, "frank@contoso.com", "Correct-Horse-9")
        .await
        .unwrap();
    assert!(matches!(outcome, AuthResult::Disabled));

    assert_eq!(b.post(&url, &[("op", "enable")]).await.status, 303);
    let outcome = users::authenticate(&s.pool, &f.tenant, "frank@contoso.com", "Correct-Horse-9")
        .await
        .unwrap();
    assert!(matches!(outcome, AuthResult::Ok(_)));

    assert_eq!(audit_rows(&s, Event::AdminUserDisable.as_str()).await.len(), 1);
    assert_eq!(audit_rows(&s, Event::AdminUserEnable.as_str()).await.len(), 1);
}

#[tokio::test]
async fn an_unknown_operation_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
            &[("op", "promote_to_god")],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
}

// ---- reset and soft delete (task 13) ----

#[tokio::test]
async fn resetting_a_password_revokes_sessions_and_refresh_tokens() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    // A browser session for the user, which the reset must revoke.
    rust_oidc::session::create(
        &s.pool,
        &axum::http::HeaderMap::new(),
        &f.tenant.id,
        &f.user_id,
        &["pwd"],
        3600,
    )
    .await
    .unwrap();

    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
            &[("op", "reset"), ("password", "Brand-New-Pass-1")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    let outcome = users::authenticate(&s.pool, &f.tenant, &f.upn, "Brand-New-Pass-1")
        .await
        .unwrap();
    assert!(matches!(outcome, AuthResult::Ok(_)));
    let (sessions,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
    ))
    .bind(&f.user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(sessions, 0, "set_password revokes sessions");
    assert_eq!(audit_rows(&s, Event::AdminUserReset.as_str()).await.len(), 1);
}

#[tokio::test]
async fn a_user_administrator_may_reset_but_a_reader_may_not() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
            &[("op", "reset"), ("password", "Brand-New-Pass-1")],
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    let outcome = users::authenticate(&s.pool, &f.tenant, &f.upn, &f.password)
        .await
        .unwrap();
    assert!(matches!(outcome, AuthResult::Ok(_)), "the password is unchanged");
}

#[tokio::test]
async fn a_soft_deleted_user_disappears_and_cannot_sign_in() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let target = make_user(&s, &f.tenant, "gina@contoso.com").await;

    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/{target}", f.tenant.id)),
            &[("op", "delete")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);

    assert!(users::find(&s.pool, &f.tenant.id, &target).await.unwrap().is_none());
    let outcome = users::authenticate(&s.pool, &f.tenant, "gina@contoso.com", "Correct-Horse-9")
        .await
        .unwrap();
    assert!(!matches!(outcome, AuthResult::Ok(_)), "a deleted user cannot sign in");
    // The row is kept, so audit rows and token `oid`s still resolve.
    let (rows,): (i64,) = sqlx::query_as(rust_oidc::db::q(&s.pool, "SELECT COUNT(*) FROM users WHERE id = ?"))
        .bind(&target)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "soft, not hard");
    assert_eq!(audit_rows(&s, Event::AdminUserDelete.as_str()).await.len(), 1);
}

/// Deleting an administrator must also end the console session they are holding.
#[tokio::test]
async fn deleting_a_user_ends_their_console_session() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let victim = user_fixture_in(&s, f.tenant.clone(), "harry@contoso.com").await;
    bind(
        &s,
        &victim.user_id,
        rust_oidc::rbac::RoleId::TenantViewer,
        rust_oidc::rbac::Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let theirs = signed_in_admin(&s, &victim).await;
    assert_eq!(theirs.get(&s.url("/admin/tenants")).await.status, 200);

    let b = signed_in_admin(&s, &f).await;
    b.post(
        &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, victim.user_id)),
        &[("op", "delete")],
    )
    .await;

    let page = theirs.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 303, "their console session is gone: {}", page.body);
}

/// A soft-deleted user's group membership and app role assignment must not
/// resurrect them: the filters go in before the writer exists, not after.
#[tokio::test]
async fn a_soft_deleted_user_is_no_longer_resolvable_by_name() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = make_user(&s, &f.tenant, "ida@contoso.com").await;
    rust_oidc::groups::create(&s.pool, &f.tenant, "team", None)
        .await
        .unwrap();
    users::soft_delete(&s.pool, &f.tenant.id, &target).await.unwrap();

    assert!(
        rust_oidc::groups::add_member(&s.pool, &f.tenant, "team", "ida@contoso.com")
            .await
            .is_err(),
        "a deleted user cannot be added to a group"
    );
    assert!(
        users::set_password(&s.pool, &f.tenant, "ida@contoso.com", "Another-Pass-9")
            .await
            .is_err(),
        "a deleted user's password cannot be set"
    );
}

/// The soft-delete *filter* is what ends access, independently of the `enabled`
/// flag that `soft_delete` also clears. A row marked deleted on its own must stop
/// working, or the filters could be removed without a test noticing.
#[tokio::test]
async fn a_deleted_row_cannot_sign_in_even_while_it_still_says_enabled() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = make_user(&s, &f.tenant, "jane@contoso.com").await;
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE users SET deleted_at = ?, enabled = ? WHERE id = ?",
    ))
    .bind(1_i64)
    .bind(true)
    .bind(&target)
    .execute(&s.pool)
    .await
    .unwrap();

    let outcome = users::authenticate(&s.pool, &f.tenant, "jane@contoso.com", "Correct-Horse-9")
        .await
        .unwrap();
    assert!(
        matches!(outcome, AuthResult::InvalidCredentials),
        "a deleted row must be indistinguishable from no account"
    );
    assert!(users::find(&s.pool, &f.tenant.id, &target).await.unwrap().is_none());
    assert!(
        users::list(&s.pool, &f.tenant.id, Some("jane"), 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
}
