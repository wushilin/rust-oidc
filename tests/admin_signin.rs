//! Console sign-in, the chrome, and what an unauthorized visitor sees.
mod common;
use common::*;

use rust_oidc::db::Event;

#[tokio::test]
async fn an_anonymous_visitor_gets_the_sign_in_form() {
    let s = TestServer::start().await;
    let b = Browser::new();
    let page = b.get(&s.url("/admin")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Sign in"), "{}", page.body);
    assert!(page.body.contains("/admin/signin"), "{}", page.body);
}

#[tokio::test]
async fn an_anonymous_visitor_to_a_console_page_is_sent_to_sign_in() {
    let s = TestServer::start().await;
    let b = Browser::new();
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(page.location.unwrap().ends_with("/admin"), "to the sign-in page");
}

#[tokio::test]
async fn signing_in_shows_the_tenant_list_to_a_platform_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Contoso"), "the tenant list: {}", page.body);
    assert!(page.body.contains(&f.upn), "the chrome names the signed-in admin");
}

#[tokio::test]
async fn signing_in_is_audited_against_the_account() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let _ = signed_in_admin(&s, &f).await;
    let rows = audit_rows(&s, Event::AdminSignIn.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id, "the actor is the account's own id");
    assert_eq!(rows[0].2.as_deref(), Some(f.tenant.id.as_str()));
}

#[tokio::test]
async fn a_user_with_no_bindings_sees_no_access_not_a_raw_error() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert!(page.body.to_lowercase().contains("no access"), "{}", page.body);
}

#[tokio::test]
async fn a_wrong_password_says_nothing_about_the_account() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = Browser::new();
    let wrong = b
        .post_form(
            &s.url("/admin/signin"),
            &[("upn", f.upn.as_str()), ("password", "not-the-password")],
        )
        .await;
    let unknown = b
        .post_form(
            &s.url("/admin/signin"),
            &[("upn", "nobody@contoso.com"), ("password", "not-the-password")],
        )
        .await;
    assert_eq!(wrong.status, 401, "{}", wrong.body);
    assert_eq!(unknown.status, 401, "{}", unknown.body);
    assert!(admin_cookie(&wrong).is_none(), "no session was created");
    // The two must be indistinguishable, or the form enumerates administrators.
    assert_eq!(
        wrong.body.replace(f.upn.as_str(), ""),
        unknown.body.replace("nobody@contoso.com", "")
    );
}

/// A domain no tenant has verified cannot be an account here, and must not write
/// an audit row: the space of invented domains is unbounded.
#[tokio::test]
async fn a_sign_in_for_an_unknown_domain_writes_nothing() {
    let s = TestServer::start().await;
    let _ = admin_fixture(&s).await;
    let b = Browser::new();
    let page = b
        .post_form(
            &s.url("/admin/signin"),
            &[("upn", "root@nowhere.invalid"), ("password", "whatever-123")],
        )
        .await;
    assert_eq!(page.status, 401);
    assert!(audit_rows(&s, Event::AdminSignInFailed.as_str()).await.is_empty());
}

#[tokio::test]
async fn a_failed_sign_in_for_a_real_account_is_audited() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = Browser::new();
    b.post_form(
        &s.url("/admin/signin"),
        &[("upn", f.upn.as_str()), ("password", "not-the-password")],
    )
    .await;
    let rows = audit_rows(&s, Event::AdminSignInFailed.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id);
}

#[tokio::test]
async fn signing_out_ends_the_session() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let out = b.post(&s.url("/admin/signout"), &[]).await;
    assert_eq!(out.status, 303, "{}", out.body);
    let after = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(after.status, 303, "the session is gone: {}", after.body);
    let (left,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_sessions")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Every console write carries a token derived from the session cookie, so a
/// cross-site post cannot act for a signed-in administrator.
#[tokio::test]
async fn a_form_post_without_the_csrf_token_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.post_raw(&s.url("/admin/signout"), &[]).await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert_eq!(
        b.get(&s.url("/admin/tenants")).await.status,
        200,
        "and the session is untouched"
    );
}

/// The token must be the session's own, not any token at all.
#[tokio::test]
async fn another_sessions_csrf_token_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let mine = signed_in_admin(&s, &f).await;
    let theirs = signed_in_admin(&s, &f).await;
    assert_ne!(mine.csrf, theirs.csrf, "tokens are per session");
    let page = mine
        .post_raw(&s.url("/admin/signout"), &[("csrf", theirs.csrf.as_str())])
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
}
