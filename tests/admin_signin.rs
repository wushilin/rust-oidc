//! Console sign-in, the chrome, and what an unauthorized visitor sees.
mod common;
use common::*;

use rust_oidc::db::Event;

/// Post the sign-in form the way a browser does: fetch the page, carry its nonce.
async fn attempt(s: &TestServer, b: &Browser, upn: &str, password: &str) -> Page {
    let form = b.get(&s.url("/admin")).await;
    let nonce = form
        .field(rust_oidc::admin::session::CSRF_FIELD)
        .expect("the sign-in form carries a login nonce");
    b.post_form(
        &s.url("/admin/signin"),
        &[
            ("upn", upn),
            ("password", password),
            (rust_oidc::admin::session::CSRF_FIELD, nonce.as_str()),
        ],
    )
    .await
}

/// Blank the nonce so two sign-in responses can be compared: each page carries a
/// fresh one, which is the point, so it is noise for an equality assertion.
fn without_nonce(body: &str) -> String {
    let marker = format!(r#"name="{}" value=""#, rust_oidc::admin::session::CSRF_FIELD);
    match body.find(&marker) {
        Some(i) => {
            let start = i + marker.len();
            match body[start..].find('"') {
                Some(j) => format!("{}{}", &body[..start], &body[start + j..]),
                None => body.to_string(),
            }
        }
        None => body.to_string(),
    }
}

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
    let wrong = attempt(&s, &b, f.upn.as_str(), "not-the-password").await;
    let unknown = attempt(&s, &b, "nobody@contoso.com", "not-the-password").await;
    assert_eq!(wrong.status, 401, "{}", wrong.body);
    assert_eq!(unknown.status, 401, "{}", unknown.body);
    assert!(admin_cookie(&wrong).is_none(), "no session was created");
    // The two must be indistinguishable, or the form enumerates administrators.
    assert_eq!(
        without_nonce(&wrong.body).replace(f.upn.as_str(), ""),
        without_nonce(&unknown.body).replace("nobody@contoso.com", "")
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
    attempt(&s, &b, f.upn.as_str(), "not-the-password").await;
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

/// Login CSRF: a sign-in post that did not come from our own form must not
/// establish a session. Without this, a third-party page could post credentials
/// the attacker controls and leave the victim signed in as the attacker.
#[tokio::test]
async fn a_sign_in_without_the_forms_nonce_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = Browser::new();

    // Correct credentials, but posted without ever fetching the form.
    let page = b
        .post_form(
            &s.url("/admin/signin"),
            &[("upn", f.upn.as_str()), ("password", f.password.as_str())],
        )
        .await;
    assert_ne!(page.status, 303, "must not redirect into a session: {}", page.body);
    assert!(
        admin_cookie(&page).is_none(),
        "no console session may be created: {}",
        page.body
    );
    // And it says the form expired rather than claiming the password was wrong,
    // because the password was never checked.
    assert!(page.body.contains("no longer valid"), "{}", page.body);

    // The same credentials through the form do work, so the refusal above was
    // about the nonce and not about the account.
    let ok = attempt(&s, &b, f.upn.as_str(), f.password.as_str()).await;
    assert_eq!(ok.status, 303, "{}", ok.body);
    assert!(admin_cookie(&ok).is_some());
}

/// A nonce minted for one browser must not authorise another's post.
#[tokio::test]
async fn one_browsers_nonce_does_not_work_in_another() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let victim = Browser::new();
    let attacker = Browser::new();

    // The attacker takes a token from a form served to them...
    let form = attacker.get(&s.url("/admin")).await;
    let stolen = form.field(rust_oidc::admin::session::CSRF_FIELD).expect("nonce");

    // ...and plants it in a post from a browser that holds no matching cookie.
    let page = victim
        .post_form(
            &s.url("/admin/signin"),
            &[
                ("upn", f.upn.as_str()),
                ("password", f.password.as_str()),
                (rust_oidc::admin::session::CSRF_FIELD, stolen.as_str()),
            ],
        )
        .await;
    assert_ne!(page.status, 303, "{}", page.body);
    assert!(admin_cookie(&page).is_none(), "{}", page.body);
}

/// The nonce is single-use: once spent on a successful sign-in its cookie is
/// cleared, so a replay of the same form cannot open a second session.
#[tokio::test]
async fn a_spent_nonce_cannot_be_replayed() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = Browser::new();
    let form = b.get(&s.url("/admin")).await;
    let nonce = form.field(rust_oidc::admin::session::CSRF_FIELD).expect("nonce");
    let fields = [
        ("upn", f.upn.as_str()),
        ("password", f.password.as_str()),
        (rust_oidc::admin::session::CSRF_FIELD, nonce.as_str()),
    ];
    let first = b.post_form(&s.url("/admin/signin"), &fields).await;
    assert_eq!(first.status, 303, "{}", first.body);

    let replay = b.post_form(&s.url("/admin/signin"), &fields).await;
    assert_ne!(
        replay.status, 303,
        "a spent nonce must not sign in again: {}",
        replay.body
    );
}

/// Someone signed in without any administrative role sees "No access" with a
/// Sign out button, and it must work: the session ends and the sign-in form
/// comes back. It used to answer "No access" again and leave them signed in.
#[tokio::test]
async fn a_user_with_no_bindings_can_sign_out() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 403);
    assert!(page.body.to_lowercase().contains("no access"), "{}", page.body);

    let out = b.post(&s.url("/admin/signout"), &[]).await;
    assert_eq!(out.status, 303, "{}", out.body);
    // Signed out: the same page now sends them to sign in, not to No access.
    let after = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(after.status, 303, "{}", after.body);
    assert!(
        after.location.as_deref().is_some_and(|l| l.ends_with("/admin")),
        "{:?}",
        after.location
    );
    assert!(b.get(&s.url("/admin")).await.body.contains(r#"name="password""#));
    let rows = audit_rows(&s, Event::AdminSignOut.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id);
}

/// Sign-out still needs the form's CSRF token: another site cannot sign you out.
#[tokio::test]
async fn sign_out_without_the_csrf_token_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let forged = b.b.post_form(&s.url("/admin/signout"), &[("csrf", "forged")]).await;
    assert_eq!(forged.status, 400, "{}", forged.body);
    assert_eq!(b.get(&s.url("/admin/tenants")).await.status, 200, "still signed in");
}
