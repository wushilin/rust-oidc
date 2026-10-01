//! The consent page, shown when a client asks for it with `prompt=consent`.
//!
//! Applications here are treated as consented by an administrator, so the page is
//! not part of an ordinary sign-in: it appears on request, names the application
//! and what it asked for, and the answer is the user's.

mod common;

use common::*;
use rust_oidc::db::Event;

fn params<'a>(
    f: &'a UserFixture,
    scope: &'a str,
    prompt: Option<&'a str>,
    challenge: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut p = vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", "st-9"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    if let Some(prompt) = prompt {
        p.push(("prompt", prompt));
    }
    p
}

/// Answer the consent page: `op` is the value of the button pressed.
async fn answer(b: &Browser, page: &Page, op: &str) -> Page {
    let csrf = page.field("csrf").expect("csrf on the consent page");
    let request = page.field("request").expect("request on the consent page");
    b.post_form(
        &page.form_action(),
        &[("csrf", csrf.as_str()), ("request", request.as_str()), ("op", op)],
    )
    .await
}

fn is_consent_page(page: &Page) -> bool {
    page.status == 200 && page.body.contains("Permissions requested")
}

#[tokio::test]
async fn prompt_consent_shows_what_the_application_asked_for_and_allow_continues() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let scope = format!("openid profile email api://{}/Orders.Read", f.api.app_id);

    // Not signed in: the sign-in page comes first, then the consent page.
    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, &scope, Some("consent"), &challenge))
        .await;
    let page = b.login(&login, &f.upn, &f.password).await;
    assert!(
        is_consent_page(&page),
        "expected the consent page: {} {}",
        page.status,
        page.body
    );

    // It names the application, the person, and each permission in words.
    assert!(page.body.contains("would like to"), "{}", page.body);
    assert!(page.body.contains(&f.upn), "{}", page.body);
    for wording in ["Sign you in", "View your basic profile", "View your email address"] {
        assert!(page.body.contains(wording), "missing {wording:?}: {}", page.body);
    }
    assert!(
        page.body.contains("Orders.Read"),
        "the API scope is listed: {}",
        page.body
    );
    assert!(
        page.body.contains(">Allow<") && page.body.contains(">Deny<"),
        "{}",
        page.body
    );

    // Allow: the flow finishes exactly as it would have without the page.
    let done = answer(&b, &page, "consent_accept").await;
    assert_eq!(done.status, 302, "{}", done.body);
    let p = done.redirect_params();
    assert!(p.contains_key("code"), "{p:?}");
    assert_eq!(p["state"], "st-9");

    let rows = audit_rows(&s, Event::ConsentGranted.as_str()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, f.user_id);
}

#[tokio::test]
async fn deny_returns_access_denied_to_the_application_and_issues_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    let login = b
        .authorize(
            &s,
            &f.tenant.id,
            &params(&f, "openid profile", Some("consent"), &challenge),
        )
        .await;
    let page = b.login(&login, &f.upn, &f.password).await;
    assert!(is_consent_page(&page), "{}", page.body);

    let done = answer(&b, &page, "consent_deny").await;
    assert_eq!(done.status, 302, "{}", done.body);
    let p = done.redirect_params();
    assert_eq!(p["error"], "access_denied", "{p:?}");
    assert!(p["error_description"].contains("AADSTS65004"), "{p:?}");
    assert_eq!(p["state"], "st-9", "the application gets its state back");
    assert!(!p.contains_key("code"), "nothing is issued on a refusal: {p:?}");

    assert_eq!(audit_rows(&s, Event::ConsentDenied.as_str()).await.len(), 1);
    assert!(audit_rows(&s, Event::ConsentGranted.as_str()).await.is_empty());
}

/// The page is on request only. An ordinary sign-in is unchanged, so every
/// existing client keeps working without an extra step.
#[tokio::test]
async fn without_prompt_consent_there_is_no_consent_page() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid profile", None, &challenge))
        .await;
    let done = b.login(&login, &f.upn, &f.password).await;
    assert_eq!(done.status, 302, "{}", done.body);
    assert!(done.redirect_params().contains_key("code"));
}

/// With a sign-in already remembered, `prompt=consent` still stops at the page.
#[tokio::test]
async fn a_remembered_sign_in_still_gets_the_consent_page() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid", None, &challenge))
        .await;
    assert_eq!(b.login(&login, &f.upn, &f.password).await.status, 302);

    let page = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid", Some("consent"), &challenge))
        .await;
    assert!(is_consent_page(&page), "{} {}", page.status, page.body);
    assert_eq!(answer(&b, &page, "consent_accept").await.status, 302);
}

/// `prompt=login consent` is sign-in, then consent, then done -- not sign-in again
/// after the consent answer.
#[tokio::test]
async fn login_and_consent_together_ask_for_each_once() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    // Signed in already, so prompt=login is what forces the sign-in page.
    let first = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid", None, &challenge))
        .await;
    assert_eq!(b.login(&first, &f.upn, &f.password).await.status, 302);

    let login = b
        .authorize(
            &s,
            &f.tenant.id,
            &params(&f, "openid", Some("login consent"), &challenge),
        )
        .await;
    assert!(
        login.field("csrf").is_some() && !is_consent_page(&login),
        "the sign-in page is first"
    );
    let page = b.login(&login, &f.upn, &f.password).await;
    assert!(is_consent_page(&page), "then the consent page: {}", page.body);
    let done = answer(&b, &page, "consent_accept").await;
    assert_eq!(
        done.status, 302,
        "and then it is finished, without a second sign-in: {}",
        done.body
    );
    assert!(done.redirect_params().contains_key("code"));
}

/// A consent answer must not be a way around `prompt=login`: on a session that
/// was not just re-authenticated, the sign-in page is still required.
#[tokio::test]
async fn a_consent_answer_does_not_skip_a_required_sign_in() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    let first = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid", None, &challenge))
        .await;
    assert_eq!(b.login(&first, &f.upn, &f.password).await.status, 302);
    // Make the remembered sign-in old.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE sessions SET auth_time = auth_time - 3600",
    ))
    .execute(&s.pool)
    .await
    .unwrap();

    // Take a consent page from a request that does not demand a sign-in...
    let page = b
        .authorize(&s, &f.tenant.id, &params(&f, "openid", Some("consent"), &challenge))
        .await;
    assert!(is_consent_page(&page), "{}", page.body);
    // ...and replay its answer against a request that does.
    let csrf = page.field("csrf").unwrap();
    let request = page
        .field("request")
        .unwrap()
        .replace("prompt=consent", "prompt=login+consent");
    let forged = b
        .post_form(
            &page.form_action(),
            &[
                ("csrf", csrf.as_str()),
                ("request", request.as_str()),
                ("op", "consent_accept"),
            ],
        )
        .await;
    assert_ne!(
        forged.status, 302,
        "a code was issued without the sign-in prompt=login demands"
    );
    assert!(
        forged.field("csrf").is_some(),
        "the sign-in page is shown instead: {}",
        forged.body
    );
}

#[tokio::test]
async fn none_cannot_be_combined_with_consent() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &params(&f, "openid", Some("none consent"), &challenge),
        )
        .await;
    assert_eq!(page.redirect_params()["error"], "invalid_request", "{}", page.body);
}
