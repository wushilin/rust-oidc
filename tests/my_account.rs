//! My Account: the user's own page.

mod common;

use common::*;
use rust_oidc::db::Event;
use rust_oidc::mfa;
use rust_oidc::util::now;

fn account(s: &TestServer, f: &UserFixture) -> String {
    s.url(&format!("/{}/myaccount", f.tenant.id))
}

/// Post one of the page's forms: its CSRF token and op, and these fields.
async fn act(b: &Browser, page: &Page, op: &str, extra: &[(&str, &str)]) -> Page {
    let mut form = vec![
        ("csrf".to_string(), page.field("csrf").expect("csrf")),
        ("op".to_string(), op.to_string()),
    ];
    for name in ["request", "mfa_ticket"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    for (k, v) in extra {
        form.push((k.to_string(), v.to_string()));
    }
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

async fn signed_in(s: &TestServer, f: &UserFixture) -> (Browser, Page) {
    let b = Browser::new();
    let login = b.get(&account(s, f)).await;
    assert!(
        login.body.contains("My account"),
        "the sign-in names the page: {}",
        login.body
    );
    let page = b.login(&login, &f.upn, &f.password).await;
    assert!(page.body.contains("<h1>My account</h1>"), "{}", page.body);
    (b, page)
}

fn key_on(page: &Page) -> String {
    let start = page.body.find(r#"<div class="key">"#).expect("a key") + 17;
    let end = page.body[start..].find("</div>").unwrap() + start;
    page.body[start..end].replace(' ', "")
}

fn codes_on(page: &Page) -> Vec<String> {
    let start = page.body.find(r#"<ul class="codes">"#).expect("codes") + 18;
    let end = page.body[start..].find("</ul>").unwrap() + start;
    page.body[start..end]
        .split("<li>")
        .filter_map(|li| li.split("</li>").next())
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn the_profile_is_shown_and_not_editable() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (_, page) = signed_in(&s, &f).await;
    assert!(page.body.contains(&f.upn), "{}", page.body);
    assert!(
        page.body.contains("Ask an administrator to change these."),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains(r#"name="display_name""#),
        "no profile fields to edit: {}",
        page.body
    );
}

#[tokio::test]
async fn a_password_is_changed_knowing_the_current_one_and_ends_other_sessions() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // Signed in to an application in another browser.
    let other = Browser::new();
    let (_, challenge) = pkce();
    let p = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let login = other.authorize(&s, &f.tenant.id, &p).await;
    assert_eq!(other.login(&login, &f.upn, &f.password).await.status, 302);

    let (b, page) = signed_in(&s, &f).await;
    let wrong = act(
        &b,
        &page,
        "account_password",
        &[
            ("current_password", "nope"),
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-1"),
        ],
    )
    .await;
    assert!(wrong.body.contains("current password is not right"), "{}", wrong.body);
    let reused = act(
        &b,
        &wrong,
        "account_password",
        &[
            ("current_password", &f.password),
            ("new_password", &f.password),
            ("confirm_password", &f.password),
        ],
    )
    .await;
    assert!(reused.body.contains("used recently"), "{}", reused.body);
    let done = act(
        &b,
        &reused,
        "account_password",
        &[
            ("current_password", &f.password),
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-1"),
        ],
    )
    .await;
    assert_eq!(done.status, 200, "{}", done.body);
    assert!(done.body.contains("Your password is changed"), "{}", done.body);
    assert_eq!(audit_rows(&s, Event::PasswordChanged.as_str()).await.len(), 1);

    // This browser stays signed in; the other one is not.
    assert!(b.get(&account(&s, &f)).await.body.contains("<h1>My account</h1>"));
    let again = other.authorize(&s, &f.tenant.id, &p).await;
    assert!(
        again.field("csrf").is_some() && again.body.contains("password"),
        "signed out: {}",
        again.status
    );
}

#[tokio::test]
async fn an_authenticator_is_set_up_replaced_and_its_codes_renewed() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (b, page) = signed_in(&s, &f).await;
    assert!(page.body.contains("Set up an authenticator"), "{}", page.body);

    // Voluntary: set up from the page, still signed in, codes shown once.
    let setup = act(&b, &page, "account_mfa_setup", &[]).await;
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    let secret = key_on(&setup);
    let set = act(&b, &setup, "mfa_enroll", &[("code", &mfa::code_for(&secret, now()))]).await;
    assert!(set.body.contains("Your authenticator is set up"), "{}", set.body);
    let codes = codes_on(&set);
    assert_eq!(codes.len(), mfa::RECOVERY_CODE_COUNT);
    assert!(set.body.contains("10 unused recovery codes"), "{}", set.body);

    // New recovery codes need an authenticator code; a recovery code will not do.
    let refused = act(&b, &set, "account_recovery_codes", &[("code", &codes[0])]).await;
    assert!(refused.body.contains("six-digit code"), "{}", refused.body);
    let renewed = act(
        &b,
        &refused,
        "account_recovery_codes",
        &[("code", &mfa::code_for(&secret, now() + mfa::STEP_SECS))],
    )
    .await;
    let fresh = codes_on(&renewed);
    assert_eq!(fresh.len(), mfa::RECOVERY_CODE_COUNT);
    assert!(fresh.iter().all(|c| !codes.contains(c)));
    assert_eq!(audit_rows(&s, Event::MfaRecoveryCodesReplaced.as_str()).await.len(), 1);

    // A new phone: confirmed with a recovery code (the old phone is gone).
    let wrong = act(&b, &renewed, "account_mfa_replace", &[("code", "000000")]).await;
    assert!(
        wrong.body.contains("didn&#x27;t work") || wrong.body.contains("didn't work"),
        "{}",
        wrong.body
    );
    let replace = act(&b, &wrong, "account_mfa_replace", &[("code", &fresh[0])]).await;
    assert!(replace.body.contains("Set up your authenticator"), "{}", replace.body);
    let new_secret = key_on(&replace);
    assert_ne!(new_secret, secret);
    let done = act(
        &b,
        &replace,
        "mfa_enroll",
        &[("code", &mfa::code_for(&new_secret, now()))],
    )
    .await;
    assert!(done.body.contains("Your authenticator is set up"), "{}", done.body);
    // The old authenticator is no longer the one.
    let (user_id, _) = (f.user_id.clone(), ());
    let row: (String,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT secret FROM user_totp WHERE user_id = ?",
    ))
    .bind(&user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(row.0, new_secret);
}

/// Signed in to an application already: no password again. With an
/// authenticator and a session without it: a code first.
#[tokio::test]
async fn an_application_session_signs_in_here_with_the_same_steps() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let p = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let login = b.authorize(&s, &f.tenant.id, &p).await;
    assert_eq!(b.login(&login, &f.upn, &f.password).await.status, 302);
    assert!(b.get(&account(&s, &f)).await.body.contains("<h1>My account</h1>"));

    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let step = b.get(&account(&s, &f)).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let page = act(
        &b,
        &step,
        "mfa_verify",
        &[("code", &mfa::code_for(&secret, now() + mfa::STEP_SECS))],
    )
    .await;
    assert!(page.body.contains("<h1>My account</h1>"), "{}", page.body);
}

#[tokio::test]
async fn sign_out_everywhere_ends_every_session_and_actions_need_the_token() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (b, _) = signed_in(&s, &f).await;
    // Without the page's token, nothing happens.
    let forged = b
        .post_form(
            &account(&s, &f),
            &[("op", "account_sign_out_everywhere"), ("csrf", "forged")],
        )
        .await;
    assert!(!forged.body.contains("You signed out"), "{}", forged.body);
    assert!(b.get(&account(&s, &f)).await.body.contains("<h1>My account</h1>"));

    let page = b.get(&account(&s, &f)).await;
    let out = act(&b, &page, "account_sign_out_everywhere", &[]).await;
    assert!(out.body.contains("You signed out"), "{}", out.body);
    let next = b.get(&account(&s, &f)).await;
    assert!(
        next.field("csrf").is_some() && next.body.contains(r#"name="password""#),
        "{}",
        next.body
    );
}
