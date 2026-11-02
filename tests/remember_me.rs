//! "Keep me signed in" and "Don't ask again on this device": both off until a
//! tenant turns them on, each thirty days, neither able to override an
//! application that asks for a fresh sign-in, and both taken back at once when
//! the tenant turns them off or the account is signed out everywhere.

mod common;

use common::*;
use rust_oidc::db::Event;
use rust_oidc::mfa::{self, Freshness, Remembered};
use rust_oidc::session::MFA_DEVICE_COOKIE;
use rust_oidc::tenant::{self, TenantSettings};
use rust_oidc::util::now;
use serde_json::Value;

const DAY: i64 = 86_400;
const KEEP: &str = "keep_signed_in";
const REMEMBER: &str = "remember_device";
const TICKED: &str = "1";

/// The owner's choice, pinned: a change must be deliberate.
#[test]
fn both_last_thirty_days() {
    assert_eq!(TenantSettings::KEEP_SIGNED_IN_SECS, 30 * DAY);
    assert_eq!(TenantSettings::REMEMBER_MFA_SECS, 30 * DAY);
}

async fn allow(s: &TestServer, f: &UserFixture, keep: bool, remember: bool) {
    let mut settings = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap().settings;
    settings.allow_keep_signed_in = keep;
    settings.allow_remember_mfa = remember;
    tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.unwrap();
}

fn params<'a>(f: &'a UserFixture, challenge: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut p = vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "st-remember"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    p.extend_from_slice(extra);
    p
}

/// Submit a sign-in form, ticking "Keep me signed in" or not.
async fn sign_in(b: &Browser, page: &Page, upn: &str, password: &str, keep: bool) -> Page {
    let mut form = vec![
        ("csrf".to_string(), page.field("csrf").expect("a sign-in form")),
        ("request".to_string(), page.field("request").unwrap_or_default()),
        ("op".to_string(), "login".to_string()),
        ("upn".to_string(), upn.to_string()),
        ("password".to_string(), password.to_string()),
    ];
    if keep {
        form.push((KEEP.to_string(), TICKED.to_string()));
    }
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

/// Post the code on a second-step page, ticking "Don't ask again" or not.
async fn send_code(b: &Browser, page: &Page, code: &str, remember: bool) -> Page {
    let mut form: Vec<(String, String)> = Vec::new();
    for name in ["csrf", "request", "op", "mfa_ticket"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    form.push(("code".into(), code.into()));
    if remember {
        form.push((REMEMBER.into(), TICKED.into()));
    }
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

fn fresh_code(secret: &str, steps_ahead: i64) -> String {
    mfa::code_for(secret, now() + steps_ahead * mfa::STEP_SECS)
}

async fn redeem(s: &TestServer, f: &UserFixture, page: &Page, verifier: &str) -> Value {
    assert_eq!(page.status, 302, "expected the redirect back: {}", page.body);
    let code = page.redirect_params()["code"].clone();
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", verifier),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    body
}

fn amr(token: &Value) -> Vec<String> {
    decode_unverified(token["id_token"].as_str().unwrap())["amr"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

/// The user's one session in the tenant: (created_at, expires_at).
async fn session_times(s: &TestServer, user_id: &str) -> (i64, i64) {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT created_at, expires_at FROM sessions WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

async fn remembered_rows(s: &TestServer, user_id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM mfa_remembered_devices WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    n
}

/// The Max-Age a response gives a cookie, if it sets it.
fn max_age(page: &Page, cookie: &str) -> Option<i64> {
    page.headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| v.starts_with(&format!("{cookie}=")) && !v.starts_with(&format!("{cookie}=;")))
        .find_map(|v| v.split("Max-Age=").nth(1)?.split(';').next()?.parse().ok())
}

async fn sign_out(s: &TestServer, b: &Browser, f: &UserFixture) {
    b.get(&s.url(&format!("/{}/oauth2/v2.0/logout", f.tenant.id))).await;
}

/// Sign in with a code and "Don't ask again" ticked; returns the authenticator secret.
async fn remember_this_browser(s: &TestServer, b: &Browser, f: &UserFixture) -> String {
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let (verifier, challenge) = pkce();
    let login = b.authorize(s, &f.tenant.id, &params(f, &challenge, &[])).await;
    let step = sign_in(b, &login, &f.upn, &f.password, false).await;
    assert!(step.body.contains(REMEMBER), "the box is offered: {}", step.body);
    let done = send_code(b, &step, &fresh_code(&secret, 1), true).await;
    assert_eq!(
        max_age(&done, MFA_DEVICE_COOKIE),
        Some(TenantSettings::REMEMBER_MFA_SECS),
        "the device cookie is set"
    );
    redeem(s, f, &done, &verifier).await;
    assert_eq!(remembered_rows(s, &f.user_id).await, 1);
    secret
}

// ---- offered only where allowed ----

#[tokio::test]
async fn the_boxes_appear_only_where_the_tenant_offers_them() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let (_, challenge) = pkce();

    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert!(!login.body.contains(KEEP), "off by default: {}", login.body);
    let step = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    assert!(!step.body.contains(REMEMBER), "off by default: {}", step.body);

    allow(&s, &f, true, true).await;
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert!(login.body.contains("Keep me signed in"), "{}", login.body);
    let step = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert!(step.body.contains("Don't ask again on this device"), "{}", step.body);
}

// ---- keep me signed in ----

#[tokio::test]
async fn keep_me_signed_in_makes_a_thirty_day_session() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;
    let (_, challenge) = pkce();

    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let done = sign_in(&b, &login, &f.upn, &f.password, true).await;
    assert_eq!(done.status, 302, "{}", done.body);
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, TenantSettings::KEEP_SIGNED_IN_SECS);
    let cookie_age = max_age(&done, "rust_oidc_session").expect("the session cookie is set");
    assert!(
        cookie_age > TenantSettings::KEEP_SIGNED_IN_SECS - 60,
        "the cookie lasts as long: {cookie_age}"
    );
    assert_eq!(audit_rows(&s, Event::SessionCreate.as_str()).await.len(), 1);

    // Not ticked: the tenant's own session lifetime.
    sign_out(&s, &b, &f).await;
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    sign_in(&b, &login, &f.upn, &f.password, false).await;
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, f.tenant.settings.session_lifetime_secs);
}

/// Security: a ticked box posted to a tenant that does not offer it is a plain
/// sign-in. (Fails if `KeepSignedIn::chosen` stops checking the tenant.)
#[tokio::test]
async fn a_forged_ticked_box_is_ignored_where_the_tenant_does_not_offer_it() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (_, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let done = sign_in(&b, &login, &f.upn, &f.password, true).await;
    assert_eq!(done.status, 302, "{}", done.body);
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, f.tenant.settings.session_lifetime_secs);
}

#[tokio::test]
async fn the_choice_survives_the_second_step() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let (verifier, challenge) = pkce();

    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let step = sign_in(&b, &login, &f.upn, &f.password, true).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let done = send_code(&b, &step, &fresh_code(&secret, 1), false).await;
    redeem(&s, &f, &done, &verifier).await;
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, TenantSettings::KEEP_SIGNED_IN_SECS);
}

#[tokio::test]
async fn turning_keep_off_cuts_kept_sessions_back_at_once() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;
    let (_, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    sign_in(&b, &login, &f.upn, &f.password, true).await;
    // Signed in two days ago: kept, it would last another 28.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE sessions SET created_at = created_at - ?, expires_at = expires_at - ? WHERE user_id = ?",
    ))
    .bind(2 * DAY)
    .bind(2 * DAY)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();

    allow(&s, &f, false, false).await;
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, f.tenant.settings.session_lifetime_secs);
    // The ordinary lifetime (a day) is long past: the session is over.
    let silent = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("prompt", "none")]))
        .await;
    assert_eq!(silent.redirect_params()["error"], "login_required");
}

// ---- don't ask again on this device ----

#[tokio::test]
async fn a_remembered_browser_skips_the_code_but_not_the_password() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    let b = Browser::new();
    remember_this_browser(&s, &b, &f).await;

    sign_out(&s, &b, &f).await;
    let (verifier, challenge) = pkce();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert!(
        login.body.contains("password"),
        "the password is still asked: {}",
        login.body
    );
    let done = sign_in(&b, &login, &f.upn, &f.password, false).await;
    let tokens = redeem(&s, &f, &done, &verifier).await;
    assert_eq!(amr(&tokens), ["pwd", "mfa"], "a remembered browser counts as MFA");
    let rows = audit_rows(&s, Event::MfaVerified.as_str()).await;
    assert_eq!(rows.len(), 2, "the code once, the remembered browser once");
}

#[tokio::test]
async fn prompt_login_asks_for_the_code_again() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    let b = Browser::new();
    remember_this_browser(&s, &b, &f).await;

    let (_, challenge) = pkce();
    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("prompt", "login")]))
        .await;
    let step = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
}

#[tokio::test]
async fn max_age_counts_from_when_the_code_was_last_given() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    let b = Browser::new();
    remember_this_browser(&s, &b, &f).await;
    // The authenticator was set up yesterday, and the code was given (and the
    // browser remembered) twenty minutes ago.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE user_totp SET enrolled_at = enrolled_at - ? WHERE user_id = ?",
    ))
    .bind(DAY)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE mfa_remembered_devices SET created_at = created_at - ? WHERE user_id = ?",
    ))
    .bind(1_200)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, challenge) = pkce();

    // Ten minutes is too old for it.
    sign_out(&s, &b, &f).await;
    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("max_age", "600")]))
        .await;
    let step = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);

    // An hour is not: the code is skipped. (The sign-in above stopped at its
    // code, so there is still no session and the password is asked again.)
    let login = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("max_age", "3600")]))
        .await;
    let done = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert_eq!(done.status, 302, "{}", done.body);
}

/// Security: a browser remembered for one account does not skip another's code.
#[tokio::test]
async fn another_account_on_the_same_browser_is_still_asked() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    let b = Browser::new();
    remember_this_browser(&s, &b, &f).await;
    sign_out(&s, &b, &f).await;

    let bob = user_fixture_in(&s, f.tenant.clone(), "bob@contoso.com").await;
    mfa::enroll(&s.pool, &bob.user_id, &mfa::new_secret()).await.unwrap();
    let (_, challenge) = pkce();
    let login = b.authorize(&s, &bob.tenant.id, &params(&bob, &challenge, &[])).await;
    let step = sign_in(&b, &login, &bob.upn, &bob.password, false).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
}

/// Security: switching it off forgets every browser, and a row that somehow
/// survived is not honoured either. (Fails if either check is removed.)
#[tokio::test]
async fn turning_remember_off_forgets_and_refuses() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let device = mfa::remember_device(&s.pool, None, &f.user_id, &home)
        .await
        .unwrap()
        .expect("remembered");
    let fresh = Freshness::default();
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &home, fresh)
            .await
            .unwrap(),
        Remembered::Yes
    );

    // Checked at use: the tenant's switch, whatever the table holds.
    let mut off = home.clone();
    off.settings.allow_remember_mfa = false;
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &off, fresh)
            .await
            .unwrap(),
        Remembered::No
    );
    // And forgotten when the switch is saved off.
    allow(&s, &f, false, false).await;
    assert_eq!(remembered_rows(&s, &f.user_id).await, 0);
}

#[tokio::test]
async fn signing_out_everywhere_or_a_new_authenticator_forgets_the_browser() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let fresh = Freshness::default();

    mfa::remember_device(&s.pool, None, &f.user_id, &home).await.unwrap();
    rust_oidc::users::end_sessions(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(remembered_rows(&s, &f.user_id).await, 0, "signed out everywhere");

    let device = mfa::remember_device(&s.pool, None, &f.user_id, &home)
        .await
        .unwrap()
        .unwrap();
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    assert_eq!(remembered_rows(&s, &f.user_id).await, 0, "a new authenticator");
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &home, fresh)
            .await
            .unwrap(),
        Remembered::No
    );
}

/// A remembered row older than the account's authenticator vouches for nothing,
/// even if it was not deleted.
#[tokio::test]
async fn a_browser_remembered_before_the_authenticator_is_not_honoured() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let device = mfa::remember_device(&s.pool, None, &f.user_id, &home)
        .await
        .unwrap()
        .unwrap();
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE mfa_remembered_devices SET created_at = created_at - ? WHERE user_id = ?",
    ))
    .bind(DAY)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &home, Freshness::default())
            .await
            .unwrap(),
        Remembered::No
    );
}

// ---- My Account ----

#[tokio::test]
async fn my_account_offers_and_honours_both() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, true).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let page_url = s.url(&format!("/{}/myaccount", f.tenant.id));

    let b = Browser::new();
    let login = b.get(&page_url).await;
    assert!(login.body.contains("Keep me signed in"), "{}", login.body);
    let step = sign_in(&b, &login, &f.upn, &f.password, true).await;
    assert!(step.body.contains("Don't ask again on this device"), "{}", step.body);
    let done = send_code(&b, &step, &fresh_code(&secret, 1), true).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let (created, expires) = session_times(&s, &f.user_id).await;
    assert_eq!(expires - created, TenantSettings::KEEP_SIGNED_IN_SECS);
    assert_eq!(remembered_rows(&s, &f.user_id).await, 1);

    // Signed out of this tenant; the next sign-in needs the password only.
    sign_out(&s, &b, &f).await;
    let login = b.get(&page_url).await;
    let done = sign_in(&b, &login, &f.upn, &f.password, false).await;
    assert!(!done.body.contains("Enter code"), "{}", done.body);
    assert!(done.body.contains(&f.upn), "the account page: {}", done.body);
}
