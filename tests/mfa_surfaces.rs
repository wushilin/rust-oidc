//! The second factor at My Account and at the device-code sign-in follows the
//! rules the application sign-in does (decision 55): a code page shown after a
//! wrong password signs nobody in, on any page; a wrong code after a right
//! password counts toward lockout; a right password does not clear the count the
//! codes built up; and a signed-in user confirming with a code gets no free
//! guesses either.
//!
//! Each test here fails when the guard it covers is removed.

mod common;

use common::*;
use rust_oidc::mfa;
use rust_oidc::tenant::{self, MfaMode};
use rust_oidc::util::now;

const WRONG_CODE_PAGE: &str = "Check the time on your phone";
const LOCKED: &str = "AADSTS50053";

async fn set_mode(s: &TestServer, tenant_id: &str, mode: MfaMode) {
    let mut t = tenant::find_for_admin(&s.pool, tenant_id).await.unwrap();
    t.settings.mfa_mode = mode;
    tenant::save_settings(&s.pool, tenant_id, &t.settings).await.unwrap();
}

async fn counter(s: &TestServer, user_id: &str) -> (i64, Option<i64>) {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT failed_logins, locked_until FROM users WHERE id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

async fn sessions_of(s: &TestServer, user_id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    n
}

/// A code the window accepts that no earlier step has spent.
fn fresh_code(secret: &str, steps_ahead: i64) -> String {
    mfa::code_for(secret, now() + steps_ahead * mfa::STEP_SECS)
}

/// Alice with an authenticator.
async fn alice(s: &TestServer) -> (UserFixture, String) {
    let f = user_fixture(s).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    (f, secret)
}

fn my_account(s: &TestServer, f: &UserFixture) -> String {
    s.url(&format!("/{}/myaccount", f.tenant.id))
}

/// Post a second-step form: the page's own hidden fields and this code.
async fn send_code(b: &Browser, page: &Page, code: &str) -> Page {
    let mut form: Vec<(String, String)> = Vec::new();
    for name in ["csrf", "request", "op", "mfa_ticket"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    form.push(("code".into(), code.into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

/// Sign in to My Account with a password, landing on the code page.
async fn my_account_password(s: &TestServer, f: &UserFixture, password: &str) -> (Browser, Page) {
    let b = Browser::new();
    let login = b.get(&my_account(s, f)).await;
    let next = b.login(&login, &f.upn, password).await;
    (b, next)
}

/// A device code for the web app, and its user code.
async fn device_code(s: &TestServer, f: &UserFixture) -> String {
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/devicecode", f.tenant.id)))
        .form(&[("client_id", f.web.app_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap();
    let issued: serde_json::Value = resp.json().await.unwrap();
    issued["user_code"].as_str().unwrap().to_string()
}

/// The device sign-in page for a user code.
async fn device_entry(s: &TestServer, f: &UserFixture, user_code: &str) -> (Browser, Page) {
    let b = Browser::new();
    let entry = b
        .get(&s.url(&format!("/{}/oauth2/deviceauth?user_code={user_code}", f.tenant.id)))
        .await;
    (b, entry)
}

/// The ticket a code page shown after a wrong password carries, under Enforced,
/// at the application sign-in: a ticket whose password was wrong, for an
/// account that exists and has an authenticator.
async fn unverified_ticket(s: &TestServer, f: &UserFixture) -> (Browser, Page) {
    let (_, challenge) = pkce();
    let params = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "st"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let b = Browser::new();
    let login = b.authorize(s, &f.tenant.id, &params).await;
    let page = b.login(&login, &f.upn, "Wrong-Horse-9").await;
    assert!(page.body.contains("Enter code"), "{}", page.body);
    (b, page)
}

/// Someone holding a current code but not the password: the code page a wrong
/// password shows them is good for nothing, on the page that showed it and on
/// every other page that reads a ticket.
#[tokio::test]
async fn a_code_page_after_a_wrong_password_signs_nobody_in_anywhere() {
    let s = TestServer::start().await;
    let (f, secret) = alice(&s).await;
    set_mode(&s, &f.tenant.id, MfaMode::Enforced).await;
    let (b, page) = unverified_ticket(&s, &f).await;
    let ticket = page.field("mfa_ticket").expect("a ticket");
    let csrf = page.field("csrf").expect("a csrf field");

    // The storage layer: an ordinary lookup never returns it.
    assert!(
        mfa::pending(&s.pool, &ticket, &f.tenant.id).await.unwrap().is_none(),
        "a ticket whose password was wrong is not a pending step"
    );
    let either = mfa::pending_either(&s.pool, &ticket, &f.tenant.id)
        .await
        .unwrap()
        .expect("the page that shows it still reads it");
    assert!(!either.password_right);

    // My Account, in the same browser (so the CSRF cookie is there), with the
    // ticket and a right code, without the `request` that binds a voluntary step.
    let at_my_account = b
        .post_form(
            &my_account(&s, &f),
            &[
                ("csrf", csrf.as_str()),
                ("op", "mfa_verify"),
                ("mfa_ticket", ticket.as_str()),
                ("code", &fresh_code(&secret, 1)),
            ],
        )
        .await;
    assert!(
        !at_my_account.body.contains("<h1>My account</h1>"),
        "signed in on the second factor alone: {}",
        at_my_account.body
    );
    assert_eq!(sessions_of(&s, &f.user_id).await, 0);

    // The device sign-in, with a pending device code to approve.
    let user_code = device_code(&s, &f).await;
    let (b, entry) = device_entry(&s, &f, &user_code).await;
    let at_device = b
        .post_form(
            &entry.form_action(),
            &[
                ("csrf", entry.field("csrf").expect("csrf").as_str()),
                ("request", entry.field("request").expect("request").as_str()),
                ("op", "mfa_verify"),
                ("mfa_ticket", ticket.as_str()),
                ("code", &fresh_code(&secret, 1)),
            ],
        )
        .await;
    assert!(
        !at_device.body.contains(r#"value="approve""#),
        "an approval page on the second factor alone: {}",
        at_device.body
    );
    assert_eq!(sessions_of(&s, &f.user_id).await, 0);
    assert_eq!(counter(&s, &f.user_id).await, (0, None), "nothing counted either way");
}

/// At My Account: a wrong code after a right password counts, re-entering the
/// right password clears nothing, and ten of them lock the account.
#[tokio::test]
async fn my_account_counts_a_wrong_code_and_a_right_password_clears_nothing() {
    let s = TestServer::start().await;
    let (f, _) = alice(&s).await;
    let (b, page) = my_account_password(&s, &f, &f.password).await;
    assert!(page.body.contains("Enter code"), "{}", page.body);
    assert_eq!(counter(&s, &f.user_id).await, (0, None), "the password settles nothing");
    let after = send_code(&b, &page, "000000").await;
    assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
    assert_eq!(counter(&s, &f.user_id).await.0, 1);

    // Each further sign-in with the right password: the count stands, and the
    // wrong code after it adds one.
    for n in 2..=10 {
        let (b, page) = my_account_password(&s, &f, &f.password).await;
        assert_eq!(
            counter(&s, &f.user_id).await.0,
            n - 1,
            "a right password cleared the count"
        );
        let after = send_code(&b, &page, "000000").await;
        assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
        assert_eq!(counter(&s, &f.user_id).await.0, n);
    }
    let (_, locked_until) = counter(&s, &f.user_id).await;
    assert!(locked_until.is_some(), "ten wrong codes lock the account");
    let (_, page) = my_account_password(&s, &f, &f.password).await;
    assert!(page.body.contains(LOCKED), "{}", page.body);
}

/// Both factors right at My Account clear the count, as at every sign-in.
#[tokio::test]
async fn a_right_code_at_my_account_clears_the_count() {
    let s = TestServer::start().await;
    let (f, secret) = alice(&s).await;
    let (b, page) = my_account_password(&s, &f, &f.password).await;
    let after = send_code(&b, &page, "000000").await;
    assert_eq!(counter(&s, &f.user_id).await.0, 1);
    let done = send_code(&b, &after, &fresh_code(&secret, 1)).await;
    assert!(done.body.contains("<h1>My account</h1>"), "{}", done.body);
    assert_eq!(counter(&s, &f.user_id).await, (0, None));
}

/// At the device sign-in: a wrong code after a right password counts, and a
/// right password at the next attempt clears nothing.
#[tokio::test]
async fn the_device_sign_in_counts_a_wrong_code_toward_lockout() {
    let s = TestServer::start().await;
    let (f, _) = alice(&s).await;
    let user_code = device_code(&s, &f).await;
    for n in 1..=10 {
        let (b, entry) = device_entry(&s, &f, &user_code).await;
        let page = b.login(&entry, &f.upn, &f.password).await;
        assert!(page.body.contains("Enter code"), "{}", page.body);
        assert_eq!(counter(&s, &f.user_id).await.0, n - 1, "the password cleared the count");
        let after = send_code(&b, &page, "000000").await;
        assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
        assert_eq!(counter(&s, &f.user_id).await.0, n);
    }
    assert!(
        counter(&s, &f.user_id).await.1.is_some(),
        "ten wrong codes lock the account"
    );
    let (b, entry) = device_entry(&s, &f, &user_code).await;
    let page = b.login(&entry, &f.upn, &f.password).await;
    assert!(page.body.contains(LOCKED), "{}", page.body);
}

/// A signed-in user confirming a new phone or new recovery codes with a code:
/// a wrong one counts, and once locked the right one is refused too, so a
/// stolen session is no place to guess at the second factor.
#[tokio::test]
async fn guessing_at_a_new_phone_from_a_session_is_locked_out() {
    let s = TestServer::start().await;
    let (f, secret) = alice(&s).await;
    let (b, page) = my_account_password(&s, &f, &f.password).await;
    let dashboard = send_code(&b, &page, &fresh_code(&secret, 1)).await;
    assert!(dashboard.body.contains("<h1>My account</h1>"), "{}", dashboard.body);
    // Every response carries a fresh CSRF token: each post takes the latest.
    let mut page = dashboard;
    for n in 1..=10 {
        let op = if n % 2 == 0 {
            "account_recovery_codes"
        } else {
            "account_mfa_replace"
        };
        let csrf = page.field("csrf").expect("csrf");
        page = b
            .post_form(
                &my_account(&s, &f),
                &[("csrf", csrf.as_str()), ("op", op), ("code", "000000")],
            )
            .await;
        assert!(page.body.contains("didn"), "try {n}: {}", page.body);
        assert_eq!(counter(&s, &f.user_id).await.0, n);
    }
    assert!(
        counter(&s, &f.user_id).await.1.is_some(),
        "ten wrong codes lock the account"
    );
    let csrf = page.field("csrf").expect("csrf");
    let refused = b
        .post_form(
            &my_account(&s, &f),
            &[
                ("csrf", csrf.as_str()),
                ("op", "account_mfa_replace"),
                ("code", &fresh_code(&secret, 2)),
            ],
        )
        .await;
    assert!(refused.body.contains(LOCKED), "{}", refused.body);
    assert!(
        !refused.body.contains("Set up your authenticator"),
        "a locked account replaced its authenticator: {}",
        refused.body
    );
}
