//! Multi-factor authentication with an authenticator app: who needs it, setting
//! it up at sign-in, the second step, recovery codes, and every way of getting a
//! token being held to it.

mod common;

use common::*;
use rust_oidc::db::Event;
use rust_oidc::mfa::{self, MfaPolicy};
use rust_oidc::tenant;
use rust_oidc::util::now;
use serde_json::Value;

fn params<'a>(f: &'a UserFixture, challenge: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut p = vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "st-mfa"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    p.extend_from_slice(extra);
    p
}

async fn require_mfa_in_tenant(s: &TestServer, f: &UserFixture, everyone: bool, console: bool) {
    let mut settings = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap().settings;
    settings.require_mfa = everyone;
    settings.require_console_mfa = console;
    tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.unwrap();
}

/// Post the code on a second-step page.
async fn send_code(b: &Browser, page: &Page, code: &str) -> Page {
    let mut form: Vec<(String, String)> = Vec::new();
    for name in ["csrf", "request", "op", "mfa_ticket", "tenant"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    form.push(("code".into(), code.into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

/// The key printed on the set-up page, as the authenticator would read it.
fn key_on(page: &Page) -> String {
    let start = page
        .body
        .find(r#"<div class="key">"#)
        .expect("the set-up page shows a key")
        + 17;
    let end = page.body[start..].find("</div>").unwrap() + start;
    page.body[start..end].replace(' ', "")
}

fn recovery_codes_on(page: &Page) -> Vec<String> {
    let start = page.body.find(r#"<ul class="codes">"#).expect("the codes are shown") + 18;
    let end = page.body[start..].find("</ul>").unwrap() + start;
    page.body[start..end]
        .split("<li>")
        .filter_map(|li| li.split("</li>").next())
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

/// A code that has not been used yet: the next step's, which the window accepts.
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

fn amr(token: &Value, key: &str) -> Vec<String> {
    decode_unverified(token[key].as_str().unwrap())["amr"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

/// The whole of it once: required by the tenant, set up at sign-in, signed out,
/// signed in again with password and code, and the token says so.
#[tokio::test]
async fn a_required_user_enrols_at_sign_in_is_signed_out_and_signs_in_with_a_code() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    require_mfa_in_tenant(&s, &f, true, false).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();

    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let setup = b.login(&login, &f.upn, &f.password).await;
    assert_eq!(setup.status, 200, "{}", setup.body);
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    assert!(setup.body.contains("<svg"), "a QR code: {}", setup.body);
    let secret = key_on(&setup);

    // A wrong code keeps the same page and the same key.
    let wrong = send_code(&b, &setup, "000000").await;
    assert_eq!(wrong.status, 401);
    assert_eq!(key_on(&wrong), secret);

    let done = send_code(&b, &wrong, &mfa::code_for(&secret, now())).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let codes = recovery_codes_on(&done);
    assert_eq!(codes.len(), mfa::RECOVERY_CODE_COUNT);
    assert!(done.body.contains("Sign in again"), "{}", done.body);
    assert_eq!(audit_rows(&s, Event::MfaEnrolled.as_str()).await.len(), 1);

    // Signed out: the application's next request asks for the password again,
    // and then for a code.
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert!(
        login.field("csrf").is_some() && login.body.contains("password"),
        "{}",
        login.body
    );
    let step = b.login(&login, &f.upn, &f.password).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let finished = send_code(&b, &step, &fresh_code(&secret, 1)).await;
    let tokens = redeem(&s, &f, &finished, &verifier).await;
    assert_eq!(amr(&tokens, "id_token"), ["pwd", "mfa"]);
    assert_eq!(amr(&tokens, "access_token"), ["pwd", "mfa"]);

    // The session now has it: the next request is answered without a page.
    let again = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert_eq!(again.status, 302, "{}", again.body);
}

#[tokio::test]
async fn a_code_works_once_and_too_many_wrong_codes_start_the_sign_in_again() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let (verifier, challenge) = pkce();

    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let step = b.login(&login, &f.upn, &f.password).await;
    let code = fresh_code(&secret, 1);
    redeem(&s, &f, &send_code(&b, &step, &code).await, &verifier).await;

    // The same code, seen over a shoulder, in another browser: refused.
    let other = Browser::new();
    let login = other.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let step = other.login(&login, &f.upn, &f.password).await;
    let replay = send_code(&other, &step, &code).await;
    assert_eq!(replay.status, 401, "{}", replay.body);

    // Wrong again and again: the fifth sends them back to the password.
    let mut page = replay;
    for _ in 0..(mfa::MAX_ATTEMPTS - 2) {
        page = send_code(&other, &page, "000000").await;
        assert!(page.body.contains("Enter code"), "{}", page.body);
    }
    let out = send_code(&other, &page, "000000").await;
    assert!(out.body.contains("too many wrong codes"), "{}", out.body);
    assert!(audit_rows(&s, Event::MfaFailed.as_str()).await.len() >= 4);
}

#[tokio::test]
async fn a_recovery_code_signs_in_once() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let codes = mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let (verifier, challenge) = pkce();

    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let step = b.login(&login, &f.upn, &f.password).await;
    // As typed by a person: upper case, with a space instead of the dash.
    let typed = codes[0].to_uppercase().replace('-', " ");
    let tokens = redeem(&s, &f, &send_code(&b, &step, &typed).await, &verifier).await;
    assert_eq!(amr(&tokens, "id_token"), ["pwd", "mfa"]);
    assert_eq!(mfa::recovery_codes_left(&s.pool, &f.user_id).await.unwrap(), 9);

    let other = Browser::new();
    let login = other.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let step = other.login(&login, &f.upn, &f.password).await;
    assert_eq!(send_code(&other, &step, &codes[0]).await.status, 401, "spent");
}

/// The user's own setting wins over the tenant's, both ways; an application's
/// switch adds to both; and nobody is asked who needs nothing.
#[tokio::test]
async fn who_needs_mfa_follows_the_user_then_the_tenant_then_the_application() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let t = || async { tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap() };
    let sp = || async {
        rust_oidc::apps::service_principal(&s.pool, &f.tenant.id, &f.web.app_id)
            .await
            .unwrap()
            .unwrap()
    };
    let step = |tn: tenant::Tenant, sp: rust_oidc::apps::ServicePrincipal| {
        let pool = s.pool.clone();
        let user = f.user_id.clone();
        async move { mfa::step(&pool, &tn, &user, mfa::At::App(&sp)).await.unwrap() }
    };
    assert_eq!(step(t().await, sp().await).await, mfa::Step::Done);

    require_mfa_in_tenant(&s, &f, true, false).await;
    assert_eq!(step(t().await, sp().await).await, mfa::Step::Enroll);
    mfa::set_policy(&s.pool, &f.tenant.id, &f.user_id, MfaPolicy::NotRequired)
        .await
        .unwrap();
    assert_eq!(
        step(t().await, sp().await).await,
        mfa::Step::Done,
        "the user's exception"
    );

    require_mfa_in_tenant(&s, &f, false, false).await;
    mfa::set_policy(&s.pool, &f.tenant.id, &f.user_id, MfaPolicy::Required)
        .await
        .unwrap();
    assert_eq!(
        step(t().await, sp().await).await,
        mfa::Step::Enroll,
        "required of them alone"
    );

    mfa::set_policy(&s.pool, &f.tenant.id, &f.user_id, MfaPolicy::NotRequired)
        .await
        .unwrap();
    rust_oidc::apps::set_mfa_required(&s.pool, &sp().await.id, true)
        .await
        .unwrap();
    assert_eq!(
        step(t().await, sp().await).await,
        mfa::Step::Enroll,
        "the application requires it of everyone"
    );

    // Whoever has an authenticator is asked for it, required or not.
    rust_oidc::apps::set_mfa_required(&s.pool, &sp().await.id, false)
        .await
        .unwrap();
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    assert_eq!(step(t().await, sp().await).await, mfa::Step::Verify);
}

/// Signed in to one application without MFA, then opening one that requires it:
/// asked for a code, not for the password again.
#[tokio::test]
async fn an_application_that_requires_mfa_steps_up_an_existing_session() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let secret = mfa::new_secret();
    let (verifier, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let first = b.login(&login, &f.upn, &f.password).await;
    let tokens = redeem(&s, &f, &first, &verifier).await;
    assert_eq!(amr(&tokens, "id_token"), ["pwd"]);

    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let sp = rust_oidc::apps::service_principal(&s.pool, &f.tenant.id, &f.web.app_id)
        .await
        .unwrap()
        .unwrap();
    rust_oidc::apps::set_mfa_required(&s.pool, &sp.id, true).await.unwrap();

    // A silent request cannot do it.
    let silent = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("prompt", "none")]))
        .await;
    let p = silent.redirect_params();
    assert_eq!(p["error"], "interaction_required", "{p:?}");
    assert!(p["error_description"].contains("AADSTS50076"), "{p:?}");

    let step = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert!(
        step.body.contains("Enter code"),
        "a code, not the password: {}",
        step.body
    );
    assert!(!step.body.contains(r#"name="password""#), "{}", step.body);
    let tokens = redeem(&s, &f, &send_code(&b, &step, &fresh_code(&secret, 1)).await, &verifier).await;
    assert_eq!(amr(&tokens, "id_token"), ["pwd", "mfa"]);
}

/// The grants that cannot show a page are refused where MFA is needed: the
/// password grant always, a refresh token whose sign-in had none.
#[tokio::test]
async fn token_grants_without_a_second_factor_are_refused_where_one_is_needed() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = rust_oidc::apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id)
        .await
        .unwrap();
    rust_oidc::apps::set_password_grant_allowed(&s.pool, &app, true)
        .await
        .unwrap();
    let ropc = || async {
        s.token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", "openid offline_access"),
            ],
        )
        .await
    };
    let (status, body) = ropc().await;
    assert_eq!(status, 200, "nothing requires it yet: {body}");
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    require_mfa_in_tenant(&s, &f, true, false).await;
    let (status, body) = ropc().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS50079"),
        "not enrolled: {body}"
    );

    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let (_, body) = ropc().await;
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS50076"),
        "{body}"
    );

    // The refresh token from before carries a password-only sign-in.
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", &refresh),
            ],
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS50076"),
        "{body}"
    );
}

/// An administrator's reset: the authenticator and codes go, the user is signed
/// out, and with MFA required they set one up again at the next sign-in.
#[tokio::test]
async fn an_admin_reset_removes_the_authenticator_and_the_next_sign_in_enrols_again() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let user = user_fixture_in(&s, f.tenant.clone(), "bob@contoso.com").await;
    mfa::enroll(&s.pool, &user.user_id, &mfa::new_secret()).await.unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, user.user_id));

    let page = b.get(&url).await;
    assert!(page.body.contains("Authenticator set up"), "{}", page.body);
    assert!(page.body.contains("10 unused recovery codes"), "{}", page.body);
    assert!(
        page.body.contains("Remove the authenticator of bob@contoso.com?"),
        "asks first: {}",
        page.body
    );

    let set = b.post(&url, &[("op", "mfa_policy"), ("mfa_policy", "Required")]).await;
    assert_eq!(set.status, 303, "{}", set.body);
    assert_eq!(mfa::policy(&s.pool, &user.user_id).await.unwrap(), MfaPolicy::Required);
    let reset = b.post(&url, &[("op", "mfa_reset")]).await;
    assert_eq!(reset.status, 303, "{}", reset.body);
    assert!(mfa::enrolled_at(&s.pool, &user.user_id).await.unwrap().is_none());
    assert_eq!(mfa::recovery_codes_left(&s.pool, &user.user_id).await.unwrap(), 0);
    assert_eq!(audit_rows(&s, Event::AdminUserMfaReset.as_str()).await.len(), 1);
    let again = b.post(&url, &[("op", "mfa_reset")]).await;
    assert_eq!(again.status, 400, "nothing left to reset");

    let (_, challenge) = pkce();
    let ub = Browser::new();
    let login = ub.authorize(&s, &f.tenant.id, &params(&user, &challenge, &[])).await;
    let next = ub.login(&login, &user.upn, &user.password).await;
    assert!(next.body.contains("Set up your authenticator"), "{}", next.body);
}

/// The console: a tenant can require MFA of its administrators.
#[tokio::test]
async fn the_console_can_require_mfa_of_administrators() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    require_mfa_in_tenant(&s, &f, false, true).await;
    let b = Browser::new();
    let form = b.get(&s.url("/admin")).await;
    let nonce = form.field("csrf").unwrap();
    let setup = b
        .post_form(
            &s.url("/admin/signin"),
            &[
                ("upn", f.upn.as_str()),
                ("password", f.password.as_str()),
                ("csrf", nonce.as_str()),
            ],
        )
        .await;
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    let secret = key_on(&setup);
    let done = send_code(&b, &setup, &mfa::code_for(&secret, now())).await;
    assert!(done.body.contains("recovery codes"), "{}", done.body);

    let form = b.get(&s.url("/admin")).await;
    let nonce = form.field("csrf").unwrap();
    let step = b
        .post_form(
            &s.url("/admin/signin"),
            &[
                ("upn", f.upn.as_str()),
                ("password", f.password.as_str()),
                ("csrf", nonce.as_str()),
            ],
        )
        .await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let signed_in = send_code(&b, &step, &fresh_code(&secret, 1)).await;
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    assert_eq!(b.get(&s.url("/admin/tenants")).await.status, 200);
}

/// The device code flow: the second step comes after the password, on the
/// browser, and the device's token says so.
#[tokio::test]
async fn the_device_code_flow_asks_for_a_code_after_the_password() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/devicecode", f.tenant.id)))
        .form(&[("client_id", f.web.app_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap();
    let issued: Value = resp.json().await.unwrap();
    let user_code = issued["user_code"].as_str().unwrap();
    let device_code = issued["device_code"].as_str().unwrap();

    let b = Browser::new();
    let entry = b
        .get(&s.url(&format!("/{}/oauth2/deviceauth?user_code={user_code}", f.tenant.id)))
        .await;
    let step = b.login(&entry, &f.upn, &f.password).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let approval = send_code(&b, &step, &fresh_code(&secret, 1)).await;
    assert!(
        approval.body.contains(r#"value="approve""#) || approval.body.contains("approve"),
        "{}",
        approval.body
    );
    let form = [
        ("csrf", approval.field("csrf").unwrap()),
        ("request", approval.field("request").unwrap()),
        ("op", "approve".to_string()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post_form(&approval.form_action(), &form).await;

    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", &f.web.app_id),
                ("device_code", device_code),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(amr(&body, "id_token"), ["pwd", "mfa"]);
}
