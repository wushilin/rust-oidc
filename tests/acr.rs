//! `acr` and `acr_values`: the level of authentication a token reports, and an
//! application asking for a stronger one (step-up).

mod common;

use common::*;
use rust_oidc::mfa;
use rust_oidc::util::now;
use serde_json::Value;

fn params<'a>(f: &'a UserFixture, challenge: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut p = vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile offline_access"),
        ("state", "st-acr"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    p.extend_from_slice(extra);
    p
}

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

fn acr(tokens: &Value, key: &str) -> String {
    decode_unverified(tokens[key].as_str().unwrap())["acr"]
        .as_str()
        .expect("an acr claim")
        .to_string()
}

#[tokio::test]
async fn discovery_lists_the_levels_and_the_claim() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (status, doc) = s
        .get_json(&format!("/{}/v2.0/.well-known/openid-configuration", f.tenant.id))
        .await;
    assert_eq!(status, 200);
    assert_eq!(doc["acr_values_supported"], serde_json::json!(["1", "2"]));
    assert!(doc["claims_supported"].as_array().unwrap().iter().any(|c| c == "acr"));
}

/// A password alone is level 1, in both tokens and after a refresh.
#[tokio::test]
async fn a_password_sign_in_is_level_one() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (verifier, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let tokens = redeem(&s, &f, &b.login(&login, &f.upn, &f.password).await, &verifier).await;
    assert_eq!(acr(&tokens, "id_token"), "1");
    assert_eq!(acr(&tokens, "access_token"), "1");

    let (status, refreshed) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(acr(&refreshed, "access_token"), "1");
}

/// Asking for level 2 makes an account without an authenticator set one up at
/// sign-in, as when MFA is required of it; after signing in again with a code,
/// the tokens say 2, and a refresh keeps saying it.
#[tokio::test]
async fn asking_for_level_two_makes_an_account_without_an_authenticator_set_one_up() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (verifier, challenge) = pkce();
    let b = Browser::new();
    let step_up = [("acr_values", "2")];

    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &step_up)).await;
    let setup = b.login(&login, &f.upn, &f.password).await;
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    let start = setup.body.find(r#"<div class="key">"#).unwrap() + 17;
    let end = setup.body[start..].find("</div>").unwrap() + start;
    let secret = setup.body[start..end].replace(' ', "");
    let done = send_code(&b, &setup, &mfa::code_for(&secret, now())).await;
    assert!(done.body.contains("Sign in again"), "{}", done.body);

    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &step_up)).await;
    let step = b.login(&login, &f.upn, &f.password).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    let tokens = redeem(&s, &f, &send_code(&b, &step, &fresh_code(&secret, 1)).await, &verifier).await;
    assert_eq!(acr(&tokens, "id_token"), "2");
    assert_eq!(acr(&tokens, "access_token"), "2");

    let (status, refreshed) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(acr(&refreshed, "access_token"), "2");

    // The session has level 2 now: asking again needs no page.
    let again = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &step_up)).await;
    assert_eq!(again.status, 302, "{}", again.body);
}

/// A session signed in with a password only is stepped up when level 2 is asked
/// for: a silent request cannot do it, an interactive one asks for set-up
/// without asking for the password again.
#[tokio::test]
async fn a_password_session_is_stepped_up_when_level_two_is_asked_for() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (verifier, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    let tokens = redeem(&s, &f, &b.login(&login, &f.upn, &f.password).await, &verifier).await;
    assert_eq!(acr(&tokens, "id_token"), "1");

    let silent = b
        .authorize(
            &s,
            &f.tenant.id,
            &params(&f, &challenge, &[("acr_values", "2"), ("prompt", "none")]),
        )
        .await;
    let p = silent.redirect_params();
    assert_eq!(p["error"], "interaction_required", "{p:?}");

    let setup = b
        .authorize(&s, &f.tenant.id, &params(&f, &challenge, &[("acr_values", "2")]))
        .await;
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    assert!(!setup.body.contains(r#"name="password""#), "{}", setup.body);

    // Without acr_values the same session is still answered silently at level 1.
    let plain = b.authorize(&s, &f.tenant.id, &params(&f, &challenge, &[])).await;
    assert_eq!(plain.status, 302, "{}", plain.body);
}

/// `acr_values` is a request, not a demand: values this server does not know are
/// ignored, and the first it knows is the one asked for.
#[tokio::test]
async fn unknown_levels_are_ignored_and_the_first_known_one_counts() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (verifier, challenge) = pkce();
    let b = Browser::new();
    let login = b
        .authorize(
            &s,
            &f.tenant.id,
            &params(&f, &challenge, &[("acr_values", "urn:example:gold 1 2")]),
        )
        .await;
    let tokens = redeem(&s, &f, &b.login(&login, &f.upn, &f.password).await, &verifier).await;
    assert_eq!(acr(&tokens, "id_token"), "1");
}
