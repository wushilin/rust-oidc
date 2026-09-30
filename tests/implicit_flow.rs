//! Implicit and hybrid response types, following Entra: `code`, `id_token`,
//! `code id_token`, `id_token token` and bare `token`, each opt-in per app
//! registration. See docs/superpowers/specs/2026-09-30-implicit-hybrid-response-types.md.

mod common;

use std::collections::HashMap;

use common::{Browser, REDIRECT, TestServer, UserFixture, user_fixture};
use rust_oidc::apps;
use serde_json::Value;

/// Entra's exact message when the app registration has not enabled the toggle.
const NOT_ALLOWED: &str = "The provided value for the input parameter 'response_type' is not allowed for this client. Expected value is 'code'";

async fn allow(s: &TestServer, f: &UserFixture, id_tokens: bool, access_tokens: bool) {
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id).await.unwrap();
    apps::set_implicit_allowed(&s.pool, &app, id_tokens, access_tokens)
        .await
        .unwrap();
}

/// Both the query and the fragment of a redirect, so a test does not have to know
/// which half the server chose -- and a value appearing in the wrong one still shows up.
fn parts(location: &str) -> (HashMap<String, String>, HashMap<String, String>) {
    let url = url::Url::parse(location).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let fragment: HashMap<_, _> = url
        .fragment()
        .map(|f| url::form_urlencoded::parse(f.as_bytes()).into_owned().collect())
        .unwrap_or_default();
    (query, fragment)
}

/// Run an authorize request, signing in if a login page comes back.
async fn authorize(s: &TestServer, f: &UserFixture, params: &[(&str, &str)]) -> (u16, Option<String>, String) {
    let b = Browser::new();
    let page = b.authorize(s, &f.tenant.id, params).await;
    let done = if page.field("csrf").is_some() {
        b.login(&page, &f.upn, &f.password).await
    } else {
        page
    };
    (done.status, done.location, done.body)
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("jwt payload");
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("json payload")
}

fn base(f: &UserFixture) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", f.web.app_id.clone()),
        ("redirect_uri", REDIRECT.to_string()),
        ("state", "st-1".to_string()),
        ("nonce", "n-1".to_string()),
    ]
}

fn with<'a>(f: &UserFixture, extra: &[(&'a str, &'a str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = base(f).into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    for (k, v) in extra {
        out.retain(|(ek, _)| ek != k);
        out.push((k.to_string(), v.to_string()));
    }
    out
}

async fn run(s: &TestServer, f: &UserFixture, extra: &[(&str, &str)]) -> (u16, Option<String>, String) {
    let owned = with(f, extra);
    let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    authorize(s, f, &params).await
}

#[tokio::test]
async fn hybrid_code_id_token_returns_both_and_binds_the_code() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;

    let (status, location, body) = run(&s, &f, &[("response_type", "code id_token"), ("scope", "openid")]).await;
    assert_eq!(status, 302, "{body}");
    let (query, fragment) = parts(&location.unwrap());
    // Entra defaults to the fragment once an id_token is involved.
    assert!(query.is_empty(), "nothing belongs in the query: {query:?}");
    let code = fragment.get("code").expect("code in fragment");
    let id_token = fragment.get("id_token").expect("id_token in fragment");
    assert_eq!(fragment.get("state").map(String::as_str), Some("st-1"));
    assert!(!fragment.contains_key("access_token"), "none was requested");

    let claims = claims_of(id_token);
    assert_eq!(claims["nonce"], "n-1");
    // c_hash binds the id_token to the code beside it, so the two cannot be mixed
    // and matched across responses.
    assert_eq!(claims["c_hash"], rust_oidc::util::half_hash(code));
    assert!(claims.get("at_hash").is_none(), "no access token travelled with it");

    // The hybrid code still redeems normally, refresh token included.
    let (status, tokens) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
            ],
        )
        .await;
    assert_eq!(status, 200, "{tokens}");
    assert!(tokens["access_token"].is_string());
}

#[tokio::test]
async fn id_token_only_returns_no_code_and_no_hashes() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;

    let (status, location, body) = run(&s, &f, &[("response_type", "id_token"), ("scope", "openid")]).await;
    assert_eq!(status, 302, "{body}");
    let (_, fragment) = parts(&location.unwrap());
    let claims = claims_of(fragment.get("id_token").expect("id_token"));
    assert!(!fragment.contains_key("code"));
    assert!(!fragment.contains_key("access_token"));
    assert!(claims.get("c_hash").is_none(), "no code to bind");
    assert!(claims.get("at_hash").is_none(), "no access token to bind");
}

#[tokio::test]
async fn id_token_token_returns_an_access_token_bound_by_at_hash() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);

    let (status, location, body) = run(&s, &f, &[("response_type", "id_token token"), ("scope", &scope)]).await;
    assert_eq!(status, 302, "{body}");
    let (_, fragment) = parts(&location.unwrap());
    let access_token = fragment.get("access_token").expect("access_token");
    assert_eq!(fragment.get("token_type").map(String::as_str), Some("Bearer"));
    assert!(fragment.contains_key("expires_in"));
    assert!(fragment.contains_key("scope"));
    // Entra: "The implicit grant doesn't provide refresh tokens."
    assert!(!fragment.contains_key("refresh_token"));
    assert!(!fragment.contains_key("code"));

    let claims = claims_of(fragment.get("id_token").expect("id_token"));
    assert_eq!(claims["at_hash"], rust_oidc::util::half_hash(access_token));
    assert!(claims.get("c_hash").is_none());
}

#[tokio::test]
async fn bare_token_returns_an_access_token_and_never_an_id_token() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, false, true).await;
    // `openid` is in scope, so an id_token *could* be minted -- it must not be
    // returned, because the client did not ask for one.
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);

    let (status, location, body) = run(&s, &f, &[("response_type", "token"), ("scope", &scope)]).await;
    assert_eq!(status, 302, "{body}");
    let (query, fragment) = parts(&location.unwrap());
    assert!(fragment.contains_key("access_token"));
    assert!(!fragment.contains_key("id_token"), "not requested");
    // An access token must never reach a query string, whatever the doc prose says.
    assert!(query.is_empty(), "{query:?}");
}

#[tokio::test]
async fn front_channel_tokens_are_refused_unless_the_app_enables_them() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;

    // Nothing enabled: every front-channel type is refused with Entra's own message.
    for rt in ["id_token", "code id_token", "id_token token", "token"] {
        let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
        let (status, location, body) = run(&s, &f, &[("response_type", rt), ("scope", &scope)]).await;
        assert_eq!(status, 302, "{rt}: {body}");
        let (query, fragment) = parts(&location.unwrap());
        let all: HashMap<_, _> = query.into_iter().chain(fragment).collect();
        assert_eq!(
            all.get("error").map(String::as_str),
            Some("unsupported_response"),
            "{rt}"
        );
        // The description carries Entra's envelope around it (AADSTS code, trace and
        // correlation ids, timestamp), so match the message itself.
        let description = all.get("error_description").expect("error_description");
        assert!(description.contains(NOT_ALLOWED), "{rt}: {description}");
        assert!(description.starts_with("AADSTS700054:"), "{rt}: {description}");
    }

    // `code` never needed a toggle.
    let (status, ..) = run(&s, &f, &[("response_type", "code"), ("scope", "openid")]).await;
    assert_eq!(status, 302);
}

#[tokio::test]
async fn each_toggle_gates_only_its_own_artifact() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);

    // ID tokens on, access tokens off: id_token passes, anything with `token` does not.
    allow(&s, &f, true, false).await;
    let (_, location, _) = run(&s, &f, &[("response_type", "id_token"), ("scope", "openid")]).await;
    let (_, fragment) = parts(&location.unwrap());
    assert!(fragment.contains_key("id_token"));

    let (_, location, _) = run(&s, &f, &[("response_type", "id_token token"), ("scope", &scope)]).await;
    let (_, fragment) = parts(&location.unwrap());
    assert_eq!(fragment.get("error").map(String::as_str), Some("unsupported_response"));

    // And the reverse.
    allow(&s, &f, false, true).await;
    let (_, location, _) = run(&s, &f, &[("response_type", "token"), ("scope", &scope)]).await;
    let (_, fragment) = parts(&location.unwrap());
    assert!(fragment.contains_key("access_token"));

    let (_, location, _) = run(&s, &f, &[("response_type", "code id_token"), ("scope", "openid")]).await;
    let (query, fragment) = parts(&location.unwrap());
    let all: HashMap<_, _> = query.into_iter().chain(fragment).collect();
    assert_eq!(all.get("error").map(String::as_str), Some("unsupported_response"));
}

#[tokio::test]
async fn combinations_entra_does_not_support_are_refused() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);

    for rt in ["code token", "code id_token token", "none", "id_token code token extra"] {
        let (status, location, body) = run(&s, &f, &[("response_type", rt), ("scope", &scope)]).await;
        assert_eq!(status, 302, "{rt}: {body}");
        let (query, fragment) = parts(&location.unwrap());
        let all: HashMap<_, _> = query.into_iter().chain(fragment).collect();
        assert_eq!(
            all.get("error").map(String::as_str),
            Some("unsupported_response"),
            "{rt} must be refused"
        );
    }
}

#[tokio::test]
async fn nonce_is_required_exactly_when_an_id_token_is_returned() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);

    for rt in ["id_token", "code id_token", "id_token token"] {
        let (_, location, _) = run(&s, &f, &[("response_type", rt), ("scope", &scope), ("nonce", "")]).await;
        let (query, fragment) = parts(&location.unwrap());
        let all: HashMap<_, _> = query.into_iter().chain(fragment).collect();
        assert!(
            all.get("error_description").is_some_and(|d| d.contains("nonce")),
            "{rt} must require a nonce, got {all:?}"
        );
    }

    // No id_token comes back, so no nonce is needed.
    for rt in ["code", "token"] {
        let (_, location, _) = run(&s, &f, &[("response_type", rt), ("scope", &scope), ("nonce", "")]).await;
        let (query, fragment) = parts(&location.unwrap());
        let all: HashMap<_, _> = query.into_iter().chain(fragment).collect();
        assert!(!all.contains_key("error"), "{rt} needs no nonce, got {all:?}");
    }
}

#[tokio::test]
async fn response_mode_query_is_refused_when_a_token_would_travel_in_it() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, true).await;

    let (status, location, _) = run(
        &s,
        &f,
        &[
            ("response_type", "id_token"),
            ("scope", "openid"),
            ("response_mode", "query"),
        ],
    )
    .await;
    assert_eq!(status, 302);
    let (query, fragment) = parts(&location.unwrap());
    assert!(query.is_empty(), "the refusal itself must not use the query: {query:?}");
    assert!(
        fragment
            .get("error_description")
            .is_some_and(|d| d.contains("response_mode")),
        "{fragment:?}"
    );

    // form_post is the mode Entra recommends here, and it still works.
    let (status, _, body) = run(
        &s,
        &f,
        &[
            ("response_type", "code id_token"),
            ("scope", "openid"),
            ("response_mode", "form_post"),
        ],
    )
    .await;
    assert_eq!(status, 200, "form_post posts a self-submitting form");
    assert!(body.contains("id_token"), "{body}");
}

#[tokio::test]
async fn response_type_is_an_unordered_set() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;

    let (status, location, body) = run(&s, &f, &[("response_type", "id_token code"), ("scope", "openid")]).await;
    assert_eq!(status, 302, "{body}");
    let (_, fragment) = parts(&location.unwrap());
    assert!(fragment.contains_key("code"), "{fragment:?}");
    assert!(fragment.contains_key("id_token"), "{fragment:?}");
}

#[tokio::test]
async fn an_id_token_request_must_ask_for_the_openid_scope() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow(&s, &f, true, false).await;
    let scope = format!("api://{}/Orders.Read", f.api.app_id);

    let (_, location, _) = run(&s, &f, &[("response_type", "id_token"), ("scope", &scope)]).await;
    let (_, fragment) = parts(&location.unwrap());
    assert!(
        fragment.get("error_description").is_some_and(|d| d.contains("openid")),
        "{fragment:?}"
    );
}
