mod common;

use common::{Browser, REDIRECT, SPA_REDIRECT, TestServer, UserFixture, aadsts, decode_unverified, pkce, user_fixture};
use rust_oidc::scopes::GRAPH_APP_ID;
use serde_json::Value;

/// Authorize + sign in; returns the code.
async fn sign_in(s: &TestServer, b: &Browser, f: &UserFixture, scope: &str, challenge: &str) -> String {
    let page = b
        .authorize(
            s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", scope),
                ("state", "st-123"),
                ("nonce", "n-456"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    // Already signed in (SSO) -> straight to the redirect; otherwise sign in.
    let done = if page.status == 302 {
        page
    } else {
        b.login(&page, &f.upn, &f.password).await
    };
    assert_eq!(done.status, 302, "{}", done.body);
    let params = done.redirect_params();
    assert_eq!(params["state"], "st-123");
    assert!(done.location.as_ref().unwrap().starts_with(REDIRECT));
    params["code"].clone()
}

async fn redeem(s: &TestServer, f: &UserFixture, code: &str, verifier: &str) -> (u16, Value) {
    s.token(
        &f.tenant.id,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &f.web.app_id),
            ("client_secret", &f.web.secret),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", verifier),
            ("client_info", "1"),
        ],
    )
    .await
}

#[tokio::test]
async fn code_flow_issues_entra_v2_tokens() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let scope = format!("openid profile email offline_access api://{}/Orders.Read", f.api.app_id);
    let code = sign_in(&s, &b, &f, &scope, &challenge).await;

    let (status, body) = redeem(&s, &f, &code, &verifier).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["refresh_token"].is_string());
    let granted = body["scope"].as_str().unwrap();
    assert!(
        granted.contains(&format!("api://{}/Orders.Read", f.api.app_id)),
        "{granted}"
    );

    // client_info as MSAL expects it.
    let info = decode_b64_json(body["client_info"].as_str().unwrap());
    assert_eq!(info["uid"], f.user_id.as_str());
    assert_eq!(info["utid"], f.tenant.id.as_str());

    let id = s
        .verify(&f.tenant.id, body["id_token"].as_str().unwrap(), &f.web.app_id)
        .await;
    assert_eq!(id["ver"], "2.0");
    assert_eq!(id["nonce"], "n-456");
    assert_eq!(id["oid"], f.user_id.as_str());
    assert_eq!(id["tid"], f.tenant.id.as_str());
    assert_eq!(id["preferred_username"], "alice@contoso.com");
    assert_eq!(id["name"], "Alice Smith");
    assert_eq!(id["given_name"], "Alice");
    assert_eq!(id["email"], "alice.smith@example.org");
    assert_eq!(id["amr"], serde_json::json!(["pwd"]));
    assert!(id["auth_time"].is_i64());
    let sub = id["sub"].as_str().unwrap();
    assert_eq!(sub.len(), 43, "pairwise sub looks like Entra's");
    assert_ne!(sub, f.user_id);

    let at = s
        .verify(&f.tenant.id, body["access_token"].as_str().unwrap(), &f.api.app_id)
        .await;
    assert_eq!(at["scp"], "Orders.Read");
    assert_eq!(at["roles"], serde_json::json!(["Orders.Approver"]));
    assert_eq!(at["azp"], f.web.app_id.as_str());
    assert_eq!(at["azpacr"], "1");
    assert_eq!(at["idtyp"], "user");
    assert_eq!(
        at["sub"], sub,
        "access token sub matches the ID token for the same client"
    );
}

fn decode_b64_json(s: &str) -> Value {
    use base64::Engine;
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap()
}

#[tokio::test]
async fn pairwise_sub_differs_per_client() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.app(&f.tenant, "other-app").await;
    let other_app = rust_oidc::apps::find(&s.pool, &other.app_id).await.unwrap().unwrap();
    rust_oidc::apps::add_redirect_uri(&s.pool, &other_app, rust_oidc::apps::RedirectPlatform::Web, REDIRECT)
        .await
        .unwrap();
    let b = Browser::new();
    let (verifier, challenge) = pkce();

    let code = sign_in(&s, &b, &f, "openid", &challenge).await;
    let (_, body) = redeem(&s, &f, &code, &verifier).await;
    let sub1 = decode_unverified(body["id_token"].as_str().unwrap())["sub"].clone();

    // Same browser (SSO), other client.
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &other.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(page.status, 302, "SSO: no login page");
    let code = page.redirect_params()["code"].clone();
    let (_, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &other.app_id),
                ("client_secret", &other.secret),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ],
        )
        .await;
    let sub2 = decode_unverified(body["id_token"].as_str().unwrap())["sub"].clone();
    assert_ne!(sub1, sub2);
}

#[tokio::test]
async fn prompt_and_max_age() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let base = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "s1"),
    ];
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut v: Vec<(&str, &str)> = base.to_vec();
        v.extend_from_slice(extra);
        v
    };

    // Not signed in + prompt=none -> login_required at the redirect URI.
    let page = b.authorize(&s, &f.tenant.id, &with(&[("prompt", "none")])).await;
    let p = page.redirect_params();
    assert_eq!(p["error"], "login_required");
    assert!(p["error_description"].starts_with("AADSTS50058:"));
    assert_eq!(p["state"], "s1");

    // Sign in.
    let page = b.authorize(&s, &f.tenant.id, &base).await;
    assert_eq!(b.login(&page, &f.upn, &f.password).await.status, 302);

    // Signed in + prompt=none -> code.
    let page = b.authorize(&s, &f.tenant.id, &with(&[("prompt", "none")])).await;
    assert!(page.redirect_params().contains_key("code"));

    // prompt=login -> login page again, then a code.
    let page = b.authorize(&s, &f.tenant.id, &with(&[("prompt", "login")])).await;
    assert_eq!(page.status, 200);
    let done = b.login(&page, &f.upn, &f.password).await;
    assert!(done.redirect_params().contains_key("code"));

    // prompt=select_account -> account picker.
    let page = b
        .authorize(&s, &f.tenant.id, &with(&[("prompt", "select_account")]))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Pick an account"));

    // max_age exceeded -> login page (or login_required with prompt=none).
    sqlx::query("UPDATE sessions SET auth_time = auth_time - 100")
        .execute(&s.pool)
        .await
        .unwrap();
    let page = b.authorize(&s, &f.tenant.id, &with(&[("max_age", "10")])).await;
    assert_eq!(page.status, 200);
    let page = b
        .authorize(&s, &f.tenant.id, &with(&[("max_age", "10"), ("prompt", "none")]))
        .await;
    assert_eq!(page.redirect_params()["error"], "login_required");
    let page = b.authorize(&s, &f.tenant.id, &with(&[("max_age", "1000")])).await;
    assert!(page.redirect_params().contains_key("code"));
}

#[tokio::test]
async fn client_and_redirect_errors_are_not_redirected() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", "https://evil.example/cb"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(page.status, 400);
    assert!(page.location.is_none());
    assert!(page.body.contains("AADSTS50011"));

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", "5a1c3d6e-0000-4000-8000-000000000000"),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(page.status, 400);
    assert!(page.body.contains("AADSTS700016"));

    // After the client is trusted, errors go to the redirect URI.
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "token"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("state", "x"),
            ],
        )
        .await;
    let p = page.redirect_params();
    // `token` is a response type Entra supports but gates per app registration, and
    // this app has not enabled it. Entra's value for that refusal is
    // `unsupported_response`, not the RFC's `unsupported_response_type`.
    assert_eq!(p["error"], "unsupported_response");
    assert_eq!(p["state"], "x");

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(page.redirect_params()["error"], "invalid_request");

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("request", "eyJ..."),
            ],
        )
        .await;
    assert_eq!(page.redirect_params()["error"], "request_not_supported");
}

#[tokio::test]
async fn response_modes() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    b.login(&page, &f.upn, &f.password).await;

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("response_mode", "fragment"),
                ("state", "f"),
            ],
        )
        .await;
    let loc = page.location.clone().unwrap();
    assert!(loc.contains("#code="), "{loc}");
    assert_eq!(page.redirect_params()["state"], "f");

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("response_mode", "form_post"),
                ("state", "p"),
            ],
        )
        .await;
    assert_eq!(page.status, 200);
    assert_eq!(page.form_action(), REDIRECT);
    assert!(page.field("code").is_some());
    assert_eq!(page.field("state").as_deref(), Some("p"));
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("form-action https://app.example.com"), "{csp}");
}

#[tokio::test]
async fn wrong_password_and_lockout() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    let mut current = b.login(&page, &f.upn, "wrong").await;
    assert_eq!(current.status, 401);
    assert!(current.body.contains("AADSTS50126"));
    for _ in 0..9 {
        current = b.login(&current, &f.upn, "wrong").await;
    }
    let locked = b.login(&current, &f.upn, &f.password).await;
    assert_eq!(locked.status, 401);
    assert!(
        locked.body.contains("AADSTS50053"),
        "correct password is refused while locked"
    );

    // Unknown users get the same message as wrong passwords.
    let unknown = b.login(&locked, "nobody@contoso.com", "whatever").await;
    assert!(unknown.body.contains("AADSTS50126"));
}

#[tokio::test]
async fn login_post_requires_csrf_cookie() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    // A different browser (no CSRF cookie) replays the form.
    let attacker = Browser::new();
    let resp = attacker
        .post_form(
            &page.form_action(),
            &[
                ("csrf", &page.field("csrf").unwrap()),
                ("request", &page.field("request").unwrap()),
                ("op", "login"),
                ("upn", &f.upn),
                ("password", &f.password),
            ],
        )
        .await;
    assert_ne!(resp.status, 302);
    assert!(resp.body.contains("session expired"));
}

#[tokio::test]
async fn code_is_single_use_and_replay_revokes_refresh_tokens() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid offline_access", &challenge).await;
    let (status, first) = redeem(&s, &f, &code, &verifier).await;
    assert_eq!(status, 200);
    let (status, body) = redeem(&s, &f, &code, &verifier).await;
    assert_eq!((status, aadsts(&body)), (400, 54005));

    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", first["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    assert_eq!((status, aadsts(&body)), (400, 50173));
}

#[tokio::test]
async fn pkce_and_redirect_uri_are_checked_at_the_token_endpoint() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid", &challenge).await;
    let (status, body) = redeem(&s, &f, &code, "not-the-verifier-not-the-verifier-not-the-verifier").await;
    assert_eq!((status, aadsts(&body)), (400, 501481));

    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid", &challenge).await;
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("code", &code),
                ("redirect_uri", "https://app.example.com/other"),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!((status, body["error"].as_str().unwrap()), (400, "invalid_grant"));

    // Web (confidential) clients must authenticate.
    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid", &challenge).await;
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!((status, aadsts(&body)), (401, 7000218));
}

#[tokio::test]
async fn spa_rules() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();

    // PKCE is mandatory for SPA redirect URIs.
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", SPA_REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    assert!(page.redirect_params()["error_description"].starts_with("AADSTS9002325:"));

    let (verifier, challenge) = pkce();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", SPA_REDIRECT),
                ("scope", "openid offline_access"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    let done = b.login(&page, &f.upn, &f.password).await;
    let code = done.redirect_params()["code"].clone();
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", f.web.app_id.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", SPA_REDIRECT),
        ("code_verifier", verifier.as_str()),
    ];
    let url = s.url(&format!("/{}/oauth2/v2.0/token", f.tenant.id));

    // Without Origin (server-side redemption) -> AADSTS9002327.
    let resp = s.http.post(&url).form(&form).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(aadsts(&resp.json().await.unwrap()), 9002327);

    // Cross-origin from the SPA's origin -> tokens + CORS header, no secret needed.
    let resp = s
        .http
        .post(&url)
        .header("origin", "https://spa.example.com")
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["access-control-allow-origin"], "https://spa.example.com");
    let body: Value = resp.json().await.unwrap();
    let at = decode_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(at["azpacr"], "0");

    // SPA refresh tokens keep a fixed 24h expiry across rotation.
    let (exp1,): (i64,) = sqlx::query_as("SELECT expires_at FROM refresh_tokens")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let resp = s
        .http
        .post(&url)
        .header("origin", "https://spa.example.com")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", f.web.app_id.as_str()),
            ("refresh_token", body["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (exp2,): (i64,) = sqlx::query_as("SELECT expires_at FROM refresh_tokens WHERE used_at IS NULL")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(exp1, exp2);
}

#[tokio::test]
async fn refresh_rotation_reuse_detection_and_resource_switch() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid profile offline_access", &challenge).await;
    let (_, body) = redeem(&s, &f, &code, &verifier).await;
    let rt1 = body["refresh_token"].as_str().unwrap().to_string();

    let refresh = |rt: String, scope: Option<String>| {
        let s = &s;
        let f = &f;
        async move {
            let mut form = vec![
                ("grant_type", "refresh_token".to_string()),
                ("client_id", f.web.app_id.clone()),
                ("client_secret", f.web.secret.clone()),
                ("refresh_token", rt),
            ];
            if let Some(scope) = scope {
                form.push(("scope", scope));
            }
            let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            s.token(&f.tenant.id, &form).await
        }
    };

    // Same refresh token, a different resource (Entra's multi-resource refresh tokens).
    let (status, body) = refresh(
        rt1.clone(),
        Some(format!("api://{}/Orders.Read offline_access", f.api.app_id)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let at = decode_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], f.api.app_id.as_str());
    let rt2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rt1, rt2);

    // Replaying rt1 revokes the family, including rt2.
    let (status, body) = refresh(rt1, None).await;
    assert_eq!((status, aadsts(&body)), (400, 50173));
    let (status, body) = refresh(rt2, None).await;
    assert_eq!((status, aadsts(&body)), (400, 50173));
}

#[tokio::test]
async fn userinfo_accepts_graph_tokens_only() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid profile email", &challenge).await;
    let (_, body) = redeem(&s, &f, &code, &verifier).await;
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(decode_unverified(at)["aud"], GRAPH_APP_ID);
    let id_sub = decode_unverified(body["id_token"].as_str().unwrap())["sub"].clone();

    let resp = s
        .http
        .get(s.url("/oidc/userinfo"))
        .bearer_auth(at)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["sub"], id_sub, "userinfo sub must equal the ID token sub");
    assert_eq!(info["name"], "Alice Smith");
    assert_eq!(info["email"], "alice.smith@example.org");

    // Token in a POST body works too (RFC 6750 §2.2).
    let resp = s
        .http
        .post(s.url("/oidc/userinfo"))
        .form(&[("access_token", at)])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // An API token is rejected.
    let (verifier, challenge) = pkce();
    let code = sign_in(
        &s,
        &b,
        &f,
        &format!("openid api://{}/Orders.Read", f.api.app_id),
        &challenge,
    )
    .await;
    let (_, body) = redeem(&s, &f, &code, &verifier).await;
    let resp = s
        .http
        .get(s.url("/oidc/userinfo"))
        .bearer_auth(body["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );

    let resp = s
        .http
        .get(s.url("/oidc/userinfo"))
        .bearer_auth("garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn scope_rules() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let authorize = |scope: String| {
        let b = &b;
        let s = &s;
        let f = &f;
        async move {
            b.authorize(
                s,
                &f.tenant.id,
                &[
                    ("client_id", &f.web.app_id),
                    ("response_type", "code"),
                    ("redirect_uri", REDIRECT),
                    ("scope", &scope),
                ],
            )
            .await
        }
    };
    let other = s.app(&f.tenant, "other-api").await;
    let page = authorize(format!(
        "openid api://{}/Orders.Read api://{}/.default",
        f.api.app_id, other.app_id
    ))
    .await;
    assert!(page.redirect_params()["error_description"].starts_with("AADSTS28000:"));

    let page = authorize(format!("openid api://{}/Nope", f.api.app_id)).await;
    assert_eq!(page.redirect_params()["error"], "invalid_scope");

    let page = authorize("openid api://unknown-api/x".to_string()).await;
    assert!(page.redirect_params()["error_description"].starts_with("AADSTS500011:"));
}

#[tokio::test]
async fn groups_wids_and_assignment_required() {
    use rust_oidc::{apps, directory, groups};
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    groups::create(&s.pool, &f.tenant, "engineering", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "engineering", &f.upn)
        .await
        .unwrap();
    rust_oidc::admin::bindings::create(
        &s.pool,
        rust_oidc::admin::bindings::PrincipalType::User,
        &f.user_id,
        rust_oidc::rbac::RoleId::TenantAdministrator,
        &rust_oidc::rbac::Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();

    let sp = apps::service_principal(&s.pool, &f.tenant.id, &f.web.app_id)
        .await
        .unwrap()
        .unwrap();
    apps::set_assignment_required(&s.pool, &sp.id, true).await.unwrap();

    let b = Browser::new();
    let params = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
    ];
    let page = b.authorize(&s, &f.tenant.id, &params).await;
    let blocked = b.login(&page, &f.upn, &f.password).await;
    assert_eq!(blocked.status, 400);
    assert!(blocked.body.contains("AADSTS50105"));

    // Assign a web-app role to the group; group members may now sign in.
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::add_role(&s.pool, &web, "Reader", "Reader", None, &[apps::MemberType::User])
        .await
        .unwrap();
    apps::assign_role(
        &s.pool,
        &f.tenant,
        &web,
        "Reader",
        &apps::Principal::Group("engineering".into()),
    )
    .await
    .unwrap();
    let page = b.authorize(&s, &f.tenant.id, &params).await;
    assert_eq!(page.status, 302, "session exists, assignment now satisfied");
    let code = page.redirect_params()["code"].clone();
    let (_, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ],
        )
        .await;
    let id = decode_unverified(body["id_token"].as_str().unwrap());
    assert_eq!(id["groups"], serde_json::json!(["engineering"]));
    assert_eq!(id["roles"], serde_json::json!(["Reader"]), "client app roles via group");
    assert_eq!(id["wids"], serde_json::json!([directory::GLOBAL_ADMINISTRATOR]));
}

#[tokio::test]
async fn logout() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let params = [
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("prompt", "none"),
    ];
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
            ],
        )
        .await;
    b.login(&page, &f.upn, &f.password).await;
    assert!(
        b.authorize(&s, &f.tenant.id, &params)
            .await
            .redirect_params()
            .contains_key("code")
    );

    // Registered post_logout_redirect_uri -> redirect with state.
    let mut url = url::Url::parse(&s.url(&format!("/{}/oauth2/v2.0/logout", f.tenant.id))).unwrap();
    url.query_pairs_mut()
        .append_pair("post_logout_redirect_uri", REDIRECT)
        .append_pair("client_id", &f.web.app_id)
        .append_pair("state", "bye");
    let page = b.get(url.as_str()).await;
    assert_eq!(page.status, 302);
    assert_eq!(page.redirect_params()["state"], "bye");

    // The session is gone.
    assert_eq!(
        b.authorize(&s, &f.tenant.id, &params).await.redirect_params()["error"],
        "login_required"
    );

    // Unregistered target -> signed-out page, no redirect.
    let mut url = url::Url::parse(&s.url(&format!("/{}/oauth2/v2.0/logout", f.tenant.id))).unwrap();
    url.query_pairs_mut()
        .append_pair("post_logout_redirect_uri", "https://evil.example/")
        .append_pair("client_id", &f.web.app_id);
    let page = b.get(url.as_str()).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("signed out"));
}

#[tokio::test]
async fn password_reset_revokes_refresh_tokens_and_sessions() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = sign_in(&s, &b, &f, "openid offline_access", &challenge).await;
    let (_, body) = redeem(&s, &f, &code, &verifier).await;

    rust_oidc::users::set_password(&s.pool, &f.tenant, &f.upn, "New-Password-77")
        .await
        .unwrap();

    let (status, err) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", body["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    assert_eq!((status, aadsts(&err)), (400, 50173));
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("prompt", "none"),
            ],
        )
        .await;
    assert_eq!(page.redirect_params()["error"], "login_required");
}
