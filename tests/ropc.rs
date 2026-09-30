//! Resource owner password credentials (ROPC). Off by default: an app must be
//! opted in, because the grant hands the user's password to the client.

mod common;

use common::*;
use rust_oidc::apps;
use serde_json::Value;

async fn allow_ropc(s: &TestServer, f: &UserFixture, allowed: bool) {
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id).await.unwrap();
    apps::set_password_grant_allowed(&s.pool, &app, allowed).await.unwrap();
}

async fn ropc(s: &TestServer, f: &UserFixture, upn: &str, password: &str, scope: &str) -> (u16, Value) {
    s.token(
        &f.tenant.id,
        &[
            ("grant_type", "password"),
            ("client_id", &f.web.app_id),
            ("client_secret", &f.web.secret),
            ("username", upn),
            ("password", password),
            ("scope", scope),
        ],
    )
    .await
}

#[tokio::test]
async fn ropc_is_refused_unless_the_app_opts_in() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    // Default: not allowed.
    let (status, err) = ropc(&s, &f, &f.upn, &f.password, &scope).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "unauthorized_client");

    allow_ropc(&s, &f, true).await;
    let (status, body) = ropc(&s, &f, &f.upn, &f.password, &scope).await;
    assert_eq!(status, 200, "after opting in: {body}");
}

#[tokio::test]
async fn ropc_issues_user_tokens() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid profile api://{}/Orders.Read", f.api.app_id);
    let (status, body) = ropc(&s, &f, &f.upn, &f.password, &scope).await;
    assert_eq!(status, 200, "{body}");

    let claims = s
        .verify(&f.tenant.id, body["access_token"].as_str().unwrap(), &f.api.app_id)
        .await;
    assert_eq!(claims["oid"], f.user_id);
    assert_eq!(claims["idtyp"], "user");
    assert_eq!(claims["azp"], f.web.app_id);
    assert_eq!(claims["scp"], "Orders.Read");
    assert_eq!(claims["amr"][0], "pwd");
    // openid was requested, so an ID token comes back too.
    assert!(body["id_token"].is_string(), "{body}");
    // offline_access was not requested.
    assert!(body["refresh_token"].is_null(), "{body}");
}

#[tokio::test]
async fn ropc_returns_a_refresh_token_with_offline_access() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid offline_access api://{}/Orders.Read", f.api.app_id);
    let (status, body) = ropc(&s, &f, &f.upn, &f.password, &scope).await;
    assert_eq!(status, 200, "{body}");
    let refresh = body["refresh_token"].as_str().expect("refresh token");

    // And that refresh token works like any other.
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("refresh_token", refresh),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!(status, 200, "refresh after ropc: {body}");
}

#[tokio::test]
async fn ropc_rejects_a_wrong_password() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    let (status, err) = ropc(&s, &f, &f.upn, "not-the-password", &scope).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
    assert_eq!(aadsts(&err), 50126);
}

#[tokio::test]
async fn ropc_rejects_an_unknown_user() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    let (status, err) = ropc(&s, &f, "nobody@contoso.com", &f.password, &scope).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
    // Indistinguishable from a wrong password, so the endpoint is not a user oracle.
    assert_eq!(aadsts(&err), 50126);
}

#[tokio::test]
async fn ropc_still_requires_client_authentication() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    let (status, err) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", "wrong"),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!(status, 401, "{err}");
    assert_eq!(err["error"], "invalid_client");
}
