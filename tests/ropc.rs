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
    let (actor, details) = audit_row(&s, &f, "auth.sign_in_failed").await;
    assert_eq!(actor, f.user_id);
    assert!(details.contains("bad_password") && !details.contains("not-the-password"));
}

/// The single audit row with this action in the fixture's tenant.
async fn audit_row(s: &TestServer, f: &UserFixture, action: &str) -> (String, String) {
    let (actor, details): (String, Option<String>) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, details FROM audit_log WHERE tenant_id = ? AND action = ?",
    ))
    .bind(&f.tenant.id)
    .bind(action)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    (actor, details.unwrap_or_default())
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
    // The audit log does tell them apart. The authenticated client is the actor.
    let (actor, details) = audit_row(&s, &f, "auth.sign_in_failed").await;
    assert_eq!(actor, f.web.app_id);
    assert!(details.contains("unknown_user") && !details.contains("nobody"));
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

/// Description with the per-request Trace ID / Correlation ID / Timestamp removed.
fn stable_description(err: &Value) -> &str {
    let d = err["error_description"].as_str().unwrap();
    d.split(" Trace ID:").next().unwrap()
}

#[tokio::test]
async fn ropc_unknown_user_and_wrong_password_are_indistinguishable() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    let (s1, wrong) = ropc(&s, &f, &f.upn, "not-the-password", &scope).await;
    let (s2, unknown) = ropc(&s, &f, "nobody@contoso.com", "not-the-password", &scope).await;
    assert_eq!(s1, s2);
    assert_eq!(wrong["error"], unknown["error"]);
    assert_eq!(wrong["error_codes"], unknown["error_codes"]);
    assert_eq!(stable_description(&wrong), stable_description(&unknown));
    // Same set of keys too: no extra field on either side.
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&wrong), keys(&unknown));
}

#[tokio::test]
async fn ropc_unknown_user_audit_row_keeps_no_local_part() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, true).await;
    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    ropc(&s, &f, "CorrectHorse-Battery9!", "x", &scope).await;
    ropc(&s, &f, "nobody@contoso.com", "x", &scope).await;
    ropc(&s, &f, "x@corp.example", "x", &scope).await;
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, details FROM audit_log WHERE tenant_id = ? AND action = ? ORDER BY id",
    ))
    .bind(&f.tenant.id)
    .bind("auth.sign_in_failed")
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    let (first, second) = (rows[0].1.as_deref().unwrap(), rows[1].1.as_deref().unwrap());
    assert!(!first.contains("CorrectHorse") && !first.contains("domain"), "{first}");
    assert!(
        second.contains(r#""domain":"contoso.com""#) && !second.contains("nobody"),
        "{second}"
    );
    let third = rows[2].1.as_deref().unwrap();
    assert!(!third.contains("corp.example") && !third.contains("domain"), "{third}");
}
