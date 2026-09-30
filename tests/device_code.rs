//! Device authorization grant (RFC 8628), in Entra's shape.

mod common;

use common::*;
use serde_json::Value;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

async fn request_device_code(s: &TestServer, tenant: &str, client_id: &str, scope: &str) -> (u16, Value) {
    let resp = s
        .http
        .post(s.url(&format!("/{tenant}/oauth2/v2.0/devicecode")))
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

async fn poll(s: &TestServer, tenant: &str, client_id: &str, device_code: &str) -> (u16, Value) {
    s.token(
        tenant,
        &[
            ("grant_type", GRANT),
            ("client_id", client_id),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Approve a pending device code in the browser: enter the code, sign in, consent.
async fn approve(s: &TestServer, b: &Browser, f: &UserFixture, user_code: &str) -> Page {
    let entry = b
        .get(&s.url(&format!("/{}/oauth2/deviceauth?user_code={user_code}", f.tenant.id)))
        .await;
    // Not signed in yet, so the code entry leads to the sign-in page.
    let signed_in = b.login(&entry, &f.upn, &f.password).await;
    // Then the approval page, which names the client.
    assert!(
        signed_in.body.contains(&f.web.app_id) || signed_in.field("csrf").is_some(),
        "expected an approval page, got: {}",
        &signed_in.body[..signed_in.body.len().min(400)]
    );
    let form = [
        ("csrf", signed_in.field("csrf").expect("csrf on approval page")),
        ("request", signed_in.field("request").expect("request on approval page")),
        ("op", "approve".to_string()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post_form(&signed_in.form_action(), &form).await
}

#[tokio::test]
async fn device_code_happy_path() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let tid = f.tenant.id.clone();

    let (status, body) = request_device_code(&s, &tid, &f.web.app_id, "openid profile offline_access").await;
    assert_eq!(status, 200, "devicecode: {body}");
    let device_code = body["device_code"].as_str().expect("device_code").to_string();
    let user_code = body["user_code"].as_str().expect("user_code").to_string();
    assert!(
        body["verification_uri"].as_str().unwrap().contains("deviceauth"),
        "verification_uri: {body}"
    );
    assert!(body["expires_in"].as_u64().unwrap() > 0);
    assert!(body["interval"].as_u64().unwrap() >= 1);
    assert!(body["message"].as_str().unwrap().contains(&user_code));

    // Polling before the user approves.
    let (status, err) = poll(&s, &tid, &f.web.app_id, &device_code).await;
    assert_eq!(status, 400, "pending poll: {err}");
    assert_eq!(err["error"], "authorization_pending");
    assert_eq!(aadsts(&err), 70016);

    // The user approves in a browser.
    let b = Browser::new();
    let done = approve(&s, &b, &f, &user_code).await;
    assert_eq!(done.status, 200, "approval page: {}", done.body);

    // Now the device gets its tokens.
    let (status, tokens) = poll(&s, &tid, &f.web.app_id, &device_code).await;
    assert_eq!(status, 200, "redeem: {tokens}");
    let access = tokens["access_token"].as_str().expect("access_token");
    let claims = s.verify(&tid, access, rust_oidc::scopes::GRAPH_APP_ID).await;
    assert_eq!(claims["oid"], f.user_id);
    assert_eq!(claims["idtyp"], "user");
    assert!(tokens["id_token"].is_string(), "openid was requested");
    assert!(tokens["refresh_token"].is_string(), "offline_access was requested");

    // A device code is single use.
    let (status, err) = poll(&s, &tid, &f.web.app_id, &device_code).await;
    assert_eq!(status, 400, "replay: {err}");
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn unknown_device_code_is_invalid_grant() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (status, err) = poll(&s, &f.tenant.id, &f.web.app_id, "not-a-real-device-code").await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn device_code_rejects_unknown_client() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (status, err) = request_device_code(&s, &f.tenant.id, "00000000-0000-0000-0000-000000000000", "openid").await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "unauthorized_client");
}

#[tokio::test]
async fn declined_device_code_reports_authorization_declined() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let tid = f.tenant.id.clone();
    let (_, body) = request_device_code(&s, &tid, &f.web.app_id, "openid").await;
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let user_code = body["user_code"].as_str().unwrap().to_string();

    let b = Browser::new();
    let entry = b
        .get(&s.url(&format!("/{tid}/oauth2/deviceauth?user_code={user_code}")))
        .await;
    let signed_in = b.login(&entry, &f.upn, &f.password).await;
    let form = [
        ("csrf", signed_in.field("csrf").unwrap()),
        ("request", signed_in.field("request").unwrap()),
        ("op", "deny".to_string()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post_form(&signed_in.form_action(), &form).await;

    let (status, err) = poll(&s, &tid, &f.web.app_id, &device_code).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "authorization_declined");
}
