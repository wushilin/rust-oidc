//! "Assignment required" must hold for every way a user can obtain a token.
//!
//! It used to be enforced only on the `/authorize` page, so an unassigned user
//! could get tokens through the password and device code grants, and a refresh
//! token kept working after its holder was unassigned. The rule is now applied
//! where every user grant ends.

mod common;

use common::*;
use rust_oidc::apps;
use serde_json::Value;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const NOT_ASSIGNED: &str = "AADSTS50105";

/// Require assignment on `app`'s service principal in the fixture tenant.
async fn require_assignment(s: &TestServer, f: &UserFixture, app: &TestApp) {
    let sp = apps::service_principal(&s.pool, &f.tenant.id, &app.app_id)
        .await
        .unwrap()
        .expect("service principal");
    apps::set_assignment_required(&s.pool, &sp.id, true).await.unwrap();
}

async fn allow_ropc(s: &TestServer, f: &UserFixture, app: &TestApp) {
    let a = apps::find_in_tenant(&s.pool, &f.tenant, &app.app_id).await.unwrap();
    apps::set_password_grant_allowed(&s.pool, &a, true).await.unwrap();
}

async fn ropc(s: &TestServer, f: &UserFixture, client: &TestApp, scope: &str) -> (u16, Value) {
    s.token(
        &f.tenant.id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("client_secret", &client.secret),
            ("username", &f.upn),
            ("password", &f.password),
            ("scope", scope),
        ],
    )
    .await
}

fn refused_as_unassigned(status: u16, body: &Value) {
    assert_eq!(status, 400, "{body}");
    assert!(body.get("access_token").is_none(), "a token was issued: {body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    let description = body["error_description"].as_str().unwrap_or_default();
    assert!(description.contains(NOT_ASSIGNED), "{description}");
}

/// The fixture's user holds no assignment on the web app.
#[tokio::test]
async fn the_password_grant_is_refused_for_an_unassigned_user() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, &f.web).await;
    require_assignment(&s, &f, &f.web).await;

    let (status, body) = ropc(&s, &f, &f.web, "openid").await;
    refused_as_unassigned(status, &body);
}

/// The control: the same grant, same rule, for a user who *is* assigned. Without
/// this the test above would also pass if the grant were simply broken.
#[tokio::test]
async fn an_assigned_user_is_still_issued_a_token() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // The fixture assigns alice the `Orders.Approver` role on the API app.
    allow_ropc(&s, &f, &f.api).await;
    require_assignment(&s, &f, &f.api).await;

    let (status, body) = ropc(&s, &f, &f.api, "openid").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["access_token"].is_string(), "{body}");
}

/// Turning the rule off again restores access, so it is the rule doing the
/// refusing and not some side effect of having touched the service principal.
#[tokio::test]
async fn without_the_requirement_an_unassigned_user_is_served() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, &f.web).await;

    let (status, body) = ropc(&s, &f, &f.web, "openid").await;
    assert_eq!(status, 200, "{body}");
}

/// Unassigning someone has to cut them off, not merely stop new sign-ins: a
/// refresh token obtained earlier must stop working.
#[tokio::test]
async fn a_refresh_token_stops_working_once_assignment_is_required() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    allow_ropc(&s, &f, &f.web).await;

    let (status, tokens) = ropc(&s, &f, &f.web, "openid offline_access").await;
    assert_eq!(status, 200, "{tokens}");
    let refresh = tokens["refresh_token"].as_str().expect("refresh token").to_string();

    require_assignment(&s, &f, &f.web).await;

    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
            ],
        )
        .await;
    refused_as_unassigned(status, &body);
}

/// The device code flow has its own sign-in page and never touched the check.
#[tokio::test]
async fn the_device_code_grant_is_refused_for_an_unassigned_user() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    require_assignment(&s, &f, &f.web).await;

    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/devicecode", f.tenant.id)))
        .form(&[("client_id", f.web.app_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap();
    let issued: Value = resp.json().await.unwrap();
    let device_code = issued["device_code"].as_str().expect("device_code").to_string();
    let user_code = issued["user_code"].as_str().expect("user_code").to_string();

    // The user signs in and approves in the browser, as they would.
    let b = Browser::new();
    let entry = b
        .get(&s.url(&format!("/{}/oauth2/deviceauth?user_code={user_code}", f.tenant.id)))
        .await;
    let signed_in = b.login(&entry, &f.upn, &f.password).await;
    if let (Some(csrf), Some(request)) = (signed_in.field("csrf"), signed_in.field("request")) {
        b.post_form(
            &signed_in.form_action(),
            &[
                ("csrf", csrf.as_str()),
                ("request", request.as_str()),
                ("op", "approve"),
            ],
        )
        .await;
    }

    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", DEVICE_GRANT),
                ("client_id", &f.web.app_id),
                ("device_code", &device_code),
            ],
        )
        .await;
    assert!(body.get("access_token").is_none(), "a token was issued: {body}");
    assert_ne!(status, 200, "{body}");
}
