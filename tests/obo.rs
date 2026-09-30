//! On-behalf-of flow (RFC 7523 jwt-bearer), in Entra's shape: a middle-tier API
//! exchanges the user token it received for a token to a downstream API.

mod common;

use common::*;
use rust_oidc::apps::{self, Principal};
use serde_json::Value;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ON_BEHALF_OF: &str = "on_behalf_of";

struct Chain {
    f: UserFixture,
    /// The downstream API the middle tier calls.
    downstream: TestApp,
    downstream_scope: String,
    /// A user access token whose audience is the middle-tier API (`f.api`).
    user_token: String,
}

/// Sign the user in to the middle-tier API, then set up a downstream API.
async fn chain(s: &TestServer) -> Chain {
    let f = user_fixture(s).await;
    let downstream = s.app(&f.tenant, "reports-api").await;
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &downstream.app_id)
        .await
        .unwrap();
    apps::add_scope(&s.pool, &app, "Reports.Read", "Read reports", "User")
        .await
        .unwrap();
    // A role on the downstream API, to prove roles are resolved for the user.
    apps::add_role(&s.pool, &app, "Reports.Admin", "Admin", None, &[apps::MEMBER_USER])
        .await
        .unwrap();
    apps::assign_role(
        &s.pool,
        &f.tenant,
        &app,
        "Reports.Admin",
        &Principal::User(f.upn.clone()),
    )
    .await
    .unwrap();

    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let scope = format!("openid offline_access api://{}/Orders.Read", f.api.app_id);
    let page = b
        .authorize(
            s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", &scope),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    let done = if page.status == 302 {
        page
    } else {
        b.login(&page, &f.upn, &f.password).await
    };
    let code = done.redirect_params()["code"].clone();
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(status, 200, "front-end sign-in: {body}");
    let user_token = body["access_token"].as_str().unwrap().to_string();
    let downstream_scope = format!("api://{}/Reports.Read", downstream.app_id);
    Chain {
        f,
        downstream,
        downstream_scope,
        user_token,
    }
}

async fn obo(s: &TestServer, c: &Chain, form_extra: &[(&str, &str)]) -> (u16, Value) {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", GRANT),
        ("client_id", &c.f.api.app_id),
        ("client_secret", &c.f.api.secret),
        ("assertion", &c.user_token),
        ("requested_token_use", ON_BEHALF_OF),
        ("scope", &c.downstream_scope),
    ];
    for (k, v) in form_extra {
        // Replace the default when the key already exists, else append.
        match form.iter_mut().find(|(key, _)| key == k) {
            Some(entry) => entry.1 = v,
            None => form.push((k, v)),
        }
    }
    s.token(&c.f.tenant.id, &form).await
}

#[tokio::test]
async fn middle_tier_exchanges_a_user_token_for_a_downstream_token() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    let (status, body) = obo(&s, &c, &[]).await;
    assert_eq!(status, 200, "{body}");

    let claims = s
        .verify(
            &c.f.tenant.id,
            body["access_token"].as_str().unwrap(),
            &c.downstream.app_id,
        )
        .await;
    // Same user, but now for the downstream API and on behalf of the middle tier.
    assert_eq!(claims["oid"], c.f.user_id);
    assert_eq!(claims["idtyp"], "user");
    assert_eq!(claims["azp"], c.f.api.app_id, "the middle tier is the calling app");
    assert_eq!(claims["scp"], "Reports.Read");
    assert_eq!(claims["roles"][0], "Reports.Admin");
    assert_eq!(claims["preferred_username"], c.f.upn);
}

#[tokio::test]
async fn obo_preserves_how_the_user_authenticated() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    // The original sign-in was a password, and auth_time must carry across.
    let original = s.verify(&c.f.tenant.id, &c.user_token, &c.f.api.app_id).await;
    let (status, body) = obo(&s, &c, &[]).await;
    assert_eq!(status, 200, "{body}");
    let claims = s
        .verify(
            &c.f.tenant.id,
            body["access_token"].as_str().unwrap(),
            &c.downstream.app_id,
        )
        .await;
    assert_eq!(claims["amr"], original["amr"]);
    assert_eq!(claims["auth_time"], original["auth_time"]);
}

#[tokio::test]
async fn obo_returns_a_refresh_token_only_with_offline_access() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    let (_, body) = obo(&s, &c, &[]).await;
    assert!(body["refresh_token"].is_null(), "not requested: {body}");

    let scope = format!("{} offline_access", c.downstream_scope);
    let (status, body) = obo(&s, &c, &[("scope", &scope)]).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["refresh_token"].is_string(), "offline_access requested: {body}");
}

#[tokio::test]
async fn a_token_for_another_audience_cannot_be_exchanged() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    // The middle tier presents a token that was issued for the downstream API,
    // not for itself; it must not be able to exchange it.
    let (_, body) = obo(&s, &c, &[]).await;
    let downstream_token = body["access_token"].as_str().unwrap().to_string();
    let (status, err) = obo(&s, &c, &[("assertion", &downstream_token)]).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn an_app_only_token_cannot_be_exchanged() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    // client_credentials gives an app-only token; OBO is for user tokens only.
    s.add_role(&c.f.tenant, &c.f.api, "Orders.Sync", &["Application"]).await;
    s.assign_to_app(&c.f.tenant, &c.f.api, "Orders.Sync", &c.f.web).await;
    let (status, app_token) = s
        .client_credentials(&c.f.tenant.id, &c.f.web, &format!("api://{}/.default", c.f.api.app_id))
        .await;
    assert_eq!(status, 200, "{app_token}");
    let assertion = app_token["access_token"].as_str().unwrap().to_string();
    let (status, err) = obo(&s, &c, &[("assertion", &assertion)]).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn obo_requires_client_authentication() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    let (status, err) = obo(&s, &c, &[("client_secret", "not-the-secret")]).await;
    assert_eq!(status, 401, "{err}");
    assert_eq!(err["error"], "invalid_client");
}

#[tokio::test]
async fn a_garbage_assertion_is_rejected() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    let (status, err) = obo(&s, &c, &[("assertion", "not.a.jwt")]).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn obo_requires_requested_token_use_on_behalf_of() {
    let s = TestServer::start().await;
    let c = chain(&s).await;
    let (status, err) = obo(&s, &c, &[("requested_token_use", "something_else")]).await;
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["error"], "invalid_request");
}
