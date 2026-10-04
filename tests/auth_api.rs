//! The Auth API: an application granted Credentials.Verify checks the password
//! and authenticator code of users assigned to it, and nothing else.

mod common;

use common::*;
use rust_oidc::apps::{self, MemberType, Principal};
use rust_oidc::auth_api::{AUTH_API_APP_ID, AuthApiPermission};
use rust_oidc::db::Event;
use rust_oidc::txn::ops::apps::{AssignApp, GrantAuthApiPermission, RevokeAuthApiPermission};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use rust_oidc::util::now;
use rust_oidc::{groups, mfa, users};
use serde_json::{Value, json};

/// The one answer to every failed check, byte for byte.
const FAILED: &str =
    r#"{"code":"invalid_credentials","msg":"The user name, password or code is not valid.","result":false}"#;

/// A tenant with alice, the web app as the calling application (granted
/// Credentials.Verify, alice assigned with the role Host.Admin and through the
/// group linux-admins), and alice's authenticator.
struct World {
    s: TestServer,
    f: UserFixture,
    secret: String,
}

impl World {
    fn tid(&self) -> String {
        self.f.tenant.id.clone()
    }

    /// A code not used yet: the next step's. Setting up the authenticator spent
    /// the current one, and a step once accepted cannot be used again, so each
    /// test can succeed once.
    fn code(&self) -> String {
        mfa::code_for(&self.secret, now() + mfa::STEP_SECS)
    }

    async fn token(&self) -> String {
        let (status, body) = self
            .s
            .client_credentials(&self.f.tenant.id, &self.f.web, &format!("{AUTH_API_APP_ID}/.default"))
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_string()
    }

    async fn call(&self, token: Option<&str>, body: Value) -> (u16, String) {
        let mut req = self
            .s
            .http
            .post(self.s.url(&format!("/{}/api/v1/authenticate", self.f.tenant.id)))
            .json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }

    async fn check(&self, token: &str, upn: &str, password: &str, otp: &str) -> (u16, String) {
        self.call(Some(token), json!({ "upn": upn, "password": password, "otp": otp }))
            .await
    }

    /// Another account in the same tenant, assigned and enrolled like alice
    /// unless the caller undoes one of those.
    async fn second_user(&self, upn: &str) -> (String, String) {
        let id = users::create(
            &self.s.pool,
            &self.f.tenant,
            users::NewUser {
                upn,
                password: &self.f.password,
                display_name: None,
                given_name: None,
                family_name: None,
                email: None,
            },
        )
        .await
        .unwrap();
        let secret = mfa::new_secret();
        mfa::enroll(&self.s.pool, &id, &secret).await.unwrap();
        assign(&self.s, &self.f, Principal::User(upn.into()), &[]).await;
        (id, secret)
    }
}

async fn assign(s: &TestServer, f: &UserFixture, principal: Principal, roles: &[&str]) {
    let t = AssignApp {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        principal,
        roles: roles.iter().map(|r| r.to_string()).collect(),
    };
    txn::run(&s.pool, &Actor::Cli, &t).await.into_result().unwrap();
}

async fn grant(s: &TestServer, f: &UserFixture) {
    let t = GrantAuthApiPermission {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    txn::run(&s.pool, &Actor::Cli, &t).await.into_result().unwrap();
}

async fn world() -> World {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::add_role(
        &s.pool,
        &web,
        "Host.Admin",
        "Host administrator",
        None,
        &[MemberType::User],
    )
    .await
    .unwrap();
    assign(&s, &f, Principal::User(f.upn.clone()), &["Host.Admin"]).await;
    groups::create(&s.pool, &f.tenant, "linux-admins", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "linux-admins", &f.upn)
        .await
        .unwrap();
    grant(&s, &f).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    World { s, f, secret }
}

async fn audit_reasons(s: &TestServer) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(Event::SignInFailed.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(d,)| {
            serde_json::from_str::<Value>(&d).unwrap()["reason"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn a_right_password_and_code_return_the_profile_groups_and_roles() {
    let w = world().await;
    let token = w.token().await;
    let (status, body) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert_eq!(status, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["result"], true, "{body}");
    assert_eq!(v["oid"], w.f.user_id.as_str());
    assert_eq!(v["tid"], w.tid().as_str());
    assert_eq!(v["preferred_username"], w.f.upn.as_str());
    assert_eq!(v["name"], "Alice Smith");
    assert_eq!(v["given_name"], "Alice");
    assert_eq!(v["family_name"], "Smith");
    assert_eq!(v["email"], "alice.smith@example.org");
    assert_eq!(v["groups"][0]["name"], "linux-admins");
    assert!(v["groups"][0]["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(v["app_roles"][0]["value"], "Host.Admin");
    assert!(v["app_roles"][0]["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(v["amr"], json!(["pwd", "mfa"]));
    assert_eq!(v["acr"], "2");

    // Recorded as a sign-in through the Auth API, by the calling application.
    let rows = audit_rows(&w.s, Event::SignIn.as_str()).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.as_deref(), Some(w.f.user_id.as_str()));
}

#[tokio::test]
async fn a_code_works_once() {
    let w = world().await;
    let token = w.token().await;
    let code = w.code();
    let (_, first) = w.check(&token, &w.f.upn, &w.f.password, &code).await;
    assert!(first.contains(r#""result":true"#), "{first}");
    let (_, again) = w.check(&token, &w.f.upn, &w.f.password, &code).await;
    assert_eq!(again, FAILED, "a code seen once is spent");
}

/// Every failure about the user is the same answer, byte for byte: a wrong
/// password, a wrong code, a recovery code, an unknown name, a disabled
/// account, one not assigned to the caller, one without an authenticator, one
/// that must change its password. The reason is in the audit log only.
#[tokio::test]
async fn every_failure_about_the_user_is_the_same_answer() {
    let w = world().await;
    let token = w.token().await;
    let upn = w.f.upn.clone();
    let pw = w.f.password.clone();

    // Not assigned.
    let (_, _) = w.second_user("bea@contoso.com").await;
    let bea = users::find_by_upn(&w.s.pool, &w.tid(), "bea@contoso.com")
        .await
        .unwrap()
        .unwrap();
    let assignment = apps::assignments(
        &w.s.pool,
        &w.tid(),
        &apps::find(&w.s.pool, &w.f.web.app_id).await.unwrap().unwrap(),
    )
    .await
    .unwrap()
    .into_iter()
    .find(|a| a.principal_id == bea.id)
    .unwrap();
    let unassign = rust_oidc::txn::ops::apps::UnassignApp {
        tenant_id: w.tid(),
        app_id: w.f.web.app_id.clone(),
        assignment_id: assignment.id,
    };
    txn::run(&w.s.pool, &Actor::Cli, &unassign).await.into_result().unwrap();
    // No authenticator.
    let (cal, _) = w.second_user("cal@contoso.com").await;
    mfa::reset(&w.s.pool, &w.tid(), &cal).await.unwrap();
    // Disabled.
    let (dee, dee_secret) = w.second_user("dee@contoso.com").await;
    users::set_enabled(&w.s.pool, &w.tid(), &dee, false).await.unwrap();
    // Must change their password.
    let (eve, eve_secret) = w.second_user("eve@contoso.com").await;
    users::set_must_change_password(&w.s.pool, &eve, true).await.unwrap();
    let recovery = mfa::replace_recovery_codes(&w.s.pool, &w.f.user_id).await.unwrap();

    let cases: Vec<(&str, String, String, String)> = vec![
        ("wrong password", upn.clone(), "Wrong-Horse-9".into(), w.code()),
        ("wrong code", upn.clone(), pw.clone(), "000000".into()),
        ("recovery code", upn.clone(), pw.clone(), recovery[0].clone()),
        ("unknown user", "nobody@contoso.com".into(), pw.clone(), w.code()),
        ("not assigned", "bea@contoso.com".into(), pw.clone(), w.code()),
        (
            "no authenticator",
            "cal@contoso.com".into(),
            pw.clone(),
            "123456".into(),
        ),
        (
            "disabled",
            "dee@contoso.com".into(),
            pw.clone(),
            mfa::code_for(&dee_secret, now() + mfa::STEP_SECS),
        ),
        (
            "must change password",
            "eve@contoso.com".into(),
            pw.clone(),
            mfa::code_for(&eve_secret, now() + mfa::STEP_SECS),
        ),
    ];
    for (case, upn, password, otp) in &cases {
        let (status, body) = w.check(&token, upn, password, otp).await;
        assert_eq!(status, 200, "{case}");
        assert_eq!(body, FAILED, "{case}");
    }
    // The reasons are all there, in the audit log.
    let reasons = audit_reasons(&w.s).await;
    for reason in [
        "bad_password",
        "bad_code",
        "unknown_user",
        "not_assigned",
        "no_authenticator",
        "disabled",
        "must_change_password",
    ] {
        assert!(reasons.iter().any(|r| r == reason), "{reason} in {reasons:?}");
    }
    // And alice still checks fine afterwards.
    let (_, body) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert!(
        body.contains(r#""result":true"#),
        "{body} {:?}",
        audit_reasons(&w.s).await
    );
}

/// An application that is not assigned a user cannot even move that user's
/// lockout counter: the assignment is checked before the password.
#[tokio::test]
async fn an_unassigned_user_is_refused_before_the_password_is_weighed() {
    let w = world().await;
    let token = w.token().await;
    let (bea, _) = w.second_user("bea@contoso.com").await;
    let assignment = apps::assignments(
        &w.s.pool,
        &w.tid(),
        &apps::find(&w.s.pool, &w.f.web.app_id).await.unwrap().unwrap(),
    )
    .await
    .unwrap()
    .into_iter()
    .find(|a| a.principal_id == bea)
    .unwrap();
    let unassign = rust_oidc::txn::ops::apps::UnassignApp {
        tenant_id: w.tid(),
        app_id: w.f.web.app_id.clone(),
        assignment_id: assignment.id,
    };
    txn::run(&w.s.pool, &Actor::Cli, &unassign).await.into_result().unwrap();
    for _ in 0..5 {
        let (_, body) = w.check(&token, "bea@contoso.com", "Wrong-Horse-9", "000000").await;
        assert_eq!(body, FAILED);
    }
    let (failed,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &w.s.pool,
        "SELECT failed_logins FROM users WHERE id = ?",
    ))
    .bind(&bea)
    .fetch_one(&w.s.pool)
    .await
    .unwrap();
    assert_eq!(
        failed, 0,
        "no password was checked for an account the caller may not ask about"
    );
}

/// Without the grant, the application's Auth API token carries no permission
/// and the API refuses it.
#[tokio::test]
async fn an_application_without_the_grant_cannot_check() {
    let w = world().await;
    let revoke = RevokeAuthApiPermission {
        tenant_id: w.tid(),
        app_id: w.f.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    txn::run(&w.s.pool, &Actor::Cli, &revoke).await.into_result().unwrap();
    let token = w.token().await;
    let claims = decode_unverified(&token);
    assert_eq!(claims["aud"], AUTH_API_APP_ID);
    assert!(claims.get("roles").is_none(), "{claims}");
    let (status, body) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("insufficient_scope"), "{body}");
}

/// Revoking the grant stops an application at once, though its token still
/// says otherwise until it expires.
#[tokio::test]
async fn a_revoked_grant_stops_at_once() {
    let w = world().await;
    let token = w.token().await;
    assert!(
        decode_unverified(&token)["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "Credentials.Verify")
    );
    let revoke = RevokeAuthApiPermission {
        tenant_id: w.tid(),
        app_id: w.f.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    txn::run(&w.s.pool, &Actor::Cli, &revoke).await.into_result().unwrap();
    let (status, _) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert_eq!(status, 403);
}

/// Only an Auth API token of this tenant, issued to an application, will do.
#[tokio::test]
async fn other_tokens_are_refused() {
    let w = world().await;
    // None at all.
    let (status, _) = w
        .call(
            None,
            json!({ "upn": w.f.upn, "password": w.f.password, "otp": w.code() }),
        )
        .await;
    assert_eq!(status, 401);
    // A token for another API.
    let (_, other) =
        w.s.client_credentials(&w.tid(), &w.f.web, &format!("{}/.default", w.f.api.app_id))
            .await;
    let (status, body) = w
        .check(
            other["access_token"].as_str().unwrap(),
            &w.f.upn,
            &w.f.password,
            &w.code(),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    // Not a token.
    let (status, _) = w.check("not-a-token", &w.f.upn, &w.f.password, &w.code()).await;
    assert_eq!(status, 401);
    // A good token sent to another tenant's endpoint.
    let other_tenant = w.s.tenant("Fabrikam", "fabrikam.com").await;
    let token = w.token().await;
    let resp =
        w.s.http
            .post(w.s.url(&format!("/{}/api/v1/authenticate", other_tenant.id)))
            .bearer_auth(&token)
            .json(&json!({ "upn": w.f.upn, "password": w.f.password, "otp": w.code() }))
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    // A malformed body is the caller's error, not a credential failure.
    let (status, body) = w.call(Some(&token), json!({ "upn": w.f.upn })).await;
    assert_eq!(status, 400, "{body}");
}

/// Ten checks a minute per account; past that the answer stays the generic
/// failure (a 429 would say the account exists), and even the right password
/// and code are refused until the window passes.
#[tokio::test]
async fn checks_of_one_account_are_limited_without_saying_so() {
    let w = world().await;
    let token = w.token().await;
    for _ in 0..10 {
        let (_, body) = w.check(&token, &w.f.upn, &w.f.password, "000000").await;
        assert_eq!(body, FAILED);
    }
    let (status, body) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert_eq!((status, body.as_str()), (200, FAILED));
    assert!(audit_reasons(&w.s).await.iter().any(|r| r == "throttled"));
}

// ---- the grant itself ----

#[tokio::test]
async fn granting_and_revoking_are_audited_transactions() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = Actor::Admin {
        user_id: f.user_id.clone(),
        bindings: rust_oidc::admin::bindings::effective_for_user(&s.pool, &f.user_id)
            .await
            .unwrap(),
    };
    let grant = GrantAuthApiPermission {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    txn::run(&s.pool, &actor, &grant).await.into_result().unwrap();
    // Again: completes, changes nothing.
    txn::run(&s.pool, &actor, &grant).await.into_result().unwrap();
    assert_eq!(audit_rows(&s, Event::AdminAuthApiGrant.as_str()).await.len(), 2);

    let revoke = RevokeAuthApiPermission {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    txn::run(&s.pool, &actor, &revoke).await.into_result().unwrap();
    // Not held any more: refused, nothing recorded.
    assert!(matches!(
        txn::run(&s.pool, &actor, &revoke).await,
        Outcome::Refused(Refusal::NotFound(_))
    ));
    assert_eq!(audit_rows(&s, Event::AdminAuthApiRevoke.as_str()).await.len(), 1);

    // A reader cannot grant.
    let s = TestServer::start().await;
    let reader = reader_fixture(&s).await;
    let reader_actor = Actor::Admin {
        user_id: reader.user_id.clone(),
        bindings: rust_oidc::admin::bindings::effective_for_user(&s.pool, &reader.user_id)
            .await
            .unwrap(),
    };
    let grant = GrantAuthApiPermission {
        tenant_id: reader.tenant.id.clone(),
        app_id: reader.web.app_id.clone(),
        permission: AuthApiPermission::CredentialsVerify,
    };
    assert_eq!(
        txn::run(&s.pool, &reader_actor, &grant).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
}

/// The console's API permissions page grants and revokes it.
#[tokio::test]
async fn the_console_grants_it_on_the_api_permissions_page() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!(
        "/admin/tenants/{}/apps/{}/api-permissions",
        f.tenant.id, f.web.app_id
    ));
    let page = b.get(&url).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("Credentials.Verify") && page.body.contains("Not granted"),
        "{}",
        page.body
    );

    let post = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let done = b
        .post(&post, &[("op", "auth_api_grant"), ("permission", "Credentials.Verify")])
        .await;
    assert_eq!(done.status, 303, "{}", done.body);
    let sp = apps::service_principal(&s.pool, &f.tenant.id, &f.web.app_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        rust_oidc::auth_api::holds(&s.pool, &sp.id, AuthApiPermission::CredentialsVerify)
            .await
            .unwrap()
    );
    assert!(b.get(&url).await.body.contains("Granted"));
}

/// The readable name works like the id, and the token's audience is the id
/// either way, as a Graph token's is whichever name was asked for.
#[tokio::test]
async fn the_api_can_be_named_api_auth_api() {
    let w = world().await;
    let (status, body) =
        w.s.client_credentials(&w.tid(), &w.f.web, "api://auth-api/.default")
            .await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let claims = decode_unverified(&token);
    assert_eq!(claims["aud"], AUTH_API_APP_ID);
    assert!(
        claims["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "Credentials.Verify")
    );
    let (_, answer) = w.check(&token, &w.f.upn, &w.f.password, &w.code()).await;
    assert!(answer.contains(r#""result":true"#), "{answer}");
}

/// No application can take the Auth API's name.
#[tokio::test]
async fn no_application_may_register_the_auth_api_name() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    for uri in ["api://auth-api", "API://Auth-API/"] {
        let add = rust_oidc::txn::ops::apps::AddIdentifierUri {
            tenant_id: f.tenant.id.clone(),
            app_id: f.api.app_id.clone(),
            uri: uri.into(),
        };
        match txn::run(&s.pool, &Actor::Cli, &add).await {
            Outcome::Refused(Refusal::Invalid(m)) => assert!(m.contains("reserved"), "{m}"),
            other => panic!("{uri}: {:?}", other.map_done()),
        }
    }
}
