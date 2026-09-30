//! The HTTP layer writes an audit trail: who signed in, which tokens were
//! issued, what was replayed. Also checks that no credential leaks into it.

mod common;

use common::{Browser, REDIRECT, TestServer, UserFixture, pkce, user_fixture};
use serde_json::Value;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// actor, action, target, details.
type RawRow = (String, Option<String>, Option<String>, Option<String>);

struct Row {
    actor: String,
    target: Option<String>,
    details: Value,
}

async fn rows(s: &TestServer, tenant_id: &str, action: &str) -> Vec<Row> {
    let raw: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, target, details FROM audit_log WHERE tenant_id = ? AND action = ? ORDER BY id",
    ))
    .bind(tenant_id)
    .bind(action)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    raw.into_iter()
        .map(|(actor, target, details)| Row {
            actor,
            target,
            details: serde_json::from_str(&details.unwrap_or_default()).unwrap_or(Value::Null),
        })
        .collect()
}

/// Every audit row of the tenant, to search for leaked secrets. Columns are
/// concatenated raw: `{:?}` would escape a quote, a backslash or a non-ASCII
/// character in the haystack but not in the needle, so a leaked value
/// containing one would sit in the table while the assertion passed.
async fn everything(s: &TestServer, tenant_id: &str) -> String {
    let all: Vec<RawRow> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, action, target, details FROM audit_log WHERE tenant_id = ? ORDER BY id",
    ))
    .bind(tenant_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    all.into_iter()
        .map(|(actor, action, target, details)| {
            format!(
                "{actor}\n{}\n{}\n{}",
                action.unwrap_or_default(),
                target.unwrap_or_default(),
                details.unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn authorize_params<'a>(f: &'a UserFixture, scope: &'a str, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", &f.web.app_id),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

/// Sign in through the browser and return the authorization code.
async fn get_code(s: &TestServer, b: &Browser, f: &UserFixture, scope: &str, challenge: &str) -> String {
    let page = b
        .authorize(s, &f.tenant.id, &authorize_params(f, scope, challenge))
        .await;
    let done = if page.status == 302 {
        page
    } else {
        b.login(&page, &f.upn, &f.password).await
    };
    assert_eq!(done.status, 302, "{}", done.body);
    done.redirect_params()["code"].clone()
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
        ],
    )
    .await
}

#[tokio::test]
async fn successful_sign_in_and_session_are_audited() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    get_code(&s, &b, &f, "openid", &challenge).await;

    let sign_ins = rows(&s, &f.tenant.id, "auth.sign_in").await;
    assert_eq!(sign_ins.len(), 1);
    assert_eq!(sign_ins[0].actor, f.user_id);
    assert_eq!(sign_ins[0].details["via"], "authorize");
    assert_eq!(sign_ins[0].details["clientId"], f.web.app_id.as_str());
    let sessions = rows(&s, &f.tenant.id, "session.create").await;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].actor, f.user_id);
}

#[tokio::test]
async fn failed_sign_ins_and_lockout_are_audited_without_the_password() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let page = b
        .authorize(&s, &f.tenant.id, &authorize_params(&f, "openid", &challenge))
        .await;

    // Wrong password for a real account, then an unknown account: the same
    // HTTP answer, but distinguishable in the audit log.
    let bad = b.login(&page, &f.upn, "hunter2-wrong").await;
    let unknown = b.login(&bad, "nobody@contoso.com", "hunter2-other").await;
    assert_eq!(bad.status, unknown.status);
    assert!(bad.body.contains("AADSTS50126") && unknown.body.contains("AADSTS50126"));

    let failed = rows(&s, &f.tenant.id, "auth.sign_in_failed").await;
    assert_eq!(failed.len(), 2);
    assert_eq!(failed[0].actor, f.user_id);
    assert_eq!(failed[0].details["reason"], "bad_password");
    assert_eq!(failed[1].actor, "anonymous");
    assert_eq!(failed[1].details["reason"], "unknown_user");
    // Unknown account: only the domain is kept, never the local part.
    assert_eq!(failed[1].details["domain"], "contoso.com");
    assert!(failed[1].details.get("upn").is_none());
    assert_eq!(
        failed[0].details["upn"],
        f.upn.as_str(),
        "a real account's UPN is safe to log"
    );
    assert!(!everything(&s, &f.tenant.id).await.contains("nobody"));

    // Push the real account over the lockout threshold, then hit the lock.
    let mut current = unknown;
    for _ in 0..9 {
        current = b.login(&current, &f.upn, "hunter2-wrong").await;
    }
    let locked = b.login(&current, &f.upn, &f.password).await;
    assert!(locked.body.contains("AADSTS50053"));

    let lockouts = rows(&s, &f.tenant.id, "auth.lockout").await;
    assert_eq!(lockouts.len(), 1);
    assert_eq!(lockouts[0].actor, f.user_id);
    let failed = rows(&s, &f.tenant.id, "auth.sign_in_failed").await;
    assert_eq!(failed.last().unwrap().details["reason"], "locked");

    let log = everything(&s, &f.tenant.id).await;
    assert!(
        !log.contains("hunter2") && !log.contains(&f.password),
        "password leaked: {log}"
    );
}

#[tokio::test]
async fn token_issuance_is_audited_and_carries_no_credentials() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = get_code(&s, &b, &f, "openid offline_access", &challenge).await;
    let (status, tokens) = redeem(&s, &f, &code, &verifier).await;
    assert_eq!(status, 200, "{tokens}");

    let issued = rows(&s, &f.tenant.id, "token.issued").await;
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].actor, f.user_id);
    assert_eq!(issued[0].target.as_deref(), Some(f.web.app_id.as_str()));
    assert_eq!(issued[0].details["grant"], "authorization_code");
    assert_eq!(issued[0].details["clientId"], f.web.app_id.as_str());
    assert_eq!(issued[0].details["refreshToken"], true);
    assert!(issued[0].details["resource"].is_string());

    // App-only grant: the client is the actor and the resource is the target.
    let scope = format!("api://{}/.default", f.api.app_id);
    let (status, _) = s.client_credentials(&f.tenant.id, &f.web, &scope).await;
    assert_eq!(status, 200);
    let issued = rows(&s, &f.tenant.id, "token.issued").await;
    assert_eq!(issued[1].actor, f.web.app_id);
    assert_eq!(issued[1].target.as_deref(), Some(f.api.app_id.as_str()));
    assert_eq!(issued[1].details["grant"], "client_credentials");

    // Nothing bearer-shaped, and no client secret, anywhere in the log.
    let log = everything(&s, &f.tenant.id).await;
    for secret in [
        code.as_str(),
        f.web.secret.as_str(),
        tokens["access_token"].as_str().unwrap(),
        tokens["refresh_token"].as_str().unwrap(),
        tokens["id_token"].as_str().unwrap(),
    ] {
        assert!(!log.contains(secret), "credential leaked into the audit log");
    }
}

#[tokio::test]
async fn bad_client_secret_is_audited() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = format!("api://{}/.default", f.api.app_id);
    let (status, _) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &f.web.app_id),
                ("client_secret", "definitely-wrong-secret"),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!(status, 401);
    let failed = rows(&s, &f.tenant.id, "token.client_auth_failed").await;
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].actor, f.web.app_id);
    assert_eq!(failed[0].details["reason"], "invalid_secret");
    assert!(!everything(&s, &f.tenant.id).await.contains("definitely-wrong-secret"));
}

/// A client that swaps its id and secret sends the secret in the `client_id`
/// field, where it does not resolve to any app. The audit row must record that
/// something unrecognised was presented without keeping the value: it is a
/// credential, and short enough to survive clipping intact.
#[tokio::test]
async fn transposed_client_credentials_do_not_leak_the_secret() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = format!("api://{}/.default", f.api.app_id);
    let secret = f.web.secret.clone();

    // The secret in the client_id slot, via the form body.
    let (status, _) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &secret),
                ("client_secret", &f.web.app_id),
                ("scope", &scope),
            ],
        )
        .await;
    // An unregistered client id is "application not found", which Entra answers
    // with 400, unlike a wrong secret (401).
    assert_eq!(status, 400);

    // And via the username half of a Basic credential, which is the other way
    // round a client library can build the pair.
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/token", f.tenant.id)))
        .basic_auth(&secret, Some(&f.web.app_id))
        .form(&[("grant_type", "client_credentials"), ("scope", &scope)])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);

    // The security property first, so a regression reports the leak itself rather
    // than tripping over a diagnostic field on the way.
    let log = everything(&s, &f.tenant.id).await;
    assert!(!log.contains(&secret), "the client secret reached the audit log: {log}");

    let failed = rows(&s, &f.tenant.id, "token.client_auth_failed").await;
    assert_eq!(failed.len(), 2);
    for row in &failed {
        assert_eq!(row.actor, rust_oidc::db::Actor::Anonymous.as_str());
        assert_eq!(row.target, None);
        assert_eq!(row.details["reason"], "unknown_client");
        // Recorded instead of the value: a secret is not GUID-shaped, so this
        // distinguishes a transposition from an id we simply do not know.
        assert_eq!(row.details["claimedShape"], "other");
        assert_eq!(row.details["clientId"], Value::Null);
    }
}

/// A password verified through ROPC is a sign-in. Without its own event the log
/// would hold only `token.issued`, and "when did this user last authenticate"
/// would be unanswerable for any client using the password grant.
#[tokio::test]
async fn a_successful_password_grant_is_audited_as_a_sign_in() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = rust_oidc::apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id)
        .await
        .unwrap();
    rust_oidc::apps::set_password_grant_allowed(&s.pool, &app, true)
        .await
        .unwrap();

    let (status, _) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(status, 200);

    let signed_in = rows(&s, &f.tenant.id, "auth.sign_in").await;
    assert_eq!(signed_in.len(), 1);
    assert_eq!(signed_in[0].actor, f.user_id);
    assert_eq!(signed_in[0].target.as_deref(), Some(f.user_id.as_str()));
    assert_eq!(signed_in[0].details["via"], "password_grant");
    assert_eq!(signed_in[0].details["clientId"], f.web.app_id);
    // No browser session exists for this grant, so none is recorded.
    assert!(rows(&s, &f.tenant.id, "session.create").await.is_empty());
    assert!(!everything(&s, &f.tenant.id).await.contains(&f.password));
}

/// The counterpart: a well-formed id that happens not to be registered is
/// reported as such, so the shape field is a real diagnostic and not a constant.
#[tokio::test]
async fn an_unregistered_guid_client_id_is_recorded_as_a_guid() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let unknown = "11111111-2222-3333-4444-555555555555";
    let (status, _) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", unknown),
                ("client_secret", "irrelevant"),
                ("scope", "https://graph.microsoft.com/.default"),
            ],
        )
        .await;
    assert_eq!(status, 400);
    let failed = rows(&s, &f.tenant.id, "token.client_auth_failed").await;
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].details["claimedShape"], "guid");
    // Still not the value itself, even though this one is harmless.
    assert!(!everything(&s, &f.tenant.id).await.contains(unknown));
}

#[tokio::test]
async fn replayed_code_is_audited_and_revocation_is_visible() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let code = get_code(&s, &b, &f, "openid offline_access", &challenge).await;
    assert_eq!(redeem(&s, &f, &code, &verifier).await.0, 200);
    assert_eq!(redeem(&s, &f, &code, &verifier).await.0, 400);

    let replays = rows(&s, &f.tenant.id, "token.code_replayed").await;
    assert_eq!(replays.len(), 1);
    assert_eq!(replays[0].actor, f.user_id);
    assert_eq!(replays[0].details["clientId"], f.web.app_id.as_str());

    let revoked = rows(&s, &f.tenant.id, "token.refresh_family_revoked").await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].actor, f.user_id);
    assert_eq!(revoked[0].details["cause"], "code_replay");
    assert!(!everything(&s, &f.tenant.id).await.contains(&code));
}

#[tokio::test]
async fn logout_is_audited() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    get_code(&s, &b, &f, "openid", &challenge).await;

    let mut url = url::Url::parse(&s.url(&format!("/{}/oauth2/v2.0/logout", f.tenant.id))).unwrap();
    url.query_pairs_mut()
        .append_pair("post_logout_redirect_uri", REDIRECT)
        .append_pair("client_id", &f.web.app_id);
    assert_eq!(b.get(url.as_str()).await.status, 302);

    let ended = rows(&s, &f.tenant.id, "session.end").await;
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].actor, f.user_id);
    assert_eq!(ended[0].details["redirected"], true);

    // A second logout has no session to end, so it is not an event.
    b.get(url.as_str()).await;
    assert_eq!(rows(&s, &f.tenant.id, "session.end").await.len(), 1);
}

#[tokio::test]
async fn device_flow_is_audited_without_the_codes() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let tid = f.tenant.id.clone();
    let resp = s
        .http
        .post(s.url(&format!("/{tid}/oauth2/v2.0/devicecode")))
        .form(&[("client_id", f.web.app_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
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
        ("op", "approve".to_string()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(b.post_form(&signed_in.form_action(), &form).await.status, 200);
    let (status, _) = s
        .token(
            &tid,
            &[
                ("grant_type", DEVICE_GRANT),
                ("client_id", &f.web.app_id),
                ("device_code", &device_code),
            ],
        )
        .await;
    assert_eq!(status, 200);

    let issued = rows(&s, &tid, "device.code_issued").await;
    assert_eq!((issued.len(), issued[0].actor.as_str()), (1, f.web.app_id.as_str()));
    for action in ["device.approved", "device.redeemed"] {
        let r = rows(&s, &tid, action).await;
        assert_eq!(r.len(), 1, "{action}");
        assert_eq!(r[0].actor, f.user_id, "{action}");
    }
    let granted = rows(&s, &tid, "token.issued").await;
    assert_eq!(granted[0].details["grant"], DEVICE_GRANT);

    let log = everything(&s, &tid).await;
    assert!(
        !log.contains(&device_code) && !log.contains(&user_code),
        "device code leaked"
    );
}

#[tokio::test]
async fn unknown_user_value_without_a_domain_is_not_logged() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let page = b
        .authorize(&s, &f.tenant.id, &authorize_params(&f, "openid", &challenge))
        .await;
    // What a user types when they paste their password into the username box.
    let typed = "CorrectHorse-Battery9!";
    let resp = b.login(&page, typed, "whatever").await;
    assert_eq!(resp.status, 401);
    let with_junk_at = b.login(&resp, "p@ss word!", "whatever").await;
    assert_eq!(with_junk_at.status, 401);
    // A DNS-shaped password fragment is not one of the tenant's domains.
    let dns_shaped = b.login(&with_junk_at, "x@corp.example", "whatever").await;
    assert_eq!(dns_shaped.status, 401);

    let failed = rows(&s, &f.tenant.id, "auth.sign_in_failed").await;
    assert_eq!(failed.len(), 3);
    for row in &failed {
        assert_eq!(row.actor, "anonymous");
        assert_eq!(row.details["reason"], "unknown_user");
        assert!(row.details.get("upn").is_none() && row.details.get("domain").is_none());
    }
    let log = everything(&s, &f.tenant.id).await;
    assert!(
        !log.contains(typed) && !log.contains("p@ss"),
        "unknown-user input leaked: {log}"
    );
}

/// Strip what legitimately differs between two responses: random tokens and
/// the echoed username.
fn normalized(page: &common::Page, csrf: &str, upns: &[&str]) -> String {
    let mut body = page.body.replace(csrf, "CSRF");
    for upn in upns {
        body = body.replace(*upn, "UPN");
    }
    body
}

#[tokio::test]
async fn unknown_user_and_wrong_password_look_identical_on_the_login_page() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (_, challenge) = pkce();
    let start = || async {
        let b = Browser::new();
        let page = b
            .authorize(&s, &f.tenant.id, &authorize_params(&f, "openid", &challenge))
            .await;
        (b, page)
    };
    let (b1, p1) = start().await;
    let (b2, p2) = start().await;
    let wrong = b1.login(&p1, &f.upn, "wrong-password").await;
    let unknown = b2.login(&p2, "nobody@contoso.com", "wrong-password").await;
    let upns = [f.upn.as_str(), "nobody@contoso.com"];
    assert_eq!(wrong.status, unknown.status);
    let (w, u) = (
        normalized(&wrong, &wrong.field("csrf").unwrap(), &upns),
        normalized(&unknown, &unknown.field("csrf").unwrap(), &upns),
    );
    assert_eq!(w, u);
    // The auditing itself must not add anything to the page.
    assert!(!w.contains("unknown_user") && !w.contains("bad_password"));
}
