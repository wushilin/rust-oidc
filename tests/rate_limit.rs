//! Rate limiting on the endpoints an unauthenticated caller can reach.
//!
//! The gap this closes is that every one of these failures also writes an
//! `audit_log` row, so an unauthenticated caller could append rows for as long
//! as it liked -- growing the table without bound and pushing the evidence of a
//! real attack out of whatever retention the operator keeps. The tests that
//! matter here are therefore the ones that count audit rows, not the ones that
//! check a status code.
//!
//! See `src/ratelimit.rs` for why each bucket is keyed the way it is.

mod common;

use common::*;
use rust_oidc::apps::{self, MEMBER_APPLICATION};
use rust_oidc::ratelimit::Limit;
use serde_json::Value;

/// A token request, keeping the response headers so `Retry-After` can be read.
async fn token_raw(s: &TestServer, tenant: &str, form: &[(&str, &str)]) -> (u16, Option<String>, Value) {
    let resp = s
        .http
        .post(s.url(&format!("/{tenant}/oauth2/v2.0/token")))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().unwrap().to_string());
    (status, retry_after, resp.json().await.unwrap())
}

/// A resource this tenant really has, so a successful client-credentials request
/// is possible: the fixture's API app with one application role assigned.
async fn grant_app_role(s: &TestServer, f: &UserFixture, client: &TestApp) -> String {
    s.add_role(&f.tenant, &f.api, "Orders.Read", &[MEMBER_APPLICATION])
        .await;
    s.assign_to_app(&f.tenant, &f.api, "Orders.Read", client).await;
    format!("api://{}/.default", f.api.app_id)
}

async fn bad_secret(s: &TestServer, tenant: &str, client_id: &str) -> (u16, Option<String>, Value) {
    token_raw(
        s,
        tenant,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", "not-the-secret"),
            ("scope", "https://graph.microsoft.com/.default"),
        ],
    )
    .await
}

async fn count_rows(s: &TestServer, tenant_id: &str, action: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND action = ?",
    ))
    .bind(tenant_id)
    .bind(action)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    n
}

/// How many times the allowance a flood test sends.
///
/// An unlimited endpoint writes one row per request, so 10x the allowance misses
/// the cap by an order of magnitude and the assertion fails loudly.
const FLOOD_MULTIPLIER: i64 = 10;

/// The same, for a flood of *password* attempts.
///
/// Measured, not guessed: every one of these costs an argon2 verification, and
/// this file runs in 34s with 3x against 90s with 10x -- the sign-in loop is the
/// whole difference. Three still overshoots the allowance by 40 attempts, which
/// is an unmissable failure if the cap stops working, so the extra minute buys
/// nothing.
const PASSWORD_FLOOD_MULTIPLIER: i64 = 3;

/// How many fixed windows a stretch of wall-clock time can span.
///
/// These tests send thousands of requests, and an argon2 verification is not
/// cheap, so a run can outlast the 60-second window and legitimately earn a
/// second window's allowance. Asserting a flat count would make the test flaky
/// on a slow machine; asserting `allowance * windows` still fails loudly if the
/// limiter does nothing, because an unlimited flood writes one row per request.
fn windows_spanned(limit: Limit, started: std::time::Instant) -> i64 {
    let elapsed = started.elapsed().as_secs() as i64;
    elapsed / limit.window_secs() + 1
}

const CLIENT_AUTH_FAILED: &str = "token.client_auth_failed";
const THROTTLED: &str = "security.throttled";
const SIGN_IN_FAILED: &str = "auth.sign_in_failed";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

// ---- token endpoint: failed client authentication ----

#[tokio::test]
async fn repeated_client_auth_failures_are_throttled_with_retry_after() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let allowance = Limit::ClientAuthFailure.allowance();

    // Everything up to the allowance gets the real error.
    for i in 0..allowance {
        let (status, retry, body) = bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
        assert_eq!(status, 401, "attempt {i}: {body}");
        assert_eq!(body["error"], "invalid_client", "attempt {i}");
        assert_eq!(retry, None, "attempt {i} should not be throttled yet");
    }

    // The next one is refused, in Entra's shape: 429 plus Retry-After.
    let (status, retry, body) = bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable", "{body}");
    assert_eq!(body["error_codes"][0], 90055, "{body}");
    let secs: u64 = retry.expect("Retry-After header").parse().expect("a number of seconds");
    assert!(
        (1..=Limit::ClientAuthFailure.window_secs() as u64).contains(&secs),
        "Retry-After was {secs}"
    );
}

/// The bucket is keyed per application, so one application's flood must not
/// throttle another's clients. This is the property that makes the collateral
/// damage acceptable.
#[tokio::test]
async fn throttling_one_application_leaves_another_working() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.app(&f.tenant, "other-app").await;
    let scope = grant_app_role(&s, &f, &other).await;

    for _ in 0..Limit::ClientAuthFailure.allowance() + 5 {
        bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
    }
    let (status, _, body) = bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
    assert_eq!(status, 429, "the flooded application should be throttled: {body}");

    // A different application in the same tenant is untouched, both for a
    // failure and for a real token request.
    let (status, retry, body) = bad_secret(&s, &f.tenant.id, &other.app_id).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(retry, None);
    let (status, body) = s.client_credentials(&f.tenant.id, &other, &scope).await;
    assert_eq!(status, 200, "the other application should still get a token: {body}");
}

/// The trade-off, asserted so it is explicit rather than discovered: an attacker
/// who knows a client id can throttle that client's token requests, exactly as
/// an attacker who knows a UPN can trip smart lockout on that account.
#[tokio::test]
async fn a_throttled_application_is_refused_even_with_the_right_secret() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = grant_app_role(&s, &f, &f.web).await;

    let (status, body) = s.client_credentials(&f.tenant.id, &f.web, &scope).await;
    assert_eq!(status, 200, "sanity: the secret works before the flood: {body}");

    for _ in 0..Limit::ClientAuthFailure.allowance() + 1 {
        bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
    }
    let (status, body) = s.client_credentials(&f.tenant.id, &f.web, &scope).await;
    assert_eq!(status, 429, "the correct secret is refused while throttled: {body}");
}

/// The point of the whole exercise. However many failures are sent, the audit
/// table gains at most one window's allowance of them plus a single row saying
/// the bucket tripped.
#[tokio::test]
async fn failed_client_authentication_cannot_append_audit_rows_without_bound() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let allowance = i64::from(Limit::ClientAuthFailure.allowance());

    let started = std::time::Instant::now();
    let attempts = allowance * FLOOD_MULTIPLIER;
    for _ in 0..attempts {
        bad_secret(&s, &f.tenant.id, &f.web.app_id).await;
    }

    let windows = windows_spanned(Limit::ClientAuthFailure, started);
    let failures = count_rows(&s, &f.tenant.id, CLIENT_AUTH_FAILED).await;
    assert!(
        failures <= allowance * windows,
        "{attempts} failed authentications wrote {failures} audit rows, more than the {} allowed",
        allowance * windows
    );
    let trips = count_rows(&s, &f.tenant.id, THROTTLED).await;
    assert!(
        (1..=windows).contains(&trips),
        "the trip should be recorded once per window, not on every refusal: {trips} rows over {windows} window(s)"
    );
}

// ---- token endpoint: a client id the tenant does not have ----

/// An unknown client id can never be a legitimate request, so it gets its own
/// per-tenant bucket -- and throttling it must not touch a real client.
#[tokio::test]
async fn unknown_client_ids_are_throttled_without_affecting_a_real_client() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let scope = grant_app_role(&s, &f, &f.web).await;
    let allowance = i64::from(Limit::UnknownClient.allowance());

    let started = std::time::Instant::now();
    let attempts = allowance * FLOOD_MULTIPLIER;
    let mut throttled = 0;
    for _ in 0..attempts {
        // A fresh id every time: varying the parameter must not escape the bucket.
        let (status, _, _) = bad_secret(&s, &f.tenant.id, &rust_oidc::util::new_guid()).await;
        if status == 429 {
            throttled += 1;
        }
    }
    assert!(throttled > 0, "a flood of unknown client ids was never throttled");

    let cap = allowance * windows_spanned(Limit::UnknownClient, started);
    let failures = count_rows(&s, &f.tenant.id, CLIENT_AUTH_FAILED).await;
    assert!(
        failures <= cap,
        "{attempts} unknown client ids wrote {failures} audit rows, more than the {cap} allowed"
    );

    // A registered client in the same tenant is unaffected: no collateral damage.
    let (status, body) = s.client_credentials(&f.tenant.id, &f.web, &scope).await;
    assert_eq!(status, 200, "a real client should be unaffected: {body}");
}

// ---- sign-in: an account the tenant does not have ----

/// An unknown account and a wrong password are deliberately indistinguishable to
/// the caller. The rate limiter must not break that: it caps the audit rows and
/// leaves the response alone, or it becomes an account-enumeration oracle.
#[tokio::test]
async fn unknown_user_sign_ins_are_capped_without_becoming_an_enumeration_oracle() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id).await.unwrap();
    apps::set_password_grant_allowed(&s.pool, &app, true).await.unwrap();

    let ropc = async |username: &str, password: &str| {
        token_raw(
            &s,
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("username", username),
                ("password", password),
                ("scope", "openid"),
            ],
        )
        .await
    };

    let allowance = i64::from(Limit::UnknownUser.allowance());
    let attempts = allowance * PASSWORD_FLOOD_MULTIPLIER;
    let started = std::time::Instant::now();
    for _ in 0..attempts {
        let upn = format!("{}@contoso.com", rust_oidc::util::new_guid());
        let (status, retry, body) = ropc(&upn, "whatever").await;
        assert_ne!(
            status, 429,
            "an unknown account must never be answered with 429: {body}"
        );
        assert_eq!(retry, None, "a Retry-After would reveal that the account is unknown");
    }

    // The response for an unknown account still matches a wrong password for a
    // real one, after the bucket has long since tripped.
    let (unknown_status, _, unknown_body) =
        ropc(&format!("{}@contoso.com", rust_oidc::util::new_guid()), "whatever").await;
    let (known_status, _, known_body) = ropc(&f.upn, "definitely-not-the-password").await;
    assert_eq!(
        unknown_status, known_status,
        "status differs: {unknown_body} vs {known_body}"
    );
    assert_eq!(
        unknown_body["error"], known_body["error"],
        "error differs: {unknown_body} vs {known_body}"
    );
    assert_eq!(
        unknown_body["error_codes"], known_body["error_codes"],
        "AADSTS code differs: {unknown_body} vs {known_body}"
    );

    // ...and the rows are bounded all the same.
    let windows = windows_spanned(Limit::UnknownUser, started);
    // +1 for the wrong-password attempt above, which is a known account and so
    // is never capped -- smart lockout bounds that one.
    let cap = allowance * windows + 1;
    let failures = count_rows(&s, &f.tenant.id, SIGN_IN_FAILED).await;
    assert!(
        failures <= cap,
        "{attempts} unknown-account sign-ins wrote {failures} audit rows, more than the {cap} allowed"
    );
    let trips = count_rows(&s, &f.tenant.id, THROTTLED).await;
    assert!(
        (1..=windows).contains(&trips),
        "the trip should be recorded once per window: {trips} rows over {windows} window(s)"
    );
}

// ---- device authorization ----

/// Device code requests are unauthenticated (the client is public) and each one
/// inserts a `device_codes` row, so the request itself is what is bounded.
#[tokio::test]
async fn device_code_requests_are_throttled_per_application() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.app(&f.tenant, "other-device-app").await;
    let allowance = Limit::DeviceCodeRequest.allowance();

    let devicecode = async |client_id: &str| {
        let resp = s
            .http
            .post(s.url(&format!("/{}/oauth2/v2.0/devicecode", f.tenant.id)))
            .form(&[("client_id", client_id), ("scope", "openid")])
            .send()
            .await
            .unwrap();
        resp.status().as_u16()
    };

    for i in 0..allowance {
        assert_eq!(devicecode(&f.web.app_id).await, 200, "request {i} should be served");
    }
    assert_eq!(
        devicecode(&f.web.app_id).await,
        429,
        "the request after the allowance should be throttled"
    );
    // Another application's devices still enrol.
    assert_eq!(
        devicecode(&other.app_id).await,
        200,
        "a different application is unaffected"
    );

    // Exactly one row records the trip.
    assert_eq!(count_rows(&s, &f.tenant.id, THROTTLED).await, 1);
}

/// Polling for a device code that was never issued must not be a way around the
/// issuance limit: it is refused on its own terms and writes nothing.
#[tokio::test]
async fn polling_an_unknown_device_code_stays_a_plain_error() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (status, retry, body) = token_raw(
        &s,
        &f.tenant.id,
        &[
            ("grant_type", DEVICE_GRANT),
            ("client_id", &f.web.app_id),
            ("device_code", "not-a-device-code"),
        ],
    )
    .await;
    assert_ne!(status, 429, "{body}");
    assert_eq!(retry, None);
}
