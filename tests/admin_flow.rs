//! The console's flow tester.
//!
//! The landing page is the feature, so most of these tests are about what it says
//! is missing and what it offers to do about it. The end-to-end ones drive a real
//! sign-in through the console and read the result page, which is the only way to
//! know that the checks on the way back actually run.

mod common;
use common::*;

use rust_oidc::apps::{self, RedirectPlatform};
use rust_oidc::flowtest;

fn flow_path(tenant_key: &str) -> String {
    format!("/admin/tenants/{tenant_key}/flow")
}

/// The callback URI this server would require, built the way the console builds it.
fn callback(s: &TestServer) -> String {
    format!("{}{}", s.base, flowtest::CALLBACK_PATH)
}

/// Register the tenant's flow tester client through the console, and return its
/// application id, which the redirect carries.
async fn create_test_client(s: &TestServer, b: &AdminBrowser, tenant_key: &str) -> String {
    let page = b
        .post(&s.url(&flow_path(tenant_key)), &[("op", "create_test_client")])
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let location = page.location.expect("a redirect back to the flow tester");
    url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "app")
        .map(|(_, v)| v.to_string())
        .expect("the redirect names the client it created")
}

/// Drive a whole flow: start it, sign in, follow the response to the callback, and
/// return the result page.
async fn run_flow(s: &TestServer, b: &AdminBrowser, f: &UserFixture, probe: &[(&str, &str)]) -> Page {
    let mut form = vec![("op", "start")];
    form.extend_from_slice(probe);
    let start = b.post(&s.url(&flow_path(&f.tenant.id)), &form).await;
    assert_eq!(start.status, 303, "start: {}", start.body);
    let authorize = start.location.expect("a redirect to the authorize endpoint");

    let login = b.b.get(&authorize).await;
    let answered = b.b.login(&login, &f.upn, &f.password).await;
    match answered.status {
        // query mode: a redirect to the callback
        302 => b.b.get(&answered.location.expect("a redirect to the callback")).await,
        // form_post mode: an auto-submitting form aimed at the callback
        200 => {
            let action = answered.form_action();
            let mut fields: Vec<(&str, String)> = Vec::new();
            for name in [
                "code",
                "state",
                "id_token",
                "access_token",
                "error",
                "error_description",
            ] {
                if let Some(value) = answered.field(name) {
                    fields.push((name, value));
                }
            }
            assert!(
                fields.iter().any(|(k, _)| *k == "state"),
                "the form_post page carries the state: {}",
                answered.body
            );
            let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
            b.b.post_form(&action, &borrowed).await
        }
        other => panic!("unexpected answer {other} to the sign-in: {}", answered.body),
    }
}

/// Every `details` value in the audit log, so a test can assert that something is
/// in none of them.
async fn all_audit_details(s: &TestServer) -> Vec<String> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(rust_oidc::db::q(&s.pool, "SELECT details FROM audit_log"))
        .fetch_all(&s.pool)
        .await
        .unwrap();
    rows.into_iter().filter_map(|(d,)| d).collect()
}

/// The point of the landing page: it states what is missing, with the exact value
/// needed, rather than letting the administrator discover it from an AADSTS code.
#[tokio::test]
async fn the_landing_page_says_what_is_missing_and_what_it_needs() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .get(&s.url(&format!(
            "{}?app={}&response_type=code+id_token&response_mode=form_post&scope=openid",
            flow_path(&f.tenant.id),
            f.web.app_id
        )))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    // The exact URI that has to be registered, and the fact that it is not.
    assert!(
        page.body.contains(&callback(&s)),
        "the exact callback URI: {}",
        page.body
    );
    assert!(
        page.body
            .contains("is not one of this application&#x27;s redirect URIs"),
        "says the callback is missing: {}",
        page.body
    );
    // The toggle that a response type containing id_token needs, named as the page
    // that holds it names it.
    assert!(
        page.body.contains("Allow implicit ID tokens"),
        "names the toggle to change: {}",
        page.body
    );
    // Two requirements are unmet, so there is no start button yet.
    assert!(
        !page.body.contains("Start the flow"),
        "nothing is offered while requirements are unmet: {}",
        page.body
    );
    assert!(page.body.contains("requirements are not met"), "{}", page.body);
}

/// Once everything is configured, the same page says so and offers to run it.
#[tokio::test]
async fn the_landing_page_offers_to_run_a_flow_that_is_ready() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &f.tenant.id).await;

    let page = b
        .get(&s.url(&format!(
            "{}?app={app_id}&response_type=code&response_mode=query&scope=openid+profile",
            flow_path(&f.tenant.id)
        )))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("Everything this flow needs is configured"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Start the flow"), "{}", page.body);
    // And it is honest about which client this is.
    assert!(page.body.contains("flow tester client"), "{}", page.body);
}

/// The callback is never added behind the administrator's back: it is a button, it
/// is audited as the redirect URI addition it is, and it shows up on the
/// application's own page where it can be removed.
#[tokio::test]
async fn adding_the_callback_is_an_explicit_audited_step() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();

    // Before: merely looking at the readiness page changes nothing.
    let _ = b
        .get(&s.url(&format!("{}?app={}", flow_path(&f.tenant.id), f.web.app_id)))
        .await;
    let before = apps::redirect_uris(&s.pool, &app).await.unwrap();
    assert!(
        !before.iter().any(|(_, uri)| *uri == callback(&s)),
        "the readiness page must not register anything: {before:?}"
    );

    let posted = b
        .post(
            &s.url(&flow_path(&f.tenant.id)),
            &[
                ("op", "add_callback"),
                ("app", &f.web.app_id),
                ("platform", RedirectPlatform::PublicClient.as_str()),
            ],
        )
        .await;
    assert_eq!(posted.status, 303, "{}", posted.body);
    let after = apps::redirect_uris(&s.pool, &app).await.unwrap();
    assert!(
        after
            .iter()
            .any(|(p, uri)| *uri == callback(&s) && *p == RedirectPlatform::PublicClient),
        "registered under the platform that was chosen: {after:?}"
    );
    let rows = audit_rows(&s, "admin.app.redirect_uri.add").await;
    assert_eq!(rows.len(), 1, "one audit row: {rows:?}");
    assert_eq!(rows[0].1.as_deref(), Some(f.web.app_id.as_str()));
}

/// The zero-side-effect path: a client of its own, registered as a public client so
/// that no secret exists to be needed.
#[tokio::test]
async fn the_console_registers_a_flow_tester_client_on_request() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let app_id = create_test_client(&s, &b, &f.tenant.id).await;
    let app = apps::find(&s.pool, &app_id).await.unwrap().unwrap();
    assert_eq!(app.display_name, flowtest::TEST_CLIENT_NAME);
    let uris = apps::redirect_uris(&s.pool, &app).await.unwrap();
    assert_eq!(uris, vec![(RedirectPlatform::PublicClient, callback(&s))]);
    // No secret, by design: a public client has none to leak and none to need.
    assert!(apps::secrets(&s.pool, &app).await.unwrap().is_empty());

    // Asking twice does not register a second one.
    let again = create_test_client(&s, &b, &f.tenant.id).await;
    assert_eq!(again, app_id);
    assert_eq!(apps::list(&s.pool, &f.tenant.id).await.unwrap().len(), 3);

    // It is an ordinary registration: the applications section lists it.
    let page = b.get(&s.url(&format!("/admin/tenants/{}/apps", f.tenant.id))).await;
    assert!(page.body.contains(flowtest::TEST_CLIENT_NAME), "{}", page.body);
}

/// The whole point: a real authorization code flow, driven from the console, with
/// the code redeemed over HTTP against our own token endpoint.
#[tokio::test]
async fn a_code_flow_runs_end_to_end_and_every_check_passes() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &f.tenant.id).await;

    let result = run_flow(
        &s,
        &b,
        &f,
        &[
            ("app", &app_id),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("scope", "openid profile email"),
        ],
    )
    .await;
    assert_eq!(result.status, 200, "{}", result.body);
    assert!(result.body.contains("checks passed"), "{}", result.body);
    assert!(
        !result.body.contains("pill bad"),
        "no check may fail on a correct flow: {}",
        result.body
    );
    // The exchange really happened, against the real endpoint.
    assert!(result.body.contains("oauth2/v2.0/token"), "{}", result.body);
    assert!(result.body.contains("HTTP 200"), "{}", result.body);
    // And the tokens were decoded and checked.
    assert!(result.body.contains("ID token"), "{}", result.body);
    assert!(result.body.contains("Access token"), "{}", result.body);
    assert!(result.body.contains(&f.upn), "the claims are shown: {}", result.body);

    // The audit trail says a flow test ran and how it ended -- and nothing else.
    let start = audit_rows(&s, "admin.flow_test.start").await;
    assert_eq!(start.len(), 1, "{start:?}");
    assert_eq!(start[0].1.as_deref(), Some(app_id.as_str()));
    let done = audit_rows(&s, "admin.flow_test.result").await;
    assert_eq!(done.len(), 1, "{done:?}");
    for details in all_audit_details(&s).await {
        assert!(!details.contains("eyJ"), "a token reached the audit log: {details}");
        assert!(
            !details.contains("code_verifier") && !details.contains("nonce") && !details.contains("state"),
            "request material reached the audit log: {details}"
        );
    }
    assert!(
        done.iter().any(|_| true),
        "the outcome is recorded: {:?}",
        all_audit_details(&s).await
    );
}

/// The hybrid flow is where `c_hash` means something: the ID token arrives in the
/// front channel beside the code it is supposed to bind.
#[tokio::test]
async fn a_hybrid_flow_checks_c_hash_against_the_code_that_came_with_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &f.tenant.id).await;
    let app = apps::find(&s.pool, &app_id).await.unwrap().unwrap();
    apps::set_implicit_allowed(&s.pool, &app, true, false).await.unwrap();

    let result = run_flow(
        &s,
        &b,
        &f,
        &[
            ("app", &app_id),
            ("response_type", "code id_token"),
            ("response_mode", "form_post"),
            ("scope", "openid profile"),
        ],
    )
    .await;
    assert_eq!(result.status, 200, "{}", result.body);
    assert!(result.body.contains("c_hash"), "{}", result.body);
    assert!(
        result.body.contains("which is the left half of SHA-256 over the code"),
        "c_hash was checked against the code: {}",
        result.body
    );
    // Both ID tokens are kept: the one that carried c_hash and the one the token
    // endpoint returned.
    assert!(
        result.body.contains("delivered in the authorize response"),
        "{}",
        result.body
    );
    assert!(
        result.body.contains("returned by the token endpoint"),
        "{}",
        result.body
    );
    assert!(!result.body.contains("pill bad"), "{}", result.body);
}

/// A response the console did not ask for is refused and said so, not quietly read.
#[tokio::test]
async fn a_state_that_names_no_pending_flow_test_is_an_error() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .get(&s.url(&format!("{}?code=whatever&state=invented", flowtest::CALLBACK_PATH)))
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("does not match a flow test"), "{}", page.body);
    let rows = audit_rows(&s, "admin.flow_test.result").await;
    assert_eq!(rows.len(), 1, "the refusal is recorded: {rows:?}");
}

/// Each flow test is single use: the row is deleted when it is answered, so a
/// replayed callback is refused like any other unknown state.
#[tokio::test]
async fn a_callback_cannot_be_replayed() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &f.tenant.id).await;

    let probe = [
        ("app", app_id.as_str()),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("scope", "openid"),
    ];
    let mut form = vec![("op", "start")];
    form.extend_from_slice(&probe);
    let start = b.post(&s.url(&flow_path(&f.tenant.id)), &form).await;
    let authorize = start.location.unwrap();
    let login = b.b.get(&authorize).await;
    let answered = b.b.login(&login, &f.upn, &f.password).await;
    let callback_url = answered.location.unwrap();

    let first = b.b.get(&callback_url).await;
    assert_eq!(first.status, 200, "{}", first.body);
    let second = b.b.get(&callback_url).await;
    assert_eq!(second.status, 400, "a second answer is refused: {}", second.body);
}

/// A web client's code cannot be redeemed by the console, and the page says exactly
/// why rather than failing obscurely: only a hash of the secret is stored.
#[tokio::test]
async fn a_web_client_is_told_the_console_cannot_redeem_its_code() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::add_redirect_uri(&s.pool, &app, RedirectPlatform::Web, &callback(&s))
        .await
        .unwrap();

    let page = b
        .get(&s.url(&format!(
            "{}?app={}&response_type=code&response_mode=query&scope=openid",
            flow_path(&f.tenant.id),
            f.web.app_id
        )))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("only a SHA-256 hash of the client secret is stored"),
        "the page explains why: {}",
        page.body
    );
    // It is still runnable: the front channel is what is being tested.
    assert!(page.body.contains("Start the flow"), "{}", page.body);

    let result = run_flow(
        &s,
        &b,
        &f,
        &[
            ("app", &f.web.app_id),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(result.status, 200, "{}", result.body);
    assert!(result.body.contains("is a web client"), "{}", result.body);
    // The request to run by hand, with the secret left to the administrator.
    assert!(
        result.body.contains("&lt;the secret you hold&gt;"),
        "the console never fills in a secret: {}",
        result.body
    );
}

/// The password grant is a readiness item, not something the console runs.
#[tokio::test]
async fn the_password_grant_is_reported_but_never_driven() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let url = format!(
        "{}?app={}&response_type=code&response_mode=query&scope=openid&password_grant=on",
        flow_path(&f.tenant.id),
        f.web.app_id
    );
    let off = b.get(&s.url(&url)).await;
    assert!(
        off.body.contains("allow_password_grant is off"),
        "names the flag: {}",
        off.body
    );
    assert!(off.body.contains("ROPC"), "{}", off.body);
    // No password box anywhere on the page.
    assert!(
        !off.body.contains(r#"type="password""#),
        "the console never collects a password here: {}",
        off.body
    );

    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::set_password_grant_allowed(&s.pool, &app, true).await.unwrap();
    let on = b.get(&s.url(&url)).await;
    assert!(on.body.contains("allow_password_grant is on"), "{}", on.body);
    assert!(on.body.contains("grant_type=password"), "{}", on.body);
}

/// Fragment mode is not captured, and the page says so instead of pretending.
#[tokio::test]
async fn fragment_mode_shows_the_url_instead_of_driving_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &f.tenant.id).await;
    let app = apps::find(&s.pool, &app_id).await.unwrap().unwrap();
    apps::set_implicit_allowed(&s.pool, &app, true, false).await.unwrap();

    let page = b
        .post(
            &s.url(&flow_path(&f.tenant.id)),
            &[
                ("op", "start"),
                ("app", &app_id),
                ("response_type", "id_token"),
                ("response_mode", "fragment"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Open this yourself"), "{}", page.body);
    assert!(page.body.contains("response_mode=fragment"), "{}", page.body);
    // Nothing was stored, because nothing can come back.
    let (pending,): (i64,) = sqlx::query_as(rust_oidc::db::q(&s.pool, "SELECT COUNT(*) FROM flow_tests"))
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0, "a flow that cannot be answered leaves no row");
}

/// A token must never be deliverable to a query string, and the page refuses the
/// combination before the server has to.
#[tokio::test]
async fn a_token_in_a_query_string_is_refused_on_the_page() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b
        .get(&s.url(&format!(
            "{}?app={}&response_type=id_token&response_mode=query&scope=openid",
            flow_path(&f.tenant.id),
            f.web.app_id
        )))
        .await;
    assert!(
        page.body.contains("response_mode=query cannot be used"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Start the flow"), "{}", page.body);
}

/// A tenant administrator must not be able to run a flow against, or change
/// anything on, another tenant's application.
#[tokio::test]
async fn a_tenant_admin_cannot_flow_test_another_tenants_app() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let victim = s.app(&other, "their-app").await;
    let b = signed_in_admin(&s, &f).await;

    let path = flow_path(&other.id);
    let page = b.get(&s.url(&path)).await;
    assert!(
        page.status == 403 || page.status == 404,
        "GET {path} leaked with {}: {}",
        page.status,
        page.body
    );
    // The domain alias must not be a way round the scope check either.
    let aliased = b.get(&s.url(&flow_path("fabrikam.test"))).await;
    assert!(aliased.status == 403 || aliased.status == 404, "{}", aliased.body);

    let posts: [Vec<(&str, &str)>; 3] = [
        vec![
            ("op", "start"),
            ("app", &victim.app_id),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("scope", "openid"),
        ],
        vec![
            ("op", "add_callback"),
            ("app", &victim.app_id),
            ("platform", "publicClient"),
        ],
        vec![("op", "create_test_client")],
    ];
    for form in posts {
        let page = b.post(&s.url(&path), &form).await;
        assert!(
            page.status == 403 || page.status == 404,
            "POST {form:?} leaked with {}: {}",
            page.status,
            page.body
        );
    }

    // And the other tenant is untouched: no redirect URI, no client, no pending row.
    let app = apps::find(&s.pool, &victim.app_id).await.unwrap().unwrap();
    assert!(apps::redirect_uris(&s.pool, &app).await.unwrap().is_empty());
    assert!(flowtest::test_client(&s.pool, &other.id).await.unwrap().is_none());
    let (pending,): (i64,) = sqlx::query_as(rust_oidc::db::q(&s.pool, "SELECT COUNT(*) FROM flow_tests"))
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}

/// Reading the *result* is scoped to the tenant, not to the row. The flow is
/// started by somebody who may administer that tenant; by the time the answer
/// comes back that may no longer be true, and the callback asks the guard again
/// rather than trusting the pending row it just matched.
///
/// The administrator keeps a binding on *another* tenant on purpose: revoking
/// their last one would make `AdminContext` answer `no_access` before the
/// callback's own check was reached, and then this test would be proving nothing
/// about the callback (decision 89's trap).
#[tokio::test]
async fn the_callback_refuses_a_tenant_the_administrator_may_no_longer_read() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    // The flow signs a user in to the *other* tenant, so it needs an account there.
    let theirs = user_fixture_in(&s, other.clone(), "carol@fabrikam.test").await;
    bind(
        &s,
        &f.user_id,
        rust_oidc::rbac::RoleId::GlobalAdministrator,
        rust_oidc::rbac::Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let revoked = bind(
        &s,
        &f.user_id,
        rust_oidc::rbac::RoleId::GlobalAdministrator,
        rust_oidc::rbac::Scope::Tenants(vec![other.id.clone()]),
    )
    .await;
    let b = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &b, &other.id).await;

    let start = b
        .post(
            &s.url(&flow_path(&other.id)),
            &[
                ("op", "start"),
                ("app", &app_id),
                ("response_type", "code"),
                ("response_mode", "query"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(start.status, 303, "{}", start.body);
    let login = b.b.get(&start.location.unwrap()).await;
    let answered = b.b.login(&login, &theirs.upn, &theirs.password).await;
    let callback_url = answered.location.expect("a redirect to the callback");

    // The grant on that tenant goes away between the authorize request and its
    // answer. The console session stays valid, because the other binding remains.
    assert!(
        rust_oidc::admin::bindings::delete(&s.pool, &revoked).await.unwrap(),
        "the binding was revoked"
    );
    let page = b.b.get(&callback_url).await;
    assert_eq!(page.status, 403, "the result must not be shown: {}", page.body);
    assert!(
        !page.body.contains("eyJ"),
        "no token may appear on a refused page: {}",
        page.body
    );
    // Still signed in, which is what makes the 403 the callback's own answer.
    assert_eq!(
        b.get(&s.url(&flow_path(&f.tenant.id))).await.status,
        200,
        "the session itself is unaffected"
    );
}

/// A flow test belongs to the console session that started it. Another
/// administrator holding the same URL gets nothing, even one who may administer
/// that tenant.
#[tokio::test]
async fn another_administrators_session_cannot_complete_a_flow_test() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let second = user_fixture_in(&s, f.tenant.clone(), "bob@contoso.com").await;
    bind(
        &s,
        &second.user_id,
        rust_oidc::rbac::RoleId::GlobalAdministrator,
        rust_oidc::rbac::Scope::All,
    )
    .await;

    let first = signed_in_admin(&s, &f).await;
    let app_id = create_test_client(&s, &first, &f.tenant.id).await;
    let start = first
        .post(
            &s.url(&flow_path(&f.tenant.id)),
            &[
                ("op", "start"),
                ("app", &app_id),
                ("response_type", "code"),
                ("response_mode", "query"),
                ("scope", "openid"),
            ],
        )
        .await;
    let login = first.b.get(&start.location.unwrap()).await;
    let answered = first.b.login(&login, &f.upn, &f.password).await;
    let callback_url = answered.location.expect("a redirect to the callback");

    let other = signed_in_admin(&s, &second).await;
    let page = other.b.get(&callback_url).await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("does not match a flow test"), "{}", page.body);
    assert!(!page.body.contains("eyJ"), "{}", page.body);

    // The row is still there for its owner, who can still complete it.
    let mine = first.b.get(&callback_url).await;
    assert_eq!(mine.status, 200, "{}", mine.body);
}

/// Anonymous access, on a console that is reachable from the internet.
#[tokio::test]
async fn the_flow_tester_is_not_reachable_without_a_console_session() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let anon = Browser::new();

    for path in [flow_path(&f.tenant.id), flowtest::CALLBACK_PATH.to_string()] {
        let page = anon.get(&s.url(&path)).await;
        assert_eq!(page.status, 303, "GET {path}: {}", page.body);
        assert!(
            page.location.as_deref().is_some_and(|l| l.ends_with("/admin")),
            "sent to sign in: {:?}",
            page.location
        );
    }
    let posted = anon
        .post_form(&s.url(&flow_path(&f.tenant.id)), &[("op", "create_test_client")])
        .await;
    assert_eq!(posted.status, 303, "{}", posted.body);
    assert!(
        apps::list(&s.pool, &f.tenant.id).await.unwrap().len() == 2,
        "nothing was created"
    );
}

/// A reader may diagnose -- that is the whole value of the page -- but must not be
/// able to change a registration from it.
#[tokio::test]
async fn a_reader_can_diagnose_but_not_register_anything() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.get(&s.url(&flow_path(&f.tenant.id))).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("What this needs"), "{}", page.body);
    assert!(
        !page.body.contains("Create a flow tester client"),
        "no button a reader cannot use: {}",
        page.body
    );
    for form in [
        vec![("op", "create_test_client")],
        vec![
            ("op", "add_callback"),
            ("app", f.web.app_id.as_str()),
            ("platform", "publicClient"),
        ],
    ] {
        let posted = b.post(&s.url(&flow_path(&f.tenant.id)), &form).await;
        assert_eq!(posted.status, 403, "{form:?}: {}", posted.body);
    }
    assert!(flowtest::test_client(&s.pool, &f.tenant.id).await.unwrap().is_none());
}

/// Every console form carries the session's token, and this one is no exception --
/// with the deliberate exception of the callback, which an identity provider's
/// form_post cannot carry one on, and where the server-generated state does that job.
#[tokio::test]
async fn the_forms_are_csrf_protected() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    for form in [
        vec![("op", "create_test_client")],
        vec![
            ("op", "add_callback"),
            ("app", f.web.app_id.as_str()),
            ("platform", "publicClient"),
        ],
        vec![
            ("op", "start"),
            ("app", f.web.app_id.as_str()),
            ("response_type", "code"),
        ],
    ] {
        let posted = b.post_raw(&s.url(&flow_path(&f.tenant.id)), &form).await;
        assert_eq!(posted.status, 400, "{form:?}: {}", posted.body);
    }
    assert!(flowtest::test_client(&s.pool, &f.tenant.id).await.unwrap().is_none());
}
