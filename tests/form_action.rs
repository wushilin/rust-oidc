//! The `form-action` directive of the sign-in pages. Chrome holds a redirect
//! that follows a form submission to `form-action` too, so a page whose form the
//! server answers with a 302 to the client lists the client's origin beside
//! `'self'`; every page whose answer stays on this server keeps `'self'` alone.

mod common;

use common::*;
use rust_oidc::apps::{self, RedirectPlatform};
use rust_oidc::mfa;
use rust_oidc::tenant;
use rust_oidc::util::now;

/// The client's redirect URI, on an origin no other test uses.
const CLIENT_REDIRECT: &str = "https://venus.example/.tlsproxy/oidc/callback";
/// What a page that may redirect to that client must send.
const CLIENT_FORM_ACTION: &str = "form-action 'self' https://venus.example;";
/// What every other page sends: the policy admin pages have always sent.
const SELF_ONLY: &str =
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn csp(page: &Page) -> String {
    page.headers["content-security-policy"].to_str().unwrap().to_string()
}

async fn client_with_redirect(s: &TestServer, f: &UserFixture) {
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::add_redirect_uri(&s.pool, &app, RedirectPlatform::Web, CLIENT_REDIRECT)
        .await
        .unwrap();
}

async fn require_mfa(s: &TestServer, f: &UserFixture) {
    let mut settings = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap().settings;
    settings.require_mfa = true;
    tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.unwrap();
}

fn params<'a>(f: &'a UserFixture, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", CLIENT_REDIRECT),
        ("scope", "openid"),
        ("state", "venus"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

/// Post the code on a second-step page.
async fn send_code(b: &Browser, page: &Page, code: &str) -> Page {
    let mut form: Vec<(String, String)> = Vec::new();
    for name in ["csrf", "request", "op", "mfa_ticket"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    form.push(("code".into(), code.into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

/// The key printed on the set-up page, as the authenticator would read it.
fn key_on(page: &Page) -> String {
    let start = page.body.find(r#"<div class="key">"#).expect("a key") + 17;
    let end = page.body[start..].find("</div>").unwrap() + start;
    page.body[start..end].replace(' ', "")
}

#[tokio::test]
async fn the_sign_in_pages_of_a_request_allow_the_clients_origin_in_form_action() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    client_with_redirect(&s, &f).await;
    require_mfa(&s, &f).await;
    let b = Browser::new();
    let (_, challenge) = pkce();

    // The login page: its form's answer may be the redirect to the client.
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge)).await;
    assert_eq!(login.status, 200, "{}", login.body);
    let policy = csp(&login);
    assert!(policy.contains(CLIENT_FORM_ACTION), "{policy}");
    assert_eq!(
        policy.replace(" https://venus.example;", ";"),
        SELF_ONLY,
        "only form-action differs"
    );

    // Setting up the authenticator, then the code page on the next sign-in.
    let setup = b.login(&login, &f.upn, &f.password).await;
    assert!(setup.body.contains("Set up your authenticator"), "{}", setup.body);
    assert!(csp(&setup).contains(CLIENT_FORM_ACTION), "{}", csp(&setup));
    let secret = key_on(&setup);
    let done = send_code(&b, &setup, &mfa::code_for(&secret, now())).await;
    assert!(done.body.contains("Sign in again"), "{}", done.body);

    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge)).await;
    let step = b.login(&login, &f.upn, &f.password).await;
    assert!(step.body.contains("Enter code"), "{}", step.body);
    assert!(csp(&step).contains(CLIENT_FORM_ACTION), "{}", csp(&step));

    // And that form's answer is indeed the redirect Chrome has to be allowed to follow.
    let finished = send_code(&b, &step, &mfa::code_for(&secret, now() + 30)).await;
    assert_eq!(finished.status, 302, "{}", finished.body);
    assert!(
        finished.location.as_deref().unwrap().starts_with(CLIENT_REDIRECT),
        "{:?}",
        finished.location
    );
}

#[tokio::test]
async fn the_origin_comes_from_the_validated_redirect_uri_not_the_request() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    client_with_redirect(&s, &f).await;
    let b = Browser::new();
    let (_, challenge) = pkce();
    let mut p = params(&f, &challenge);
    p[2] = ("redirect_uri", "https://evil.example/cb");
    let page = b.authorize(&s, &f.tenant.id, &p).await;
    // An unregistered redirect URI gets an error page on this server, and no
    // page ever names its origin.
    assert_eq!(page.status, 400, "{}", page.body);
    assert_eq!(csp(&page), SELF_ONLY);
}

#[tokio::test]
async fn admin_pages_keep_form_action_self_alone() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let anonymous = Browser::new().get(&s.url("/admin")).await;
    assert_eq!(csp(&anonymous), SELF_ONLY, "the console sign-in form");
    let admin = signed_in_admin(&s, &f).await;
    // A signed-in /admin sends the administrator to their tenant's console.
    let mut page = admin.get(&s.url("/admin")).await;
    while let Some(next) = page.location.clone() {
        let next = if next.starts_with('/') { s.url(&next) } else { next };
        page = admin.get(&next).await;
    }
    assert_eq!(page.status, 200, "{}", page.body);
    assert_eq!(csp(&page), SELF_ONLY, "the console home page");
}

#[tokio::test]
async fn pages_whose_answer_stays_on_this_server_keep_form_action_self_alone() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    // The device flow ends on a page of its own, never at the client.
    let device = b.get(&s.url(&format!("/{}/oauth2/deviceauth", f.tenant.id))).await;
    assert_eq!(device.status, 200, "{}", device.body);
    assert_eq!(csp(&device), SELF_ONLY, "the device code page");
    // My Account's sign-in form answers with the account page.
    let account = b.get(&s.url(&format!("/{}/myaccount", f.tenant.id))).await;
    assert_eq!(account.status, 200, "{}", account.body);
    assert_eq!(csp(&account), SELF_ONLY, "the My Account sign-in page");
}
