//! "Must choose a new password at next sign-in", and not reusing recent ones.

mod common;

use common::*;
use rust_oidc::db::Event;
use rust_oidc::mfa;
use rust_oidc::tenant;
use rust_oidc::users::{self, PasswordReused, PasswordSetBy};
use rust_oidc::util::now;

fn params<'a>(f: &'a UserFixture, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "st-pw"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

/// Post a second-step page with these extra fields.
async fn submit(b: &Browser, page: &Page, extra: &[(&str, &str)]) -> Page {
    let mut form: Vec<(String, String)> = Vec::new();
    for name in ["csrf", "request", "op", "mfa_ticket", "tenant"] {
        if let Some(v) = page.field(name) {
            form.push((name.to_string(), v));
        }
    }
    for (k, v) in extra {
        form.push((k.to_string(), v.to_string()));
    }
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

async fn fresh_tenant(s: &TestServer, f: &UserFixture) -> tenant::Tenant {
    tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap()
}

#[tokio::test]
async fn an_admin_reset_makes_the_user_choose_a_new_password_at_sign_in() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let user = user_fixture_in(&s, f.tenant.clone(), "bob@contoso.com").await;
    let admin = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, user.user_id));
    let page = admin.get(&url).await;
    assert!(
        page.body.contains(r#"name="require_change" checked"#),
        "ticked by default: {}",
        page.body
    );
    let reset = admin
        .post(
            &url,
            &[
                ("op", "reset"),
                ("password", "Temporary-Pass-1"),
                ("require_change", "on"),
            ],
        )
        .await;
    assert_eq!(reset.status, 303, "{}", reset.body);
    assert!(users::must_change_password(&s.pool, &user.user_id).await.unwrap());

    // The password grant cannot show the page, so it is refused.
    let app = rust_oidc::apps::find_in_tenant(&s.pool, &f.tenant, &user.web.app_id)
        .await
        .unwrap();
    rust_oidc::apps::set_password_grant_allowed(&s.pool, &app, true)
        .await
        .unwrap();
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &user.web.app_id),
                ("client_secret", &user.web.secret),
                ("username", &user.upn),
                ("password", "Temporary-Pass-1"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS50055"),
        "{body}"
    );

    // In a browser: the temporary password, then the page to choose one.
    let b = Browser::new();
    let (_, challenge) = pkce();
    let login = b.authorize(&s, &f.tenant.id, &params(&user, &challenge)).await;
    let change = b.login(&login, &user.upn, "Temporary-Pass-1").await;
    assert!(change.body.contains("Update your password"), "{}", change.body);

    let mismatch = submit(
        &b,
        &change,
        &[
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-2"),
        ],
    )
    .await;
    assert_eq!(mismatch.status, 400);
    assert!(
        mismatch.body.contains("don&#x27;t match") || mismatch.body.contains("don't match"),
        "{}",
        mismatch.body
    );
    // Their old password is among their last three: refused.
    let reused = submit(
        &b,
        &mismatch,
        &[("new_password", &user.password), ("confirm_password", &user.password)],
    )
    .await;
    assert_eq!(reused.status, 400);
    assert!(reused.body.contains("used recently"), "{}", reused.body);

    let done = submit(
        &b,
        &reused,
        &[
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-1"),
        ],
    )
    .await;
    assert_eq!(done.status, 302, "{}", done.body);
    assert!(done.redirect_params().contains_key("code"));
    assert!(!users::must_change_password(&s.pool, &user.user_id).await.unwrap());
    assert_eq!(audit_rows(&s, Event::PasswordChanged.as_str()).await.len(), 1);

    // From now on, the new password, and no page.
    let other = Browser::new();
    let login = other.authorize(&s, &f.tenant.id, &params(&user, &challenge)).await;
    let signed = other.login(&login, &user.upn, "Brand-New-Pass-1").await;
    assert_eq!(signed.status, 302, "{}", signed.body);
}

#[tokio::test]
async fn the_last_few_passwords_cannot_be_used_again() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await; // created with "Correct-Horse-9"
    let set = |p: &'static str, by| {
        let pool = s.pool.clone();
        let (tenant_id, user) = (f.tenant.id.clone(), f.user_id.clone());
        async move {
            let t = tenant::find_for_admin(&pool, &tenant_id).await.unwrap();
            users::change_password(&pool, &t, &user, p, by).await
        }
    };
    set("Second-Pass-2", PasswordSetBy::User).await.unwrap();
    set("Third-Pass-3", PasswordSetBy::User).await.unwrap();
    // Default 3: the current one and the two before are refused.
    for old in ["Third-Pass-3", "Second-Pass-2", "Correct-Horse-9"] {
        let err = set(old, PasswordSetBy::User).await.unwrap_err();
        assert!(err.downcast_ref::<PasswordReused>().is_some(), "{old}: {err}");
    }
    // An administrator's temporary password is exempt; one the user keeps is not.
    set("Second-Pass-2", PasswordSetBy::AdminTemporary).await.unwrap();
    assert!(set("Third-Pass-3", PasswordSetBy::Admin).await.is_err());

    // Fewer remembered: older ones are free again; none: anything goes.
    let mut settings = fresh_tenant(&s, &f).await.settings;
    settings.password_history = 1;
    tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.unwrap();
    set("Correct-Horse-9", PasswordSetBy::User).await.unwrap();
    settings.password_history = 0;
    tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.unwrap();
    set("Correct-Horse-9", PasswordSetBy::User).await.unwrap();
    settings.password_history = 25;
    assert!(
        tenant::save_settings(&s.pool, &f.tenant.id, &settings).await.is_err(),
        "at most 24"
    );
}

/// With MFA too: password, then code, then the new password, and the session
/// that follows carries both methods.
#[tokio::test]
async fn the_change_comes_after_the_second_factor() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    let t = fresh_tenant(&s, &f).await;
    users::change_password(
        &s.pool,
        &t,
        &f.user_id,
        "Temporary-Pass-1",
        PasswordSetBy::AdminTemporary,
    )
    .await
    .unwrap();

    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge)).await;
    let code_page = b.login(&login, &f.upn, "Temporary-Pass-1").await;
    assert!(code_page.body.contains("Enter code"), "{}", code_page.body);
    let code = mfa::code_for(&secret, now() + mfa::STEP_SECS);
    let change = submit(&b, &code_page, &[("code", &code)]).await;
    assert!(change.body.contains("Update your password"), "{}", change.body);
    let done = submit(
        &b,
        &change,
        &[
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-1"),
        ],
    )
    .await;
    assert_eq!(done.status, 302, "{}", done.body);
    let (status, tokens) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("code", &done.redirect_params()["code"]),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        decode_unverified(tokens["id_token"].as_str().unwrap())["amr"],
        serde_json::json!(["pwd", "mfa"])
    );
}

/// A new account made in the console chooses its own password at first sign-in,
/// unless the box is unticked; and the console's own sign-in asks too.
#[tokio::test]
async fn new_accounts_and_console_sign_in_follow_the_same_rule() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let admin = signed_in_admin(&s, &f).await;
    let new = s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id));
    let page = admin.get(&new).await;
    assert!(page.body.contains(r#"name="require_change" checked"#), "{}", page.body);
    for (upn, tick) in [("dana", true), ("erin", false)] {
        let mut form = vec![
            ("upn", upn),
            ("upn_domain", "contoso.com"),
            ("password", "Initial-Pass-1"),
        ];
        if tick {
            form.push(("require_change", "on"));
        }
        assert_eq!(admin.post(&new, &form).await.status, 303);
        let t = fresh_tenant(&s, &f).await;
        let id = users::find_by_upn(&s.pool, &t.id, &format!("{upn}@contoso.com"))
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(users::must_change_password(&s.pool, &id).await.unwrap(), tick, "{upn}");
    }

    // The console: an administrator whose password was reset chooses a new one.
    let t = fresh_tenant(&s, &f).await;
    users::change_password(
        &s.pool,
        &t,
        &f.user_id,
        "Temporary-Pass-1",
        PasswordSetBy::AdminTemporary,
    )
    .await
    .unwrap();
    let b = Browser::new();
    let form = b.get(&s.url("/admin")).await;
    let nonce = form.field("csrf").unwrap();
    let change = b
        .post_form(
            &s.url("/admin/signin"),
            &[
                ("upn", f.upn.as_str()),
                ("password", "Temporary-Pass-1"),
                ("csrf", nonce.as_str()),
            ],
        )
        .await;
    assert!(change.body.contains("Update your password"), "{}", change.body);
    let done = submit(
        &b,
        &change,
        &[
            ("new_password", "Brand-New-Pass-1"),
            ("confirm_password", "Brand-New-Pass-1"),
        ],
    )
    .await;
    assert_eq!(done.status, 303, "{}", done.body);
    assert_eq!(b.get(&s.url("/admin/tenants")).await.status, 200);
}
