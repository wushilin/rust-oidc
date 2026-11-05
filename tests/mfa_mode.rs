//! A tenant's MFA mode: Permissive (the account's own setting, the tenant's
//! default and the application's switch decide) or Enforced (every sign-in needs
//! a second factor, nobody is exempt, and a remembered browser is not trusted).

mod common;

use common::*;
use rust_oidc::apps;
use rust_oidc::mfa::{self, At, Freshness, MfaPolicy, Remembered, Step};
use rust_oidc::tenant::{self, MfaMode, Tenant, TenantSettings};

async fn set_mode(s: &TestServer, tenant_id: &str, mode: MfaMode) -> Tenant {
    let mut t = tenant::find_for_admin(&s.pool, tenant_id).await.unwrap();
    t.settings.mfa_mode = mode;
    tenant::save_settings(&s.pool, tenant_id, &t.settings).await.unwrap();
    tenant::find_for_admin(&s.pool, tenant_id).await.unwrap()
}

async fn remembered_rows(s: &TestServer, user_id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM mfa_remembered_devices WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    n
}

/// Enforced overrides an account's "Not required", the application's switch
/// being off, and every place a sign-in happens.
#[tokio::test]
async fn enforced_requires_mfa_of_everyone_everywhere() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    mfa::set_policy(&s.pool, &f.tenant.id, &f.user_id, MfaPolicy::NotRequired)
        .await
        .unwrap();
    let sp = apps::service_principal(&s.pool, &f.tenant.id, &f.web.app_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!sp.mfa_required);
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    assert_eq!(home.settings.mfa_mode, MfaMode::Permissive, "the default");
    assert_eq!(
        mfa::step(&s.pool, &home, &f.user_id, At::App(&sp)).await.unwrap(),
        Step::Done
    );

    let home = set_mode(&s, &f.tenant.id, MfaMode::Enforced).await;
    for at in [At::App(&sp), At::MyAccount, At::Console] {
        assert_eq!(
            mfa::step(&s.pool, &home, &f.user_id, at).await.unwrap(),
            Step::Enroll,
            "no authenticator yet: set one up"
        );
    }
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    assert_eq!(
        mfa::step(&s.pool, &home, &f.user_id, At::App(&sp)).await.unwrap(),
        Step::Verify
    );
}

/// An application of a tenant that enforces MFA requires it of accounts of
/// other tenants too, whatever their own tenant says.
#[tokio::test]
async fn an_enforcing_tenants_application_requires_it_of_other_tenants_accounts() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.com").await;
    let app = s.app(&fabrikam, "Fabrikam portal").await;
    let sp = apps::service_principal(&s.pool, &fabrikam.id, &app.app_id)
        .await
        .unwrap()
        .unwrap();
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    assert_eq!(
        mfa::step(&s.pool, &home, &f.user_id, At::App(&sp)).await.unwrap(),
        Step::Done
    );
    set_mode(&s, &fabrikam.id, MfaMode::Enforced).await;
    assert_eq!(
        mfa::step(&s.pool, &home, &f.user_id, At::App(&sp)).await.unwrap(),
        Step::Enroll
    );
}

/// Enforced asks for a code at every new sign-in: a browser is neither
/// remembered nor trusted, and those remembered before are forgotten.
#[tokio::test]
async fn enforced_neither_remembers_nor_trusts_a_browser() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let mut t = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    t.settings.allow_remember_mfa = true;
    tenant::save_settings(&s.pool, &f.tenant.id, &t.settings).await.unwrap();
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let home = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    let device = mfa::remember_device(&s.pool, None, &f.user_id, &home)
        .await
        .unwrap()
        .expect("remembered while permissive");
    let fresh = Freshness::default();

    // Checked at use, whatever the table holds.
    let mut enforced = home.clone();
    enforced.settings.mfa_mode = MfaMode::Enforced;
    assert!(!enforced.settings.remembers_mfa());
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &enforced, fresh)
            .await
            .unwrap(),
        Remembered::No
    );
    assert!(
        mfa::remember_device(&s.pool, None, &f.user_id, &enforced)
            .await
            .unwrap()
            .is_none(),
        "nothing new is remembered"
    );
    // Saved: forgotten, and going back to Permissive does not bring them back.
    set_mode(&s, &f.tenant.id, MfaMode::Enforced).await;
    assert_eq!(remembered_rows(&s, &f.user_id).await, 0);
    let back = set_mode(&s, &f.tenant.id, MfaMode::Permissive).await;
    assert_eq!(
        mfa::remembered(&s.pool, Some(&device), &f.user_id, &back, fresh)
            .await
            .unwrap(),
        Remembered::No
    );
}

/// A tenant created from now on asks its administrators for MFA in the
/// console; one stored before this setting existed keeps what it had.
#[tokio::test]
async fn a_new_tenant_requires_mfa_in_the_console() {
    let s = TestServer::start().await;
    let t = tenant::create(&s.pool, "Northwind", "northwind.example", false)
        .await
        .unwrap();
    assert!(t.settings.require_console_mfa);
    assert!(
        tenant::find_for_admin(&s.pool, &t.id)
            .await
            .unwrap()
            .settings
            .require_console_mfa
    );
    assert!(!TenantSettings::default().require_console_mfa);
    assert_eq!(TenantSettings::default().mfa_mode, MfaMode::Permissive);
}

/// The console's Settings page sets the mode, and the audit row says which.
#[tokio::test]
async fn the_settings_page_sets_the_mode() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/settings", f.tenant.id));
    let page = b.get(&url).await;
    assert!(page.body.contains(r#"value="permissive" checked"#), "{}", page.body);

    let saved = b
        .post(
            &url,
            &[
                ("access_token_lifetime_secs", "3599"),
                ("session_lifetime_secs", "86400"),
                ("refresh_token_lifetime_secs", "7776000"),
                ("mfa_mode", "enforced"),
            ],
        )
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let after = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap().settings;
    assert_eq!(after.mfa_mode, MfaMode::Enforced);
    let (details,): (String,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ? ORDER BY id DESC",
    ))
    .bind("admin.tenant.settings")
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(details.contains(r#""mfaMode":"enforced""#), "{details}");

    // The page shows it, and the user's MFA setting greyed as required.
    let page = b.get(&url).await;
    assert!(page.body.contains(r#"value="enforced" checked"#), "{}", page.body);
    let user = b
        .get(&s.url(&format!(
            "/admin/tenants/{}/users/{}/authentication",
            f.tenant.id, f.user_id
        )))
        .await;
    assert!(user.body.contains("Required (enforced by the tenant)"), "{}", user.body);
}

// ---- "Set up an authenticator?" at sign-in ----

fn params<'a>(f: &'a UserFixture, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "st-suggest"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

async fn suggest(s: &TestServer, f: &UserFixture, on: bool) {
    let mut t = tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap();
    t.settings.suggest_mfa_setup = on;
    tenant::save_settings(&s.pool, &f.tenant.id, &t.settings).await.unwrap();
}

/// Sign in with the password, landing wherever the sign-in goes next.
async fn password(s: &TestServer, f: &UserFixture) -> (Browser, Page) {
    let (_, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(s, &f.tenant.id, &params(f, &challenge)).await;
    let next = b.login(&login, &f.upn, &f.password).await;
    (b, next)
}

/// Answer the suggestion page with one of its two buttons.
async fn answer(b: &Browser, page: &Page, op: &str) -> Page {
    let mut form: Vec<(&str, String)> = vec![("op", op.to_string())];
    for name in ["csrf", "request", "mfa_ticket"] {
        form.push((name, page.field(name).unwrap_or_default()));
    }
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post_form(&page.form_action(), &form).await
}

#[tokio::test]
async fn not_now_carries_on_and_is_not_asked_again_for_a_while() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    suggest(&s, &f, true).await;

    let (b, page) = password(&s, &f).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Protect your account"), "{}", page.body);
    let done = answer(&b, &page, "mfa_setup_later").await;
    assert_eq!(done.status, 302, "signed in: {}", done.body);
    assert!(done.redirect_params().contains_key("code"));

    // Asked again only after the snooze.
    let (_, again) = password(&s, &f).await;
    assert_eq!(again.status, 302, "not asked again yet: {}", again.body);
    let (until,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT snoozed_until FROM mfa_setup_snoozed WHERE user_id = ?",
    ))
    .bind(&f.user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    let left = until - rust_oidc::util::now();
    assert!(left > TenantSettings::MFA_SETUP_SNOOZE_SECS - 60, "{left}");
}

#[tokio::test]
async fn set_it_up_now_goes_on_to_setting_one_up() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    suggest(&s, &f, true).await;
    let (b, page) = password(&s, &f).await;
    let enrol = answer(&b, &page, "mfa_setup_now").await;
    assert_eq!(enrol.status, 200, "{}", enrol.body);
    assert!(enrol.body.contains("Set up your authenticator"), "{}", enrol.body);
}

/// Off (the default), with an authenticator, or under Enforced, there is no offer.
#[tokio::test]
async fn there_is_no_offer_where_it_does_not_apply() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (_, page) = password(&s, &f).await;
    assert_eq!(page.status, 302, "off by default: {}", page.body);

    suggest(&s, &f, true).await;
    set_mode(&s, &f.tenant.id, MfaMode::Enforced).await;
    let (_, page) = password(&s, &f).await;
    assert!(
        page.body.contains("Set up your authenticator"),
        "required, not offered: {}",
        page.body
    );
    assert!(!page.body.contains("Not now"), "{}", page.body);

    set_mode(&s, &f.tenant.id, MfaMode::Permissive).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let (_, page) = password(&s, &f).await;
    assert!(page.body.contains("Enter code"), "{}", page.body);
}

// ---- browser sign-in under Enforced: lockout only when exactly one factor is right ----

const WRONG_CODE_PAGE: &str = "Check the time on your phone";

/// Alice with an authenticator, in a tenant that enforces MFA.
async fn enforced_alice(s: &TestServer) -> (UserFixture, String) {
    let f = user_fixture(s).await;
    let secret = mfa::new_secret();
    mfa::enroll(&s.pool, &f.user_id, &secret).await.unwrap();
    set_mode(s, &f.tenant.id, MfaMode::Enforced).await;
    (f, secret)
}

async fn sign_in(s: &TestServer, f: &UserFixture, upn: &str, password: &str) -> (Browser, Page) {
    let (_, challenge) = pkce();
    let b = Browser::new();
    let login = b.authorize(s, &f.tenant.id, &params(f, &challenge)).await;
    let next = b.login(&login, upn, password).await;
    (b, next)
}

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

async fn counter(s: &TestServer, user_id: &str) -> (i64, Option<i64>) {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT failed_logins, locked_until FROM users WHERE id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

/// Someone with neither the password nor the code cannot lock the account, and
/// is never told which was wrong.
#[tokio::test]
async fn neither_factor_never_locks_and_never_says_which() {
    let s = TestServer::start().await;
    let (f, secret) = enforced_alice(&s).await;
    for _ in 0..12 {
        let (b, page) = sign_in(&s, &f, &f.upn, "Wrong-Horse-9").await;
        assert_eq!(page.status, 200, "a code page, as for a right password: {}", page.body);
        assert!(page.body.contains("Enter code"), "{}", page.body);
        let after = send_code(&b, &page, "000000").await;
        assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
    }
    assert_eq!(counter(&s, &f.user_id).await, (0, None), "never counted");
    // And alice still signs in.
    let (b, page) = sign_in(&s, &f, &f.upn, &f.password).await;
    let done = send_code(
        &b,
        &page,
        &mfa::code_for(&secret, rust_oidc::util::now() + mfa::STEP_SECS),
    )
    .await;
    assert_eq!(done.status, 302, "{}", done.body);
}

/// A right code with a wrong password counts, and is told the password was wrong.
#[tokio::test]
async fn a_right_code_with_a_wrong_password_counts() {
    let s = TestServer::start().await;
    let (f, secret) = enforced_alice(&s).await;
    let (b, page) = sign_in(&s, &f, &f.upn, "Wrong-Horse-9").await;
    let code = mfa::code_for(&secret, rust_oidc::util::now() + mfa::STEP_SECS);
    let after = send_code(&b, &page, &code).await;
    assert!(after.body.contains("AADSTS50126"), "{}", after.body);
    assert_eq!(counter(&s, &f.user_id).await.0, 1);
}

/// A right password with a wrong code counts; both right clear the count.
#[tokio::test]
async fn a_right_password_with_a_wrong_code_counts_and_success_clears() {
    let s = TestServer::start().await;
    let (f, secret) = enforced_alice(&s).await;
    let (b, page) = sign_in(&s, &f, &f.upn, &f.password).await;
    assert_eq!(counter(&s, &f.user_id).await.0, 0, "the password alone settles nothing");
    let after = send_code(&b, &page, "000000").await;
    assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
    assert_eq!(counter(&s, &f.user_id).await.0, 1);
    let done = send_code(
        &b,
        &after,
        &mfa::code_for(&secret, rust_oidc::util::now() + mfa::STEP_SECS),
    )
    .await;
    assert_eq!(done.status, 302, "{}", done.body);
    assert_eq!(counter(&s, &f.user_id).await, (0, None));
}

/// A name that names no account gets the same code page, and the same answer
/// to a code, as a real account with a wrong password.
#[tokio::test]
async fn an_unknown_name_looks_like_a_wrong_password() {
    let s = TestServer::start().await;
    let (f, _) = enforced_alice(&s).await;
    let (b, page) = sign_in(&s, &f, "nobody@contoso.com", "Wrong-Horse-9").await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Enter code"), "{}", page.body);
    let after = send_code(&b, &page, "123456").await;
    assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
}

/// In Permissive a wrong password counts at once, as before: a code page there
/// would say which accounts exist and have an authenticator.
#[tokio::test]
async fn permissive_counts_a_wrong_password_at_once() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    let (_, page) = sign_in(&s, &f, &f.upn, "Wrong-Horse-9").await;
    assert!(page.body.contains("AADSTS50126"), "{}", page.body);
    assert_eq!(counter(&s, &f.user_id).await.0, 1);
}

/// The console, under Enforced: someone without the password or the code
/// cannot lock an administrator out from the console's own sign-in page.
#[tokio::test]
async fn the_console_cannot_be_used_to_lock_an_administrator_out() {
    use rust_oidc::admin::session::CSRF_FIELD;
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();
    set_mode(&s, &f.tenant.id, MfaMode::Enforced).await;
    for _ in 0..12 {
        let b = Browser::new();
        let form = b.get(&s.url("/admin")).await;
        let nonce = form.field(CSRF_FIELD).expect("a login nonce");
        let page = b
            .post_form(
                &s.url("/admin/signin"),
                &[
                    ("upn", f.upn.as_str()),
                    ("password", "Wrong-Horse-9"),
                    (CSRF_FIELD, nonce.as_str()),
                ],
            )
            .await;
        assert!(page.body.contains("Enter code"), "{}", page.body);
        let mut fields: Vec<(String, String)> = Vec::new();
        for name in [CSRF_FIELD, "tenant", "op", "mfa_ticket"] {
            if let Some(v) = page.field(name) {
                fields.push((name.to_string(), v));
            }
        }
        fields.push(("code".into(), "000000".into()));
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let after = b.post_form(&s.url("/admin/signin"), &fields).await;
        assert!(after.body.contains(WRONG_CODE_PAGE), "{}", after.body);
    }
    assert_eq!(counter(&s, &f.user_id).await, (0, None));
}
