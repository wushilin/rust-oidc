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
