//! Tenant settings, through HTTP: the first write path `TenantSettings` has ever
//! had.
//!
//! The bounds this section enforces are invented (see `docs/decisions-log.md`), so
//! they are pinned here: a value outside one must be refused *and* must leave the
//! stored settings alone, because a partially applied change would be worse than a
//! refused one.

mod common;

use common::*;
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::tenant::{self, TenantSettings};

async fn settings_of(s: &TestServer, tenant_id: &str) -> TenantSettings {
    tenant::find_for_admin(&s.pool, tenant_id).await.unwrap().settings
}

fn form(access: &str, session: &str, refresh: &str) -> Vec<(&'static str, String)> {
    vec![
        ("access_token_lifetime_secs", access.to_string()),
        ("session_lifetime_secs", session.to_string()),
        ("refresh_token_lifetime_secs", refresh.to_string()),
    ]
}

/// `AdminBrowser::post` takes `&[(&str, &str)]`; the forms above own their values.
fn as_pairs<'a>(form: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    form.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

#[tokio::test]
async fn the_lifetimes_are_saved_and_shown_back() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/settings", f.tenant.id));

    // Until now nothing has ever written these: the tenant carries the defaults.
    let before = settings_of(&s, &f.tenant.id).await;
    assert_eq!(before.access_token_lifetime_secs, 3599);

    let page = b.get(&url).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("3599"), "{}", page.body);

    let saved = b.post(&url, &as_pairs(&form("1800", "7200", "1209600"))).await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let after = settings_of(&s, &f.tenant.id).await;
    assert_eq!(after.access_token_lifetime_secs, 1800);
    assert_eq!(after.session_lifetime_secs, 7200);
    assert_eq!(after.refresh_token_lifetime_secs, 1_209_600);

    // Read back, the page shows what was stored.
    let page = b.get(&url).await;
    assert!(page.body.contains("1800"), "{}", page.body);
    assert!(page.body.contains("1209600"), "{}", page.body);

    // Lifetimes are configuration, not anybody's data, so the row carries them.
    let rows = audit_rows(&s, "admin.tenant.settings").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.user_id);
    assert_eq!(rows[0].2.as_deref(), Some(f.tenant.id.as_str()));
}

#[tokio::test]
async fn a_lifetime_outside_its_bounds_is_refused_and_changes_nothing() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/settings", f.tenant.id));
    let before = settings_of(&s, &f.tenant.id).await;

    let refused = [
        // Below and above each bound.
        form(
            &(TenantSettings::MIN_ACCESS_TOKEN_SECS - 1).to_string(),
            "7200",
            "1209600",
        ),
        form(
            &(TenantSettings::MAX_ACCESS_TOKEN_SECS + 1).to_string(),
            "7200",
            "1209600",
        ),
        form("1800", "1", "1209600"),
        form("1800", &(TenantSettings::MAX_SESSION_SECS + 1).to_string(), "1209600"),
        form("1800", "7200", &(TenantSettings::MIN_REFRESH_SECS - 1).to_string()),
        form("1800", "7200", &(TenantSettings::MAX_REFRESH_SECS + 1).to_string()),
        // A refresh token that expires before the access token it mints.
        form("7200", "7200", "3600"),
        // Not a number at all, which must not be read as a default.
        form("an hour", "7200", "1209600"),
        form("", "", ""),
    ];
    for fields in refused {
        let page = b.post(&url, &as_pairs(&fields)).await;
        assert_eq!(page.status, 400, "{fields:?} was accepted: {}", page.body);
        let now = settings_of(&s, &f.tenant.id).await;
        assert_eq!(
            (
                now.access_token_lifetime_secs,
                now.session_lifetime_secs,
                now.refresh_token_lifetime_secs
            ),
            (
                before.access_token_lifetime_secs,
                before.session_lifetime_secs,
                before.refresh_token_lifetime_secs
            ),
            "{fields:?} changed the stored settings"
        );
    }
    assert!(
        audit_rows(&s, "admin.tenant.settings").await.is_empty(),
        "a refused change was recorded as one"
    );
    // The form shows the stored values again, not the rejected ones.
    let page = b.post(&url, &as_pairs(&form("1", "1", "1"))).await;
    assert!(page.body.contains("3599"), "{}", page.body);
    assert!(!page.body.contains(r#"value="1""#), "{}", page.body);
}

/// A role with `Tenant:Read` but not `Tenant:Write` may look and not touch.
#[tokio::test]
async fn a_reader_sees_the_settings_but_cannot_change_them() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/settings", f.tenant.id));

    let page = b.get(&url).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("3599"), "{}", page.body);
    assert!(!page.body.contains("Save settings"), "{}", page.body);

    let refused = b.post(&url, &as_pairs(&form("1800", "7200", "1209600"))).await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(settings_of(&s, &f.tenant.id).await.access_token_lifetime_secs, 3599);
}

/// The isolation test for this section.
#[tokio::test]
async fn a_tenant_admin_cannot_read_or_write_another_tenants_settings() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    for path in [
        format!("/admin/tenants/{}/settings", other.id),
        "/admin/tenants/fabrikam.test/settings".to_string(),
    ] {
        let page = b.get(&s.url(&path)).await;
        assert!(
            page.status == 403 || page.status == 404,
            "GET {path} leaked with {}: {}",
            page.status,
            page.body
        );
        let write = b.post(&s.url(&path), &as_pairs(&form("300", "300", "3600"))).await;
        assert!(
            write.status == 403 || write.status == 404,
            "POST {path} leaked with {}: {}",
            write.status,
            write.body
        );
    }
    // The other tenant still issues what it did.
    let untouched = settings_of(&s, &other.id).await;
    assert_eq!(untouched.access_token_lifetime_secs, 3599);
    assert_eq!(untouched.session_lifetime_secs, 86_400);
    assert!(audit_rows(&s, "admin.tenant.settings").await.is_empty());

    // Their own tenant's settings they may change, so the refusal is about
    // identity and not about the route.
    let own = s.url(&format!("/admin/tenants/{}/settings", f.tenant.id));
    let saved = b.post(&own, &as_pairs(&form("1800", "7200", "1209600"))).await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    assert_eq!(settings_of(&s, &f.tenant.id).await.access_token_lifetime_secs, 1800);
}

/// A tenant administrator bound to one tenant holds `Tenant:Write` there, which is
/// what the settings page requires — but a *platform* administrator holds it
/// everywhere, which is how the same page serves both.
#[tokio::test]
async fn a_platform_administrator_can_set_any_tenants_settings() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    bind(&s, &f.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let url = s.url(&format!("/admin/tenants/{}/settings", other.id));
    let saved = b.post(&url, &as_pairs(&form("600", "3600", "86400"))).await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    assert_eq!(settings_of(&s, &other.id).await.access_token_lifetime_secs, 600);
}
