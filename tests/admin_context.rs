//! The console session, and the promise that a grant is recomputed per request.
mod common;
use common::*;

use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::admin::session;
use rust_oidc::rbac::{RoleId, Scope};

fn cookie_headers(cookie: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("{}={cookie}", session::ADMIN_COOKIE).parse().unwrap(),
    );
    headers
}

#[tokio::test]
async fn an_admin_session_round_trips_and_can_be_ended() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let cookie = session::create(&s.pool, &f.user_id, &f.tenant.id).await.unwrap();
    let headers = cookie_headers(&cookie);

    let found = session::find(&s.pool, &headers).await.unwrap().unwrap();
    assert_eq!(found.user_id, f.user_id);
    assert_eq!(found.home_tenant, f.tenant.id);

    session::end(&s.pool, &headers).await.unwrap();
    assert!(session::find(&s.pool, &headers).await.unwrap().is_none());
}

/// The cookie is stored hashed, so a stolen database does not hand over live
/// sessions.
#[tokio::test]
async fn the_session_cookie_is_not_stored_in_the_clear() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let cookie = session::create(&s.pool, &f.user_id, &f.tenant.id).await.unwrap();
    let stored: Vec<(String,)> = sqlx::query_as("SELECT cookie_hash FROM admin_sessions")
        .fetch_all(&s.pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0].0, cookie);
}

#[tokio::test]
async fn an_expired_session_is_not_found() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let cookie = session::create(&s.pool, &f.user_id, &f.tenant.id).await.unwrap();
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE admin_sessions SET expires_at = ? WHERE user_id = ?",
    ))
    .bind(1_i64)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    assert!(
        session::find(&s.pool, &cookie_headers(&cookie))
            .await
            .unwrap()
            .is_none()
    );
}

/// Review Focus 3: grants must be recomputed per request, never cached.
#[tokio::test]
async fn revoking_a_binding_takes_effect_on_the_next_request() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users", f.tenant.id));
    assert_eq!(b.get(&url).await.status, 200);

    sqlx::query("DELETE FROM role_bindings").execute(&s.pool).await.unwrap();

    let after = b.get(&url).await;
    assert_eq!(
        after.status, 403,
        "the session survived but the grant did not: {}",
        after.body
    );
}

#[tokio::test]
async fn losing_group_membership_takes_effect_on_the_next_request() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let group_id = rust_oidc::groups::create(&s.pool, &f.tenant, "admins", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&s.pool, &f.tenant, "admins", &f.upn)
        .await
        .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &group_id,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users", f.tenant.id));
    assert_eq!(b.get(&url).await.status, 200, "the group grants it");

    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
    ))
    .bind(&group_id)
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    assert_eq!(b.get(&url).await.status, 403, "and losing it takes it away");
}

/// Disabling an administrator ends their console session, rather than leaving it
/// usable until it expires.
#[tokio::test]
async fn disabling_an_admin_ends_their_console_session() {
    let s = TestServer::start().await;
    // A tenant's administrator: the last Global Administrator cannot be disabled.
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(b.get(&s.url("/admin/tenants")).await.status, 200);

    rust_oidc::users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false)
        .await
        .unwrap();

    let page = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(page.location.unwrap().ends_with("/admin"), "back to sign-in");
}
