//! Browser sign-in sessions and cookies.
//!
//! One cookie (`rust_oidc_session`) identifies the browser; the `sessions`
//! table maps it to a signed-in user per tenant. On https the cookies are
//! `SameSite=None; Secure` so silent sign-in (`prompt=none` in a hidden
//! iframe) works, as with Entra's cookies; CSRF is covered by a separate
//! double-submit token on the login form.

use axum::http::{HeaderMap, HeaderValue, header};
use crate::db::DbPool;

use crate::config::PublicUrl;
use crate::util::{b64url, now, random_bytes, sha256_hex};

pub const SESSION_COOKIE: &str = "rust_oidc_session";
pub const CSRF_COOKIE: &str = "rust_oidc_csrf";

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

pub fn set_cookie(url: &PublicUrl, name: &str, value: &str, max_age: i64) -> HeaderValue {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let secure = url.base().starts_with("https://");
    let same_site = if secure { "None; Secure" } else { "Lax" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite={same_site}"
    ))
    .expect("cookie value is ASCII")
}

pub fn clear_cookie(url: &PublicUrl, name: &str) -> HeaderValue {
    set_cookie(url, name, "", 0)
}

pub fn new_token() -> String {
    b64url(&random_bytes(32))
}

pub async fn find(pool: &DbPool, headers: &HeaderMap, tenant_id: &str) -> anyhow::Result<Option<Session>> {
    let Some(cookie) = cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let row: Option<(String, i64, String)> = sqlx::query_as(
        crate::db::q(pool, "SELECT s.user_id, s.auth_time, s.amr FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.cookie_hash = ? AND s.tenant_id = ? AND s.expires_at > ? AND u.enabled = ?"),
    )
    .bind(sha256_hex(cookie.as_bytes()))
    .bind(tenant_id)
    .bind(now())
    .bind(true)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, auth_time, amr)| Session {
        user_id,
        auth_time,
        amr: serde_json::from_str(&amr).unwrap_or_default(),
    }))
}

/// Record a sign-in for this browser in `tenant_id`. Reuses the browser's
/// cookie if it has one, so sessions in other tenants are kept. Returns the
/// cookie value to set.
pub async fn create(
    pool: &DbPool,
    headers: &HeaderMap,
    tenant_id: &str,
    user_id: &str,
    amr: &[&str],
    lifetime: i64,
) -> anyhow::Result<String> {
    let cookie = cookie(headers, SESSION_COOKIE).unwrap_or_else(new_token);
    let ts = now();
    let engine = crate::db::engine_of(pool);
    let hash = sha256_hex(cookie.as_bytes());
    let amr_json = serde_json::to_string(amr)?;
    // Refresh the browser's row if it exists, else insert; a unique violation
    // means a concurrent sign-in inserted it first, so go round and refresh.
    for _ in 0..crate::db::UPSERT_ATTEMPTS {
        let updated = sqlx::query(crate::db::sql_stmt(
            engine,
            "UPDATE sessions SET user_id = ?, auth_time = ?, amr = ?, created_at = ?, expires_at = ?
             WHERE cookie_hash = ? AND tenant_id = ?",
        ))
        .bind(user_id)
        .bind(ts)
        .bind(&amr_json)
        .bind(ts)
        .bind(ts + lifetime)
        .bind(&hash)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        if updated.rows_affected() > 0 {
            return Ok(cookie);
        }
        let done = crate::db::inserted(
            sqlx::query(crate::db::sql_stmt(
                engine,
                "INSERT INTO sessions (cookie_hash, tenant_id, user_id, auth_time, amr, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            ))
            .bind(&hash)
            .bind(tenant_id)
            .bind(user_id)
            .bind(ts)
            .bind(&amr_json)
            .bind(ts)
            .bind(ts + lifetime)
            .execute(pool)
            .await,
        )?;
        if done {
            return Ok(cookie);
        }
    }
    anyhow::bail!("session could not be recorded after {} attempts (concurrent writers)", crate::db::UPSERT_ATTEMPTS)
}

pub async fn end(pool: &DbPool, headers: &HeaderMap, tenant_id: &str) -> anyhow::Result<()> {
    if let Some(cookie) = cookie(headers, SESSION_COOKIE) {
        sqlx::query(crate::db::q(pool, "DELETE FROM sessions WHERE cookie_hash = ? AND tenant_id = ?"))
            .bind(sha256_hex(cookie.as_bytes()))
            .bind(tenant_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Whether this browser still has a session in any tenant.
pub async fn has_any(pool: &DbPool, headers: &HeaderMap) -> anyhow::Result<bool> {
    let Some(cookie) = cookie(headers, SESSION_COOKIE) else {
        return Ok(false);
    };
    let (n,): (i64,) = sqlx::query_as(crate::db::q(pool, "SELECT COUNT(*) FROM sessions WHERE cookie_hash = ? AND expires_at > ?"))
        .bind(sha256_hex(cookie.as_bytes()))
        .bind(now())
        .fetch_one(pool)
        .await?;
    Ok(n > 0)
}
