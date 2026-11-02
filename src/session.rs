//! Browser sign-in sessions and cookies.
//!
//! One cookie (`rust_oidc_session`) identifies the browser; the `sessions`
//! table maps it to a signed-in user per tenant. On https the cookies are
//! `SameSite=None; Secure` so silent sign-in (`prompt=none` in a hidden
//! iframe) works, as with Entra's cookies; CSRF is covered by a separate
//! double-submit token on the login form.

use crate::db::DbPool;
use axum::http::{HeaderMap, HeaderValue, header};

use crate::config::PublicUrl;
use crate::tenant::{Tenant, TenantSettings};
use crate::util::{b64url, now, random_bytes, sha256_hex};

pub const SESSION_COOKIE: &str = "rust_oidc_session";
pub const CSRF_COOKIE: &str = "rust_oidc_csrf";
/// The browser's "don't ask again on this device" value (see `mfa::remember_device`).
pub const MFA_DEVICE_COOKIE: &str = "rust_oidc_mfa_device";

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    /// Whether the user asked to keep it ("Keep me signed in").
    pub keep: KeepSignedIn,
}

/// The user's answer to "Keep me signed in", as the tenant allows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepSignedIn {
    No,
    Yes,
}

impl KeepSignedIn {
    /// What the sign-in form asked for, honoured only where `tenant` (the one
    /// the session is made in) offers it: a ticked box posted to a tenant that
    /// does not is a plain sign-in.
    pub fn chosen(tenant: &Tenant, ticked: bool) -> Self {
        if ticked && tenant.settings.allow_keep_signed_in {
            Self::Yes
        } else {
            Self::No
        }
    }

    pub fn from_flag(kept: bool) -> Self {
        if kept { Self::Yes } else { Self::No }
    }

    pub fn is_kept(self) -> bool {
        self == Self::Yes
    }

    /// How long a session made in `tenant` lasts.
    pub fn lifetime(self, tenant: &Tenant) -> i64 {
        match self {
            Self::No => tenant.settings.session_lifetime_secs,
            Self::Yes => TenantSettings::KEEP_SIGNED_IN_SECS.max(tenant.settings.session_lifetime_secs),
        }
    }
}

/// A session recorded for this browser: the cookie value, and how long the
/// cookie must live, which is as long as the longest-lived session it carries
/// in any tenant -- one cookie serves them all, so a plain sign-in in one tenant
/// must not cut short a kept one in another. Each session still ends at its own
/// `expires_at`, checked by [`find`].
pub struct Created {
    pub cookie: String,
    pub max_age: i64,
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
    let row: Option<(String, i64, String, crate::db::Flag)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT s.user_id, s.auth_time, s.amr, s.keep_signed_in FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.cookie_hash = ? AND s.tenant_id = ? AND s.expires_at > ? AND u.enabled = ?
           AND u.deleted_at IS NULL",
    ))
    .bind(sha256_hex(cookie.as_bytes()))
    .bind(tenant_id)
    .bind(now())
    .bind(true)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, auth_time, amr, kept)| Session {
        user_id,
        auth_time,
        amr: serde_json::from_str(&amr).unwrap_or_default(),
        keep: KeepSignedIn::from_flag(kept.into()),
    }))
}

/// Record a sign-in for this browser in `tenant`. Reuses the browser's cookie if
/// it has one, so sessions in other tenants are kept.
pub async fn create(
    pool: &DbPool,
    headers: &HeaderMap,
    tenant: &Tenant,
    user_id: &str,
    amr: &[&str],
    keep: KeepSignedIn,
) -> anyhow::Result<Created> {
    let cookie = record(pool, headers, tenant, user_id, amr, keep).await?;
    let max_age = cookie_lifetime(pool, &cookie).await?;
    Ok(Created { cookie, max_age })
}

async fn record(
    pool: &DbPool,
    headers: &HeaderMap,
    tenant: &Tenant,
    user_id: &str,
    amr: &[&str],
    keep: KeepSignedIn,
) -> anyhow::Result<String> {
    let tenant_id = tenant.id.as_str();
    let lifetime = keep.lifetime(tenant);
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
            "UPDATE sessions SET user_id = ?, auth_time = ?, amr = ?, created_at = ?, expires_at = ?, keep_signed_in = ?
             WHERE cookie_hash = ? AND tenant_id = ?",
        ))
        .bind(user_id)
        .bind(ts)
        .bind(&amr_json)
        .bind(ts)
        .bind(ts + lifetime)
        .bind(keep.is_kept())
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
                "INSERT INTO sessions (cookie_hash, tenant_id, user_id, auth_time, amr, created_at, expires_at, keep_signed_in)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ))
            .bind(&hash)
            .bind(tenant_id)
            .bind(user_id)
            .bind(ts)
            .bind(&amr_json)
            .bind(ts)
            .bind(ts + lifetime)
            .bind(keep.is_kept())
            .execute(pool)
            .await,
        )?;
        if done {
            return Ok(cookie);
        }
    }
    anyhow::bail!(
        "session could not be recorded after {} attempts (concurrent writers)",
        crate::db::UPSERT_ATTEMPTS
    )
}

/// Seconds until the last of this cookie's sessions ends, in any tenant.
async fn cookie_lifetime(pool: &DbPool, cookie: &str) -> anyhow::Result<i64> {
    let (latest,): (Option<i64>,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT MAX(expires_at) FROM sessions WHERE cookie_hash = ?",
    ))
    .bind(sha256_hex(cookie.as_bytes()))
    .fetch_one(pool)
    .await?;
    Ok(latest.map_or(0, |at| (at - now()).max(0)))
}

pub async fn end(pool: &DbPool, headers: &HeaderMap, tenant_id: &str) -> anyhow::Result<()> {
    if let Some(cookie) = cookie(headers, SESSION_COOKIE) {
        sqlx::query(crate::db::q(
            pool,
            "DELETE FROM sessions WHERE cookie_hash = ? AND tenant_id = ?",
        ))
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
    let (n,): (i64,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT COUNT(*) FROM sessions WHERE cookie_hash = ? AND expires_at > ?",
    ))
    .bind(sha256_hex(cookie.as_bytes()))
    .bind(now())
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}
