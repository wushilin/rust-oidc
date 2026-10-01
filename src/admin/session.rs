//! The console's own sign-in session.
//!
//! Deliberately separate from [`crate::session`]: that one is a browser's
//! sign-in *to a tenant*, keyed by tenant, and is handed out to any relying
//! party's authorize request. This one is the console's, is not tenant-scoped,
//! and records which tenant a platform administrator has assumed. Mixing the two
//! would mean an OIDC sign-in to any application silently granted console access.
//!
//! The cookie is `SameSite=Lax`, not the `None` the OIDC cookies need for silent
//! sign-in in an iframe: the console is never embedded, and `Lax` means a
//! cross-site form post does not carry it at all.

use axum::http::{HeaderMap, HeaderValue};

use crate::config::PublicUrl;
use crate::db::DbPool;
use crate::util::{b64url, now, random_bytes, sha256_hex};

pub const ADMIN_COOKIE: &str = "rust_oidc_admin";

/// How long a console session lasts. Invented: eight hours, a working day, so an
/// unattended console stops being one by the next morning. Entra's own
/// administrator sessions are shorter but are backed by MFA and re-authentication
/// prompts this does not have yet. Recorded in `docs/decisions-log.md`.
pub const ADMIN_SESSION_LIFETIME_SECS: i64 = 8 * 3600;

/// Domain separation for the CSRF token derived from the session cookie. The
/// token is `sha256(context || cookie)`, so it is unguessable without the cookie
/// and is bound to that one session; no second cookie and no stored column.
const CSRF_CONTEXT: &str = "rust-oidc admin csrf v1";

/// The field every console form submits, echoing [`csrf_for`].
pub const CSRF_FIELD: &str = "csrf";

#[derive(Debug, Clone)]
pub struct AdminSession {
    pub cookie_hash: String,
    pub user_id: String,
    /// The tenant the administrator's own account lives in.
    pub home_tenant: String,
    /// The tenant a platform administrator is acting in, if any.
    pub acting_tenant: Option<String>,
}

/// The CSRF token for the session whose cookie value is `cookie`.
pub fn csrf_for(cookie: &str) -> String {
    sha256_hex(format!("{CSRF_CONTEXT}{cookie}").as_bytes())
}

/// Start a console session and return the cookie value to set.
pub async fn create(pool: &DbPool, user_id: &str, home_tenant: &str) -> anyhow::Result<String> {
    let cookie = b64url(&random_bytes(32));
    let ts = now();
    // Expired rows are nobody's session; clear them while we are writing anyway,
    // because there is no scheduler in this process.
    sqlx::query(crate::db::q(pool, "DELETE FROM admin_sessions WHERE expires_at < ?"))
        .bind(ts)
        .execute(pool)
        .await?;
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO admin_sessions (cookie_hash, user_id, home_tenant, acting_tenant, created_at, expires_at)
         VALUES (?, ?, ?, NULL, ?, ?)",
    ))
    .bind(sha256_hex(cookie.as_bytes()))
    .bind(user_id)
    .bind(home_tenant)
    .bind(ts)
    .bind(ts + ADMIN_SESSION_LIFETIME_SECS)
    .execute(pool)
    .await?;
    Ok(cookie)
}

/// The live session this request's cookie names, if any.
pub async fn find(pool: &DbPool, headers: &HeaderMap) -> anyhow::Result<Option<AdminSession>> {
    let Some(cookie) = crate::session::cookie(headers, ADMIN_COOKIE) else {
        return Ok(None);
    };
    let hash = sha256_hex(cookie.as_bytes());
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT user_id, home_tenant, acting_tenant FROM admin_sessions
         WHERE cookie_hash = ? AND expires_at > ?",
    ))
    .bind(&hash)
    .bind(now())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, home_tenant, acting_tenant)| AdminSession {
        cookie_hash: hash,
        user_id,
        home_tenant,
        acting_tenant,
    }))
}

/// Enter (`Some`) or leave (`None`) an assumed tenant.
pub async fn set_acting_tenant(pool: &DbPool, cookie_hash: &str, tenant_id: Option<&str>) -> anyhow::Result<()> {
    sqlx::query(crate::db::q(
        pool,
        "UPDATE admin_sessions SET acting_tenant = ? WHERE cookie_hash = ?",
    ))
    .bind(tenant_id)
    .bind(cookie_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn end(pool: &DbPool, headers: &HeaderMap) -> anyhow::Result<()> {
    if let Some(cookie) = crate::session::cookie(headers, ADMIN_COOKIE) {
        sqlx::query(crate::db::q(pool, "DELETE FROM admin_sessions WHERE cookie_hash = ?"))
            .bind(sha256_hex(cookie.as_bytes()))
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// `Set-Cookie` for the console session. `SameSite=Lax` unlike
/// [`crate::session::set_cookie`]: see the module comment.
pub fn set_cookie(url: &PublicUrl, value: &str, max_age: i64) -> HeaderValue {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let secure = if url.base().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{ADMIN_COOKIE}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    ))
    .expect("cookie value is ASCII")
}

pub fn clear_cookie(url: &PublicUrl) -> HeaderValue {
    set_cookie(url, "", 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_csrf_token_is_bound_to_the_session_cookie() {
        assert_eq!(csrf_for("abc"), csrf_for("abc"));
        assert_ne!(csrf_for("abc"), csrf_for("abd"));
        // Not the cookie itself, and not the value stored in the database either.
        assert_ne!(csrf_for("abc"), "abc");
        assert_ne!(csrf_for("abc"), sha256_hex(b"abc"));
    }

    #[test]
    fn the_console_cookie_is_lax_and_http_only() {
        let url = PublicUrl::parse("https://auth.example.com/rust-oidc").unwrap();
        let header = set_cookie(&url, "v", 60).to_str().unwrap().to_string();
        assert!(header.contains("SameSite=Lax"), "{header}");
        assert!(header.contains("HttpOnly"), "{header}");
        assert!(header.contains("Secure"), "{header}");
        assert!(header.contains("Path=/rust-oidc"), "{header}");
    }
}
