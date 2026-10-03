//! The console's own sign-in session.
//!
//! Deliberately separate from [`crate::session`]: that one is a browser's
//! sign-in *to a tenant*, keyed by tenant, and is handed out to any relying
//! party's authorize request. This one is the console's, is not tenant-scoped,
//! and is not handed to any application. Mixing the two
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

/// Cookie carrying the nonce that protects the *sign-in* form.
///
/// [`csrf_for`] cannot protect that form: it derives the token from the session
/// cookie, and at sign-in there is no session yet. Without this a third-party
/// page could post credentials the attacker controls and silently place the
/// victim in the attacker's console session (login CSRF).
pub const LOGIN_NONCE_COOKIE: &str = "rust_oidc_admin_login";

/// Long enough to fill in a password manager prompt, short enough that a stale
/// tab does not keep a usable nonce all day. Invented.
pub const LOGIN_NONCE_LIFETIME_SECS: i64 = 900;

/// Domain separation for the sign-in nonce, kept distinct from [`CSRF_CONTEXT`]
/// so a token minted for one purpose can never satisfy the other.
const LOGIN_NONCE_CONTEXT: &str = "rust-oidc admin login nonce v1";

/// A fresh sign-in nonce: the cookie value to set, and the token the form carries.
/// The form never carries the cookie value itself, so a page that leaks its own
/// HTML does not leak the cookie.
pub fn new_login_nonce() -> (String, String) {
    let cookie = b64url(&random_bytes(32));
    let token = login_token_for(&cookie);
    (cookie, token)
}

/// The form token belonging to a sign-in nonce cookie.
pub fn login_token_for(cookie: &str) -> String {
    sha256_hex(format!("{LOGIN_NONCE_CONTEXT}{cookie}").as_bytes())
}

/// Whether a submitted sign-in form carries the token for the nonce cookie the
/// browser was given. Compared in constant time; a missing cookie or token fails.
pub fn login_nonce_ok(headers: &HeaderMap, submitted: &str) -> bool {
    let Some(cookie) = crate::session::cookie(headers, LOGIN_NONCE_COOKIE) else {
        return false;
    };
    !submitted.is_empty() && crate::util::ct_eq(&login_token_for(&cookie), submitted)
}

/// Set the sign-in nonce cookie.
pub fn set_login_nonce(url: &PublicUrl, value: &str, max_age: i64) -> HeaderValue {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let secure = if url.base().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{LOGIN_NONCE_COOKIE}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    ))
    .expect("cookie value is ASCII")
}

/// Clear it, once it has been spent.
pub fn clear_login_nonce(url: &PublicUrl) -> HeaderValue {
    set_login_nonce(url, "", 0)
}

#[derive(Debug, Clone)]
pub struct AdminSession {
    pub cookie_hash: String,
    pub user_id: String,
    /// The tenant the administrator's own account lives in.
    pub home_tenant: String,
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
    let row: Option<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT user_id, home_tenant FROM admin_sessions
         WHERE cookie_hash = ? AND expires_at > ?",
    ))
    .bind(&hash)
    .bind(now())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, home_tenant)| AdminSession {
        cookie_hash: hash,
        user_id,
        home_tenant,
    }))
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
