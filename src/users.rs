use crate::db::DbPool;
use anyhow::{Context, anyhow, bail};
use argon2::{Argon2, PasswordHasher};

use crate::tenant::{self, Tenant};
use crate::util::{new_guid, now};

pub struct NewUser<'a> {
    pub upn: &'a str,
    pub password: &'a str,
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Like Entra, a UPN must be `local@domain` where `domain` is verified in the tenant.
pub async fn validate_upn(pool: &DbPool, tenant: &Tenant, upn: &str) -> anyhow::Result<String> {
    let upn = upn.trim();
    let Some((local, domain)) = upn.rsplit_once('@') else {
        bail!("UPN '{upn}' must be in the form user@domain");
    };
    if local.is_empty() || local.chars().any(|c| c.is_whitespace() || c == '@') {
        bail!("invalid UPN '{upn}'");
    }
    let domain = tenant::normalize_domain(domain)?;
    if !tenant::domains(pool, &tenant.id).await?.contains(&domain) {
        bail!("domain '{domain}' is not a verified domain of tenant '{}'", tenant.name);
    }
    Ok(format!("{local}@{domain}"))
}

pub async fn create(pool: &DbPool, tenant: &Tenant, user: NewUser<'_>) -> anyhow::Result<String> {
    let upn = validate_upn(pool, tenant, user.upn).await?;
    if user.password.chars().count() < 8 {
        bail!("password must be at least 8 characters");
    }
    let id = new_guid();
    let ts = now();
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO users (id, tenant_id, upn, upn_folded, email, email_verified, display_name, given_name,
                            family_name, password_hash, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(&tenant.id)
    .bind(&upn)
    .bind(crate::util::fold(&upn))
    .bind(user.email)
    .bind(false)
    .bind(user.display_name)
    .bind(user.given_name)
    .bind(user.family_name)
    .bind(hash_password(user.password)?)
    .bind(true)
    .bind(ts)
    .bind(ts)
    .execute(pool)
    .await?;
    Ok(id)
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub upn: String,
    pub email: Option<String>,
    #[sqlx(try_from = "crate::db::Flag")]
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    #[sqlx(try_from = "crate::db::Flag")]
    pub enabled: bool,
}

pub async fn find(pool: &DbPool, tenant_id: &str, user_id: &str) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

pub enum AuthResult {
    Ok(User),
    /// Unknown user or wrong password (indistinguishable to the caller).
    InvalidCredentials,
    Locked,
    Disabled,
}

/// Entra smart lockout: 10 failures lock the account for 60 seconds, doubling
/// with each further failure up to an hour.
const LOCKOUT_THRESHOLD: i64 = 10;

fn lockout_secs(failures: i64) -> i64 {
    let extra = (failures - LOCKOUT_THRESHOLD).clamp(0, 6) as u32;
    (60 * 2i64.pow(extra)).min(3600)
}

/// A fixed hash to verify against when the user does not exist, so unknown
/// and known accounts take the same time.
static DUMMY_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| hash_password("not-a-real-password").expect("argon2"));

/// What an authentication attempt learned beyond the caller-visible
/// [`AuthResult`], for the audit log only. It must never reach an HTTP
/// response: it tells an unknown account from a wrong password.
#[derive(Debug, Default)]
pub struct AuthTrace {
    /// The account the name resolved to, if any.
    pub user_id: Option<String>,
    /// This very attempt pushed the account over the lockout threshold.
    pub lockout_triggered: bool,
}

pub async fn authenticate(pool: &DbPool, tenant: &Tenant, upn: &str, password: &str) -> anyhow::Result<AuthResult> {
    Ok(authenticate_traced(pool, tenant, upn, password).await?.0)
}

/// [`authenticate`], plus the [`AuthTrace`] the audit log needs.
pub async fn authenticate_traced(
    pool: &DbPool,
    tenant: &Tenant,
    upn: &str,
    password: &str,
) -> anyhow::Result<(AuthResult, AuthTrace)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        password_hash: Option<String>,
        #[sqlx(try_from = "crate::db::Flag")]
        enabled: bool,
        failed_logins: i64,
        locked_until: Option<i64>,
    }
    let row: Option<Row> = sqlx::query_as(
        crate::db::q(pool, "SELECT id, password_hash, enabled, failed_logins, locked_until FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL"),
    )
    .bind(&tenant.id)
    .bind(crate::util::fold(upn))
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        let _ = verify_password(password, &DUMMY_HASH);
        return Ok((AuthResult::InvalidCredentials, AuthTrace::default()));
    };
    let ts = now();
    let mut trace = AuthTrace {
        user_id: Some(row.id.clone()),
        lockout_triggered: false,
    };
    if row.locked_until.is_some_and(|until| until > ts) {
        return Ok((AuthResult::Locked, trace));
    }
    let ok = row
        .password_hash
        .as_deref()
        .is_some_and(|h| verify_password(password, h));
    if !ok {
        let failures = row.failed_logins + 1;
        let locked_until = (failures >= LOCKOUT_THRESHOLD).then(|| ts + lockout_secs(failures));
        sqlx::query(crate::db::q(
            pool,
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
        ))
        .bind(failures)
        .bind(locked_until)
        .bind(&row.id)
        .execute(pool)
        .await?;
        trace.lockout_triggered = locked_until.is_some();
        return Ok((AuthResult::InvalidCredentials, trace));
    }
    if !row.enabled {
        return Ok((AuthResult::Disabled, trace));
    }
    sqlx::query(crate::db::q(
        pool,
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
    ))
    .bind(&row.id)
    .execute(pool)
    .await?;
    let user = find(pool, &tenant.id, &row.id).await?.context("user vanished")?;
    Ok((AuthResult::Ok(user), trace))
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::PasswordVerifier;
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

pub async fn set_password(pool: &DbPool, tenant: &Tenant, upn: &str, password: &str) -> anyhow::Result<()> {
    if password.chars().count() < 8 {
        bail!("password must be at least 8 characters");
    }
    let res = sqlx::query(crate::db::q(
        pool,
        "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, updated_at = ?
         WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(hash_password(password)?)
    .bind(now())
    .bind(&tenant.id)
    .bind(crate::util::fold(upn))
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        bail!("user '{upn}' not found");
    }
    // As in Entra, a password reset revokes the user's refresh tokens and sessions.
    let user: (String,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(&tenant.id)
    .bind(crate::util::fold(upn))
    .fetch_one(pool)
    .await?;
    sqlx::query(crate::db::q(
        pool,
        "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
    ))
    .bind(now())
    .bind(&user.0)
    .execute(pool)
    .await?;
    sqlx::query(crate::db::q(pool, "DELETE FROM sessions WHERE user_id = ?"))
        .bind(&user.0)
        .execute(pool)
        .await?;
    Ok(())
}

/// Largest page the console will ask for, so a tenant with many users cannot
/// produce an unbounded response. Invented; paging the console past this is a
/// later task.
pub const LIST_LIMIT: i64 = 200;

/// A page of users in a tenant, optionally filtered by UPN or display name.
/// Soft-deleted users are never returned.
///
/// UPN matching is against `upn_folded`, so it is case-insensitive the same way
/// on every engine. Display-name matching is a plain `LIKE` and is therefore
/// case-sensitive on SQLite and Postgres and case-insensitive under MySQL's
/// default collation; display names are not identities, so the difference is
/// cosmetic. `%` and `_` in the search term are wildcards.
pub async fn list(
    pool: &DbPool,
    tenant_id: &str,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<User>> {
    let pattern = match query.map(str::trim).filter(|q| !q.is_empty()) {
        Some(q) => format!("%{q}%"),
        None => "%".to_string(),
    };
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users
         WHERE tenant_id = ? AND deleted_at IS NULL
           AND (upn_folded LIKE ? OR COALESCE(display_name, '') LIKE ?)
         ORDER BY upn LIMIT ? OFFSET ?",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(&pattern))
    .bind(&pattern)
    .bind(limit.clamp(1, LIST_LIMIT))
    .bind(offset.max(0))
    .fetch_all(pool)
    .await?)
}

/// The attributes the console can edit. Not the UPN: changing an identity is a
/// different operation from editing a profile, and nothing needs it yet.
pub struct UserAttributes<'a> {
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub email_verified: bool,
}

/// Overwrite a user's profile attributes. `false` when no such live user exists
/// **in that tenant**: `tenant_id` is in the `WHERE`, so a handler cannot be
/// talked into editing another tenant's user by guessing an id.
pub async fn update_attributes(
    pool: &DbPool,
    tenant_id: &str,
    user_id: &str,
    attrs: &UserAttributes<'_>,
) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::q(
        pool,
        "UPDATE users SET display_name = ?, given_name = ?, family_name = ?, email = ?,
                          email_verified = ?, updated_at = ?
         WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(attrs.display_name)
    .bind(attrs.given_name)
    .bind(attrs.family_name)
    .bind(attrs.email)
    .bind(attrs.email_verified)
    .bind(now())
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Enable or disable a user. Disabling also ends their browser sessions and
/// revokes their refresh tokens: leaving those alive would mean a disabled
/// account kept working until every token expired.
pub async fn set_enabled(pool: &DbPool, tenant_id: &str, user_id: &str, enabled: bool) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let done = sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE users SET enabled = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(enabled)
    .bind(now())
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    if !enabled {
        revoke_access(&mut tx, engine, user_id).await?;
    }
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// Mark a user deleted. Kept rather than removed so audit rows and the `oid` in
/// already-issued tokens still resolve to something, and so the UPN is not freed
/// for reuse by a different person.
pub async fn soft_delete(pool: &DbPool, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of(pool);
    let ts = now();
    let mut tx = pool.begin().await?;
    let done = sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE users SET deleted_at = ?, enabled = ?, updated_at = ?
         WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(ts)
    .bind(false)
    .bind(ts)
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    revoke_access(&mut tx, engine, user_id).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// End every live credential a user holds: browser sessions, console sessions and
/// refresh tokens. One definition, so disabling and deleting cannot diverge.
async fn revoke_access(tx: &mut sqlx::AnyConnection, engine: crate::db::Engine, user_id: &str) -> anyhow::Result<()> {
    sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM sessions WHERE user_id = ?"))
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM admin_sessions WHERE user_id = ?",
    ))
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
    ))
    .bind(now())
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// A live user by UPN within a tenant. Case-insensitive, through `upn_folded`,
/// like every other identity lookup.
pub async fn find_by_upn(pool: &DbPool, tenant_id: &str, upn: &str) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .fetch_optional(pool)
    .await?)
}
