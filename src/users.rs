use crate::admin::lockout;
use crate::db::Handle;
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
pub async fn validate_upn<'c>(db: impl Handle<'c>, tenant: &Tenant, upn: &str) -> anyhow::Result<String> {
    let mut conn = db.acquire().await?;
    validate_upn_in(&mut conn, tenant, upn).await
}

pub(crate) async fn validate_upn_in(conn: &mut crate::db::Conn, tenant: &Tenant, upn: &str) -> anyhow::Result<String> {
    let upn = upn.trim();
    let Some((local, domain)) = upn.rsplit_once('@') else {
        bail!("UPN '{upn}' must be in the form user@domain");
    };
    if local.is_empty() || local.chars().any(|c| c.is_whitespace() || c == '@') {
        bail!("invalid UPN '{upn}'");
    }
    let domain = tenant::normalize_domain(domain)?;
    if !tenant::domains_in(&mut *conn, &tenant.id).await?.contains(&domain) {
        bail!("domain '{domain}' is not a verified domain of tenant '{}'", tenant.name);
    }
    Ok(format!("{local}@{domain}"))
}

pub async fn create<'c>(db: impl Handle<'c>, tenant: &Tenant, user: NewUser<'_>) -> anyhow::Result<String> {
    let password = NewPassword::for_new_account(user.password)?;
    let mut conn = db.acquire().await?;
    create_in(&mut conn, tenant, &user.account(), &password).await
}

/// A new account, without its password: what [`create_in`] stores beside a
/// [`NewPassword`] prepared before the transaction began.
#[derive(Debug, Clone, Copy)]
pub struct NewAccount<'a> {
    pub upn: &'a str,
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
}

impl<'a> NewUser<'a> {
    pub fn account(&self) -> NewAccount<'a> {
        NewAccount {
            upn: self.upn,
            display_name: self.display_name,
            given_name: self.given_name,
            family_name: self.family_name,
            email: self.email,
        }
    }
}

pub(crate) async fn create_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    user: &NewAccount<'_>,
    password: &NewPassword,
) -> anyhow::Result<String> {
    let upn = validate_upn_in(&mut *conn, tenant, user.upn).await?;
    // Looked for first, deleted accounts included (they keep their name): inside
    // a transaction the unique index would be a database failure, not a refusal.
    let taken: Option<(Option<i64>,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT deleted_at FROM users WHERE tenant_id = ? AND upn_folded = ?",
    ))
    .bind(&tenant.id)
    .bind(crate::util::fold(&upn))
    .fetch_optional(&mut *conn)
    .await?;
    match taken {
        Some((None,)) => bail!("user '{upn}' already exists"),
        Some((Some(_),)) => bail!("a deleted account is named '{upn}'; restore it instead"),
        None => {}
    }
    let id = new_guid();
    let ts = now();
    sqlx::query(crate::db::qc(
        &conn,
        "INSERT INTO users (id, tenant_id, upn, upn_folded, email, email_verified, display_name, given_name,
                            family_name, password_hash, enabled, must_change_password, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(&password.hash)
    .bind(true)
    .bind(password.by == PasswordSetBy::AdminTemporary)
    .bind(ts)
    .bind(ts)
    .execute(&mut *conn)
    .await?;
    let engine = crate::db::engine_of_conn(&conn);
    remember_password(&mut *conn, engine, &id, &password.hash).await?;
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

/// A live account by its object id, whatever its tenant: for an application
/// that accepts accounts of other tenants, where the account need not be of the
/// tenant the request came to. What it may do there is [`crate::access`]'s to say.
pub async fn find_by_id<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Option<User>> {
    let mut conn = db.acquire().await?;
    find_by_id_in(&mut conn, user_id).await
}

pub(crate) async fn find_by_id_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users WHERE id = ? AND deleted_at IS NULL",
    ))
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?)
}

pub async fn find<'c>(db: impl Handle<'c>, tenant_id: &str, user_id: &str) -> anyhow::Result<Option<User>> {
    let mut conn = db.acquire().await?;
    find_in(&mut conn, tenant_id, user_id).await
}

pub(crate) async fn find_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    user_id: &str,
) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
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

pub async fn authenticate<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    upn: &str,
    password: &str,
) -> anyhow::Result<AuthResult> {
    let mut conn = db.acquire().await?;
    authenticate_in(&mut conn, tenant, upn, password).await
}

pub(crate) async fn authenticate_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    upn: &str,
    password: &str,
) -> anyhow::Result<AuthResult> {
    Ok(authenticate_traced_in(&mut *conn, tenant, upn, password).await?.0)
}

/// [`authenticate`], plus the [`AuthTrace`] the audit log needs.
pub async fn authenticate_traced<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    upn: &str,
    password: &str,
) -> anyhow::Result<(AuthResult, AuthTrace)> {
    let mut conn = db.acquire().await?;
    authenticate_traced_in(&mut conn, tenant, upn, password).await
}

pub(crate) async fn authenticate_traced_in(
    conn: &mut crate::db::Conn,
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
        crate::db::qc(&conn, "SELECT id, password_hash, enabled, failed_logins, locked_until FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL"),
    )
    .bind(&tenant.id)
    .bind(crate::util::fold(upn))
    .fetch_optional(&mut *conn)
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
        sqlx::query(crate::db::qc(
            &conn,
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
        ))
        .bind(failures)
        .bind(locked_until)
        .bind(&row.id)
        .execute(&mut *conn)
        .await?;
        trace.lockout_triggered = locked_until.is_some();
        return Ok((AuthResult::InvalidCredentials, trace));
    }
    if !row.enabled {
        return Ok((AuthResult::Disabled, trace));
    }
    sqlx::query(crate::db::qc(
        &conn,
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
    ))
    .bind(&row.id)
    .execute(&mut *conn)
    .await?;
    let user = find_in(&mut *conn, &tenant.id, &row.id)
        .await?
        .context("user vanished")?;
    Ok((AuthResult::Ok(user), trace))
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::PasswordVerifier;
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

/// Who is setting a password, which decides what it is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSetBy {
    /// An administrator's temporary password: the user must replace it at their
    /// next sign-in. Not held to the history rule; the replacement is.
    AdminTemporary,
    /// An administrator setting a password the user keeps.
    Admin,
    /// The user, choosing their own.
    User,
}

/// The most passwords a tenant may remember, and how many are kept per user.
pub const MAX_PASSWORD_HISTORY: i64 = 24;

/// Refusal of a password that is one of the user's last few.
#[derive(Debug, thiserror::Error)]
#[error("That password was used recently. Choose one that is not among the last {0} used for this account.")]
pub struct PasswordReused(pub i64);

/// The fewest characters a password may have.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// A password checked against the rules and hashed, ready to store.
///
/// Hashing (and checking a password against the remembered ones) is deliberately
/// slow, so it happens before a transaction begins: a transaction is given one of
/// these, never a plain password. The only ways to make one are
/// [`NewPassword::for_new_account`] and [`prepare_password`], which apply the rules.
#[derive(Clone)]
pub struct NewPassword {
    hash: String,
    by: PasswordSetBy,
}

impl std::fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPassword")
            .field("by", &self.by)
            .finish_non_exhaustive()
    }
}

impl NewPassword {
    /// The first password of an account an administrator is creating: there is
    /// no history yet. `temporary` makes them choose their own at first sign-in.
    pub fn for_new_account_as(password: &str, by: PasswordSetBy) -> anyhow::Result<Self> {
        check_length(password)?;
        Ok(Self {
            hash: hash_password(password)?,
            by,
        })
    }

    pub fn for_new_account(password: &str) -> anyhow::Result<Self> {
        Self::for_new_account_as(password, PasswordSetBy::Admin)
    }

    pub fn by(&self) -> PasswordSetBy {
        self.by
    }
}

fn check_length(password: &str) -> anyhow::Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        bail!("password must be at least {MIN_PASSWORD_CHARS} characters");
    }
    Ok(())
}

/// Check a new password for an existing account against the tenant's rules for
/// who is setting it, and hash it. Run before the transaction that stores it.
pub async fn prepare_password<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    user_id: &str,
    password: &str,
    by: PasswordSetBy,
) -> anyhow::Result<NewPassword> {
    let mut conn = db.acquire().await?;
    prepare_password_in(&mut conn, tenant, user_id, password, by).await
}

pub(crate) async fn prepare_password_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    user_id: &str,
    password: &str,
    by: PasswordSetBy,
) -> anyhow::Result<NewPassword> {
    check_length(password)?;
    let current: Option<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT password_hash FROM users WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(user_id)
    .bind(&tenant.id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((current,)) = current else {
        bail!("no such account in this tenant");
    };
    let remembered = tenant.settings.password_history.clamp(0, MAX_PASSWORD_HISTORY);
    if by != PasswordSetBy::AdminTemporary && remembered > 0 {
        let mut recent: Vec<String> = sqlx::query_as::<_, (String,)>(crate::db::qc(
            &conn,
            "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC",
        ))
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(|(h,)| h)
        .take(remembered as usize)
        .collect();
        // An account from before history was kept still remembers its current one.
        if recent.is_empty() {
            recent.push(current);
        }
        if recent.iter().any(|hash| verify_password(password, hash)) {
            return Err(PasswordReused(remembered).into());
        }
    }
    Ok(NewPassword {
        hash: hash_password(password)?,
        by,
    })
}

/// Set a user's password, held to the tenant's rules for who is setting it.
///
/// Like Entra, any new password revokes the user's refresh tokens and ends their
/// sessions. A temporary password also marks the account as having to choose
/// its own at the next sign-in; any other clears that mark.
pub async fn change_password<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    user_id: &str,
    password: &str,
    by: PasswordSetBy,
) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    change_password_in(&mut conn, tenant, user_id, password, by).await
}

async fn change_password_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    user_id: &str,
    password: &str,
    by: PasswordSetBy,
) -> anyhow::Result<()> {
    let password = prepare_password_in(&mut *conn, tenant, user_id, password, by).await?;
    if !store_password_in(&mut *conn, &tenant.id, user_id, &password).await? {
        bail!("no such account in this tenant");
    }
    Ok(())
}

/// Store a prepared password: see [`change_password`]. False when the tenant
/// has no such live account.
pub(crate) async fn store_password_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    user_id: &str,
    password: &NewPassword,
) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of_conn(&conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let changed = sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, must_change_password = ?,
                          updated_at = ?
         WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(&password.hash)
    .bind(password.by == PasswordSetBy::AdminTemporary)
    .bind(now())
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Ok(false);
    }
    remember_password(&mut tx, engine, user_id, &password.hash).await?;
    // As in Entra, a new password revokes the user's refresh tokens and sessions.
    revoke_access(&mut tx, engine, user_id).await?;
    tx.commit().await?;
    Ok(true)
}

/// Record a password in the user's history, keeping the newest few only.
async fn remember_password(
    conn: &mut sqlx::AnyConnection,
    engine: crate::db::Engine,
    user_id: &str,
    hash: &str,
) -> anyhow::Result<()> {
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO password_history (id, user_id, password_hash, created_at) VALUES (?, ?, ?, ?)",
    ))
    .bind(new_guid())
    .bind(user_id)
    .bind(hash)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    let ids: Vec<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC, id",
    ))
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    for (id,) in ids.into_iter().skip(MAX_PASSWORD_HISTORY as usize) {
        sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM password_history WHERE id = ?"))
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Whether the user must choose a new password before anything is issued to them.
pub async fn must_change_password<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    must_change_password_in(&mut conn, user_id).await
}

pub(crate) async fn must_change_password_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<bool> {
    let row: Option<(crate::db::Flag,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT must_change_password FROM users WHERE id = ?",
    ))
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.is_some_and(|(f,)| f.into()))
}

/// Mark or unmark an account as having to choose its own password at the next
/// sign-in, without changing the password.
pub async fn set_must_change_password<'c>(db: impl Handle<'c>, user_id: &str, must: bool) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    set_must_change_password_in(&mut conn, user_id, must).await
}

pub(crate) async fn set_must_change_password_in(
    conn: &mut crate::db::Conn,
    user_id: &str,
    must: bool,
) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        &conn,
        "UPDATE users SET must_change_password = ? WHERE id = ?",
    ))
    .bind(must)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// [`change_password`] by an administrator, for an account named by its user
/// name, as the command line names it.
pub async fn set_password<'c>(db: impl Handle<'c>, tenant: &Tenant, upn: &str, password: &str) -> anyhow::Result<()> {
    set_password_as(db, tenant, upn, password, PasswordSetBy::Admin).await
}

pub async fn set_password_as<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    upn: &str,
    password: &str,
    by: PasswordSetBy,
) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    let Some(user) = find_by_upn_in(&mut conn, &tenant.id, upn).await? else {
        bail!("user '{upn}' not found");
    };
    change_password_in(&mut conn, tenant, &user.id, password, by).await
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
pub async fn list<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<User>> {
    let mut conn = db.acquire().await?;
    list_in(&mut conn, tenant_id, query, limit, offset).await
}

pub(crate) async fn list_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<User>> {
    let pattern = match query.map(str::trim).filter(|q| !q.is_empty()) {
        Some(q) => format!("%{q}%"),
        None => "%".to_string(),
    };
    Ok(sqlx::query_as(crate::db::qc(
        &conn,
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
    .fetch_all(&mut *conn)
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
pub async fn update_attributes<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    user_id: &str,
    attrs: &UserAttributes<'_>,
) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    update_attributes_in(&mut conn, tenant_id, user_id, attrs).await
}

pub(crate) async fn update_attributes_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    user_id: &str,
    attrs: &UserAttributes<'_>,
) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::qc(
        &conn,
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
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Enable or disable a user. Disabling also ends their browser sessions and
/// revokes their refresh tokens: leaving those alive would mean a disabled
/// account kept working until every token expired.
pub async fn set_enabled<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    user_id: &str,
    enabled: bool,
) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    set_enabled_in(&mut conn, tenant_id, user_id, enabled).await
}

pub(crate) async fn set_enabled_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    user_id: &str,
    enabled: bool,
) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of_conn(&conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let admins = lockout::global_administrators(&mut tx, engine).await?;
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
    lockout::ensure_one_remains(&mut tx, engine, admins).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// Mark a user deleted. Kept rather than removed so audit rows and the `oid` in
/// already-issued tokens still resolve to something, and so the UPN is not freed
/// for reuse by a different person.
pub async fn soft_delete<'c>(db: impl Handle<'c>, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    soft_delete_in(&mut conn, tenant_id, user_id).await
}

pub(crate) async fn soft_delete_in(conn: &mut crate::db::Conn, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of_conn(&conn);
    let ts = now();
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let admins = lockout::global_administrators(&mut tx, engine).await?;
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
    lockout::ensure_one_remains(&mut tx, engine, admins).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// Bring a deleted account back, enabled, with the password, groups and roles it
/// had. The way back from deleting somebody by mistake; `false` when no deleted
/// account has that name.
pub async fn restore<'c>(db: impl Handle<'c>, tenant_id: &str, upn: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    restore_in(&mut conn, tenant_id, upn).await
}

pub(crate) async fn restore_in(conn: &mut crate::db::Conn, tenant_id: &str, upn: &str) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::qc(
        &conn,
        "UPDATE users SET deleted_at = NULL, enabled = ?, updated_at = ?
         WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NOT NULL",
    ))
    .bind(true)
    .bind(now())
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// [`restore`] by object id, as Find by id offers it. `false` when that id is not
/// a deleted account of this tenant.
pub async fn restore_id<'c>(db: impl Handle<'c>, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    restore_id_in(&mut conn, tenant_id, user_id).await
}

/// The id of a deleted account of the tenant, by its user name: the newest, if
/// the name was deleted more than once.
pub(crate) async fn deleted_id_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    upn: &str,
) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NOT NULL
         ORDER BY deleted_at DESC",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id,)| id))
}

pub(crate) async fn restore_id_in(conn: &mut crate::db::Conn, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::qc(
        &conn,
        "UPDATE users SET deleted_at = NULL, enabled = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND deleted_at IS NOT NULL",
    ))
    .bind(true)
    .bind(now())
    .bind(tenant_id)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// End every session and refresh token a user holds, as disabling them does,
/// without changing anything else about the account.
pub async fn end_sessions<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    end_sessions_in(&mut conn, user_id).await
}

pub(crate) async fn end_sessions_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<()> {
    let engine = crate::db::engine_of_conn(&conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    revoke_access(&mut tx, engine, user_id).await?;
    tx.commit().await?;
    Ok(())
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
pub async fn find_by_upn<'c>(db: impl Handle<'c>, tenant_id: &str, upn: &str) -> anyhow::Result<Option<User>> {
    let mut conn = db.acquire().await?;
    find_by_upn_in(&mut conn, tenant_id, upn).await
}

pub(crate) async fn find_by_upn_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    upn: &str,
) -> anyhow::Result<Option<User>> {
    Ok(sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .fetch_optional(&mut *conn)
    .await?)
}
