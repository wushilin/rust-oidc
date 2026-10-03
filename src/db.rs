use std::sync::Once;
use std::time::Duration;

use sqlx::Executor;
use sqlx::any::{AnyPoolOptions, AnyTypeInfo, AnyTypeInfoKind, AnyValueRef};
use sqlx::pool::PoolConnectionMetadata;

/// The one place an engine is named. Everything above this module uses `DbPool`.
pub type Db = sqlx::Any;
pub type DbPool = sqlx::Pool<Db>;
/// One connection, possibly inside a transaction.
pub type Conn = sqlx::AnyConnection;

/// What a storage function takes to reach the database: the pool, for a call on
/// its own, or an open transaction (`&mut Conn`), for a call that is part of a
/// larger change. Inside a transaction, a function that begins its own makes a
/// savepoint, so everything still commits or rolls back together.
pub trait Handle<'c>: sqlx::Acquire<'c, Database = Db> + Send {}
impl<'c, T> Handle<'c> for T where T: sqlx::Acquire<'c, Database = Db> + Send {}

/// The engine behind a connection.
pub fn engine_of_conn(conn: &Conn) -> Engine {
    match conn.backend_name() {
        "PostgreSQL" => Engine::Postgres,
        "MySQL" => Engine::MySql,
        _ => Engine::Sqlite,
    }
}

/// [`q`] for a connection.
pub fn qc(conn: &Conn, statement: &'static str) -> sqlx::AssertSqlSafe<std::borrow::Cow<'static, str>> {
    sql_stmt(engine_of_conn(conn), statement)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Sqlite,
    Postgres,
    MySql,
}

impl Engine {
    pub const ALL: &'static [Engine] = &[Self::Sqlite, Self::Postgres, Self::MySql];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_str() == raw)
    }

    /// Which engine a connection URL selects. Accepts the aliases sqlx accepts.
    pub fn from_url(url: &str) -> Option<Self> {
        // Scheme is everything before the first ':' so `sqlite:x.db` (no "//") resolves too.
        let (scheme, _) = url.split_once(':')?;
        match scheme.to_ascii_lowercase().as_str() {
            "sqlite" => Some(Self::Sqlite),
            "postgres" | "postgresql" => Some(Self::Postgres),
            "mysql" | "mariadb" => Some(Self::MySql),
            _ => None,
        }
    }
}

/// A boolean column, whichever way the engine stores it. Postgres BOOLEAN
/// arrives as a bool; SQLite INTEGER and MySQL SMALLINT arrive as integers (MySQL columns must not
/// be TINYINT: the `Any` driver refuses that type outright). The
/// `Any` driver's own `bool` decode accepts only the former. Anything else
/// (text, blob, float, NULL) is an error, never a silent false: a disabled
/// account must not read back as enabled or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag(bool);

/// What a column held, as far as `Flag` cares.
#[derive(Debug)]
enum Raw {
    Bool(bool),
    Int(i64),
    Other(AnyTypeInfoKind),
}

impl Flag {
    fn from_raw(raw: Raw) -> Result<Self, sqlx::error::BoxDynError> {
        match raw {
            Raw::Bool(b) => Ok(Flag(b)),
            Raw::Int(i) => Ok(Flag(i != 0)),
            Raw::Other(kind) => Err(format!("expected a boolean or integer column, got {kind:?}").into()),
        }
    }
}

impl From<Flag> for bool {
    fn from(f: Flag) -> bool {
        f.0
    }
}

impl sqlx::Type<Db> for Flag {
    fn type_info() -> AnyTypeInfo {
        <bool as sqlx::Type<Db>>::type_info()
    }

    fn compatible(ty: &AnyTypeInfo) -> bool {
        matches!(
            ty.kind(),
            AnyTypeInfoKind::Bool | AnyTypeInfoKind::SmallInt | AnyTypeInfoKind::Integer | AnyTypeInfoKind::BigInt
        )
    }
}

impl<'r> sqlx::Decode<'r, Db> for Flag {
    fn decode(value: AnyValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let kind = sqlx::ValueRef::type_info(&value).kind();
        let raw = match kind {
            AnyTypeInfoKind::Bool => Raw::Bool(<bool as sqlx::Decode<Db>>::decode(value)?),
            AnyTypeInfoKind::SmallInt | AnyTypeInfoKind::Integer | AnyTypeInfoKind::BigInt => {
                Raw::Int(<i64 as sqlx::Decode<Db>>::decode(value)?)
            }
            other => Raw::Other(other),
        };
        Self::from_raw(raw)
    }
}

static INSTALL_DRIVERS: Once = Once::new();

/// Register the sqlx `Any` drivers (idempotent; installing twice panics).
pub fn install_drivers() {
    INSTALL_DRIVERS.call_once(sqlx::any::install_default_drivers);
}

/// Query parameter that lets SQLite create a missing database file.
const SQLITE_MODE_PARAM: &str = "mode=";
const SQLITE_MEMORY_PATH: &str = ":memory:";
const SQLITE_CREATE_MODE: &str = "mode=rwc";

/// Database used when none is configured.
pub const DEFAULT_DATABASE_URL: &str = "sqlite://data/rust-oidc.db";

pub async fn connect(url: &str) -> anyhow::Result<DbPool> {
    connect_with(url, FoldPolicy::FailClosed).await
}

/// What `connect` does when identifier folding finds colliding rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldPolicy {
    /// Refuse to open the database (the server).
    FailClosed,
    /// Log the collisions and carry on (CLI subcommands, so they stay usable during an upgrade).
    ReportOnly,
}

/// Two rows in one uniqueness scope fold to the same identifier. Typed so the
/// policy can tell it from a real database failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FoldConflict(pub String);

/// Apply `policy` to the outcome of [`reconcile_folded`]. A [`FoldConflict`] is
/// tolerated (logged) under `ReportOnly`; every other error propagates under both.
pub fn apply_fold_policy(policy: FoldPolicy, outcome: anyhow::Result<()>) -> anyhow::Result<()> {
    match outcome {
        Err(e) if policy == FoldPolicy::ReportOnly && e.is::<FoldConflict>() => {
            tracing::error!("identifier folding skipped, data untouched: {e}");
            Ok(())
        }
        other => other,
    }
}

/// `connect` with an explicit collision policy.
pub async fn connect_with(url: &str, policy: FoldPolicy) -> anyhow::Result<DbPool> {
    let engine = Engine::from_url(url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database URL scheme; use sqlite://, postgres:// or mysql://"))?;
    // Installing the drivers twice panics; tests create many pools per process.
    install_drivers();

    let mut url = url.to_string();
    // Only the query string counts: a directory named `mode=x` must not suppress it.
    let query_has_mode = url
        .split_once('?')
        .is_some_and(|(_, q)| q.split('&').any(|p| p.starts_with(SQLITE_MODE_PARAM)));
    if engine == Engine::Sqlite && !query_has_mode {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(SQLITE_CREATE_MODE);
    }

    let pool = AnyPoolOptions::new()
        .max_connections(8)
        .after_connect(move |conn, _meta: PoolConnectionMetadata| {
            Box::pin(async move {
                if engine == Engine::Sqlite {
                    conn.execute("PRAGMA journal_mode = WAL").await?;
                    conn.execute("PRAGMA foreign_keys = ON").await?;
                    conn.execute("PRAGMA busy_timeout = 5000").await?;
                }
                Ok(())
            })
        })
        .acquire_timeout(Duration::from_secs(30))
        .connect(&url)
        .await?;
    // `migrate!` embeds one literal directory at compile time, so each engine
    // gets its own Migrator.
    let migrator = match engine {
        Engine::Sqlite => sqlx::migrate!("./migrations/sqlite"),
        Engine::Postgres => sqlx::migrate!("./migrations/postgres"),
        Engine::MySql => sqlx::migrate!("./migrations/mysql"),
    };
    migrator.run(&pool).await?;
    apply_fold_policy(policy, reconcile_folded(&pool).await.map(|_| ()))?;
    Ok(pool)
}

/// Recompute every folded identity column in Rust and rewrite the rows that
/// disagree. The `0007` migration fills them with SQL `lower()`, which is
/// ASCII-only on SQLite and locale-dependent on Postgres, so rows with non-ASCII
/// identifiers would otherwise never match `util::fold` and their owners could
/// not sign in. Idempotent: a no-op once every row agrees. Returns rows rewritten.
///
/// Fails closed: if two rows in one uniqueness scope fold to the same value they
/// are the same identity under the rule, and neither is silently merged or
/// dropped. All conflicts across all tables are detected before any row is
/// written and reported together, leaving the data untouched.
pub async fn reconcile_folded(pool: &DbPool) -> anyhow::Result<usize> {
    use std::collections::BTreeMap;

    struct Plan {
        table: &'static str,
        scope_desc: &'static str,
        /// Rows are (key, scope, display value, stored fold); scope is "" when global.
        select: &'static str,
        update: &'static str,
    }
    let plans = [
        Plan {
            table: "users",
            scope_desc: "tenant_id",
            select: "SELECT id, tenant_id, upn, upn_folded FROM users",
            update: "UPDATE users SET upn_folded = ? WHERE id = ?",
        },
        Plan {
            table: "tenant_domains",
            scope_desc: "global",
            select: "SELECT domain, '', domain, domain_folded FROM tenant_domains",
            update: "UPDATE tenant_domains SET domain_folded = ? WHERE domain = ?",
        },
        Plan {
            table: "user_groups",
            scope_desc: "tenant_id",
            select: "SELECT id, tenant_id, name, name_folded FROM user_groups",
            update: "UPDATE user_groups SET name_folded = ? WHERE id = ?",
        },
    ];
    let engine = engine_of(pool);

    let mut conflicts = Vec::new();
    // (update statement, key, wanted fold) for rows that disagree.
    let mut writes: Vec<(&'static str, String, String)> = Vec::new();
    for plan in &plans {
        let rows: Vec<(String, String, String, Option<String>)> =
            sqlx::query_as(sql_stmt(engine, plan.select)).fetch_all(pool).await?;
        let mut claims: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
        for (key, scope, display, stored) in rows {
            let want = crate::util::fold(&display);
            if stored.as_deref() != Some(want.as_str()) {
                writes.push((plan.update, key.clone(), want.clone()));
            }
            claims.entry((scope, want)).or_default().push((key, display));
        }
        for ((scope, folded), members) in claims {
            if members.len() > 1 {
                let rows = members
                    .iter()
                    .map(|(key, display)| format!("      id/key '{key}' = '{display}'"))
                    .collect::<Vec<_>>()
                    .join("\n");
                conflicts.push(format!(
                    "  table {} (unique per {}{}): folded value '{folded}' is claimed by {} rows:\n{rows}",
                    plan.table,
                    plan.scope_desc,
                    if scope.is_empty() {
                        String::new()
                    } else {
                        format!(" = '{scope}'")
                    },
                    members.len(),
                ));
            }
        }
    }
    if !conflicts.is_empty() {
        return Err(FoldConflict(format!(
            "refusing to start: {} case-insensitive identity conflict(s) found while normalising \
             identifiers; rows that differ only by case are the same identity.\n{}\n\
             Rename or remove one of the conflicting rows in each group, then restart. \
             No command of this product can do that; use the database's own client \
             (`sqlite3`, `psql` or `mysql`). No data was modified.",
            conflicts.len(),
            conflicts.join("\n"),
        ))
        .into());
    }

    // One transaction so a failure part-way leaves nothing half-rewritten.
    // Safety argument: a stale value always retains an uppercase non-ASCII char or
    // untrimmed whitespace, so it can never equal a `fold()` output and the writes
    // cannot collide with rows that are already correct. That holds only while
    // `fold` merely lowercases and trims; revisit if it ever normalises further
    // (e.g. NFKC), since two different stale values could then map to one result.
    let fixed = writes.len();
    let mut tx = pool.begin().await?;
    for (update, key, want) in writes {
        sqlx::query(sql_stmt(engine, update))
            .bind(want)
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(fixed)
}

/// Attempts an upsert makes before giving up. A unique violation means another
/// writer got there first; a fresh attempt then sees its committed row.
pub const UPSERT_ATTEMPTS: usize = 3;

/// Engine-neutral test for "this row already exists".
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(e) if e.is_unique_violation())
}

/// Turn the outcome of a plain `INSERT` into "was a row inserted": a unique
/// violation is `Ok(false)`, any other error propagates. Replaces
/// the SQLite-only and Postgres-only ignore-duplicate insert forms.
pub fn inserted(result: Result<sqlx::any::AnyQueryResult, sqlx::Error>) -> Result<bool, sqlx::Error> {
    match result {
        Ok(done) => Ok(done.rows_affected() > 0),
        Err(e) if is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The filesystem path of a file-backed database, if the URL names one, so the
/// caller can create its parent directory. `None` for server engines and for
/// in-memory or empty SQLite paths. Handles `sqlite:path` and `sqlite://path`.
pub fn database_file_path(url: &str) -> Option<&str> {
    if Engine::from_url(url)? != Engine::Sqlite {
        return None;
    }
    let (_, rest) = url.split_once(':')?;
    let path = rest.strip_prefix("//").unwrap_or(rest);
    let path = path.split('?').next().unwrap_or_default();
    (!path.is_empty() && path != SQLITE_MEMORY_PATH).then_some(path)
}

/// The engine behind a pool, derived from the URL it was opened with.
pub fn engine_of(pool: &DbPool) -> Engine {
    let opts = pool.connect_options();
    // Unreachable today: connect() is the only constructor of a DbPool and it rejects unknown schemes.
    Engine::from_url(opts.database_url.as_str()).expect("connect() only opens URLs with a supported scheme")
}

/// Rewrite placeholders for the target engine. SQLite and MySQL use `?`;
/// Postgres needs `$1`, `$2`, ... in order. A `?` inside a single-quoted literal
/// is data and must be left alone; `''` is an escaped quote, not a terminator.
pub fn sql(engine: Engine, sql: &str) -> std::borrow::Cow<'_, str> {
    if engine != Engine::Postgres || !sql.contains('?') {
        return std::borrow::Cow::Borrowed(sql);
    }
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0usize;
    let mut in_literal = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                out.push(c);
                if in_literal && chars.peek() == Some(&'\'') {
                    out.push(chars.next().expect("peeked"));
                } else {
                    in_literal = !in_literal;
                }
            }
            '?' if !in_literal => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// [`sql`] for a statement handed to `sqlx::query*`. sqlx 0.9 refuses non-static
/// SQL unless it is wrapped in `AssertSqlSafe`. Requiring `&'static str` makes
/// that assertion sound: only source-code literals get in, never runtime data.
pub fn sql_stmt(engine: Engine, statement: &'static str) -> sqlx::AssertSqlSafe<std::borrow::Cow<'static, str>> {
    sqlx::AssertSqlSafe(sql(engine, statement))
}

/// `sql_stmt` for the common case: derive the engine from the pool.
pub fn q(pool: &DbPool, statement: &'static str) -> sqlx::AssertSqlSafe<std::borrow::Cow<'static, str>> {
    sql_stmt(engine_of(pool), statement)
}

// ---- audit trail vocabulary ----

/// Who performed an audited action: the `actor` column.
///
/// `Id` carries an identifier this server owns -- a user id, an application id
/// or a service principal id -- and never caller-supplied text. An identifier
/// that did not resolve is not an identifier, so it is [`Actor::Anonymous`] and
/// the submitted value is not recorded at all; see [`crate::routes::audit`] for
/// why (a client transposing `client_id` and `client_secret` would otherwise
/// write its secret into the table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor<'a> {
    /// The command line, run by an operator who already has database access.
    Cli,
    /// No user or client was identified.
    Anonymous,
    /// A user, application or service principal, by id.
    Id(&'a str),
}

impl<'a> Actor<'a> {
    pub fn as_str(self) -> &'a str {
        match self {
            Self::Cli => "cli",
            Self::Anonymous => "anonymous",
            Self::Id(id) => id,
        }
    }
}

impl<'a> From<Option<&'a str>> for Actor<'a> {
    /// `Some(id)` is that principal, `None` is [`Actor::Anonymous`]. Lets a call
    /// site pass an `Option<&str>` straight through without restating the rule.
    fn from(id: Option<&'a str>) -> Self {
        match id {
            Some(id) => Self::Id(id),
            None => Self::Anonymous,
        }
    }
}

/// Every value the `audit_log.action` column can hold, `area.event`.
///
/// This lives beside [`audit`] deliberately. The names used to exist in two
/// places -- an enum for the HTTP layer and nineteen bare strings in the CLI --
/// which gave one column two sources of truth, so a typo in either half was
/// invisible and no single list said what the column could contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    // -- browser and API sign-in --
    SignIn,
    SignInFailed,
    /// The second step of a sign-in passed: an authenticator or recovery code.
    MfaVerified,
    /// A wrong code at the second step.
    MfaFailed,
    /// An authenticator was set up.
    MfaEnrolled,
    /// The user chose a new password: at a forced change, or in My Account.
    PasswordChanged,
    /// The user replaced their recovery codes.
    MfaRecoveryCodesReplaced,
    Lockout,
    SessionCreate,
    SessionEnd,
    /// The user signed themselves out everywhere, from My Account.
    SessionEndEverywhere,
    /// The user answered the consent page for an application.
    ConsentGranted,
    ConsentDenied,
    // -- token endpoint --
    TokenIssued,
    TokenClientAuthFailed,
    TokenAssertionRejected,
    TokenAssertionReplayed,
    TokenCodeReplayed,
    RefreshFamilyRevoked,
    // -- device authorization grant --
    DeviceCodeIssued,
    DeviceApproved,
    DeviceDenied,
    DeviceRedeemed,
    // -- protection --
    /// A rate-limit bucket reached its allowance. Written once per bucket per
    /// window, by the event that trips it, so the flood it reports cannot itself
    /// flood the table. See [`crate::ratelimit`].
    Throttled,
    // -- command line --
    Bootstrap,
    TenantCreate,
    TenantAddDomain,
    TenantChangeDomain,
    UserCreate,
    UserSetPassword,
    UserRestore,
    GroupCreate,
    GroupAddMember,
    AppCreate,
    AppRedirectUriAdd,
    AppScopeAdd,
    AppSecretAdd,
    AppSecretRemove,
    AppImplicit,
    AppPasswordGrant,
    AppKeyAdd,
    AppKeyRemove,
    AppRoleAdd,
    AppRoleAssign,
    KeyRotate,
    // -- admin console --
    /// Signed in to the console itself, which is not an OAuth client of this
    /// server: `auth.sign_in` stays the answer to "did this account authenticate
    /// to an application".
    AdminSignIn,
    AdminSignInFailed,
    AdminSignOut,
    /// A platform administrator entered a tenant. The actor is always the person,
    /// never a tenant-local identity.
    AdminTenantAssume,
    AdminTenantLeave,
    AdminUserCreate,
    AdminUserUpdate,
    AdminUserEnable,
    AdminUserDisable,
    AdminUserReset,
    AdminUserDelete,
    AdminRoleGrant,
    AdminRoleRevoke,
    // -- the console's remaining sections --
    AdminAppCreate,
    AdminAppFlags,
    AdminAppIdentifierUriAdd,
    AdminAppIdentifierUriRemove,
    AdminAppRedirectUriAdd,
    AdminAppRedirectUriRemove,
    AdminAppScopeAdd,
    AdminAppSecretAdd,
    AdminAppSecretRemove,
    AdminAppKeyAdd,
    AdminAppKeyRemove,
    AdminAppRoleAdd,
    AdminAppRoleAssign,
    AdminAppRoleUnassign,
    AdminAppAssign,
    AdminAppUnassign,
    /// Assignment required turned on or off for an application.
    AdminAppAssignmentRequired,
    AdminTenantCreate,
    AdminTenantRename,
    AdminTenantEnable,
    AdminTenantDisable,
    AdminTenantDomainAdd,
    AdminTenantDomainRemove,
    AdminTenantDomainChange,
    AdminTenantSettings,
    AdminKeyRotate,
    AdminKeyPrune,
    AdminGroupCreate,
    AdminGroupMemberAdd,
    AdminGroupMemberRemove,
    AdminGroupDelete,
    AdminUserRestore,
    AdminUserMfaReset,
    AdminUserMfaPolicy,
    AdminUserCrossTenantPolicy,
    /// Which of the tenant's groups an account is in was set from its page: one
    /// entry, on the account, listing the groups joined and left.
    AdminUserGroups,
    /// An administrator sent an authorize request from the console's flow tester.
    /// The row records who, against which application, and with what response
    /// type -- never the state, the nonce or the PKCE verifier it generated.
    AdminFlowTestStart,
    /// What came back. The outcome only: never a code, a token or a claim value.
    AdminFlowTestResult,
}

impl Event {
    pub const ALL: &'static [Event] = &[
        Self::SignIn,
        Self::SignInFailed,
        Self::MfaVerified,
        Self::MfaFailed,
        Self::MfaEnrolled,
        Self::PasswordChanged,
        Self::MfaRecoveryCodesReplaced,
        Self::Lockout,
        Self::SessionCreate,
        Self::SessionEnd,
        Self::SessionEndEverywhere,
        Self::ConsentGranted,
        Self::ConsentDenied,
        Self::TokenIssued,
        Self::TokenClientAuthFailed,
        Self::TokenAssertionRejected,
        Self::TokenAssertionReplayed,
        Self::TokenCodeReplayed,
        Self::RefreshFamilyRevoked,
        Self::DeviceCodeIssued,
        Self::DeviceApproved,
        Self::DeviceDenied,
        Self::DeviceRedeemed,
        Self::Throttled,
        Self::Bootstrap,
        Self::TenantCreate,
        Self::TenantAddDomain,
        Self::TenantChangeDomain,
        Self::UserCreate,
        Self::UserSetPassword,
        Self::UserRestore,
        Self::GroupCreate,
        Self::GroupAddMember,
        Self::AppCreate,
        Self::AppRedirectUriAdd,
        Self::AppScopeAdd,
        Self::AppSecretAdd,
        Self::AppSecretRemove,
        Self::AppImplicit,
        Self::AppPasswordGrant,
        Self::AppKeyAdd,
        Self::AppKeyRemove,
        Self::AppRoleAdd,
        Self::AppRoleAssign,
        Self::KeyRotate,
        Self::AdminSignIn,
        Self::AdminSignInFailed,
        Self::AdminSignOut,
        Self::AdminTenantAssume,
        Self::AdminTenantLeave,
        Self::AdminUserCreate,
        Self::AdminUserUpdate,
        Self::AdminUserEnable,
        Self::AdminUserDisable,
        Self::AdminUserReset,
        Self::AdminUserDelete,
        Self::AdminRoleGrant,
        Self::AdminRoleRevoke,
        Self::AdminAppCreate,
        Self::AdminAppFlags,
        Self::AdminAppIdentifierUriAdd,
        Self::AdminAppIdentifierUriRemove,
        Self::AdminAppRedirectUriAdd,
        Self::AdminAppRedirectUriRemove,
        Self::AdminAppScopeAdd,
        Self::AdminAppSecretAdd,
        Self::AdminAppSecretRemove,
        Self::AdminAppKeyAdd,
        Self::AdminAppKeyRemove,
        Self::AdminAppRoleAdd,
        Self::AdminAppRoleAssign,
        Self::AdminAppRoleUnassign,
        Self::AdminAppAssign,
        Self::AdminAppUnassign,
        Self::AdminAppAssignmentRequired,
        Self::AdminTenantCreate,
        Self::AdminTenantRename,
        Self::AdminTenantEnable,
        Self::AdminTenantDisable,
        Self::AdminTenantDomainAdd,
        Self::AdminTenantDomainRemove,
        Self::AdminTenantDomainChange,
        Self::AdminTenantSettings,
        Self::AdminKeyRotate,
        Self::AdminKeyPrune,
        Self::AdminGroupCreate,
        Self::AdminGroupMemberAdd,
        Self::AdminGroupMemberRemove,
        Self::AdminGroupDelete,
        Self::AdminUserRestore,
        Self::AdminUserMfaReset,
        Self::AdminUserMfaPolicy,
        Self::AdminUserCrossTenantPolicy,
        Self::AdminUserGroups,
        Self::AdminFlowTestStart,
        Self::AdminFlowTestResult,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "auth.sign_in",
            Self::SignInFailed => "auth.sign_in_failed",
            Self::MfaVerified => "auth.mfa_verified",
            Self::MfaFailed => "auth.mfa_failed",
            Self::MfaEnrolled => "auth.mfa_enrolled",
            Self::PasswordChanged => "auth.password_changed",
            Self::MfaRecoveryCodesReplaced => "auth.mfa_recovery_codes_replaced",
            Self::Lockout => "auth.lockout",
            Self::SessionCreate => "session.create",
            Self::SessionEnd => "session.end",
            Self::SessionEndEverywhere => "session.end_everywhere",
            Self::ConsentGranted => "auth.consent_granted",
            Self::ConsentDenied => "auth.consent_denied",
            Self::TokenIssued => "token.issued",
            Self::TokenClientAuthFailed => "token.client_auth_failed",
            Self::TokenAssertionRejected => "token.assertion_rejected",
            Self::TokenAssertionReplayed => "token.assertion_replayed",
            Self::TokenCodeReplayed => "token.code_replayed",
            Self::RefreshFamilyRevoked => "token.refresh_family_revoked",
            Self::DeviceCodeIssued => "device.code_issued",
            Self::DeviceApproved => "device.approved",
            Self::DeviceDenied => "device.denied",
            Self::DeviceRedeemed => "device.redeemed",
            Self::Throttled => "security.throttled",
            // The one action with no `area.` prefix. It predates the convention
            // and rows carrying it already exist, so renaming it would split
            // "when was this server bootstrapped" across two spellings.
            Self::Bootstrap => "bootstrap",
            Self::TenantCreate => "tenant.create",
            Self::TenantAddDomain => "tenant.add_domain",
            Self::TenantChangeDomain => "tenant.change_domain",
            Self::UserCreate => "user.create",
            Self::UserSetPassword => "user.set_password",
            Self::UserRestore => "user.restore",
            Self::GroupCreate => "group.create",
            Self::GroupAddMember => "group.add_member",
            Self::AppCreate => "app.create",
            Self::AppRedirectUriAdd => "app.redirect_uri.add",
            Self::AppScopeAdd => "app.scope.add",
            Self::AppSecretAdd => "app.secret.add",
            Self::AppSecretRemove => "app.secret.remove",
            Self::AppImplicit => "app.implicit",
            Self::AppPasswordGrant => "app.password_grant",
            Self::AppKeyAdd => "app.key.add",
            Self::AppKeyRemove => "app.key.remove",
            Self::AppRoleAdd => "app.role.add",
            Self::AppRoleAssign => "app.role.assign",
            Self::KeyRotate => "key.rotate",
            Self::AdminSignIn => "admin.sign_in",
            Self::AdminSignInFailed => "admin.sign_in_failed",
            Self::AdminSignOut => "admin.sign_out",
            Self::AdminTenantAssume => "admin.tenant.assume",
            Self::AdminTenantLeave => "admin.tenant.leave",
            Self::AdminUserCreate => "admin.user.create",
            Self::AdminUserUpdate => "admin.user.update",
            Self::AdminUserEnable => "admin.user.enable",
            Self::AdminUserDisable => "admin.user.disable",
            Self::AdminUserReset => "admin.user.reset",
            Self::AdminUserDelete => "admin.user.delete",
            Self::AdminRoleGrant => "admin.role.grant",
            Self::AdminRoleRevoke => "admin.role.revoke",
            Self::AdminAppCreate => "admin.app.create",
            Self::AdminAppFlags => "admin.app.flags",
            Self::AdminAppIdentifierUriAdd => "admin.app.identifier_uri.add",
            Self::AdminAppIdentifierUriRemove => "admin.app.identifier_uri.remove",
            Self::AdminAppRedirectUriAdd => "admin.app.redirect_uri.add",
            Self::AdminAppRedirectUriRemove => "admin.app.redirect_uri.remove",
            Self::AdminAppScopeAdd => "admin.app.scope.add",
            Self::AdminAppSecretAdd => "admin.app.secret.add",
            Self::AdminAppSecretRemove => "admin.app.secret.remove",
            Self::AdminAppKeyAdd => "admin.app.key.add",
            Self::AdminAppKeyRemove => "admin.app.key.remove",
            Self::AdminAppRoleAdd => "admin.app.role.add",
            Self::AdminAppRoleAssign => "admin.app.role.assign",
            Self::AdminAppRoleUnassign => "admin.app.role.unassign",
            Self::AdminAppAssign => "admin.app.assign",
            Self::AdminAppUnassign => "admin.app.unassign",
            Self::AdminAppAssignmentRequired => "admin.app.assignment_required",
            Self::AdminTenantCreate => "admin.tenant.create",
            Self::AdminTenantRename => "admin.tenant.rename",
            Self::AdminTenantEnable => "admin.tenant.enable",
            Self::AdminTenantDisable => "admin.tenant.disable",
            Self::AdminTenantDomainAdd => "admin.tenant.domain.add",
            Self::AdminTenantDomainRemove => "admin.tenant.domain.remove",
            Self::AdminTenantDomainChange => "admin.tenant.domain.change",
            Self::AdminTenantSettings => "admin.tenant.settings",
            Self::AdminKeyRotate => "admin.key.rotate",
            Self::AdminKeyPrune => "admin.key.prune",
            Self::AdminGroupCreate => "admin.group.create",
            Self::AdminGroupMemberAdd => "admin.group.member.add",
            Self::AdminGroupMemberRemove => "admin.group.member.remove",
            Self::AdminGroupDelete => "admin.group.delete",
            Self::AdminUserRestore => "admin.user.restore",
            Self::AdminUserMfaReset => "admin.user.mfa_reset",
            Self::AdminUserMfaPolicy => "admin.user.mfa_policy",
            Self::AdminUserCrossTenantPolicy => "admin.user.cross_tenant_policy",
            Self::AdminUserGroups => "admin.user.groups",
            Self::AdminFlowTestStart => "admin.flow_test.start",
            Self::AdminFlowTestResult => "admin.flow_test.result",
        }
    }

    /// An action read back from a stored row. `None` for anything this build does
    /// not know, because a row written by a newer build must not stop an older
    /// one reading the table.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_str() == raw)
    }
}

/// Append one row to `audit_log`.
///
/// `actor` and `event` are enums rather than strings so that the `actor` and
/// `action` columns have exactly one source of truth each: the CLI used to pass
/// nineteen bare action strings past an enum that the HTTP layer was already
/// using for the same column.
pub async fn audit(
    pool: &DbPool,
    tenant_id: Option<&str>,
    actor: Actor<'_>,
    event: Event,
    target: Option<&str>,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(sql_stmt(
        engine_of(pool),
        "INSERT INTO audit_log (tenant_id, actor, action, target, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(tenant_id)
    .bind(actor.as_str())
    .bind(event.as_str())
    .bind(target)
    .bind(details.to_string())
    .bind(crate::util::now())
    .execute(pool)
    .await?;
    Ok(())
}

/// One row of `audit_log`, for the console's audit page.
pub struct AuditEntry {
    pub id: i64,
    /// Who did it: a user, application or service principal id, or one of the
    /// two spelled-out non-identifiers. See [`Actor`].
    pub actor: String,
    /// The action, when this build knows it. `None` for a row written by a newer
    /// build, which must still be listed rather than hidden.
    pub action: Option<Event>,
    /// The stored action string, so an unrecognised one can still be shown.
    pub action_raw: String,
    pub target: Option<String>,
    pub details: Option<String>,
    pub created_at: i64,
}

/// The most rows the audit page will read at once. The table is append-only,
/// unbounded, and unauthenticated requests can append to it, so a page over it
/// must be capped rather than trusted to be small. **Invented**: 100, recorded in
/// `docs/decisions-log.md`.
pub const AUDIT_PAGE_LIMIT: i64 = 100;

/// The newest audit rows belonging to one tenant, optionally filtered.
///
/// `tenant_id` is never optional: a tenant administrator must only ever see
/// their own tenant's rows, so there is no shape of this call that reads across
/// the boundary and none that returns the platform's own `tenant_id IS NULL`
/// rows (key rotation).
///
/// The four query shapes are spelled out rather than assembled, because
/// [`sql_stmt`] takes a `&'static str` -- that is what makes its SQL-safety
/// assertion sound -- and because each shape is the one the `0009` indexes serve:
/// `(tenant_id, created_at)`, `(tenant_id, action, created_at)` and `(target)`.
pub async fn audit_for_tenant(
    pool: &DbPool,
    tenant_id: &str,
    action: Option<Event>,
    target: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<AuditEntry>> {
    let limit = limit.clamp(1, AUDIT_PAGE_LIMIT);
    type Row = (i64, String, String, Option<String>, Option<String>, i64);
    let rows: Vec<Row> = match (action, target) {
        (None, None) => {
            sqlx::query_as(q(
                pool,
                "SELECT id, actor, action, target, details, created_at FROM audit_log
                 WHERE tenant_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            ))
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (Some(event), None) => {
            sqlx::query_as(q(
                pool,
                "SELECT id, actor, action, target, details, created_at FROM audit_log
                 WHERE tenant_id = ? AND action = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            ))
            .bind(tenant_id)
            .bind(event.as_str())
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (None, Some(target)) => {
            sqlx::query_as(q(
                pool,
                "SELECT id, actor, action, target, details, created_at FROM audit_log
                 WHERE tenant_id = ? AND target = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            ))
            .bind(tenant_id)
            .bind(target)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (Some(event), Some(target)) => {
            sqlx::query_as(q(
                pool,
                "SELECT id, actor, action, target, details, created_at FROM audit_log
                 WHERE tenant_id = ? AND action = ? AND target = ?
                 ORDER BY created_at DESC, id DESC LIMIT ?",
            ))
            .bind(tenant_id)
            .bind(event.as_str())
            .bind(target)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(|(id, actor, action_raw, target, details, created_at)| AuditEntry {
            id,
            actor,
            action: Event::parse(&action_raw),
            action_raw,
            target,
            details,
            created_at,
        })
        .collect())
}

/// Delete audit rows older than `older_than_secs`.
///
/// The table is append-only and grows without bound, and unauthenticated
/// requests can append to it (a failed client authentication is an event), so
/// retention is not optional. There is no scheduler in this process, so this
/// follows `keys::prune`: an operator or cron calls the CLI.
pub async fn prune_audit(pool: &DbPool, older_than_secs: i64) -> anyhow::Result<u64> {
    let res = sqlx::query(q(pool, "DELETE FROM audit_log WHERE created_at < ?"))
        .bind(crate::util::now() - older_than_secs)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_file_path_handles_both_sqlite_forms() {
        assert_eq!(database_file_path("sqlite:x.db"), Some("x.db"));
        assert_eq!(database_file_path("sqlite:/abs/p.db?mode=rwc"), Some("/abs/p.db"));
        assert_eq!(database_file_path("sqlite:///abs/p.db"), Some("/abs/p.db"));
        assert_eq!(database_file_path("sqlite://rel/p.db"), Some("rel/p.db"));
        assert_eq!(database_file_path("sqlite::memory:"), None);
        assert_eq!(database_file_path("sqlite://"), None);
        assert_eq!(database_file_path("postgres://u@h/db"), None);
    }

    fn decode(raw: Raw) -> Result<bool, sqlx::error::BoxDynError> {
        Flag::from_raw(raw).map(bool::from)
    }

    #[test]
    fn integers_decode_by_zero_or_not() {
        assert!(!decode(Raw::Int(0)).unwrap());
        assert!(decode(Raw::Int(1)).unwrap());
        assert!(decode(Raw::Int(2)).unwrap());
    }

    #[test]
    fn bools_decode_as_themselves() {
        assert!(decode(Raw::Bool(true)).unwrap());
        assert!(!decode(Raw::Bool(false)).unwrap());
    }

    #[test]
    fn anything_else_is_rejected_not_false() {
        assert!(decode(Raw::Other(AnyTypeInfoKind::Text)).is_err());
        assert!(decode(Raw::Other(AnyTypeInfoKind::Double)).is_err());
        assert!(decode(Raw::Other(AnyTypeInfoKind::Null)).is_err());
    }

    #[test]
    fn sqlite_and_mysql_keep_question_marks() {
        let q = "SELECT a FROM t WHERE b = ? AND c = ?";
        assert_eq!(sql(Engine::Sqlite, q), q);
        assert_eq!(sql(Engine::MySql, q), q);
    }

    #[test]
    fn postgres_gets_numbered_parameters() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT a FROM t WHERE b = ? AND c = ?"),
            "SELECT a FROM t WHERE b = $1 AND c = $2"
        );
    }

    #[test]
    fn postgres_numbering_counts_every_placeholder_in_order() {
        assert_eq!(
            sql(Engine::Postgres, "INSERT INTO t (a,b,c) VALUES (?, ?, ?)"),
            "INSERT INTO t (a,b,c) VALUES ($1, $2, $3)"
        );
    }

    /// A `?` inside a quoted literal is data, not a placeholder.
    #[test]
    fn a_question_mark_inside_a_string_literal_is_left_alone() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT a FROM t WHERE b = ? AND c = 'why?'"),
            "SELECT a FROM t WHERE b = $1 AND c = 'why?'"
        );
        assert_eq!(
            sql(Engine::Postgres, "SELECT 'a?b' AS x WHERE y = ?"),
            "SELECT 'a?b' AS x WHERE y = $1"
        );
    }

    #[test]
    fn a_doubled_quote_inside_a_literal_does_not_end_it() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT 'it''s ?' WHERE y = ?"),
            "SELECT 'it''s ?' WHERE y = $1"
        );
    }

    #[test]
    fn sql_without_placeholders_is_unchanged_and_not_reallocated() {
        let q = "SELECT 1";
        assert!(matches!(sql(Engine::Postgres, q), std::borrow::Cow::Borrowed(_)));
    }
}
