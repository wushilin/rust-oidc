use std::sync::Once;
use std::time::Duration;

use sqlx::Executor;
use sqlx::any::{AnyPoolOptions, AnyTypeInfo, AnyTypeInfoKind, AnyValueRef};
use sqlx::pool::PoolConnectionMetadata;

/// The one place an engine is named. Everything above this module uses `DbPool`.
pub type Db = sqlx::Any;
pub type DbPool = sqlx::Pool<Db>;

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
    match policy {
        FoldPolicy::FailClosed => {
            reconcile_folded(&pool).await?;
        }
        FoldPolicy::ReportOnly => {
            if let Err(e) = reconcile_folded(&pool).await {
                tracing::error!("identifier folding skipped, data untouched: {e}");
            }
        }
    }
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
        anyhow::bail!(
            "refusing to start: {} case-insensitive identity conflict(s) found while normalising \
             identifiers; rows that differ only by case are the same identity.\n{}\n\
             Rename or remove one of the conflicting rows in each group, then restart. \
             No command of this product can do that; use the database's own client \
             (`sqlite3`, `psql` or `mysql`). No data was modified.",
            conflicts.len(),
            conflicts.join("\n"),
        );
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

pub async fn audit(
    pool: &DbPool,
    tenant_id: Option<&str>,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(sql_stmt(
        engine_of(pool),
        "INSERT INTO audit_log (tenant_id, actor, action, target, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(tenant_id)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(details.to_string())
    .bind(crate::util::now())
    .execute(pool)
    .await?;
    Ok(())
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
