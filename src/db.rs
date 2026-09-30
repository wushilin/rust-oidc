use std::sync::Once;
use std::time::Duration;

use sqlx::any::{AnyPoolOptions, AnyTypeInfo, AnyTypeInfoKind, AnyValueRef};
use sqlx::pool::PoolConnectionMetadata;
use sqlx::Executor;

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
/// arrives as a bool; SQLite and MySQL (TINYINT(1)) arrive as integers. The
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

/// Query parameter that lets SQLite create a missing database file.
const SQLITE_MODE_PARAM: &str = "mode=";
const SQLITE_MEMORY_PATH: &str = ":memory:";
const SQLITE_CREATE_MODE: &str = "mode=rwc";

pub async fn connect(url: &str) -> anyhow::Result<DbPool> {
    let engine = Engine::from_url(url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database URL scheme; use sqlite://, postgres:// or mysql://"))?;
    // Installing the drivers twice panics; tests create many pools per process.
    INSTALL_DRIVERS.call_once(sqlx::any::install_default_drivers);

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
    Ok(pool)
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
