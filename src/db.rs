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
        let scheme = url.split("://").next()?.to_ascii_lowercase();
        match scheme.as_str() {
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
const SQLITE_CREATE_MODE: &str = "mode=rwc";

pub async fn connect(url: &str) -> anyhow::Result<DbPool> {
    let engine = Engine::from_url(url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database URL scheme; use sqlite://, postgres:// or mysql://"))?;
    // Installing the drivers twice panics; tests create many pools per process.
    INSTALL_DRIVERS.call_once(sqlx::any::install_default_drivers);

    let mut url = url.to_string();
    if engine == Engine::Sqlite && !url.contains(SQLITE_MODE_PARAM) {
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
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// The engine behind a pool, derived from the URL it was opened with.
pub fn engine_of(pool: &DbPool) -> Engine {
    let opts = pool.connect_options();
    Engine::from_url(opts.database_url.as_str()).expect("connect() only opens URLs with a supported scheme")
}

pub async fn audit(
    pool: &DbPool,
    tenant_id: Option<&str>,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor, action, target, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
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
}
