use std::sync::Once;
use std::time::Duration;

use sqlx::any::AnyPoolOptions;
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

/// A 0/1 column. The `Any` driver reports SQLite booleans as BIGINT and refuses
/// to decode them into `bool`, so row structs read this and convert.
#[derive(sqlx::Type)]
#[sqlx(transparent)]
pub struct Flag(i64);

impl From<Flag> for bool {
    fn from(f: Flag) -> bool {
        f.0 != 0
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
