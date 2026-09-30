//! Server-wide secrets and derived identifiers.

use crate::db::DbPool;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::OnceCell;

use crate::util::{b64url, now, random_bytes};

pub struct Secrets {
    pool: DbPool,
    pairwise: OnceCell<Vec<u8>>,
}

impl Secrets {
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            pairwise: OnceCell::new(),
        }
    }

    /// Pairwise subject identifier, as in Entra: stable for a (user, app) pair,
    /// different for every app. 43 base64url characters like Entra's `sub`.
    pub async fn pairwise_sub(&self, user_id: &str, app_id: &str) -> anyhow::Result<String> {
        let key = self
            .pairwise
            .get_or_try_init(|| load_or_create(&self.pool, "pairwise_sub"))
            .await?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(user_id.as_bytes());
        mac.update(b"\0");
        mac.update(app_id.to_ascii_lowercase().as_bytes());
        Ok(b64url(&mac.finalize().into_bytes()))
    }
}

/// Read the secret, creating it on first use. Every caller, in this process or
/// another, must end up with the same bytes: the first committed insert wins and
/// everyone else reads it back. Bounded retry covers the window where a
/// concurrent writer's row is not yet visible.
async fn load_or_create(pool: &DbPool, name: &str) -> anyhow::Result<Vec<u8>> {
    let engine = crate::db::engine_of(pool);
    for _ in 0..crate::db::UPSERT_ATTEMPTS {
        let existing: Option<(Vec<u8>,)> = sqlx::query_as(crate::db::sql_stmt(
            engine,
            "SELECT value FROM server_secrets WHERE name = ?",
        ))
        .bind(name)
        .fetch_optional(pool)
        .await?;
        if let Some((value,)) = existing {
            return Ok(value);
        }
        // Whether we inserted or lost the race, the next read returns the winner's value.
        crate::db::inserted(
            sqlx::query(crate::db::sql_stmt(
                engine,
                "INSERT INTO server_secrets (name, value, created_at) VALUES (?, ?, ?)",
            ))
            .bind(name)
            .bind(random_bytes(32))
            .bind(now())
            .execute(pool)
            .await,
        )?;
    }
    // One last read after the final insert attempt.
    let last: Option<(Vec<u8>,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT value FROM server_secrets WHERE name = ?",
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    last.map(|(v,)| v).ok_or_else(|| {
        anyhow::anyhow!(
            "server secret '{name}' could not be created or read after {} attempts",
            crate::db::UPSERT_ATTEMPTS
        )
    })
}
