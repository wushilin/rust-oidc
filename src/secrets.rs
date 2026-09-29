//! Server-wide secrets and derived identifiers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::SqlitePool;
use tokio::sync::OnceCell;

use crate::util::{b64url, now, random_bytes};

pub struct Secrets {
    pool: SqlitePool,
    pairwise: OnceCell<Vec<u8>>,
}

impl Secrets {
    pub fn new(pool: SqlitePool) -> Self {
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

async fn load_or_create(pool: &SqlitePool, name: &str) -> anyhow::Result<Vec<u8>> {
    sqlx::query("INSERT OR IGNORE INTO server_secrets (name, value, created_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(random_bytes(32))
        .bind(now())
        .execute(pool)
        .await?;
    let (value,): (Vec<u8>,) = sqlx::query_as("SELECT value FROM server_secrets WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(value)
}
