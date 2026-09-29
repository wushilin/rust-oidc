pub mod apps;
pub mod config;
pub mod db;
pub mod directory;
pub mod error;
pub mod keys;
pub mod routes;
pub mod server;
pub mod tenant;
pub mod users;
pub mod util;

use std::sync::Arc;

use config::PublicUrl;
use keys::KeyStore;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub public_url: Arc<PublicUrl>,
    pub keys: Arc<KeyStore>,
}

impl AppState {
    pub fn new(pool: SqlitePool, public_url: PublicUrl) -> Self {
        let keys = Arc::new(KeyStore::new(pool.clone()));
        Self {
            pool,
            public_url: Arc::new(public_url),
            keys,
        }
    }
}
