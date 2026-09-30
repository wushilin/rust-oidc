pub mod admin;
pub mod apps;
pub mod claims;
pub mod config;
pub mod db;
pub mod directory;
pub mod error;
pub mod groups;
pub mod html;
pub mod keys;
pub mod rbac;
pub mod routes;
pub mod scopes;
pub mod secrets;
pub mod server;
pub mod session;
pub mod tenant;
pub mod users;
pub mod util;

use std::sync::Arc;

use config::PublicUrl;
use keys::KeyStore;
use secrets::Secrets;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub public_url: Arc<PublicUrl>,
    pub keys: Arc<KeyStore>,
    pub secrets: Arc<Secrets>,
}

impl AppState {
    pub fn new(pool: SqlitePool, public_url: PublicUrl) -> Self {
        let keys = Arc::new(KeyStore::new(pool.clone()));
        Self {
            secrets: Arc::new(Secrets::new(pool.clone())),
            pool,
            public_url: Arc::new(public_url),
            keys,
        }
    }
}
