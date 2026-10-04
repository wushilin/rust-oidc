pub mod access;
pub mod admin;
pub mod apps;
pub mod claims;
pub mod config;
pub mod config_file;
pub mod db;
pub mod directory;
pub mod error;
pub mod flowtest;
pub mod groups;
pub mod html;
pub mod keys;
pub mod mfa;
pub mod ratelimit;
pub mod rbac;
pub mod routes;
pub mod scopes;
pub mod secrets;
pub mod server;
pub mod session;
pub mod tenant;
pub mod txn;
pub mod users;
pub mod util;

use std::sync::Arc;

use crate::db::DbPool;
use config::PublicUrl;
use keys::KeyStore;
use ratelimit::Limiter;
use secrets::Secrets;

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub public_url: Arc<PublicUrl>,
    pub keys: Arc<KeyStore>,
    pub secrets: Arc<Secrets>,
    /// Rate-limit counters. In-process: see [`ratelimit::Limiter`].
    pub limits: Arc<Limiter>,
}

impl AppState {
    pub fn new(pool: DbPool, public_url: PublicUrl) -> Self {
        let keys = Arc::new(KeyStore::new(pool.clone()));
        Self {
            secrets: Arc::new(Secrets::new(pool.clone())),
            pool,
            public_url: Arc::new(public_url),
            keys,
            limits: Arc::new(Limiter::new()),
        }
    }
}
