//! Token signing keys. Shared by all tenants, as in Entra.
//!
//! Each key is RSA-2048 wrapped in a self-signed certificate. As in Entra, the
//! key id is the certificate thumbprint: `kid == x5t == base64url(SHA-1(cert DER))`.
//!
//! Lifecycle: `next` (published, not yet signing) -> `active` (signing) ->
//! `retired` (published until tokens it signed have expired, then pruned).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::db::DbPool;
use anyhow::{Context, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use sha1::{Digest, Sha1};
use tokio::sync::RwLock;

use crate::util::{b64, b64url, now};

const CERT_VALIDITY_DAYS: i64 = 5 * 365;
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Lifecycle of a signing key. The database enforces the same three values in a
/// CHECK constraint (`0001_init.sql`), so a row can never hold anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Pre-published so clients cache it before it ever signs anything.
    Next,
    /// The one key that signs. At most one, by unique index.
    Active,
    /// Published until every token it signed has expired, then pruned.
    Retired,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "next" => Some(Self::Next),
            "active" => Some(Self::Active),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

pub struct LoadedKey {
    pub kid: String,
    pub status: KeyStatus,
    pub cert_der: Vec<u8>,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub kid: String,
    pub x5t: String,
    pub n: String,
    pub e: String,
    pub x5c: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl LoadedKey {
    pub fn jwk(&self, issuer: Option<String>) -> Jwk {
        Jwk {
            kty: "RSA",
            use_: "sig",
            kid: self.kid.clone(),
            x5t: self.kid.clone(),
            n: b64url(&self.n),
            e: b64url(&self.e),
            x5c: vec![b64(&self.cert_der)],
            issuer,
        }
    }

    /// JWT header as Entra emits it: `typ`, `alg`, `x5t` and `kid`.
    pub fn header(&self) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header.x5t = Some(self.kid.clone());
        header
    }
}

pub struct KeyStore {
    pool: DbPool,
    cache: RwLock<Option<(Instant, Arc<Vec<LoadedKey>>)>>,
}

impl KeyStore {
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            cache: RwLock::new(None),
        }
    }

    /// All published keys (next, active, retired). Cached briefly so key
    /// rotation done through the CLI is picked up by a running server.
    pub async fn published(&self) -> anyhow::Result<Arc<Vec<LoadedKey>>> {
        if let Some((at, keys)) = self.cache.read().await.as_ref()
            && at.elapsed() < CACHE_TTL
        {
            return Ok(keys.clone());
        }
        let keys = Arc::new(load_keys(&self.pool).await?);
        *self.cache.write().await = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    pub async fn active(&self) -> anyhow::Result<(Arc<Vec<LoadedKey>>, usize)> {
        let keys = self.published().await?;
        let idx = keys
            .iter()
            .position(|k| k.status == KeyStatus::Active)
            .ok_or_else(|| anyhow!("no active signing key; run `rust-oidc key rotate`"))?;
        Ok((keys, idx))
    }

    /// Verify a token we issued: RS256, signed by a published key, not expired.
    /// Issuer and audience checks are left to the caller.
    pub async fn verify(&self, token: &str) -> anyhow::Result<serde_json::Value> {
        self.verify_inner(token, true).await
    }

    /// Like [`verify`](Self::verify) but accepts expired tokens (for hints).
    pub async fn verify_ignoring_expiry(&self, token: &str) -> anyhow::Result<serde_json::Value> {
        self.verify_inner(token, false).await
    }

    async fn verify_inner(&self, token: &str, check_exp: bool) -> anyhow::Result<serde_json::Value> {
        let kid = jsonwebtoken::decode_header(token)?
            .kid
            .ok_or_else(|| anyhow!("token has no kid"))?;
        let keys = self.published().await?;
        let key = keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| anyhow!("unknown kid"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.validate_exp = check_exp;
        validation.set_required_spec_claims(&["exp", "iss"]);
        Ok(jsonwebtoken::decode::<serde_json::Value>(token, &key.decoding_key, &validation)?.claims)
    }

    pub async fn sign<T: Serialize>(&self, claims: &T) -> anyhow::Result<String> {
        let (keys, idx) = self.active().await?;
        let key = &keys[idx];
        Ok(jsonwebtoken::encode(&key.header(), claims, &key.encoding_key)?)
    }
}

async fn load_keys(pool: &DbPool) -> anyhow::Result<Vec<LoadedKey>> {
    let rows: Vec<(String, String, Vec<u8>, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT kid, private_key_pem, cert_der, status FROM signing_keys
         ORDER BY CASE status WHEN ? THEN 0 WHEN ? THEN 1 ELSE 2 END, created_at DESC",
    ))
    .bind(KeyStatus::Active.as_str())
    .bind(KeyStatus::Next.as_str())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(kid, pem, cert_der, status)| {
            let status = KeyStatus::parse(&status)
                .ok_or_else(|| anyhow!("signing key {kid} has an unknown status {status:?}"))?;
            let private = RsaPrivateKey::from_pkcs8_pem(&pem).context("bad signing key PEM")?;
            let (n, e) = (private.n().to_bytes_be(), private.e().to_bytes_be());
            Ok(LoadedKey {
                decoding_key: DecodingKey::from_rsa_raw_components(&n, &e),
                n,
                e,
                encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes())?,
                kid,
                status,
                cert_der,
            })
        })
        .collect()
}

/// Generate a key + self-signed certificate and store it with `status`.
pub async fn generate(pool: &DbPool, status: KeyStatus) -> anyhow::Result<String> {
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "rust-oidc token signing");
    params.distinguished_name = dn;
    let now_dt = time::OffsetDateTime::now_utc();
    params.not_before = now_dt - time::Duration::days(1);
    params.not_after = now_dt + time::Duration::days(CERT_VALIDITY_DAYS);
    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let kid = b64url(&Sha1::digest(&cert_der));

    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO signing_keys (kid, private_key_pem, cert_der, status, created_at, not_after)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(&kid)
    .bind(key_pair.serialize_pem())
    .bind(&cert_der)
    .bind(status.as_str())
    .bind(now())
    .bind(params.not_after.unix_timestamp())
    .execute(pool)
    .await?;
    Ok(kid)
}

/// Make sure there is an active key and a pre-published next key.
pub async fn ensure(pool: &DbPool) -> anyhow::Result<()> {
    let count = |status: KeyStatus| async move {
        let (n,): (i64,) = sqlx::query_as(crate::db::q(pool, "SELECT COUNT(*) FROM signing_keys WHERE status = ?"))
            .bind(status.as_str())
            .fetch_one(pool)
            .await?;
        anyhow::Ok(n)
    };
    for status in [KeyStatus::Active, KeyStatus::Next] {
        if count(status).await? == 0 {
            generate(pool, status).await?;
        }
    }
    Ok(())
}

/// Attempts `rotate` makes before giving up; each retry follows a lost race.
const ROTATE_ATTEMPTS: usize = 5;

/// active -> retired, next -> active, new next. The new active key was already
/// published as `next`, so clients that cache JWKS have had time to see it.
///
/// Safe under concurrent rotations. The transaction opens with a write to the
/// single `key_rotation_lock` row (migration 0008), which always exists and so
/// always takes a lock on every engine: a row lock on Postgres/MySQL, the
/// database write lock on SQLite (taken before any read, so the snapshot is
/// fresh). A waiting rotation therefore resumes only after the winner commits and
/// sees its state. Locking the active key instead would not work: after the
/// winner commits that row is no longer active, so a waiter's UPDATE would match
/// nothing and hold no lock. No `SELECT ... FOR UPDATE`, which SQLite lacks.
///
/// Each racer performs its own rotation in turn. The replacement `next` key is
/// published after commit, not under the lock (RSA generation is slow, and on
/// SQLite `generate` would block on the write lock we hold), and only if none
/// exists, so racers do not pile up spare keys. With the lock the retry paths
/// below are defence in depth: if a rotation still finds no `next` to promote it
/// publishes one and retries, and a unique violation on the single-active index
/// is retried too.
pub async fn rotate(pool: &DbPool) -> anyhow::Result<()> {
    for _ in 0..ROTATE_ATTEMPTS {
        ensure(pool).await?;
        match try_rotate(pool).await {
            Ok(true) => {
                ensure(pool).await?;
                return Ok(());
            }
            // Nothing to promote yet: a concurrent rotation used the last `next` key.
            Ok(false) => {}
            Err(e)
                if e.downcast_ref::<sqlx::Error>()
                    .is_some_and(crate::db::is_unique_violation) => {}
            Err(e) => return Err(e),
        }
    }
    Err(anyhow!(
        "key rotation kept losing races with concurrent rotations; try again"
    ))
}

/// One rotation attempt. `Ok(false)` means there was no `next` key to promote
/// and nothing was changed.
async fn try_rotate(pool: &DbPool) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    // Mutex on the sentinel row; see `rotate`.
    sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE key_rotation_lock SET held_at = ? WHERE id = 1",
    ))
    .bind(now())
    .execute(&mut *tx)
    .await?;
    // Two statements, not `UPDATE ... WHERE kid = (SELECT ... FROM signing_keys)`:
    // MySQL refuses to update a table it also selects from (error 1093).
    let next: Option<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT kid FROM signing_keys WHERE status = ? ORDER BY created_at LIMIT 1",
    ))
    .bind(KeyStatus::Next.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((kid,)) = next else {
        tx.rollback().await?;
        return Ok(false);
    };
    sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE signing_keys SET status = ?, retired_at = ? WHERE status = ?",
    ))
    .bind(KeyStatus::Retired.as_str())
    .bind(now())
    .bind(KeyStatus::Active.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "UPDATE signing_keys SET status = ? WHERE kid = ?",
    ))
    .bind(KeyStatus::Active.as_str())
    .bind(kid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Delete keys retired more than `older_than_secs` ago (must exceed token lifetimes).
pub async fn prune(pool: &DbPool, older_than_secs: i64) -> anyhow::Result<u64> {
    let res = sqlx::query(crate::db::q(
        pool,
        "DELETE FROM signing_keys WHERE status = ? AND retired_at < ?",
    ))
    .bind(KeyStatus::Retired.as_str())
    .bind(now() - older_than_secs)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// A signing key as the console lists it: no key material, only the lifecycle.
pub struct StoredKey {
    pub kid: String,
    pub status: KeyStatus,
    pub created_at: i64,
    /// When `active` became `retired`; `None` for a key that never has.
    pub retired_at: Option<i64>,
    /// Expiry of the self-signed certificate wrapping the key.
    pub not_after: i64,
}

/// Every signing key, active first, as `rust-oidc key list` prints them.
///
/// An unknown status is an error rather than a skipped row, exactly as in
/// [`load_keys`]: such a key is published in JWKS but cannot be classified, and
/// hiding it from the page that decides whether to rotate would be the wrong
/// direction. In practice it cannot happen -- the schema has a CHECK constraint
/// and `load_keys` would already have stopped the server from signing.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<StoredKey>> {
    let rows: Vec<(String, String, i64, Option<i64>, i64)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT kid, status, created_at, retired_at, not_after FROM signing_keys
         ORDER BY CASE status WHEN ? THEN 0 WHEN ? THEN 1 ELSE 2 END, created_at DESC",
    ))
    .bind(KeyStatus::Active.as_str())
    .bind(KeyStatus::Next.as_str())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(kid, status, created_at, retired_at, not_after)| {
            let parsed = KeyStatus::parse(&status)
                .ok_or_else(|| anyhow!("signing key {kid} has an unknown status {status:?}"))?;
            Ok(StoredKey {
                kid,
                status: parsed,
                created_at,
                retired_at,
                not_after,
            })
        })
        .collect()
}
