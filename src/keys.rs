//! Token signing keys. Shared by all tenants, as in Entra.
//!
//! Each key is RSA-2048 wrapped in a self-signed certificate. As in Entra, the
//! key id is the certificate thumbprint: `kid == x5t == base64url(SHA-1(cert DER))`.
//!
//! Lifecycle: `next` (published, not yet signing) -> `active` (signing) ->
//! `retired` (published until tokens it signed have expired, then pruned).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use sha1::{Digest, Sha1};
use sqlx::SqlitePool;
use tokio::sync::RwLock;

use crate::util::{b64, b64url, now};

const CERT_VALIDITY_DAYS: i64 = 5 * 365;
const CACHE_TTL: Duration = Duration::from_secs(30);

pub struct LoadedKey {
    pub kid: String,
    pub status: String,
    pub cert_der: Vec<u8>,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub encoding_key: EncodingKey,
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
    pool: SqlitePool,
    cache: RwLock<Option<(Instant, Arc<Vec<LoadedKey>>)>>,
}

impl KeyStore {
    pub fn new(pool: SqlitePool) -> Self {
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
            .position(|k| k.status == "active")
            .ok_or_else(|| anyhow!("no active signing key; run `rust-oidc key rotate`"))?;
        Ok((keys, idx))
    }

    pub async fn sign<T: Serialize>(&self, claims: &T) -> anyhow::Result<String> {
        let (keys, idx) = self.active().await?;
        let key = &keys[idx];
        Ok(jsonwebtoken::encode(&key.header(), claims, &key.encoding_key)?)
    }
}

async fn load_keys(pool: &SqlitePool) -> anyhow::Result<Vec<LoadedKey>> {
    let rows: Vec<(String, String, Vec<u8>, String)> = sqlx::query_as(
        "SELECT kid, private_key_pem, cert_der, status FROM signing_keys
         ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'next' THEN 1 ELSE 2 END, created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(kid, pem, cert_der, status)| {
            let private = RsaPrivateKey::from_pkcs8_pem(&pem).context("bad signing key PEM")?;
            Ok(LoadedKey {
                n: private.n().to_bytes_be(),
                e: private.e().to_bytes_be(),
                encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes())?,
                kid,
                status,
                cert_der,
            })
        })
        .collect()
}

/// Generate a key + self-signed certificate and store it with `status`.
pub async fn generate(pool: &SqlitePool, status: &str) -> anyhow::Result<String> {
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

    sqlx::query(
        "INSERT INTO signing_keys (kid, private_key_pem, cert_der, status, created_at, not_after)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&kid)
    .bind(key_pair.serialize_pem())
    .bind(&cert_der)
    .bind(status)
    .bind(now())
    .bind(params.not_after.unix_timestamp())
    .execute(pool)
    .await?;
    Ok(kid)
}

/// Make sure there is an active key and a pre-published next key.
pub async fn ensure(pool: &SqlitePool) -> anyhow::Result<()> {
    let count = |status: &'static str| async move {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM signing_keys WHERE status = ?")
            .bind(status)
            .fetch_one(pool)
            .await?;
        anyhow::Ok(n)
    };
    if count("active").await? == 0 {
        generate(pool, "active").await?;
    }
    if count("next").await? == 0 {
        generate(pool, "next").await?;
    }
    Ok(())
}

/// active -> retired, next -> active, new next. The new active key was already
/// published as `next`, so clients that cache JWKS have had time to see it.
pub async fn rotate(pool: &SqlitePool) -> anyhow::Result<()> {
    ensure(pool).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE signing_keys SET status = 'retired', retired_at = ? WHERE status = 'active'")
        .bind(now())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE signing_keys SET status = 'active'
         WHERE kid = (SELECT kid FROM signing_keys WHERE status = 'next' ORDER BY created_at LIMIT 1)",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    generate(pool, "next").await?;
    Ok(())
}

/// Delete keys retired more than `older_than_secs` ago (must exceed token lifetimes).
pub async fn prune(pool: &SqlitePool, older_than_secs: i64) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM signing_keys WHERE status = 'retired' AND retired_at < ?")
        .bind(now() - older_than_secs)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
