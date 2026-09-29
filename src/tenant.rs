use anyhow::bail;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

use crate::util::{is_guid, new_guid, now};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantSettings {
    /// Access token lifetime. Entra's default is 60-90 minutes; we use 60.
    pub access_token_lifetime_secs: i64,
    /// Browser sign-in session lifetime.
    pub session_lifetime_secs: i64,
    /// Refresh token inactivity lifetime (Entra: 90 days).
    pub refresh_token_lifetime_secs: i64,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            access_token_lifetime_secs: 3599,
            session_lifetime_secs: 86_400,
            refresh_token_lifetime_secs: 90 * 86_400,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub is_root: bool,
    pub enabled: bool,
    pub settings: TenantSettings,
}

#[derive(FromRow)]
struct TenantRow {
    id: String,
    name: String,
    is_root: bool,
    enabled: bool,
    settings: String,
}

impl From<TenantRow> for Tenant {
    fn from(r: TenantRow) -> Self {
        Tenant {
            id: r.id,
            name: r.name,
            is_root: r.is_root,
            enabled: r.enabled,
            settings: serde_json::from_str(&r.settings).unwrap_or_default(),
        }
    }
}

/// Resolve the `{tenant}` path segment: a tenant GUID or one of its verified
/// domains. Deleted and disabled tenants do not resolve.
pub async fn resolve(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<Tenant>> {
    let row: Option<TenantRow> = if is_guid(key) {
        sqlx::query_as(
            "SELECT id, name, is_root, enabled, settings FROM tenants
             WHERE id = ? COLLATE NOCASE AND deleted_at IS NULL AND enabled = 1",
        )
        .bind(key)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT t.id, t.name, t.is_root, t.enabled, t.settings FROM tenants t
             JOIN tenant_domains d ON d.tenant_id = t.id
             WHERE d.domain = ? AND t.deleted_at IS NULL AND t.enabled = 1",
        )
        .bind(key)
        .fetch_optional(pool)
        .await?
    };
    Ok(row.map(Tenant::from))
}

pub async fn root(pool: &SqlitePool) -> anyhow::Result<Option<Tenant>> {
    let row: Option<TenantRow> =
        sqlx::query_as("SELECT id, name, is_root, enabled, settings FROM tenants WHERE is_root = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Tenant::from))
}

pub async fn list(pool: &SqlitePool) -> anyhow::Result<Vec<(Tenant, Vec<String>)>> {
    let rows: Vec<TenantRow> = sqlx::query_as(
        "SELECT id, name, is_root, enabled, settings FROM tenants
         WHERE deleted_at IS NULL ORDER BY is_root DESC, created_at",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for row in rows {
        let t = Tenant::from(row);
        let domains = domains(pool, &t.id).await?;
        out.push((t, domains));
    }
    Ok(out)
}

pub async fn domains(pool: &SqlitePool, tenant_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT domain FROM tenant_domains WHERE tenant_id = ? ORDER BY is_default DESC, domain")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}

pub fn normalize_domain(domain: &str) -> anyhow::Result<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    // A GUID-looking domain would be ambiguous with tenant ids in URLs.
    if !valid || is_guid(&d) || d == "common" || d == "organizations" || d == "consumers" {
        bail!("invalid domain name '{domain}'");
    }
    Ok(d)
}

pub async fn create(pool: &SqlitePool, name: &str, domain: &str, is_root: bool) -> anyhow::Result<Tenant> {
    let domain = normalize_domain(domain)?;
    let id = new_guid();
    let settings = TenantSettings::default();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO tenants (id, name, is_root, enabled, settings, created_at) VALUES (?, ?, ?, 1, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(is_root)
        .bind(serde_json::to_string(&settings)?)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    insert_domain(&mut tx, &id, &domain, true).await?;
    tx.commit().await?;
    Ok(Tenant {
        id,
        name: name.to_string(),
        is_root,
        enabled: true,
        settings,
    })
}

pub async fn add_domain(pool: &SqlitePool, tenant_id: &str, domain: &str) -> anyhow::Result<()> {
    let domain = normalize_domain(domain)?;
    let mut tx = pool.begin().await?;
    insert_domain(&mut tx, tenant_id, &domain, false).await?;
    tx.commit().await?;
    Ok(())
}

async fn insert_domain(
    tx: &mut sqlx::SqliteConnection,
    tenant_id: &str,
    domain: &str,
    is_default: bool,
) -> anyhow::Result<()> {
    let taken: Option<(String,)> = sqlx::query_as("SELECT tenant_id FROM tenant_domains WHERE domain = ?")
        .bind(domain)
        .fetch_optional(&mut *tx)
        .await?;
    if taken.is_some() {
        bail!("domain '{domain}' is already registered to a tenant");
    }
    sqlx::query("INSERT INTO tenant_domains (domain, tenant_id, is_default, created_at) VALUES (?, ?, ?, ?)")
        .bind(domain)
        .bind(tenant_id)
        .bind(is_default)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// Resolve a tenant for CLI use; unlike [`resolve`] this also finds disabled tenants.
pub async fn find_for_admin(pool: &SqlitePool, key: &str) -> anyhow::Result<Tenant> {
    let row: Option<TenantRow> = sqlx::query_as(
        "SELECT t.id, t.name, t.is_root, t.enabled, t.settings FROM tenants t
         WHERE t.deleted_at IS NULL AND (t.id = ?1 COLLATE NOCASE
               OR t.id IN (SELECT tenant_id FROM tenant_domains WHERE domain = ?1))",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(r.into()),
        None => bail!("tenant '{key}' not found"),
    }
}
