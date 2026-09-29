use anyhow::{anyhow, bail};
use argon2::{Argon2, PasswordHasher};
use sqlx::SqlitePool;

use crate::tenant::{self, Tenant};
use crate::util::{new_guid, now};

pub struct NewUser<'a> {
    pub upn: &'a str,
    pub password: &'a str,
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Like Entra, a UPN must be `local@domain` where `domain` is verified in the tenant.
pub async fn validate_upn(pool: &SqlitePool, tenant: &Tenant, upn: &str) -> anyhow::Result<String> {
    let upn = upn.trim();
    let Some((local, domain)) = upn.rsplit_once('@') else {
        bail!("UPN '{upn}' must be in the form user@domain");
    };
    if local.is_empty() || local.chars().any(|c| c.is_whitespace() || c == '@') {
        bail!("invalid UPN '{upn}'");
    }
    let domain = tenant::normalize_domain(domain)?;
    if !tenant::domains(pool, &tenant.id).await?.contains(&domain) {
        bail!("domain '{domain}' is not a verified domain of tenant '{}'", tenant.name);
    }
    Ok(format!("{local}@{domain}"))
}

pub async fn create(pool: &SqlitePool, tenant: &Tenant, user: NewUser<'_>) -> anyhow::Result<String> {
    let upn = validate_upn(pool, tenant, user.upn).await?;
    if user.password.chars().count() < 8 {
        bail!("password must be at least 8 characters");
    }
    let id = new_guid();
    let ts = now();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, upn, email, email_verified, display_name, given_name,
                            family_name, password_hash, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(&id)
    .bind(&tenant.id)
    .bind(&upn)
    .bind(user.email)
    .bind(user.display_name)
    .bind(user.given_name)
    .bind(user.family_name)
    .bind(hash_password(user.password)?)
    .bind(ts)
    .bind(ts)
    .execute(pool)
    .await?;
    Ok(id)
}
