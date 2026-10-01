use crate::db::DbPool;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::util::{fold, is_guid, new_guid, now};

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

impl TenantSettings {
    /// The bounds the console accepts. **Every one of these is invented**: Entra
    /// publishes no equivalent range for v2.0 (its configurable token lifetimes
    /// were retired), so these are chosen to exclude the values that would be
    /// obviously wrong rather than to match a documented limit. They are recorded
    /// in `docs/decisions-log.md`.
    ///
    /// Five minutes is the shortest access token a client can plausibly use
    /// across a clock skew allowance; a day is the longest that is still a
    /// short-lived credential.
    pub const MIN_ACCESS_TOKEN_SECS: i64 = 300;
    pub const MAX_ACCESS_TOKEN_SECS: i64 = 86_400;
    /// A browser session: five minutes to thirty days.
    pub const MIN_SESSION_SECS: i64 = 300;
    pub const MAX_SESSION_SECS: i64 = 30 * 86_400;
    /// A refresh token's inactivity window: an hour to a year. Entra's default is
    /// ninety days, which is this type's default.
    pub const MIN_REFRESH_SECS: i64 = 3_600;
    pub const MAX_REFRESH_SECS: i64 = 365 * 86_400;

    /// Refuse a combination that cannot work, rather than storing it and issuing
    /// tokens nobody can use.
    pub fn validate(&self) -> anyhow::Result<()> {
        let range = |what: &str, value: i64, lo: i64, hi: i64| -> anyhow::Result<()> {
            if (lo..=hi).contains(&value) {
                Ok(())
            } else {
                bail!("{what} must be between {lo} and {hi} seconds")
            }
        };
        range(
            "the access token lifetime",
            self.access_token_lifetime_secs,
            Self::MIN_ACCESS_TOKEN_SECS,
            Self::MAX_ACCESS_TOKEN_SECS,
        )?;
        range(
            "the session lifetime",
            self.session_lifetime_secs,
            Self::MIN_SESSION_SECS,
            Self::MAX_SESSION_SECS,
        )?;
        range(
            "the refresh token lifetime",
            self.refresh_token_lifetime_secs,
            Self::MIN_REFRESH_SECS,
            Self::MAX_REFRESH_SECS,
        )?;
        // A refresh token that expires before the access token it mints is a
        // credential with nothing to refresh.
        if self.refresh_token_lifetime_secs < self.access_token_lifetime_secs {
            bail!("the refresh token lifetime must not be shorter than the access token lifetime");
        }
        Ok(())
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
    #[sqlx(try_from = "crate::db::Flag")]
    is_root: bool,
    #[sqlx(try_from = "crate::db::Flag")]
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
pub async fn resolve(pool: &DbPool, key: &str) -> anyhow::Result<Option<Tenant>> {
    let row: Option<TenantRow> = if is_guid(key) {
        sqlx::query_as(crate::db::q(
            pool,
            "SELECT id, name, is_root, enabled, settings FROM tenants
             WHERE id = ? AND deleted_at IS NULL AND enabled = ?",
        ))
        .bind(fold(key))
        .bind(true)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(crate::db::q(
            pool,
            "SELECT t.id, t.name, t.is_root, t.enabled, t.settings FROM tenants t
             JOIN tenant_domains d ON d.tenant_id = t.id
             WHERE d.domain_folded = ? AND t.deleted_at IS NULL AND t.enabled = ?",
        ))
        .bind(fold(key))
        .bind(true)
        .fetch_optional(pool)
        .await?
    };
    Ok(row.map(Tenant::from))
}

pub async fn root(pool: &DbPool) -> anyhow::Result<Option<Tenant>> {
    let row: Option<TenantRow> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, name, is_root, enabled, settings FROM tenants WHERE is_root = ?",
    ))
    .bind(true)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Tenant::from))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<(Tenant, Vec<String>)>> {
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

pub async fn domains(pool: &DbPool, tenant_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT domain FROM tenant_domains WHERE tenant_id = ? ORDER BY is_default DESC, domain",
    ))
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

pub async fn create(pool: &DbPool, name: &str, domain: &str, is_root: bool) -> anyhow::Result<Tenant> {
    let domain = normalize_domain(domain)?;
    let id = new_guid();
    let settings = TenantSettings::default();
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO tenants (id, name, is_root, enabled, settings, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(name)
    .bind(is_root)
    .bind(true)
    .bind(serde_json::to_string(&settings)?)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    insert_domain(&mut tx, engine, &id, &domain, true).await?;
    tx.commit().await?;
    Ok(Tenant {
        id,
        name: name.to_string(),
        is_root,
        enabled: true,
        settings,
    })
}

pub async fn add_domain(pool: &DbPool, tenant_id: &str, domain: &str) -> anyhow::Result<()> {
    let domain = normalize_domain(domain)?;
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    insert_domain(&mut tx, engine, tenant_id, &domain, false).await?;
    tx.commit().await?;
    Ok(())
}

async fn insert_domain(
    tx: &mut sqlx::AnyConnection,
    engine: crate::db::Engine,
    tenant_id: &str,
    domain: &str,
    is_default: bool,
) -> anyhow::Result<()> {
    let taken: Option<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT tenant_id FROM tenant_domains WHERE domain_folded = ?",
    ))
    .bind(fold(domain))
    .fetch_optional(&mut *tx)
    .await?;
    if taken.is_some() {
        bail!("domain '{domain}' is already registered to a tenant");
    }
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO tenant_domains (domain, domain_folded, tenant_id, is_default, created_at) VALUES (?, ?, ?, ?, ?)",
    ))
    .bind(domain)
    .bind(fold(domain))
    .bind(tenant_id)
    .bind(is_default)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Resolve a tenant for CLI use; unlike [`resolve`] this also finds disabled tenants.
pub async fn find_for_admin(pool: &DbPool, key: &str) -> anyhow::Result<Tenant> {
    let row: Option<TenantRow> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT t.id, t.name, t.is_root, t.enabled, t.settings FROM tenants t
         WHERE t.deleted_at IS NULL AND (t.id = ?
               OR t.id IN (SELECT tenant_id FROM tenant_domains WHERE domain_folded = ?))",
    ))
    .bind(fold(key))
    .bind(fold(key))
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(r.into()),
        None => bail!("tenant '{key}' not found"),
    }
}

/// Replace a tenant's settings. The first write path for [`TenantSettings`],
/// which until now was only ever read: a tenant has carried whatever
/// [`TenantSettings::default`] produced at `create`.
///
/// Validated before it is stored, so a tenant cannot hold a combination the
/// console would refuse to show.
pub async fn save_settings(pool: &DbPool, tenant_id: &str, settings: &TenantSettings) -> anyhow::Result<()> {
    settings.validate()?;
    sqlx::query(crate::db::q(pool, "UPDATE tenants SET settings = ? WHERE id = ?"))
        .bind(serde_json::to_string(settings)?)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Rename a tenant. The display name only: the id and the verified domains are
/// what anything else refers to, so a rename breaks nothing.
pub async fn set_name(pool: &DbPool, tenant_id: &str, name: &str) -> anyhow::Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("a tenant needs a name");
    }
    sqlx::query(crate::db::q(pool, "UPDATE tenants SET name = ? WHERE id = ?"))
        .bind(name)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Enable or disable a tenant. A disabled tenant does not [`resolve`], so every
/// OIDC endpoint and every console page addressed by it stops answering.
///
/// **The root tenant cannot be disabled.** Its administrators are the ones who
/// could re-enable anything, their console session is dropped the moment their
/// home tenant stops resolving, and there is no CLI command to undo it -- the
/// admin surface is deliberately web-only. So disabling it would lock every
/// administrator out of the deployment with no path back short of editing the
/// database by hand. The same shape of rule as `admin::authz::check_delete`.
pub async fn set_enabled(pool: &DbPool, tenant_id: &str, enabled: bool) -> anyhow::Result<()> {
    let tenant = find_for_admin(pool, tenant_id).await?;
    if !enabled && tenant.is_root {
        bail!(
            "the root tenant cannot be disabled: it holds the administrators who would \
             have to re-enable it, and nothing outside the database could undo it"
        );
    }
    sqlx::query(crate::db::q(pool, "UPDATE tenants SET enabled = ? WHERE id = ?"))
        .bind(enabled)
        .bind(&tenant.id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Withdraw a verified domain.
///
/// Three refusals, each because the alternative is an identity that silently
/// stops working:
/// - a domain this tenant does not hold (it may be another tenant's);
/// - the tenant's last domain, which would leave it with no UPN suffix at all;
/// - a domain still used by a live account's UPN. Such an account could still be
///   authenticated through its own tenant, but the console's sign-in resolves the
///   tenant *from the UPN's domain*, so it could no longer sign in there.
pub async fn remove_domain(pool: &DbPool, tenant_id: &str, domain: &str) -> anyhow::Result<()> {
    let domain = normalize_domain(domain)?;
    let held = domains(pool, tenant_id).await?;
    let Some(stored) = held.iter().find(|d| fold(d) == domain) else {
        bail!("'{domain}' is not a verified domain of this tenant");
    };
    if held.len() <= 1 {
        bail!("a tenant must keep at least one verified domain");
    }
    // `normalize_domain` admits only letters, digits, '-' and '.', so the pattern
    // can hold no LIKE wildcard.
    let (in_use,): (i64,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT COUNT(*) FROM users WHERE tenant_id = ? AND deleted_at IS NULL AND upn_folded LIKE ?",
    ))
    .bind(tenant_id)
    .bind(format!("%@{domain}"))
    .fetch_one(pool)
    .await?;
    if in_use > 0 {
        bail!("{in_use} account(s) still use '{domain}' in their user name");
    }
    sqlx::query(crate::db::q(
        pool,
        "DELETE FROM tenant_domains WHERE tenant_id = ? AND domain_folded = ?",
    ))
    .bind(tenant_id)
    .bind(fold(stored))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_settings_are_within_their_own_bounds() {
        TenantSettings::default().validate().unwrap();
    }

    #[test]
    fn a_lifetime_outside_its_bounds_is_refused() {
        let refused = [
            TenantSettings {
                access_token_lifetime_secs: TenantSettings::MIN_ACCESS_TOKEN_SECS - 1,
                ..Default::default()
            },
            TenantSettings {
                access_token_lifetime_secs: TenantSettings::MAX_ACCESS_TOKEN_SECS + 1,
                ..Default::default()
            },
            TenantSettings {
                session_lifetime_secs: 0,
                ..Default::default()
            },
            TenantSettings {
                session_lifetime_secs: TenantSettings::MAX_SESSION_SECS + 1,
                ..Default::default()
            },
            TenantSettings {
                refresh_token_lifetime_secs: TenantSettings::MIN_REFRESH_SECS - 1,
                ..Default::default()
            },
            TenantSettings {
                refresh_token_lifetime_secs: TenantSettings::MAX_REFRESH_SECS + 1,
                ..Default::default()
            },
        ];
        for s in refused {
            assert!(s.validate().is_err(), "{s:?} should be refused");
        }
    }

    #[test]
    fn a_refresh_token_shorter_than_the_access_token_it_mints_is_refused() {
        let s = TenantSettings {
            access_token_lifetime_secs: 7_200,
            session_lifetime_secs: 86_400,
            refresh_token_lifetime_secs: 3_600,
        };
        assert!(s.validate().is_err());
    }
}
