//! Application registrations and service principals, modelled on Entra ID.

use anyhow::{Context, bail};
use sqlx::{FromRow, SqlitePool};

use crate::tenant::Tenant;
use crate::util::{ct_eq, generate_client_secret, is_guid, new_guid, now, sha256_hex};

#[derive(Clone, Debug, FromRow)]
pub struct Application {
    pub id: String,
    pub app_id: String,
    pub tenant_id: String,
    pub display_name: String,
}

#[derive(Clone, Debug, FromRow)]
pub struct ServicePrincipal {
    pub id: String,
    pub tenant_id: String,
    pub app_id: String,
    pub enabled: bool,
}

pub struct CreatedApp {
    pub application: Application,
    pub service_principal_id: String,
    pub identifier_uri: String,
}

/// Register an app in its home tenant: application object, default identifier
/// URI `api://{appId}` and the home-tenant service principal.
pub async fn create(pool: &SqlitePool, tenant: &Tenant, display_name: &str) -> anyhow::Result<CreatedApp> {
    let application = Application {
        id: new_guid(),
        app_id: new_guid(),
        tenant_id: tenant.id.clone(),
        display_name: display_name.to_string(),
    };
    let sp_id = new_guid();
    let identifier_uri = format!("api://{}", application.app_id);
    let ts = now();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO applications (id, app_id, tenant_id, display_name, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&application.id)
        .bind(&application.app_id)
        .bind(&tenant.id)
        .bind(display_name)
        .bind(ts)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO app_identifier_uris (application_id, tenant_id, uri) VALUES (?, ?, ?)")
        .bind(&application.id)
        .bind(&tenant.id)
        .bind(&identifier_uri)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO service_principals (id, tenant_id, app_id, enabled, created_at) VALUES (?, ?, ?, 1, ?)")
        .bind(&sp_id)
        .bind(&tenant.id)
        .bind(&application.app_id)
        .bind(ts)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(CreatedApp {
        application,
        service_principal_id: sp_id,
        identifier_uri,
    })
}

pub async fn find(pool: &SqlitePool, app_id: &str) -> anyhow::Result<Option<Application>> {
    if !is_guid(app_id) {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT id, app_id, tenant_id, display_name FROM applications
         WHERE app_id = ? COLLATE NOCASE AND deleted_at IS NULL",
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn find_in_tenant(pool: &SqlitePool, tenant: &Tenant, app_id: &str) -> anyhow::Result<Application> {
    match find(pool, app_id).await? {
        Some(app) if app.tenant_id == tenant.id => Ok(app),
        _ => bail!("application '{app_id}' not found in tenant '{}'", tenant.name),
    }
}

pub async fn list(pool: &SqlitePool, tenant_id: &str) -> anyhow::Result<Vec<Application>> {
    Ok(sqlx::query_as(
        "SELECT id, app_id, tenant_id, display_name FROM applications
         WHERE tenant_id = ? AND deleted_at IS NULL ORDER BY created_at",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?)
}

pub async fn service_principal(
    pool: &SqlitePool,
    tenant_id: &str,
    app_id: &str,
) -> anyhow::Result<Option<ServicePrincipal>> {
    Ok(sqlx::query_as(
        "SELECT id, tenant_id, app_id, enabled FROM service_principals
         WHERE tenant_id = ? AND app_id = ? COLLATE NOCASE",
    )
    .bind(tenant_id)
    .bind(app_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn add_identifier_uri(pool: &SqlitePool, app: &Application, uri: &str) -> anyhow::Result<()> {
    url::Url::parse(uri).with_context(|| format!("identifier URI '{uri}' is not a valid URI"))?;
    sqlx::query("INSERT INTO app_identifier_uris (application_id, tenant_id, uri) VALUES (?, ?, ?)")
        .bind(&app.id)
        .bind(&app.tenant_id)
        .bind(uri)
        .execute(pool)
        .await
        .with_context(|| format!("identifier URI '{uri}' is already used in this tenant"))?;
    Ok(())
}

pub async fn identifier_uris(pool: &SqlitePool, app: &Application) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT uri FROM app_identifier_uris WHERE application_id = ? ORDER BY uri")
            .bind(&app.id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(u,)| u).collect())
}

/// Resolve a resource named in a scope (`api://...` or a bare appId) to the
/// resource's service principal in `tenant_id`.
pub async fn resolve_resource(
    pool: &SqlitePool,
    tenant_id: &str,
    resource: &str,
) -> anyhow::Result<Option<(Application, ServicePrincipal)>> {
    let app: Option<Application> = if is_guid(resource) {
        find(pool, resource).await?
    } else {
        sqlx::query_as(
            "SELECT a.id, a.app_id, a.tenant_id, a.display_name FROM applications a
             JOIN app_identifier_uris u ON u.application_id = a.id
             WHERE u.tenant_id = ? AND u.uri = ? AND a.deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(resource)
        .fetch_optional(pool)
        .await?
    };
    let Some(app) = app else { return Ok(None) };
    let sp = service_principal(pool, tenant_id, &app.app_id).await?;
    Ok(sp.map(|sp| (app, sp)))
}

// ---- client secrets ----

pub struct NewSecret {
    pub key_id: String,
    pub secret: String,
    pub end_at: i64,
}

pub async fn add_secret(
    pool: &SqlitePool,
    app: &Application,
    display_name: Option<&str>,
    valid_days: i64,
) -> anyhow::Result<NewSecret> {
    if !(1..=730).contains(&valid_days) {
        bail!("secret lifetime must be between 1 and 730 days (Entra's maximum is 24 months)");
    }
    let secret = generate_client_secret();
    let key_id = new_guid();
    let ts = now();
    let end_at = ts + valid_days * 86_400;
    sqlx::query(
        "INSERT INTO app_secrets (key_id, application_id, display_name, hint, secret_hash, start_at, end_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&key_id)
    .bind(&app.id)
    .bind(display_name)
    .bind(&secret[..3])
    .bind(sha256_hex(secret.as_bytes()))
    .bind(ts)
    .bind(end_at)
    .bind(ts)
    .execute(pool)
    .await?;
    Ok(NewSecret { key_id, secret, end_at })
}

pub async fn remove_secret(pool: &SqlitePool, app: &Application, key_id: &str) -> anyhow::Result<()> {
    let res = sqlx::query("DELETE FROM app_secrets WHERE application_id = ? AND key_id = ?")
        .bind(&app.id)
        .bind(key_id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        bail!("secret '{key_id}' not found");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretCheck {
    Valid,
    Expired,
    Invalid,
}

pub async fn verify_secret(pool: &SqlitePool, app: &Application, secret: &str) -> anyhow::Result<SecretCheck> {
    let rows: Vec<(String, i64, i64)> =
        sqlx::query_as("SELECT secret_hash, start_at, end_at FROM app_secrets WHERE application_id = ?")
            .bind(&app.id)
            .fetch_all(pool)
            .await?;
    let presented = sha256_hex(secret.as_bytes());
    let ts = now();
    let mut result = SecretCheck::Invalid;
    for (hash, start_at, end_at) in rows {
        if ct_eq(&hash, &presented) {
            if ts >= start_at && ts < end_at {
                return Ok(SecretCheck::Valid);
            }
            result = SecretCheck::Expired;
        }
    }
    Ok(result)
}

// ---- app roles ----

pub const MEMBER_USER: &str = "User";
pub const MEMBER_APPLICATION: &str = "Application";

pub async fn add_role(
    pool: &SqlitePool,
    app: &Application,
    value: &str,
    display_name: &str,
    description: Option<&str>,
    member_types: &[&str],
) -> anyhow::Result<String> {
    if value.is_empty() || value.chars().any(|c| c.is_whitespace()) || value.starts_with('.') {
        bail!("invalid app role value '{value}' (no spaces, must not start with '.')");
    }
    if member_types.is_empty()
        || member_types
            .iter()
            .any(|t| *t != MEMBER_USER && *t != MEMBER_APPLICATION)
    {
        bail!("allowed member types must be User and/or Application");
    }
    let id = new_guid();
    sqlx::query(
        "INSERT INTO app_roles (id, application_id, value, display_name, description, allowed_member_types, enabled)
         VALUES (?, ?, ?, ?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&app.id)
    .bind(value)
    .bind(display_name)
    .bind(description)
    .bind(serde_json::to_string(member_types)?)
    .execute(pool)
    .await
    .with_context(|| format!("app role '{value}' already exists"))?;
    Ok(id)
}

#[derive(Debug, FromRow)]
pub struct AppRole {
    pub id: String,
    pub value: String,
    pub display_name: String,
    pub allowed_member_types: String,
    pub enabled: bool,
}

impl AppRole {
    pub fn allows(&self, member_type: &str) -> bool {
        serde_json::from_str::<Vec<String>>(&self.allowed_member_types)
            .map(|types| types.iter().any(|t| t == member_type))
            .unwrap_or(false)
    }
}

pub async fn roles(pool: &SqlitePool, app: &Application) -> anyhow::Result<Vec<AppRole>> {
    Ok(sqlx::query_as(
        "SELECT id, value, display_name, allowed_member_types, enabled FROM app_roles
         WHERE application_id = ? ORDER BY value",
    )
    .bind(&app.id)
    .fetch_all(pool)
    .await?)
}

pub enum Principal {
    /// A client application, by appId; resolves to its service principal.
    App(String),
    /// A user, by UPN.
    User(String),
    /// A group, by name.
    Group(String),
}

/// Assign app role `role_value` of `resource` to a principal in the same tenant.
pub async fn assign_role(
    pool: &SqlitePool,
    tenant: &Tenant,
    resource: &Application,
    role_value: &str,
    principal: &Principal,
) -> anyhow::Result<()> {
    let Some(resource_sp) = service_principal(pool, &tenant.id, &resource.app_id).await? else {
        bail!(
            "app '{}' has no service principal in tenant '{}'",
            resource.app_id,
            tenant.name
        );
    };
    let role = roles(pool, resource)
        .await?
        .into_iter()
        .find(|r| r.value == role_value)
        .with_context(|| format!("app '{}' has no role '{role_value}'", resource.display_name))?;

    let (principal_id, principal_type, member_type) = match principal {
        Principal::App(app_id) => {
            let sp = service_principal(pool, &tenant.id, app_id)
                .await?
                .with_context(|| format!("app '{app_id}' not found in tenant '{}'", tenant.name))?;
            (sp.id, "ServicePrincipal", MEMBER_APPLICATION)
        }
        Principal::User(upn) => {
            let row: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE tenant_id = ? AND upn = ?")
                .bind(&tenant.id)
                .bind(upn)
                .fetch_optional(pool)
                .await?;
            let (id,) = row.with_context(|| format!("user '{upn}' not found"))?;
            (id, "User", MEMBER_USER)
        }
        Principal::Group(name) => {
            let row: Option<(String,)> = sqlx::query_as("SELECT id FROM groups WHERE tenant_id = ? AND name = ?")
                .bind(&tenant.id)
                .bind(name)
                .fetch_optional(pool)
                .await?;
            let (id,) = row.with_context(|| format!("group '{name}' not found"))?;
            (id, "Group", MEMBER_USER)
        }
    };
    if !role.allows(member_type) {
        bail!("app role '{role_value}' cannot be assigned to {member_type} principals");
    }
    sqlx::query(
        "INSERT OR IGNORE INTO app_role_assignments
            (id, tenant_id, resource_id, app_role_id, principal_id, principal_type, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(new_guid())
    .bind(&tenant.id)
    .bind(&resource_sp.id)
    .bind(&role.id)
    .bind(&principal_id)
    .bind(principal_type)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Role values of `resource_sp` assigned to the client service principal
/// `client_sp_id` (the `roles` claim of an app-only token).
pub async fn app_roles_for_service_principal(
    pool: &SqlitePool,
    resource_sp_id: &str,
    client_sp_id: &str,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT r.value, r.allowed_member_types FROM app_role_assignments a
         JOIN app_roles r ON r.id = a.app_role_id
         WHERE a.resource_id = ? AND a.principal_id = ? AND a.principal_type = 'ServicePrincipal'
           AND r.enabled = 1
         ORDER BY r.value",
    )
    .bind(resource_sp_id)
    .bind(client_sp_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, types)| types.contains(MEMBER_APPLICATION))
        .map(|(value, _)| value)
        .collect())
}
