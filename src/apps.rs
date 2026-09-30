//! Application registrations and service principals, modelled on Entra ID.

use anyhow::{Context, bail};
use sqlx::{FromRow, SqlitePool};

use crate::tenant::Tenant;
use crate::util::{b64url, ct_eq, generate_client_secret, is_guid, new_guid, now, sha256_hex};

#[derive(Clone, Debug, FromRow)]
pub struct Application {
    pub id: String,
    pub app_id: String,
    pub tenant_id: String,
    pub display_name: String,
    /// ROPC is refused unless an administrator has turned it on for this app.
    pub allow_password_grant: bool,
}

#[derive(Clone, Debug, FromRow)]
pub struct ServicePrincipal {
    pub id: String,
    pub tenant_id: String,
    pub app_id: String,
    pub enabled: bool,
    pub app_role_assignment_required: bool,
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
        allow_password_grant: false,
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
        "SELECT id, app_id, tenant_id, display_name, allow_password_grant FROM applications
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
        "SELECT id, app_id, tenant_id, display_name, allow_password_grant FROM applications
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
        "SELECT id, tenant_id, app_id, enabled, app_role_assignment_required FROM service_principals
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
            "SELECT a.id, a.app_id, a.tenant_id, a.display_name, a.allow_password_grant FROM applications a
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

// ---- redirect URIs ----

pub const PLATFORM_WEB: &str = "web";
pub const PLATFORM_SPA: &str = "spa";
pub const PLATFORM_PUBLIC: &str = "publicClient";

fn is_loopback_http(url: &url::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Entra's rules: web and SPA URIs must be https (or http on loopback); no
/// fragments anywhere; public clients may use custom schemes.
pub fn validate_redirect_uri(platform: &str, uri: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(uri).with_context(|| format!("redirect URI '{uri}' is not an absolute URI"))?;
    if url.fragment().is_some() {
        bail!("redirect URI must not contain a fragment");
    }
    match platform {
        PLATFORM_WEB | PLATFORM_SPA => {
            if url.scheme() != "https" && !is_loopback_http(&url) {
                bail!("{platform} redirect URIs must use https (http is allowed only for localhost)");
            }
        }
        PLATFORM_PUBLIC => {}
        _ => bail!("platform must be one of web, spa, publicClient"),
    }
    Ok(())
}

pub async fn add_redirect_uri(pool: &SqlitePool, app: &Application, platform: &str, uri: &str) -> anyhow::Result<()> {
    validate_redirect_uri(platform, uri)?;
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT platform FROM app_redirect_uris WHERE application_id = ? AND uri = ?")
            .bind(&app.id)
            .bind(uri)
            .fetch_optional(pool)
            .await?;
    if let Some((p,)) = existing {
        bail!("redirect URI '{uri}' is already registered for platform {p}");
    }
    sqlx::query("INSERT INTO app_redirect_uris (application_id, platform, uri) VALUES (?, ?, ?)")
        .bind(&app.id)
        .bind(platform)
        .bind(uri)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn redirect_uris(pool: &SqlitePool, app: &Application) -> anyhow::Result<Vec<(String, String)>> {
    Ok(
        sqlx::query_as("SELECT platform, uri FROM app_redirect_uris WHERE application_id = ? ORDER BY platform, uri")
            .bind(&app.id)
            .fetch_all(pool)
            .await?,
    )
}

/// Exact match, except that the port is ignored for http loopback URIs, as in Entra.
pub fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    match (url::Url::parse(registered), url::Url::parse(requested)) {
        (Ok(mut a), Ok(mut b)) if is_loopback_http(&a) && is_loopback_http(&b) => {
            let _ = a.set_port(None);
            let _ = b.set_port(None);
            a.as_str() == b.as_str()
        }
        _ => false,
    }
}

/// The platform of the registered redirect URI matching `requested`, if any.
pub async fn match_redirect_uri(
    pool: &SqlitePool,
    app: &Application,
    requested: &str,
) -> anyhow::Result<Option<String>> {
    Ok(redirect_uris(pool, app)
        .await?
        .into_iter()
        .find(|(_, uri)| redirect_uri_matches(uri, requested))
        .map(|(platform, _)| platform))
}

// ---- delegated permission scopes ----

pub async fn add_scope(
    pool: &SqlitePool,
    app: &Application,
    value: &str,
    display_name: &str,
    scope_type: &str,
) -> anyhow::Result<String> {
    if value.is_empty() || value.contains(char::is_whitespace) || value.starts_with('.') || value.contains('/') {
        bail!("invalid scope value '{value}'");
    }
    if scope_type != "User" && scope_type != "Admin" {
        bail!("scope type must be User or Admin");
    }
    let id = new_guid();
    sqlx::query(
        "INSERT INTO app_scopes (id, application_id, value, display_name, type, enabled) VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&app.id)
    .bind(value)
    .bind(display_name)
    .bind(scope_type)
    .execute(pool)
    .await
    .with_context(|| format!("scope '{value}' already exists"))?;
    Ok(id)
}

pub async fn enabled_scopes(pool: &SqlitePool, app: &Application) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT value FROM app_scopes WHERE application_id = ? AND enabled = 1 ORDER BY value")
            .bind(&app.id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(v,)| v).collect())
}

/// Role values of `resource_sp_id` a user holds directly or through group
/// membership (the `roles` claim of user tokens).
pub async fn app_roles_for_user(pool: &SqlitePool, resource_sp_id: &str, user_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT r.value, r.allowed_member_types FROM app_role_assignments a
         JOIN app_roles r ON r.id = a.app_role_id
         WHERE a.resource_id = ?1 AND r.enabled = 1
           AND ((a.principal_type = 'User' AND a.principal_id = ?2)
             OR (a.principal_type = 'Group' AND a.principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?2)))
         ORDER BY r.value",
    )
    .bind(resource_sp_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, types)| types.contains(MEMBER_USER))
        .map(|(value, _)| value)
        .collect())
}

/// Whether the user may sign in to an app that requires assignment
/// (`appRoleAssignmentRequired`), directly or through a group.
pub async fn user_is_assigned(pool: &SqlitePool, sp_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM app_role_assignments
         WHERE resource_id = ?1
           AND ((principal_type = 'User' AND principal_id = ?2)
             OR (principal_type = 'Group' AND principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?2)))",
    )
    .bind(sp_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub async fn set_assignment_required(pool: &SqlitePool, sp_id: &str, required: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE service_principals SET app_role_assignment_required = ? WHERE id = ?")
        .bind(required)
        .bind(sp_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Compare certificate thumbprints across the spellings clients actually send.
///
/// We store base64url without padding. MSAL sends base64url *with* `=` padding,
/// and some clients use standard base64 (`+`/`/`) or hex. Normalising means an
/// `x5t` is matched on the bytes it denotes rather than on its spelling.
pub fn normalize_thumbprint(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('=');
    // A hex thumbprint (SHA-1 is 40 hex chars, possibly colon-separated).
    let hex_digits: String = trimmed.chars().filter(|c| !matches!(c, ':' | ' ')).collect();
    if hex_digits.len() == 40
        && hex_digits.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(bytes) = hex::decode(&hex_digits)
    {
        return b64url(&bytes);
    }
    trimmed.replace('+', "-").replace('/', "_")
}

/// Allow or forbid the resource owner password grant for this app.
pub async fn set_password_grant_allowed(pool: &SqlitePool, app: &Application, allowed: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE applications SET allow_password_grant = ? WHERE id = ?")
        .bind(allowed)
        .bind(&app.id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---- certificate (key) credentials, for private_key_jwt ----

/// A registered certificate a client may sign assertions with.
#[derive(FromRow)]
pub struct KeyCredential {
    pub key_id: String,
    pub display_name: Option<String>,
    #[sqlx(rename = "public_n")]
    pub n: Vec<u8>,
    #[sqlx(rename = "public_e")]
    pub e: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

impl KeyCredential {
    pub fn is_current(&self, at: i64) -> bool {
        self.not_before <= at && at < self.not_after
    }
}

/// A client certificate broken into the parts needed to verify assertions.
pub struct ParsedCertificate {
    /// Entra-style thumbprint: base64url(SHA-1(cert DER)), matching `x5t`.
    pub key_id: String,
    pub cert_der: Vec<u8>,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

/// Parse a PEM X.509 certificate. Only RSA certificates are supported, which is
/// what Entra accepts for client assertions.
pub fn parse_certificate(pem: &str) -> anyhow::Result<ParsedCertificate> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use sha1::{Digest, Sha1};
    use x509_cert::der::{DecodePem, Encode};
    use x509_cert::Certificate;

    let cert = Certificate::from_pem(pem.as_bytes()).context("not a PEM X.509 certificate")?;
    let cert_der = cert.to_der().context("re-encoding the certificate")?;
    let key_id = b64url(&Sha1::digest(&cert_der));

    let spki = cert.tbs_certificate().subject_public_key_info();
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .context("the certificate's public key is not byte-aligned")?;
    let public = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
        .context("only RSA certificates are supported for client assertions")?;
    let (n, e) = (
        rsa::traits::PublicKeyParts::n(&public).to_bytes_be(),
        rsa::traits::PublicKeyParts::e(&public).to_bytes_be(),
    );

    let validity = cert.tbs_certificate().validity();
    Ok(ParsedCertificate {
        key_id,
        cert_der,
        n,
        e,
        not_before: validity.not_before.to_unix_duration().as_secs() as i64,
        not_after: validity.not_after.to_unix_duration().as_secs() as i64,
    })
}

/// Register a certificate credential. Returns its thumbprint (`key_id`).
pub async fn add_key_credential(
    pool: &SqlitePool,
    app: &Application,
    cert_pem: &str,
    display_name: Option<&str>,
) -> anyhow::Result<String> {
    let cert = parse_certificate(cert_pem)?;
    sqlx::query(
        "INSERT INTO app_key_credentials
            (application_id, key_id, display_name, cert_der, public_n, public_e, created_at, not_before, not_after)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (application_id, key_id) DO UPDATE SET
            display_name = excluded.display_name, cert_der = excluded.cert_der,
            public_n = excluded.public_n, public_e = excluded.public_e,
            not_before = excluded.not_before, not_after = excluded.not_after",
    )
    .bind(&app.id)
    .bind(&cert.key_id)
    .bind(display_name)
    .bind(&cert.cert_der)
    .bind(&cert.n)
    .bind(&cert.e)
    .bind(now())
    .bind(cert.not_before)
    .bind(cert.not_after)
    .execute(pool)
    .await?;
    Ok(cert.key_id)
}

pub async fn key_credentials(pool: &SqlitePool, app: &Application) -> anyhow::Result<Vec<KeyCredential>> {
    Ok(sqlx::query_as::<_, KeyCredential>(
        "SELECT key_id, display_name, public_n, public_e, not_before, not_after
         FROM app_key_credentials WHERE application_id = ? ORDER BY created_at",
    )
    .bind(&app.id)
    .fetch_all(pool)
    .await?)
}

pub async fn remove_key_credential(pool: &SqlitePool, app: &Application, key_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query("DELETE FROM app_key_credentials WHERE application_id = ? AND key_id = ?")
        .bind(&app.id)
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}
