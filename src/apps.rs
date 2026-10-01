//! Application registrations and service principals, modelled on Entra ID.

use crate::db::DbPool;
use anyhow::{Context, bail};
use sqlx::FromRow;

use crate::directory::PrincipalType;
use crate::tenant::Tenant;
use crate::util::{b64url, ct_eq, generate_client_secret, is_guid, new_guid, now, sha256_hex};

#[derive(Clone, Debug, FromRow)]
pub struct Application {
    pub id: String,
    pub app_id: String,
    pub tenant_id: String,
    pub display_name: String,
    /// ROPC is refused unless an administrator has turned it on for this app.
    #[sqlx(try_from = "crate::db::Flag")]
    pub allow_password_grant: bool,
    /// Entra's "ID tokens" toggle: allows `response_type` values containing
    /// `id_token`. Off by default.
    #[sqlx(try_from = "crate::db::Flag")]
    pub allow_id_token_implicit: bool,
    /// Entra's "access tokens" toggle: allows `response_type` values containing
    /// `token`. Off by default.
    #[sqlx(try_from = "crate::db::Flag")]
    pub allow_access_token_implicit: bool,
}

#[derive(Clone, Debug, FromRow)]
pub struct ServicePrincipal {
    pub id: String,
    pub tenant_id: String,
    pub app_id: String,
    #[sqlx(try_from = "crate::db::Flag")]
    pub enabled: bool,
    #[sqlx(try_from = "crate::db::Flag")]
    pub app_role_assignment_required: bool,
}

pub struct CreatedApp {
    pub application: Application,
    pub service_principal_id: String,
    pub identifier_uri: String,
}

/// Register an app in its home tenant: application object, default identifier
/// URI `api://{appId}` and the home-tenant service principal.
pub async fn create(pool: &DbPool, tenant: &Tenant, display_name: &str) -> anyhow::Result<CreatedApp> {
    let application = Application {
        id: new_guid(),
        app_id: new_guid(),
        tenant_id: tenant.id.clone(),
        display_name: display_name.to_string(),
        allow_password_grant: false,
        allow_id_token_implicit: false,
        allow_access_token_implicit: false,
    };
    let sp_id = new_guid();
    let identifier_uri = format!("api://{}", application.app_id);
    let ts = now();
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO applications (id, app_id, tenant_id, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
    ))
    .bind(&application.id)
    .bind(&application.app_id)
    .bind(&tenant.id)
    .bind(display_name)
    .bind(ts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO app_identifier_uris (application_id, tenant_id, uri) VALUES (?, ?, ?)",
    ))
    .bind(&application.id)
    .bind(&tenant.id)
    .bind(&identifier_uri)
    .execute(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO service_principals (id, tenant_id, app_id, enabled, created_at) VALUES (?, ?, ?, ?, ?)",
    ))
    .bind(&sp_id)
    .bind(&tenant.id)
    .bind(&application.app_id)
    .bind(true)
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

pub async fn find(pool: &DbPool, app_id: &str) -> anyhow::Result<Option<Application>> {
    if !is_guid(app_id) {
        return Ok(None);
    }
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, app_id, tenant_id, display_name, allow_password_grant, allow_id_token_implicit,
                allow_access_token_implicit FROM applications
         WHERE app_id = ? AND deleted_at IS NULL",
    ))
    // GUIDs are stored lowercase; fold the probe so `ABC-..` still finds them.
    .bind(crate::util::fold(app_id))
    .fetch_optional(pool)
    .await?)
}

pub async fn find_in_tenant(pool: &DbPool, tenant: &Tenant, app_id: &str) -> anyhow::Result<Application> {
    match find(pool, app_id).await? {
        Some(app) if app.tenant_id == tenant.id => Ok(app),
        _ => bail!("application '{app_id}' not found in tenant '{}'", tenant.name),
    }
}

pub async fn list(pool: &DbPool, tenant_id: &str) -> anyhow::Result<Vec<Application>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, app_id, tenant_id, display_name, allow_password_grant, allow_id_token_implicit,
                allow_access_token_implicit FROM applications
         WHERE tenant_id = ? AND deleted_at IS NULL ORDER BY created_at",
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await?)
}

pub async fn service_principal(
    pool: &DbPool,
    tenant_id: &str,
    app_id: &str,
) -> anyhow::Result<Option<ServicePrincipal>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, tenant_id, app_id, enabled, app_role_assignment_required FROM service_principals
         WHERE tenant_id = ? AND app_id = ?",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(app_id))
    .fetch_optional(pool)
    .await?)
}

pub async fn add_identifier_uri(pool: &DbPool, app: &Application, uri: &str) -> anyhow::Result<()> {
    url::Url::parse(uri).with_context(|| format!("identifier URI '{uri}' is not a valid URI"))?;
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO app_identifier_uris (application_id, tenant_id, uri) VALUES (?, ?, ?)",
    ))
    .bind(&app.id)
    .bind(&app.tenant_id)
    .bind(uri)
    .execute(pool)
    .await
    .with_context(|| format!("identifier URI '{uri}' is already used in this tenant"))?;
    Ok(())
}

pub async fn identifier_uris(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT uri FROM app_identifier_uris WHERE application_id = ? ORDER BY uri",
    ))
    .bind(&app.id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(u,)| u).collect())
}

/// Resolve a resource named in a scope (`api://...` or a bare appId) to the
/// resource's service principal in `tenant_id`.
pub async fn resolve_resource(
    pool: &DbPool,
    tenant_id: &str,
    resource: &str,
) -> anyhow::Result<Option<(Application, ServicePrincipal)>> {
    let app: Option<Application> = if is_guid(resource) {
        find(pool, resource).await?
    } else {
        sqlx::query_as(crate::db::q(
            pool,
            "SELECT a.id, a.app_id, a.tenant_id, a.display_name, a.allow_password_grant,
                    a.allow_id_token_implicit, a.allow_access_token_implicit FROM applications a
             JOIN app_identifier_uris u ON u.application_id = a.id
             WHERE u.tenant_id = ? AND u.uri = ? AND a.deleted_at IS NULL",
        ))
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
    pool: &DbPool,
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
        crate::db::q(pool, "INSERT INTO app_secrets (key_id, application_id, display_name, hint, secret_hash, start_at, end_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
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

pub async fn remove_secret(pool: &DbPool, app: &Application, key_id: &str) -> anyhow::Result<()> {
    let res = sqlx::query(crate::db::q(
        pool,
        "DELETE FROM app_secrets WHERE application_id = ? AND key_id = ?",
    ))
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

pub async fn verify_secret(pool: &DbPool, app: &Application, secret: &str) -> anyhow::Result<SecretCheck> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT secret_hash, start_at, end_at FROM app_secrets WHERE application_id = ?",
    ))
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

/// Who may consent to a delegated permission: the `type` column of `app_scopes`.
///
/// Graph's `permissionScope.type`, verified against Microsoft's reference:
/// *"The possible values are: `User` and `Admin`."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ScopeConsent {
    /// Safe for a non-admin user to consent to on their own behalf.
    #[value(name = "User")]
    User,
    /// Administrator consent is always required.
    #[value(name = "Admin")]
    Admin,
}

impl ScopeConsent {
    pub const ALL: &'static [ScopeConsent] = &[Self::User, Self::Admin];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Admin => "Admin",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == raw)
    }
}

/// What kind of principal an app role may be assigned to: Entra's
/// `appRole.allowedMemberTypes`, stored as a JSON array in
/// `app_roles.allowed_member_types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MemberType {
    /// Users and groups.
    #[value(name = "User")]
    User,
    /// Applications, through the client credentials grant.
    #[value(name = "Application")]
    Application,
}

impl MemberType {
    pub const ALL: &'static [MemberType] = &[Self::User, Self::Application];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Application => "Application",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|m| m.as_str() == raw)
    }

    /// The member types in a stored `allowed_member_types` array.
    ///
    /// Values this build does not know are dropped rather than failing the read:
    /// a role written by a newer build must still be usable for the types this
    /// build does understand. Dropping is the safe direction -- an unknown type
    /// grants nothing -- and it is why this replaces the old
    /// `types.contains("Application")` substring test, which would have matched
    /// a type merely *containing* the word.
    pub fn parse_list(json: &str) -> Vec<MemberType> {
        serde_json::from_str::<Vec<String>>(json)
            .unwrap_or_default()
            .iter()
            .filter_map(|t| Self::parse(t))
            .collect()
    }
}

/// The platform a redirect URI is registered under, which decides the client
/// rules: the `platform` column of `app_redirect_uris`, and of the `auth_codes`
/// and `refresh_tokens` rows issued through them.
///
/// Entra's own values, as the application manifest spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RedirectPlatform {
    /// Confidential client: must authenticate at the token endpoint.
    #[value(name = "web")]
    Web,
    /// Single-page application: PKCE required, redeems cross-origin, 24h
    /// refresh-token lifetime.
    #[value(name = "spa")]
    Spa,
    /// Public client: no secret.
    #[value(name = "publicClient")]
    PublicClient,
}

impl RedirectPlatform {
    pub const ALL: &'static [RedirectPlatform] = &[Self::Web, Self::Spa, Self::PublicClient];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Spa => "spa",
            Self::PublicClient => "publicClient",
        }
    }

    /// A platform read back from a stored row. `None` for anything this build
    /// does not know.
    ///
    /// **Every caller must fail closed on `None`.** The rules this value selects
    /// get *weaker* as they go — `web` authenticates, `spa` needs PKCE,
    /// `publicClient` needs neither — so anything that treated an unrecognised
    /// platform as "none of the above" would be treating it as a public client,
    /// which is the weakest of the three. Before this was an enum, that is
    /// exactly what `authenticate_for_platform` did.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }
}

pub async fn add_role(
    pool: &DbPool,
    app: &Application,
    value: &str,
    display_name: &str,
    description: Option<&str>,
    member_types: &[MemberType],
) -> anyhow::Result<String> {
    if value.is_empty() || value.chars().any(|c| c.is_whitespace()) || value.starts_with('.') {
        bail!("invalid app role value '{value}' (no spaces, must not start with '.')");
    }
    if member_types.is_empty() {
        bail!("allowed member types must be User and/or Application");
    }
    let id = new_guid();
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO app_roles (id, application_id, value, display_name, description, allowed_member_types, enabled)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(&app.id)
    .bind(value)
    .bind(display_name)
    .bind(description)
    .bind(serde_json::to_string(
        &member_types.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
    )?)
    .bind(true)
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
    #[sqlx(try_from = "crate::db::Flag")]
    pub enabled: bool,
}

impl AppRole {
    pub fn allows(&self, member_type: MemberType) -> bool {
        MemberType::parse_list(&self.allowed_member_types).contains(&member_type)
    }
}

pub async fn roles(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<AppRole>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, value, display_name, allowed_member_types, enabled FROM app_roles
         WHERE application_id = ? ORDER BY value",
    ))
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
    pool: &DbPool,
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
            (sp.id, PrincipalType::ServicePrincipal, MemberType::Application)
        }
        Principal::User(upn) => {
            let row: Option<(String,)> = sqlx::query_as(crate::db::q(
                pool,
                "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
            ))
            .bind(&tenant.id)
            .bind(crate::util::fold(upn))
            .fetch_optional(pool)
            .await?;
            let (id,) = row.with_context(|| format!("user '{upn}' not found"))?;
            (id, PrincipalType::User, MemberType::User)
        }
        Principal::Group(name) => {
            let row: Option<(String,)> = sqlx::query_as(crate::db::q(
                pool,
                "SELECT id FROM user_groups WHERE tenant_id = ? AND name_folded = ?",
            ))
            .bind(&tenant.id)
            .bind(crate::util::fold(name))
            .fetch_optional(pool)
            .await?;
            let (id,) = row.with_context(|| format!("group '{name}' not found"))?;
            (id, PrincipalType::Group, MemberType::User)
        }
    };
    if !role.allows(member_type) {
        bail!(
            "app role '{role_value}' cannot be assigned to {} principals",
            member_type.as_str()
        );
    }
    // Re-assigning is a no-op: UNIQUE (resource_id, app_role_id, principal_id).
    crate::db::inserted(
        sqlx::query(crate::db::q(
            pool,
            "INSERT INTO app_role_assignments
                (id, tenant_id, resource_id, app_role_id, principal_id, principal_type, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(new_guid())
        .bind(&tenant.id)
        .bind(&resource_sp.id)
        .bind(&role.id)
        .bind(&principal_id)
        .bind(principal_type.as_str())
        .bind(now())
        .execute(pool)
        .await,
    )?;
    Ok(())
}

/// Role values of `resource_sp` assigned to the client service principal
/// `client_sp_id` (the `roles` claim of an app-only token).
pub async fn app_roles_for_service_principal(
    pool: &DbPool,
    resource_sp_id: &str,
    client_sp_id: &str,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT r.value, r.allowed_member_types FROM app_role_assignments a
         JOIN app_roles r ON r.id = a.app_role_id
         WHERE a.resource_id = ? AND a.principal_id = ? AND a.principal_type = ?
           AND r.enabled = ?
         ORDER BY r.value",
    ))
    .bind(resource_sp_id)
    .bind(client_sp_id)
    .bind(PrincipalType::ServicePrincipal.as_str())
    .bind(true)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, types)| MemberType::parse_list(types).contains(&MemberType::Application))
        .map(|(value, _)| value)
        .collect())
}

// ---- redirect URIs ----

fn is_loopback_http(url: &url::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Entra's rules: web and SPA URIs must be https (or http on loopback); no
/// fragments anywhere; public clients may use custom schemes.
pub fn validate_redirect_uri(platform: RedirectPlatform, uri: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(uri).with_context(|| format!("redirect URI '{uri}' is not an absolute URI"))?;
    if url.fragment().is_some() {
        bail!("redirect URI must not contain a fragment");
    }
    match platform {
        RedirectPlatform::Web | RedirectPlatform::Spa => {
            if url.scheme() != "https" && !is_loopback_http(&url) {
                bail!(
                    "{} redirect URIs must use https (http is allowed only for localhost)",
                    platform.as_str()
                );
            }
        }
        RedirectPlatform::PublicClient => {}
    }
    Ok(())
}

pub async fn add_redirect_uri(
    pool: &DbPool,
    app: &Application,
    platform: RedirectPlatform,
    uri: &str,
) -> anyhow::Result<()> {
    validate_redirect_uri(platform, uri)?;
    let existing: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT platform FROM app_redirect_uris WHERE application_id = ? AND uri = ?",
    ))
    .bind(&app.id)
    .bind(uri)
    .fetch_optional(pool)
    .await?;
    if let Some((p,)) = existing {
        bail!("redirect URI '{uri}' is already registered for platform {p}");
    }
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO app_redirect_uris (application_id, platform, uri) VALUES (?, ?, ?)",
    ))
    .bind(&app.id)
    .bind(platform.as_str())
    .bind(uri)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every registered redirect URI, with its platform.
///
/// A row whose platform this build does not recognise is **skipped**, with a
/// warning. Skipping is the fail-closed direction everywhere this is used: the
/// URI then matches nothing (so the client is told its redirect URI is not
/// registered) and grants no SPA CORS origin. Keeping it and defaulting the
/// platform would be the unsafe direction, because the rules get weaker from
/// `web` to `spa` to `publicClient`. `add_redirect_uri` only ever writes a
/// [`RedirectPlatform`], so this cannot happen from our own writes.
pub async fn redirect_uris(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<(RedirectPlatform, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT platform, uri FROM app_redirect_uris WHERE application_id = ? ORDER BY platform, uri",
    ))
    .bind(&app.id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(platform, uri)| match RedirectPlatform::parse(&platform) {
            Some(p) => Some((p, uri)),
            None => {
                tracing::warn!(
                    application = %app.app_id,
                    %platform,
                    "ignoring a redirect URI registered under an unknown platform"
                );
                None
            }
        })
        .collect())
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
    pool: &DbPool,
    app: &Application,
    requested: &str,
) -> anyhow::Result<Option<RedirectPlatform>> {
    Ok(redirect_uris(pool, app)
        .await?
        .into_iter()
        .find(|(_, uri)| redirect_uri_matches(uri, requested))
        .map(|(platform, _)| platform))
}

// ---- delegated permission scopes ----

pub async fn add_scope(
    pool: &DbPool,
    app: &Application,
    value: &str,
    display_name: &str,
    consent: ScopeConsent,
) -> anyhow::Result<String> {
    if value.is_empty() || value.contains(char::is_whitespace) || value.starts_with('.') || value.contains('/') {
        bail!("invalid scope value '{value}'");
    }
    let id = new_guid();
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO app_scopes (id, application_id, value, display_name, type, enabled) VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(&app.id)
    .bind(value)
    .bind(display_name)
    .bind(consent.as_str())
    .bind(true)
    .execute(pool)
    .await
    .with_context(|| format!("scope '{value}' already exists"))?;
    Ok(id)
}

pub async fn enabled_scopes(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT value FROM app_scopes WHERE application_id = ? AND enabled = ? ORDER BY value",
    ))
    .bind(&app.id)
    .bind(true)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(v,)| v).collect())
}

/// Role values of `resource_sp_id` a user holds directly or through group
/// membership (the `roles` claim of user tokens).
pub async fn app_roles_for_user(pool: &DbPool, resource_sp_id: &str, user_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT DISTINCT r.value, r.allowed_member_types FROM app_role_assignments a
         JOIN app_roles r ON r.id = a.app_role_id
         WHERE a.resource_id = ? AND r.enabled = ?
           AND ((a.principal_type = ? AND a.principal_id = ?)
             OR (a.principal_type = ? AND a.principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?)))
         ORDER BY r.value",
    ))
    .bind(resource_sp_id)
    .bind(true)
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, types)| MemberType::parse_list(types).contains(&MemberType::User))
        .map(|(value, _)| value)
        .collect())
}

/// Whether the user may sign in to an app that requires assignment
/// (`appRoleAssignmentRequired`), directly or through a group.
pub async fn user_is_assigned(pool: &DbPool, sp_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let (n,): (i64,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT COUNT(*) FROM app_role_assignments
         WHERE resource_id = ?
           AND ((principal_type = ? AND principal_id = ?)
             OR (principal_type = ? AND principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?)))",
    ))
    .bind(sp_id)
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

/// The AADSTS50105 text for a user who is not assigned to an app that requires it.
/// One function, because the rule is enforced in two places (the authorize page
/// and token issuance) and they must say the same thing.
pub fn not_assigned_message(app: &Application) -> String {
    format!(
        "Your administrator has configured the application {} ('{}') to block users unless they are specifically granted ('assigned') access to the application.",
        app.display_name, app.app_id
    )
}

pub async fn set_assignment_required(pool: &DbPool, sp_id: &str, required: bool) -> anyhow::Result<()> {
    sqlx::query(crate::db::q(
        pool,
        "UPDATE service_principals SET app_role_assignment_required = ? WHERE id = ?",
    ))
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
pub async fn set_password_grant_allowed(pool: &DbPool, app: &Application, allowed: bool) -> anyhow::Result<()> {
    sqlx::query(crate::db::q(
        pool,
        "UPDATE applications SET allow_password_grant = ? WHERE id = ?",
    ))
    .bind(allowed)
    .bind(&app.id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Allow or forbid front-channel tokens for this app: Entra's "ID tokens" and
/// "access tokens" toggles. Both off means `response_type` must be `code`.
pub async fn set_implicit_allowed(
    pool: &DbPool,
    app: &Application,
    id_token: bool,
    access_token: bool,
) -> anyhow::Result<()> {
    sqlx::query(crate::db::q(
        pool,
        "UPDATE applications SET allow_id_token_implicit = ?, allow_access_token_implicit = ? WHERE id = ?",
    ))
    .bind(id_token)
    .bind(access_token)
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
    use x509_cert::Certificate;
    use x509_cert::der::{DecodePem, Encode};

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
    pool: &DbPool,
    app: &Application,
    cert_pem: &str,
    display_name: Option<&str>,
) -> anyhow::Result<String> {
    let cert = parse_certificate(cert_pem)?;
    let engine = crate::db::engine_of(pool);
    // UPDATE first, INSERT if nothing matched; a unique violation means a
    // concurrent registration inserted it meanwhile, so go round and UPDATE.
    // (sqlx's MySQL driver sets FOUND_ROWS, so an unchanged row still counts.)
    for _ in 0..crate::db::UPSERT_ATTEMPTS {
        let updated = sqlx::query(crate::db::sql_stmt(
            engine,
            "UPDATE app_key_credentials SET display_name = ?, cert_der = ?, public_n = ?, public_e = ?,
                not_before = ?, not_after = ?
             WHERE application_id = ? AND key_id = ?",
        ))
        .bind(display_name)
        .bind(&cert.cert_der)
        .bind(&cert.n)
        .bind(&cert.e)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&app.id)
        .bind(&cert.key_id)
        .execute(pool)
        .await?;
        if updated.rows_affected() > 0 {
            return Ok(cert.key_id);
        }
        let done = crate::db::inserted(
            sqlx::query(crate::db::sql_stmt(
                engine,
                "INSERT INTO app_key_credentials
                    (application_id, key_id, display_name, cert_der, public_n, public_e, created_at, not_before, not_after)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ))
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
            .await,
        )?;
        if done {
            return Ok(cert.key_id);
        }
    }
    anyhow::bail!(
        "certificate credential {} could not be registered after {} attempts (concurrent writers)",
        cert.key_id,
        crate::db::UPSERT_ATTEMPTS
    )
}

pub async fn key_credentials(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<KeyCredential>> {
    Ok(sqlx::query_as::<_, KeyCredential>(crate::db::q(
        pool,
        "SELECT key_id, display_name, public_n, public_e, not_before, not_after
         FROM app_key_credentials WHERE application_id = ? ORDER BY created_at",
    ))
    .bind(&app.id)
    .fetch_all(pool)
    .await?)
}

pub async fn remove_key_credential(pool: &DbPool, app: &Application, key_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::q(
        pool,
        "DELETE FROM app_key_credentials WHERE application_id = ? AND key_id = ?",
    ))
    .bind(&app.id)
    .bind(key_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

// ---- reading back what is registered (the console's pages) ----

/// A registered client secret, **without** the secret itself: only the hint,
/// which is the first three characters, exactly as Entra shows it. The value
/// exists once, in the response that created it, and nowhere else.
#[derive(FromRow)]
pub struct StoredSecret {
    pub key_id: String,
    pub display_name: Option<String>,
    pub hint: String,
    pub start_at: i64,
    pub end_at: i64,
}

impl StoredSecret {
    pub fn is_current(&self, at: i64) -> bool {
        self.start_at <= at && at < self.end_at
    }
}

pub async fn secrets(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<StoredSecret>> {
    Ok(sqlx::query_as(crate::db::q(
        pool,
        "SELECT key_id, display_name, hint, start_at, end_at FROM app_secrets
         WHERE application_id = ? ORDER BY created_at",
    ))
    .bind(&app.id)
    .fetch_all(pool)
    .await?)
}

/// An exposed delegated permission. `consent` is `None` when the stored value is
/// one this build does not know, which is the same fail-closed direction
/// [`RedirectPlatform::parse`] takes: an unknown consent type is displayed as
/// unknown rather than quietly shown as `User`.
pub struct StoredScope {
    pub id: String,
    pub value: String,
    pub display_name: String,
    pub consent: Option<ScopeConsent>,
    pub enabled: bool,
}

#[derive(FromRow)]
struct ScopeRow {
    id: String,
    value: String,
    display_name: String,
    #[sqlx(rename = "type")]
    consent: String,
    #[sqlx(try_from = "crate::db::Flag")]
    enabled: bool,
}

pub async fn scopes(pool: &DbPool, app: &Application) -> anyhow::Result<Vec<StoredScope>> {
    let rows: Vec<ScopeRow> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, value, display_name, type, enabled FROM app_scopes
         WHERE application_id = ? ORDER BY value",
    ))
    .bind(&app.id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| StoredScope {
            id: r.id,
            value: r.value,
            display_name: r.display_name,
            consent: ScopeConsent::parse(&r.consent),
            enabled: r.enabled,
        })
        .collect())
}

/// Remove a registered redirect URI. `false` when it was not registered under
/// that platform, so the caller can say so rather than report a silent success.
pub async fn remove_redirect_uri(
    pool: &DbPool,
    app: &Application,
    platform: RedirectPlatform,
    uri: &str,
) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::q(
        pool,
        "DELETE FROM app_redirect_uris WHERE application_id = ? AND platform = ? AND uri = ?",
    ))
    .bind(&app.id)
    .bind(platform.as_str())
    .bind(uri)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Remove an Application ID URI.
///
/// The last one is refused: `api://{appId}` is how a scope names this app as a
/// resource, so an application with no identifier URI could no longer be asked
/// for a token by name. Entra enforces nothing here; we do, because the
/// alternative is a registration that silently stops working.
pub async fn remove_identifier_uri(pool: &DbPool, app: &Application, uri: &str) -> anyhow::Result<()> {
    let registered = identifier_uris(pool, app).await?;
    if !registered.iter().any(|u| u == uri) {
        bail!("identifier URI '{uri}' is not registered on this application");
    }
    if registered.len() <= 1 {
        bail!("an application must keep at least one Application ID URI");
    }
    sqlx::query(crate::db::q(
        pool,
        "DELETE FROM app_identifier_uris WHERE application_id = ? AND tenant_id = ? AND uri = ?",
    ))
    .bind(&app.id)
    .bind(&app.tenant_id)
    .bind(uri)
    .execute(pool)
    .await?;
    Ok(())
}

/// One app-role assignment on a resource, with the principal named rather than
/// only identified: a page showing raw object ids is not usable.
pub struct StoredAssignment {
    pub id: String,
    pub role_value: String,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    /// UPN, group name or application display name; the id when the principal
    /// has since been removed.
    pub principal_name: String,
}

/// Every app-role assignment on `resource`'s service principal in `tenant_id`.
pub async fn role_assignments(
    pool: &DbPool,
    tenant_id: &str,
    resource: &Application,
) -> anyhow::Result<Vec<StoredAssignment>> {
    let Some(sp) = service_principal(pool, tenant_id, &resource.app_id).await? else {
        return Ok(Vec::new());
    };
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT a.id, r.value, a.principal_type, a.principal_id FROM app_role_assignments a
         JOIN app_roles r ON r.id = a.app_role_id
         WHERE a.tenant_id = ? AND a.resource_id = ? ORDER BY r.value",
    ))
    .bind(tenant_id)
    .bind(&sp.id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for (id, role_value, principal_type, principal_id) in rows {
        // A principal type this build does not know is skipped rather than shown
        // with a guessed kind: the row grants nothing we can describe.
        let Some(principal_type) = PrincipalType::parse(&principal_type) else {
            continue;
        };
        let principal_name = principal_name(pool, principal_type, &principal_id).await;
        out.push(StoredAssignment {
            id,
            role_value,
            principal_type,
            principal_id,
            principal_name,
        });
    }
    Ok(out)
}

/// The display name behind an assignment's principal id, falling back to the id.
async fn principal_name(pool: &DbPool, principal_type: PrincipalType, principal_id: &str) -> String {
    let sql = match principal_type {
        PrincipalType::User => "SELECT upn FROM users WHERE id = ? AND deleted_at IS NULL",
        PrincipalType::Group => "SELECT name FROM user_groups WHERE id = ?",
        PrincipalType::ServicePrincipal => {
            "SELECT a.display_name FROM service_principals sp
             JOIN applications a ON a.app_id = sp.app_id
             WHERE sp.id = ? AND a.deleted_at IS NULL"
        }
    };
    let found: Option<(String,)> = sqlx::query_as(crate::db::q(pool, sql))
        .bind(principal_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    found.map(|(n,)| n).unwrap_or_else(|| principal_id.to_string())
}

/// Withdraw one app-role assignment.
///
/// Scoped by tenant *and* by the resource's service principal, so an assignment
/// id alone cannot reach another tenant's row even if one were guessed.
pub async fn remove_role_assignment(
    pool: &DbPool,
    tenant_id: &str,
    resource: &Application,
    assignment_id: &str,
) -> anyhow::Result<bool> {
    let Some(sp) = service_principal(pool, tenant_id, &resource.app_id).await? else {
        return Ok(false);
    };
    let done = sqlx::query(crate::db::q(
        pool,
        "DELETE FROM app_role_assignments WHERE id = ? AND tenant_id = ? AND resource_id = ?",
    ))
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(&sp.id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}
