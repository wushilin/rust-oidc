//! The console's applications section: the registration list, and one page per
//! application covering its credentials, URIs, exposed scopes, app roles, role
//! assignments and grant flags.
//!
//! Three actions divide the page, and they are the design spec's own division:
//! `App:Read` to see it, `App:Write` for the registration itself (URIs, scopes,
//! roles, flags), `App:Rotate` for credentials, and `Assignment:Write` for who
//! holds a role. `CloudApplicationAdministrator` holds every one of those except
//! `App:Rotate`, so on that role's pages the credential sections are read-only
//! and nothing offers a button the guard would refuse.
//!
//! **A client secret is shown exactly once.** Only its SHA-256 hash is stored, so
//! there is nowhere to show it from a second time. That is the one post in the
//! console that answers `200` with a page instead of `303` to one: the value
//! exists in that response and nowhere else. It is never written to `audit_log`
//! (the row carries the key id) and never re-rendered into a later page.

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, Settled, TenantTab, checked, chrome, field, optional, parse_form, settle};
use crate::admin::view::{self, e};
use crate::admin::{APP_READ, APP_ROTATE, APP_WRITE, ASSIGNMENT_READ, ASSIGNMENT_WRITE};
use crate::apps::{self, Application, MemberType, Principal, RedirectPlatform, ScopeConsent};
use crate::directory::PrincipalType;
use crate::rbac::Action;
use crate::tenant::Tenant;
use crate::txn::ops::apps::{
    AddAppCertificate, AddAppRole, AddAppScope, AddAppSecret, AddIdentifierUri, AddRedirectUri, AssignApp, CreateApp,
    GrantAppRole, GrantAuthApiPermission, RemoveAppCertificate, RemoveAppSecret, RemoveIdentifierUri,
    RemoveRedirectUri, RevokeAppRole, RevokeAuthApiPermission, SaveAppFlags, UnassignApp,
};
use crate::txn::{self, Actor, Outcome, Refusal, Transaction};
use crate::util::now;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;

/// What a post to an application's page asks for.
///
/// An enum rather than a bare string so a new operation cannot be added without
/// deciding which action authorizes it and which event records it.
/// How close to expiry a client secret is flagged on the overview: 30 days.
const SECRET_EXPIRY_WARNING_SECS: i64 = 30 * 24 * 60 * 60;

/// A part of an application's page, each at its own address. The same split as
/// Entra's app registration blades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppSection {
    Overview,
    Authentication,
    Credentials,
    Api,
    Roles,
    Assignments,
    Permissions,
    /// Permissions this application holds on built-in APIs (the Auth API).
    ApiPermissions,
    /// Would this user be let in, and if not, why.
    Check,
}

impl AppSection {
    pub const ALL: &'static [AppSection] = &[
        Self::Overview,
        Self::Authentication,
        Self::Credentials,
        Self::Api,
        Self::Roles,
        Self::Assignments,
        Self::Permissions,
        Self::ApiPermissions,
        Self::Check,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Authentication => "Authentication",
            Self::Credentials => "Certificates & secrets",
            Self::Api => "Expose an API",
            Self::Roles => "App roles",
            Self::Assignments => "Users and groups",
            Self::Permissions => "Application permissions",
            Self::ApiPermissions => "API permissions",
            Self::Check => "Check sign-in",
        }
    }

    /// The last part of its address; the overview is the application's own.
    pub fn path(self) -> &'static str {
        match self {
            Self::Overview => "",
            Self::Authentication => "authentication",
            Self::Credentials => "credentials",
            Self::Api => "api",
            Self::Roles => "roles",
            Self::Assignments => "users",
            Self::Permissions => "permissions",
            Self::ApiPermissions => "api-permissions",
            Self::Check => "check",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.path() == raw)
    }

    /// What it takes to open it, beyond seeing the application.
    fn action(self) -> Action {
        match self {
            Self::Assignments | Self::Permissions | Self::ApiPermissions | Self::Check => ASSIGNMENT_READ,
            _ => APP_READ,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppOp {
    /// `allow_password_grant` and the two implicit toggles, saved together.
    Flags,
    SecretAdd,
    SecretRemove,
    CertificateAdd,
    CertificateRemove,
    RedirectUriAdd,
    RedirectUriRemove,
    IdentifierUriAdd,
    IdentifierUriRemove,
    ScopeAdd,
    RoleAdd,
    /// Assign a user or group, with the roles ticked; also how their roles change.
    Assign,
    Unassign,
    /// Grant one role to a client application (an application permission).
    RoleAssign,
    RoleUnassign,
    /// Grant this application a permission of the built-in Auth API.
    AuthApiGrant,
    AuthApiRevoke,
}

impl AppOp {
    /// The section the operation belongs to: where its form is, and where the
    /// page goes back to after it.
    fn section(self) -> AppSection {
        match self {
            Self::Flags | Self::RedirectUriAdd | Self::RedirectUriRemove => AppSection::Authentication,
            Self::SecretAdd | Self::SecretRemove | Self::CertificateAdd | Self::CertificateRemove => {
                AppSection::Credentials
            }
            Self::IdentifierUriAdd | Self::IdentifierUriRemove | Self::ScopeAdd => AppSection::Api,
            Self::RoleAdd => AppSection::Roles,
            Self::Assign | Self::Unassign => AppSection::Assignments,
            Self::RoleAssign | Self::RoleUnassign => AppSection::Permissions,
            Self::AuthApiGrant | Self::AuthApiRevoke => AppSection::ApiPermissions,
        }
    }

    pub const ALL: &'static [AppOp] = &[
        Self::Flags,
        Self::SecretAdd,
        Self::SecretRemove,
        Self::CertificateAdd,
        Self::CertificateRemove,
        Self::RedirectUriAdd,
        Self::RedirectUriRemove,
        Self::IdentifierUriAdd,
        Self::IdentifierUriRemove,
        Self::ScopeAdd,
        Self::RoleAdd,
        Self::Assign,
        Self::Unassign,
        Self::RoleAssign,
        Self::RoleUnassign,
        Self::AuthApiGrant,
        Self::AuthApiRevoke,
    ];

    /// The form's `op` field.
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flags => "flags",
            Self::SecretAdd => "secret_add",
            Self::SecretRemove => "secret_remove",
            Self::CertificateAdd => "certificate_add",
            Self::CertificateRemove => "certificate_remove",
            Self::RedirectUriAdd => "redirect_uri_add",
            Self::RedirectUriRemove => "redirect_uri_remove",
            Self::IdentifierUriAdd => "identifier_uri_add",
            Self::IdentifierUriRemove => "identifier_uri_remove",
            Self::ScopeAdd => "scope_add",
            Self::RoleAdd => "role_add",
            Self::Assign => "assign",
            Self::Unassign => "unassign",
            Self::RoleAssign => "role_assign",
            Self::RoleUnassign => "role_unassign",
            Self::AuthApiGrant => "auth_api_grant",
            Self::AuthApiRevoke => "auth_api_revoke",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// The action that authorizes it.
    fn action(self) -> Action {
        match self {
            // Credentials are their own action: a role may administer an
            // application without being able to mint a credential for it.
            Self::SecretAdd | Self::SecretRemove | Self::CertificateAdd | Self::CertificateRemove => APP_ROTATE,
            // Who holds a role is an assignment, not the registration.
            Self::Assign
            | Self::Unassign
            | Self::RoleAssign
            | Self::RoleUnassign
            | Self::AuthApiGrant
            | Self::AuthApiRevoke => ASSIGNMENT_WRITE,
            Self::Flags
            | Self::RedirectUriAdd
            | Self::RedirectUriRemove
            | Self::IdentifierUriAdd
            | Self::IdentifierUriRemove
            | Self::ScopeAdd
            | Self::RoleAdd => APP_WRITE,
        }
    }

    /// The transaction it runs, for the test that the page asks for the same
    /// action the transaction needs.
    #[cfg(test)]
    fn kind(self) -> crate::txn::TxnKind {
        use crate::txn::TxnKind;
        match self {
            Self::Flags => TxnKind::SaveAppFlags,
            Self::SecretAdd => TxnKind::AddAppSecret,
            Self::SecretRemove => TxnKind::RemoveAppSecret,
            Self::CertificateAdd => TxnKind::AddAppCertificate,
            Self::CertificateRemove => TxnKind::RemoveAppCertificate,
            Self::RedirectUriAdd => TxnKind::AddRedirectUri,
            Self::RedirectUriRemove => TxnKind::RemoveRedirectUri,
            Self::IdentifierUriAdd => TxnKind::AddIdentifierUri,
            Self::IdentifierUriRemove => TxnKind::RemoveIdentifierUri,
            Self::ScopeAdd => TxnKind::AddAppScope,
            Self::RoleAdd => TxnKind::AddAppRole,
            Self::Assign => TxnKind::AssignApp,
            Self::Unassign => TxnKind::UnassignApp,
            Self::RoleAssign => TxnKind::GrantAppRole,
            Self::RoleUnassign => TxnKind::RevokeAppRole,
            Self::AuthApiGrant => TxnKind::GrantAuthApiPermission,
            Self::AuthApiRevoke => TxnKind::RevokeAuthApiPermission,
        }
    }
}

/// Form field names, spelled once.
const NAME: &str = "name";
const DAYS: &str = "days";
const KEY_ID: &str = "key_id";
const CERT: &str = "certificate";
const URI: &str = "uri";
const PLATFORM: &str = "platform";
const VALUE: &str = "value";
const DISPLAY_NAME: &str = "display_name";
const DESCRIPTION: &str = "description";
const CONSENT: &str = "consent";
const ROLE: &str = "role";
/// An Auth API permission, by its value.
const PERMISSION: &str = "permission";
const PRINCIPAL: &str = "principal";
const PRINCIPAL_TYPE: &str = "principal_type";
const ASSIGNMENT: &str = "assignment";
const ALLOW_PASSWORD_GRANT: &str = "allow_password_grant";
const REQUIRE_MFA: &str = "require_mfa";
const ACCEPT_OTHER_TENANTS: &str = "accept_other_tenants";
const ALLOW_ID_TOKEN: &str = "allow_id_token_implicit";
const ALLOW_ACCESS_TOKEN: &str = "allow_access_token_implicit";
/// One checkbox per [`MemberType`], named by the type itself.
fn member_field(t: MemberType) -> String {
    format!("member_{}", t.as_str())
}

/// The default secret lifetime offered by the form. 180 days, the same default
/// `app secret add --days` has, well inside Entra's 730-day maximum.
const DEFAULT_SECRET_DAYS: i64 = 180;

fn apps_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/apps", tenant.id)
}

fn section_url(base: &str, tenant: &Tenant, app: &Application, section: AppSection) -> String {
    match section {
        AppSection::Overview => app_url(base, tenant, app),
        other => format!("{}/{}", app_url(base, tenant, app), other.path()),
    }
}

fn app_url(base: &str, tenant: &Tenant, app: &Application) -> String {
    format!("{}/{}", apps_url(base, tenant), app.app_id)
}

// ---- the registration list ----

pub async fn list_page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(APP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    list(&st, &ctx, tenant, None, StatusCode::OK).await
}

async fn list(st: &AppState, ctx: &AdminContext, tenant: &Tenant, error: Option<&str>, status: StatusCode) -> Response {
    let registered = match apps::list(&st.pool, &tenant.id).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("application list failed: {err}");
            return view::server_error();
        }
    };
    let base = st.public_url.base();
    let rows: String = registered
        .iter()
        .map(|a| {
            format!(
                r#"<tr><td><a href="{url}">{name}</a></td><td class="muted">{app_id}</td><td>{flags}</td></tr>"#,
                url = e(&app_url(base, tenant, a)),
                name = e(&a.display_name),
                app_id = e(&a.app_id),
                flags = flag_pills(a),
            )
        })
        .collect();
    // Offered only where permitted, so the console never shows a button the
    // guard would refuse.
    let create = if ctx.can_in(APP_WRITE, tenant) {
        view::expander(
            "Register an application",
            &format!(
                r#"<form method="post" action="{url}">{csrf}
<label for="name">Display name</label><input id="name" name="{NAME}" type="text" required>
<div class="actions"><button type="submit">Register</button></div>
<p class="muted">Creates the application, its service principal in this tenant and the
Application ID URI <code>api://{{appId}}</code>.</p></form>"#,
                url = e(&apps_url(base, tenant)),
                csrf = view::csrf_input(&ctx.csrf),
            ),
            error.is_some(),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>Applications</h1><p class="sub">{tenant_name}</p>{error}
<table><tr><th>Name</th><th>Application (client) id</th><th>Enabled grants</th></tr>{rows}</table>{create}"#,
        tenant_name = e(&tenant.name),
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Apps)),
        status,
        "Applications",
        &body,
    )
}

/// The non-default grant flags, as pills. Nothing is shown for an application
/// with all three off, which is the default and the common case.
fn flag_pills(app: &Application) -> String {
    let mut out = String::new();
    for (on, label) in [
        (app.allow_password_grant, "password grant"),
        (app.allow_id_token_implicit, "implicit id_token"),
        (app.allow_access_token_implicit, "implicit token"),
    ] {
        if on {
            out.push_str(&format!(r#"<span class="pill">{label}</span>"#));
        }
    }
    out
}

pub async fn create_app(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(resp) = ctx.require(APP_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let create = CreateApp {
        tenant_id: tenant.id.clone(),
        display_name: field(&form, NAME).to_string(),
    };
    match settle(txn::run(&st.pool, &ctx.actor(), &create).await) {
        Settled::Done(app) => view::see_other(&app_url(st.public_url.base(), tenant, &app)),
        Settled::Refused(message) => list(&st, &ctx, tenant, Some(&message), StatusCode::BAD_REQUEST).await,
        Settled::Respond(resp) => resp,
    }
}

// ---- one application ----

pub async fn detail_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, app_key)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = ctx.require(APP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    // The tenant is in the `WHERE`, so an appId from another tenant is simply not
    // found; the message that would have named the tenant is not surfaced.
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, &app_key).await else {
        return view::not_found();
    };
    detail(
        &st,
        &ctx,
        tenant,
        &app,
        AppSection::Overview,
        Page::default(),
        StatusCode::OK,
    )
    .await
}

/// One section of an application's page.
pub async fn section_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, app_key, section)): Path<(String, String, String)>,
    Query(query): Query<Params>,
) -> Response {
    let Some(section) = AppSection::parse(&section).filter(|s| *s != AppSection::Overview) else {
        return view::not_found();
    };
    if let Err(resp) = ctx.require(APP_READ, On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.require(section.action(), On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, &app_key).await else {
        return view::not_found();
    };
    let page = Page {
        check: query
            .get(CHECK_UPN)
            .map(String::as_str)
            .filter(|u| !u.trim().is_empty()),
        ..Page::default()
    };
    detail(&st, &ctx, tenant, &app, section, page, StatusCode::OK).await
}

/// The user name the Check sign-in form asks about.
const CHECK_UPN: &str = "upn";

/// What a render of the application page needs beyond the application itself.
#[derive(Default)]
struct Page<'a> {
    error: Option<&'a str>,
    /// A value that exists only in this response: a freshly created secret.
    reveal: Option<&'a str>,
    /// The user name the Check sign-in section was asked about.
    check: Option<&'a str>,
}

async fn detail(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    app: &Application,
    section: AppSection,
    page: Page<'_>,
    status: StatusCode,
) -> Response {
    let base = st.public_url.base();
    let url = app_url(base, tenant, app);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_write = ctx.can_in(APP_WRITE, tenant);
    let may_rotate = ctx.can_in(APP_ROTATE, tenant);
    let may_assign = ctx.can_in(ASSIGNMENT_WRITE, tenant);

    let content = match section {
        AppSection::Overview => overview(st, ctx, tenant, app).await,
        AppSection::Authentication => {
            let redirect_uris = apps::redirect_uris(&st.pool, app).await.unwrap_or_default();
            let sp = apps::service_principal(&st.pool, &tenant.id, &app.app_id)
                .await
                .ok()
                .flatten();
            let switches = Switches {
                mfa_required: sp.as_ref().is_some_and(|sp| sp.mfa_required),
                accept_other_tenants: sp.as_ref().is_some_and(|sp| sp.accept_other_tenants),
            };
            format!(
                "{}{}",
                redirect_section(&url, &csrf, &redirect_uris, may_write),
                flags_form(&url, &csrf, app, switches, may_write)
            )
        }
        AppSection::Credentials => {
            let secrets = apps::secrets(&st.pool, app).await.unwrap_or_default();
            let certificates = apps::key_credentials(&st.pool, app).await.unwrap_or_default();
            format!(
                "{}{}",
                secrets_section(&url, &csrf, &secrets, may_rotate),
                certificates_section(&url, &csrf, &certificates, may_rotate)
            )
        }
        AppSection::Api => {
            let identifier_uris = apps::identifier_uris(&st.pool, app).await.unwrap_or_default();
            let scopes = apps::scopes(&st.pool, app).await.unwrap_or_default();
            format!(
                "{}{}",
                identifier_section(&url, &csrf, &identifier_uris, may_write),
                scope_section(&url, &csrf, &scopes, may_write)
            )
        }
        AppSection::Roles => {
            let roles = apps::roles(&st.pool, app).await.unwrap_or_default();
            role_section(&url, &csrf, &roles, may_write)
        }
        AppSection::Assignments => {
            let roles = apps::roles(&st.pool, app).await.unwrap_or_default();
            let assigned = apps::assignments(&st.pool, &tenant.id, app).await.unwrap_or_default();
            let accepts_others = apps::service_principal(&st.pool, &tenant.id, &app.app_id)
                .await
                .ok()
                .flatten()
                .is_some_and(|sp| sp.accept_other_tenants);
            assignment_section(&url, &csrf, &assigned, &roles, tenant, accepts_others, may_assign)
        }
        AppSection::Permissions => {
            let roles = apps::roles(&st.pool, app).await.unwrap_or_default();
            let granted = apps::role_assignments(&st.pool, &tenant.id, app)
                .await
                .unwrap_or_default();
            let section = application_roles_section(&url, &csrf, &granted, &roles, may_assign);
            if section.is_empty() {
                r#"<h2>Application permissions</h2><p class="empty">This application defines no role that
other applications may hold. Add one under App roles, with the Application member type, to grant it here.</p>"#
                    .to_string()
            } else {
                section
            }
        }
        AppSection::ApiPermissions => {
            let sp = apps::service_principal(&st.pool, &tenant.id, &app.app_id)
                .await
                .ok()
                .flatten();
            let held = match &sp {
                Some(sp) => crate::auth_api::granted(&st.pool, &sp.id).await.unwrap_or_default(),
                None => Vec::new(),
            };
            api_permissions_section(&url, &csrf, base, tenant, &held, may_assign)
        }
        AppSection::Check => check_section(st, tenant, app, page.check, &format!("{url}/check")).await,
    };

    let reveal = page
        .reveal
        .map(|secret| {
            view::shown_once(
                "This is the only time the secret value is shown.",
                secret,
                "Only a SHA-256 hash of it is stored, so it cannot be shown again. \
                 Copy it now; if it is lost, delete this secret and add another.",
            )
        })
        .unwrap_or_default();

    // The application's own row of tabs, under the tenant's.
    let subtabs: String = AppSection::ALL
        .iter()
        .filter(|s| ctx.can_in(s.action(), tenant))
        .map(|s| {
            let href = e(&section_url(base, tenant, app, *s));
            if *s == section {
                format!(
                    r#"<a class="active" aria-current="page" href="{href}">{}</a>"#,
                    e(s.label())
                )
            } else {
                format!(r#"<a href="{href}">{}</a>"#, e(s.label()))
            }
        })
        .collect();

    let body = format!(
        r#"<p class="crumb"><a href="{list}">Applications</a></p><h1>{name}</h1><p class="sub">{tenant_name} &middot; application registration</p>
<nav class="subtabs" aria-label="Application">{subtabs}</nav>
{reveal}{error}{content}"#,
        list = e(&format!("{base}/admin/tenants/{}/apps", tenant.id)),
        name = e(&app.display_name),
        tenant_name = e(&tenant.name),
        error = view::error_block(page.error),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Apps)),
        status,
        &format!("{} \u{b7} {}", app.display_name, section.label()),
        &body,
    )
}

/// The overview: what the application is, and a card per section saying what is
/// in it and whether anything needs attention.
async fn overview(st: &AppState, ctx: &AdminContext, tenant: &Tenant, app: &Application) -> String {
    let base = st.public_url.base();
    let facts = format!(
        r#"<dl class="facts"><dt>Application (client) id</dt><dd>{app_id}</dd>
<dt>Object id</dt><dd>{id}</dd><dt>Tenant</dt><dd>{tenant_name}</dd></dl>"#,
        app_id = e(&app.app_id),
        id = e(&app.id),
        tenant_name = e(&tenant.name),
    );
    let count = |n: usize, one: &str, many: &str| match n {
        0 => format!("No {many}"),
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    };
    let now = now();
    let secrets = apps::secrets(&st.pool, app).await.unwrap_or_default();
    let expiring = secrets
        .iter()
        .filter(|s| s.is_current(now) && s.end_at - now < SECRET_EXPIRY_WARNING_SECS)
        .count();
    let certificates = apps::key_credentials(&st.pool, app).await.unwrap_or_default();
    let redirect_uris = apps::redirect_uris(&st.pool, app).await.unwrap_or_default();
    let scopes = apps::scopes(&st.pool, app).await.unwrap_or_default();
    let identifier_uris = apps::identifier_uris(&st.pool, app).await.unwrap_or_default();
    let roles = apps::roles(&st.pool, app).await.unwrap_or_default();

    let mut cards: Vec<(AppSection, String, Option<String>)> = vec![
        (
            AppSection::Authentication,
            count(redirect_uris.len(), "redirect URI", "redirect URIs"),
            None,
        ),
        (
            AppSection::Credentials,
            format!(
                "{}, {}",
                count(secrets.len(), "client secret", "client secrets"),
                count(certificates.len(), "certificate", "certificates").to_lowercase()
            ),
            (expiring > 0).then(|| count(expiring, "secret expires soon", "secrets expire soon")),
        ),
        (
            AppSection::Api,
            if identifier_uris.is_empty() {
                "Not exposed as an API".to_string()
            } else {
                count(scopes.len(), "scope", "scopes")
            },
            None,
        ),
        (AppSection::Roles, count(roles.len(), "role", "roles"), None),
    ];
    if ctx.can_in(ASSIGNMENT_READ, tenant) {
        let assigned = apps::assignments(&st.pool, &tenant.id, app).await.unwrap_or_default();
        let granted = apps::role_assignments(&st.pool, &tenant.id, app)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.principal_type == PrincipalType::ServicePrincipal)
            .count();
        cards.push((
            AppSection::Assignments,
            count(assigned.len(), "user or group assigned", "users and groups assigned"),
            None,
        ));
        let held = match apps::service_principal(&st.pool, &tenant.id, &app.app_id).await {
            Ok(Some(sp)) => crate::auth_api::granted(&st.pool, &sp.id).await.unwrap_or_default(),
            _ => Vec::new(),
        };
        cards.push((
            AppSection::ApiPermissions,
            count(held.len(), "Auth API permission", "Auth API permissions"),
            None,
        ));
        cards.push((
            AppSection::Permissions,
            count(
                granted,
                "role granted to an application",
                "roles granted to applications",
            ),
            None,
        ));
    }
    let cards: String = cards
        .iter()
        .map(|(section, summary, warning)| {
            format!(
                r#"<a class="tile" href="{href}"><strong>{label}</strong><span>{summary}</span>{warning}</a>"#,
                href = e(&section_url(base, tenant, app, *section)),
                label = e(section.label()),
                summary = e(summary),
                warning = warning
                    .as_ref()
                    .map(|w| format!(r#"<span class="pill bad">{}</span>"#, e(w)))
                    .unwrap_or_default(),
            )
        })
        .collect();
    let flow = if ctx.can_in(APP_WRITE, tenant) {
        format!(
            r#"<p class="muted"><a href="{}">Test a sign-in flow with this application</a>, which says what the
flow needs before it runs anything.</p>"#,
            e(&format!(
                "{base}/admin/tenants/{}/flow?{}={}",
                tenant.id,
                crate::flowtest::APP_FIELD,
                app.app_id
            ))
        )
    } else {
        String::new()
    };
    format!(r#"{facts}<div class="tiles">{cards}</div>{flow}"#)
}

/// The service principal's own switches, shown with the application's flags.
#[derive(Clone, Copy)]
struct Switches {
    mfa_required: bool,
    accept_other_tenants: bool,
}

/// Check sign-in: a user name in, and every check that decides it out, from
/// [`crate::access::explain`] -- the same decision the sign-in makes.
async fn check_section(st: &AppState, tenant: &Tenant, app: &Application, upn: Option<&str>, url: &str) -> String {
    let form = format!(
        r#"<h2>Check sign-in</h2><p class="sub">Whether an account would be let in to this application, and what decides it:
its state, its assignment and real group memberships, every setting involved, and what the token would carry. Nothing is
changed and no password is asked for.</p>
<form method="get" action="{url}" class="find"><input name="{CHECK_UPN}" type="search" value="{value}" placeholder="User name" aria-label="User name" autocapitalize="none" spellcheck="false" autofocus>
<button type="submit">Check</button></form>"#,
        url = e(url),
        value = e(upn.unwrap_or_default()),
    );
    let Some(upn) = upn else {
        return form;
    };
    let sp = match apps::service_principal(&st.pool, &tenant.id, &app.app_id).await {
        Ok(Some(sp)) => sp,
        _ => return format!(r#"{form}<p class="error">This application has no service principal here.</p>"#),
    };
    let report = match crate::access::explain(&st.pool, tenant, &sp, app, upn).await {
        Ok(r) => r,
        Err(err) => return format!(r#"{form}{}"#, view::error_block(Some(&err.to_string()))),
    };
    use crate::access::Mark;
    let mark = |m: Mark| match m {
        Mark::Pass => r#"<span class="mark pass" aria-label="passes">&#x2713;</span>"#,
        Mark::Fail => r#"<span class="mark fail" aria-label="fails">&#x2717;</span>"#,
        Mark::Note => r#"<span class="mark note" aria-hidden="true">&middot;</span>"#,
    };
    let flows: String = report
        .flows
        .iter()
        .map(|f| {
            format!(
                "<tr><td>{}{}</td><td>{}</td></tr>",
                mark(if f.works { Mark::Pass } else { Mark::Fail }),
                e(f.flow.label()),
                e(&f.detail)
            )
        })
        .collect();
    let sections: String = report
        .sections
        .iter()
        .map(|sec| {
            let lines: String = sec
                .lines
                .iter()
                .map(|l| format!("<li>{}{}</li>", mark(l.mark), e(&l.text)))
                .collect();
            format!(r#"<h3>{}</h3><ul class="checks">{lines}</ul>"#, e(sec.title))
        })
        .collect();
    let flows = if flows.is_empty() {
        String::new()
    } else {
        format!(r#"<table><tr><th>Way of signing in</th><th>Result</th></tr>{flows}</table>"#)
    };
    format!(
        r#"{form}<p class="verdict {class}">{headline}</p>{flows}{sections}"#,
        class = if report.works { "works" } else { "refused" },
        headline = e(&report.headline),
    )
}

fn flags_form(url: &str, csrf: &str, app: &Application, switches: Switches, may_write: bool) -> String {
    let checkbox = |name: &str, on: bool, label: &str, note: &str| {
        format!(
            r#"<label><input type="checkbox" name="{name}"{on}{disabled}> {label}</label>
<p class="muted">{note}</p>"#,
            on = if on { " checked" } else { "" },
            disabled = if may_write { "" } else { " disabled" },
            label = e(label),
            note = e(note),
        )
    };
    format!(
        r#"<h2>Sign-in and grants</h2><form method="post" action="{url}">{csrf}
<input type="hidden" name="{op_field}" value="{op}">
{others}{mfa}{password}{id_token}{access_token}{save}</form>"#,
        url = e(url),
        op_field = AppOp::FIELD,
        op = AppOp::Flags.as_str(),
        others = checkbox(
            ACCEPT_OTHER_TENANTS,
            switches.accept_other_tenants,
            "Accept accounts of other tenants",
            "Accounts and groups of other tenants can then be assigned under Users and groups, and only those \
             assigned can sign in. Their own tenant must also allow it. This cannot be turned off while any are assigned.",
        ),
        mfa = checkbox(
            REQUIRE_MFA,
            switches.mfa_required,
            "Require multi-factor authentication",
            "Everyone signing in to this application must use MFA, whatever their own or the tenant's setting. \
             Whoever has not set up an authenticator does so at that sign-in.",
        ),
        password = checkbox(
            ALLOW_PASSWORD_GRANT,
            app.allow_password_grant,
            "Allow the resource owner password grant (ROPC)",
            "Off by default: the client sees the user's password and no second factor can apply.",
        ),
        id_token = checkbox(
            ALLOW_ID_TOKEN,
            app.allow_id_token_implicit,
            "Allow implicit ID tokens",
            "Permits response_type values containing id_token.",
        ),
        access_token = checkbox(
            ALLOW_ACCESS_TOKEN,
            app.allow_access_token_implicit,
            "Allow implicit access tokens",
            "Permits response_type values containing token.",
        ),
        save = if may_write {
            r#"<div class="actions"><button type="submit">Save grants</button></div>"#
        } else {
            r#"<p class="muted">Your roles allow reading this application but not changing it.</p>"#
        },
    )
}

/// A one-field remove button, used by every section that removes a row by id.
fn remove_button(url: &str, csrf: &str, op: AppOp, field_name: &str, value: &str, label: &str) -> String {
    format!(
        r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{field_name}" value="{value}">
<button class="danger" type="submit" name="{op_field}" value="{op}">{label}</button></form>"#,
        url = e(url),
        value = e(value),
        op_field = AppOp::FIELD,
        op = op.as_str(),
        label = e(label),
    )
}

/// [`remove_button`] for what cannot be undone: it asks first, in a dialog.
fn confirm_remove(
    url: &str,
    csrf: &str,
    op: AppOp,
    field_name: &str,
    value: &str,
    question: &str,
    detail: &str,
) -> String {
    view::confirm_post(
        &view::dom_id(&[op.as_str(), value]),
        "Delete\u{2026}",
        question,
        detail,
        url,
        &format!(
            r#"{csrf}<input type="hidden" name="{field_name}" value="{value}">"#,
            value = e(value)
        ),
        AppOp::FIELD,
        op.as_str(),
        "Delete",
    )
}

fn secrets_section(url: &str, csrf: &str, secrets: &[apps::StoredSecret], may_rotate: bool) -> String {
    let at = now();
    let rows: String = secrets
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{name}</td><td class=\"muted\">{hint}&hellip;</td><td>{expires}</td><td>{state}</td><td>{remove}</td></tr>",
                name = e(s.display_name.as_deref().unwrap_or("")),
                hint = e(&s.hint),
                expires = e(&view::ts(s.end_at)),
                state = if s.is_current(at) {
                    "Valid"
                } else {
                    r#"<span class="pill">expired</span>"#
                },
                remove = if may_rotate {
                    confirm_remove(url, csrf, AppOp::SecretRemove, KEY_ID, &s.key_id, "Delete this client secret?", "Anything still using it can no longer sign in.")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let add = if may_rotate {
        view::expander(
            "Add a client secret",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="secret_name">Description</label><input id="secret_name" name="{NAME}" type="text">
<label for="secret_days">Valid for (days)</label><input id="secret_days" name="{DAYS}" type="text" value="{DEFAULT_SECRET_DAYS}">
<div class="actions"><button type="submit">Add a client secret</button></div>
<p class="muted">The value is shown once, on the page that follows, and is never stored in clear.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::SecretAdd.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Client secrets</h2>
<table><tr><th>Description</th><th>Starts with</th><th>Expires</th><th>State</th><th></th></tr>{rows}</table>{add}"#
    )
}

fn certificates_section(url: &str, csrf: &str, certs: &[apps::KeyCredential], may_rotate: bool) -> String {
    let at = now();
    let rows: String = certs
        .iter()
        .map(|c| {
            format!(
                "<tr><td>{name}</td><td class=\"muted\">{thumb}</td><td>{from}</td><td>{to}</td><td>{state}</td><td>{remove}</td></tr>",
                name = e(c.display_name.as_deref().unwrap_or("")),
                thumb = e(&c.key_id),
                from = e(&view::ts(c.not_before)),
                to = e(&view::ts(c.not_after)),
                state = if c.is_current(at) {
                    "Valid"
                } else {
                    r#"<span class="pill">not current</span>"#
                },
                remove = if may_rotate {
                    confirm_remove(url, csrf, AppOp::CertificateRemove, KEY_ID, &c.key_id, "Delete this certificate?", "Assertions signed with its key are refused from now on.")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let add = if may_rotate {
        view::expander(
            "Upload a certificate",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="cert_name">Description</label><input id="cert_name" name="{NAME}" type="text">
<label for="certificate">PEM certificate</label>
<textarea id="certificate" name="{CERT}" required placeholder="-----BEGIN CERTIFICATE-----"></textarea>
<div class="actions"><button type="submit">Upload a certificate</button></div>
<p class="muted">The certificate only, never the private key. RSA only, as Entra requires for
client assertions. Its thumbprint becomes the credential's key id.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::CertificateAdd.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Certificates</h2><p class="sub">For <code>private_key_jwt</code> client assertions.</p>
<table><tr><th>Description</th><th>Thumbprint</th><th>From</th><th>Until</th><th>State</th><th></th></tr>{rows}</table>{add}"#
    )
}

/// A `<select>` over a closed set, so a form cannot submit a value the parse
/// would refuse.
fn platform_select(id: &str) -> String {
    let options: String = RedirectPlatform::ALL
        .iter()
        .map(|p| format!(r#"<option value="{v}">{v}</option>"#, v = e(p.as_str())))
        .collect();
    format!(
        r#"<label for="{id}">Platform</label><select id="{id}" name="{PLATFORM}">{options}</select>"#,
        id = e(id),
    )
}

fn redirect_section(url: &str, csrf: &str, uris: &[(RedirectPlatform, String)], may_write: bool) -> String {
    let rows: String = uris
        .iter()
        .map(|(platform, uri)| {
            format!(
                r#"<tr><td><span class="pill">{platform}</span></td><td>{uri}</td><td>{remove}</td></tr>"#,
                platform = e(platform.as_str()),
                uri = e(uri),
                remove = if may_write {
                    // Both fields: a URI may be registered under more than one
                    // platform, and the row names which one is being removed.
                    format!(
                        r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{URI}" value="{uri}"><input type="hidden" name="{PLATFORM}" value="{platform}">
<button class="danger" type="submit" name="{op_field}" value="{op}">Remove</button></form>"#,
                        url = e(url),
                        uri = e(uri),
                        platform = e(platform.as_str()),
                        op_field = AppOp::FIELD,
                        op = AppOp::RedirectUriRemove.as_str(),
                    )
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let add = if may_write {
        view::expander(
            "Add a redirect URI",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
{platform}<label for="redirect_uri">Redirect URI</label>
<input id="redirect_uri" name="{URI}" type="text" required>
<div class="actions"><button type="submit">Add a redirect URI</button></div>
<p class="muted">web and spa must use https, except on localhost. No fragments. The platform
decides the client rules: web authenticates, spa needs PKCE, publicClient needs neither.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::RedirectUriAdd.as_str(),
                platform = platform_select("redirect_platform"),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(r#"<h2>Redirect URIs</h2><table><tr><th>Platform</th><th>URI</th><th></th></tr>{rows}</table>{add}"#)
}

fn identifier_section(url: &str, csrf: &str, uris: &[String], may_write: bool) -> String {
    let rows: String = uris
        .iter()
        .map(|uri| {
            format!(
                "<tr><td>{uri}</td><td>{remove}</td></tr>",
                uri = e(uri),
                remove = if may_write {
                    remove_button(url, csrf, AppOp::IdentifierUriRemove, URI, uri, "Remove")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let add = if may_write {
        view::expander(
            "Add an Application ID URI",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="identifier_uri">Application ID URI</label>
<input id="identifier_uri" name="{URI}" type="text" required>
<div class="actions"><button type="submit">Add an Application ID URI</button></div>
<p class="muted">How a scope names this application as a resource, e.g.
<code>api://&hellip;/Orders.Read</code>. Unique across the tenant; the last one cannot be removed.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::IdentifierUriAdd.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(r#"<h2>Application ID URIs</h2><table><tr><th>URI</th><th></th></tr>{rows}</table>{add}"#)
}

fn scope_section(url: &str, csrf: &str, scopes: &[apps::StoredScope], may_write: bool) -> String {
    let rows: String = scopes
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{value}</td><td>{name}</td><td>{consent}</td><td>{state}</td></tr>",
                value = e(&s.value),
                name = e(&s.display_name),
                // An unrecognised stored value is shown as unknown rather than as
                // the weaker of the two: who may consent is a security property.
                consent = match s.consent {
                    Some(c) => e(c.as_str()),
                    None => r#"<span class="muted">unknown</span>"#.to_string(),
                },
                state = if s.enabled {
                    "Enabled"
                } else {
                    r#"<span class="pill">disabled</span>"#
                },
            )
        })
        .collect();
    let add = if may_write {
        let options: String = ScopeConsent::ALL
            .iter()
            .map(|c| format!(r#"<option value="{v}">{v}</option>"#, v = e(c.as_str())))
            .collect();
        view::expander(
            "Expose a scope",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="scope_value">Scope name</label><input id="scope_value" name="{VALUE}" type="text" required>
<label for="scope_display">Display name</label><input id="scope_display" name="{DISPLAY_NAME}" type="text">
<label for="scope_consent">Who can consent</label>
<select id="scope_consent" name="{CONSENT}">{options}</select>
<div class="actions"><button type="submit">Expose a scope</button></div>
<p class="muted">Emitted in the <code>scp</code> claim. The display name is what the consent page
shows when a client asks for it with <code>prompt=consent</code>.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::ScopeAdd.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Exposed scopes</h2>
<table><tr><th>Scope</th><th>Display name</th><th>Consent</th><th>State</th></tr>{rows}</table>{add}"#
    )
}

fn role_section(url: &str, csrf: &str, roles: &[apps::AppRole], may_write: bool) -> String {
    let rows: String = roles
        .iter()
        .map(|r| {
            let types: String = MemberType::parse_list(&r.allowed_member_types)
                .iter()
                .map(|t| format!(r#"<span class="pill">{}</span>"#, e(t.as_str())))
                .collect();
            format!(
                "<tr><td>{value}</td><td>{name}</td><td>{types}</td><td>{state}</td></tr>",
                value = e(&r.value),
                name = e(&r.display_name),
                state = if r.enabled {
                    "Enabled"
                } else {
                    r#"<span class="pill">disabled</span>"#
                },
            )
        })
        .collect();
    let add = if may_write {
        let boxes: String = MemberType::ALL
            .iter()
            .map(|t| {
                format!(
                    r#"<label><input type="checkbox" name="{field}" checked> {label}</label>"#,
                    field = e(&member_field(*t)),
                    label = e(t.as_str()),
                )
            })
            .collect();
        view::expander(
            "Define an app role",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="role_value">Role value</label><input id="role_value" name="{VALUE}" type="text" required>
<label for="role_display">Display name</label><input id="role_display" name="{DISPLAY_NAME}" type="text">
<label for="role_description">Description</label><input id="role_description" name="{DESCRIPTION}" type="text">
<p>Allowed member types</p>{boxes}
<div class="actions"><button type="submit">Define an app role</button></div>
<p class="muted">Emitted in the <code>roles</code> claim. <em>User</em> covers users and groups;
<em>Application</em> covers service principals through the client credentials grant.</p></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::RoleAdd.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>App roles</h2>
<table><tr><th>Value</th><th>Display name</th><th>Member types</th><th>State</th></tr>{rows}</table>{add}"#
    )
}

/// One tick box per role a user or group may hold, the held ones ticked.
fn role_boxes(roles: &[&apps::AppRole], held: &[String]) -> String {
    roles
        .iter()
        .map(|r| {
            format!(
                r#"<label><input type="checkbox" name="{ROLE}" value="{v}"{on}> {v}</label>"#,
                v = e(&r.value),
                on = if held.contains(&r.value) { " checked" } else { "" },
            )
        })
        .collect()
}

/// Who is assigned to the application, and the roles each was given. A user or
/// group is assigned first; roles are optional and are ticked, not assigned one
/// at a time.
/// How an assignment's principal is named, so it can be named again: a group of
/// another tenant as `name@domain`.
fn address(a: &apps::Assignment) -> String {
    match (&a.outside, a.principal_type) {
        (Some(o), PrincipalType::Group) => format!("{}@{}", a.principal_name, o.domain),
        _ => a.principal_name.clone(),
    }
}

fn assignment_section(
    url: &str,
    csrf: &str,
    assignments: &[apps::Assignment],
    roles: &[apps::AppRole],
    tenant: &Tenant,
    accepts_others: bool,
    may_assign: bool,
) -> String {
    let user_roles: Vec<&apps::AppRole> = roles
        .iter()
        .filter(|r| r.enabled && r.allows(MemberType::User))
        .collect();
    let rows: String = assignments
        .iter()
        .map(|a| {
            let held = if a.roles.is_empty() {
                r#"<span class="muted">no role</span>"#.to_string()
            } else {
                a.roles
                    .iter()
                    .map(|r| format!(r#"<span class="pill">{}</span> "#, e(r)))
                    .collect()
            };
            // Changing roles is assigning again with a different set ticked.
            let change = if may_assign && !user_roles.is_empty() {
                format!(
                    r#"<details class="inline-edit"><summary>Change roles</summary>
<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<input type="hidden" name="{PRINCIPAL_TYPE}" value="{kind}"><input type="hidden" name="{PRINCIPAL}" value="{who}">
<fieldset class="choice">{boxes}</fieldset>
<div class="actions"><button type="submit">Save roles</button></div></form></details>"#,
                    url = e(url),
                    op_field = AppOp::FIELD,
                    op = AppOp::Assign.as_str(),
                    kind = e(a.principal_type.as_str()),
                    who = e(&address(a)),
                    boxes = role_boxes(&user_roles, &a.roles),
                )
            } else {
                String::new()
            };
            let outside = match &a.outside {
                None => String::new(),
                Some(o) => {
                    let mut pills = format!(r#" <span class="pill">{}</span>"#, e(&o.tenant_name));
                    if a.principal_type == PrincipalType::Group {
                        pills.push_str(&format!(
                            r#" <span class="pill bad" title="Who is in this group is decided by {t}, not here.">membership managed by {t}</span>"#,
                            t = e(&o.tenant_name)
                        ));
                    } else if !o.may_sign_in {
                        pills.push_str(&format!(
                            r#" <span class="pill bad">{} does not allow it to sign in here</span>"#,
                            e(&o.tenant_name)
                        ));
                    }
                    pills
                }
            };
            format!(
                "<tr><td>{who}{outside}</td><td>{kind}</td><td>{held}{change}</td><td>{remove}</td></tr>",
                who = e(&address(a)),
                kind = e(a.principal_type.as_str()),
                remove = if may_assign {
                    remove_button(url, csrf, AppOp::Unassign, ASSIGNMENT, &a.id, "Remove")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let add = if may_assign {
        let kind_options: String = [
            (PrincipalType::User, "User, by user name"),
            (PrincipalType::Group, "Group, by name"),
        ]
        .iter()
        .map(|(t, label)| {
            format!(
                r#"<option value="{v}">{label}</option>"#,
                v = e(t.as_str()),
                label = e(label)
            )
        })
        .collect();
        let boxes = if user_roles.is_empty() {
            r#"<p class="muted">This application defines no roles for users, so there is none to give.</p>"#.to_string()
        } else {
            format!(
                r#"<fieldset class="choice"><legend>Roles</legend>{}</fieldset>
<p class="muted">Optional. With none ticked they are assigned and hold no role.</p>"#,
                role_boxes(&user_roles, &[])
            )
        };
        view::expander(
            "Assign a user or group",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="assign_kind">Assign</label>
<select id="assign_kind" name="{PRINCIPAL_TYPE}">{kind_options}</select>
<label for="assign_principal">Name</label>
<input id="assign_principal" name="{PRINCIPAL}" type="text" required autocapitalize="none" spellcheck="false">
<p class="muted">A user name, or a group name of {tenant_name}. {others}</p>
{boxes}
<div class="actions"><button type="submit">Assign</button></div></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::Assign.as_str(),
                tenant_name = e(&tenant.name),
                others = if accepts_others {
                    "An account of another tenant is named by its user name; a group of another tenant as \
                     group@its-domain, or with the prefixes user: and group:."
                } else {
                    "This application accepts only this tenant's accounts; turn on \"Accept accounts of other \
                     tenants\" under Authentication to assign others."
                },
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Users and groups</h2><p class="sub">Who is assigned to this application, and the roles they were
given. When assignment is required, only these people can sign in to it; a group assigns its members.</p>
<table><tr><th>Who</th><th>Type</th><th>Roles</th><th></th></tr>{rows}</table>{add}"#
    )
}

/// Roles granted to client applications: what they get in `roles` when they call
/// this one with their own credentials. Not an assignment of people.
fn application_roles_section(
    url: &str,
    csrf: &str,
    granted: &[apps::StoredAssignment],
    roles: &[apps::AppRole],
    may_assign: bool,
) -> String {
    let app_roles: Vec<&apps::AppRole> = roles
        .iter()
        .filter(|r| r.enabled && r.allows(MemberType::Application))
        .collect();
    let rows: String = granted
        .iter()
        .filter(|a| a.principal_type == PrincipalType::ServicePrincipal)
        .map(|a| {
            format!(
                "<tr><td>{who}</td><td>{role}</td><td>{remove}</td></tr>",
                who = e(&a.principal_name),
                role = e(&a.role_value),
                remove = if may_assign {
                    remove_button(url, csrf, AppOp::RoleUnassign, ASSIGNMENT, &a.id, "Withdraw")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    // Nothing to show and nothing that could be granted: leave the section out.
    if rows.is_empty() && app_roles.is_empty() {
        return String::new();
    }
    let add = if may_assign && !app_roles.is_empty() {
        let role_options: String = app_roles
            .iter()
            .map(|r| format!(r#"<option value="{v}">{v}</option>"#, v = e(&r.value)))
            .collect();
        view::expander(
            "Grant a role to an application",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<input type="hidden" name="{PRINCIPAL_TYPE}" value="{kind}">
<label for="grant_app">Client application id</label>
<input id="grant_app" name="{PRINCIPAL}" type="text" required>
<label for="grant_role">Role</label><select id="grant_role" name="{ROLE}">{role_options}</select>
<div class="actions"><button type="submit">Grant</button></div></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::RoleAssign.as_str(),
                kind = e(PrincipalType::ServicePrincipal.as_str()),
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Application permissions</h2><p class="sub">Roles granted to other applications, which they receive
when they call this one with their own credentials.</p>
<table><tr><th>Application</th><th>Role</th><th></th></tr>{rows}</table>{add}"#
    )
}

/// The permissions this application holds on the built-in Auth API, with how to
/// use them.
fn api_permissions_section(
    url: &str,
    csrf: &str,
    base: &str,
    tenant: &Tenant,
    held: &[crate::auth_api::AuthApiPermission],
    may_assign: bool,
) -> String {
    use crate::auth_api::{AUTH_API_APP_ID, AUTH_API_NAME, AuthApiPermission};
    let rows: String = AuthApiPermission::ALL
        .iter()
        .map(|p| {
            let granted = held.contains(p);
            let (state, op, label, class) = if granted {
                ("Granted", AppOp::AuthApiRevoke, "Revoke", "danger")
            } else {
                ("Not granted", AppOp::AuthApiGrant, "Grant", "secondary")
            };
            let button = if may_assign {
                format!(
                    r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{PERMISSION}" value="{value}">
<button class="{class}" type="submit" name="{op_field}" value="{op}">{label}</button></form>"#,
                    url = e(url),
                    value = e(p.as_str()),
                    op_field = AppOp::FIELD,
                    op = op.as_str(),
                )
            } else {
                String::new()
            };
            format!(
                r#"<tr><td><code>{value}</code></td><td>{description}</td><td>{state}</td><td>{button}</td></tr>"#,
                value = e(p.as_str()),
                description = e(p.description()),
            )
        })
        .collect();
    format!(
        r#"<h2>API permissions</h2><p class="sub">Permissions this application holds on the built-in
{name}, granted by an administrator. The application uses them with its own credentials: no user consents.</p>
<table><tr><th>Permission</th><th>What it allows</th><th>Status</th><th></th></tr>{rows}</table>
<h3>Using it</h3>
<p>Get a token with the client credentials grant, <code>scope={api}/.default</code>, then send each check
to <code>POST {endpoint}</code> with <code>Authorization: Bearer &lt;token&gt;</code> and a JSON body
<code>{{"upn": "…", "password": "…", "otp": "…"}}</code>. Only users assigned to this application, with an
authenticator set up, can be checked.</p>"#,
        name = e(AUTH_API_NAME),
        api = e(AUTH_API_APP_ID),
        endpoint = e(&format!("{base}/{}/api/v1/authenticate", tenant.id)),
    )
}

// ---- writes ----

/// What a completed operation leaves to render.
enum Applied {
    /// Back to the section, `303`.
    Redirect,
    /// A value that must be shown exactly once, so the response is the page
    /// itself rather than a redirect to it.
    Reveal(String),
}

pub async fn detail_post(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, app_key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Some(op) = AppOp::parse(field(&form, AppOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    // The operation's own action, so `App:Write` cannot mint a credential and
    // `App:Rotate` cannot rewrite the registration.
    if let Err(resp) = ctx.require(op.action(), On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, &app_key).await else {
        return view::not_found();
    };

    // The role tick boxes repeat one field name, which the form map keeps only
    // one value of, so they are read from the body.
    let ticked: Vec<String> = url::form_urlencoded::parse(&body)
        .filter(|(k, _)| k == ROLE)
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    match settle(apply(&st, &ctx, tenant, &app, op, &form, ticked).await) {
        Settled::Done(Applied::Redirect) => {
            view::see_other(&section_url(st.public_url.base(), tenant, &app, op.section()))
        }
        // The one deliberate exception to "303 after a post": the value lives in
        // this response and nowhere else.
        Settled::Done(Applied::Reveal(secret)) => {
            let page = Page {
                reveal: Some(&secret),
                ..Page::default()
            };
            detail(&st, &ctx, tenant, &app, op.section(), page, StatusCode::OK).await
        }
        Settled::Refused(message) => {
            let page = Page {
                error: Some(&message),
                ..Page::default()
            };
            detail(&st, &ctx, tenant, &app, op.section(), page, StatusCode::BAD_REQUEST).await
        }
        Settled::Respond(resp) => resp,
    }
}

/// A form that cannot become a transaction: refused before one begins.
fn invalid(message: &str) -> Outcome<Applied> {
    Outcome::Refused(Refusal::Invalid(message.to_string()))
}

/// Run one transaction; a completed one goes back to its section.
async fn redirect<T: Transaction>(st: &AppState, actor: &Actor, t: &T) -> Outcome<Applied> {
    match txn::run(&st.pool, actor, t).await {
        Outcome::Done(_) => Outcome::Done(Applied::Redirect),
        Outcome::Refused(r) => Outcome::Refused(r),
        Outcome::Failed(m) => Outcome::Failed(m),
    }
}

/// Carry out one operation as the signed-in administrator: one transaction,
/// which checks, changes and records it, or does none of that. Only reading the
/// form happens here; every rule about an application is in [`crate::apps`].
async fn apply(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    app: &Application,
    op: AppOp,
    form: &Params,
    ticked: Vec<String>,
) -> Outcome<Applied> {
    let actor = ctx.actor();
    let (tenant_id, app_id) = (tenant.id.clone(), app.app_id.clone());
    let text = |name: &str| field(form, name).to_string();
    let maybe = |name: &str| optional(form, name).map(str::to_string);
    match op {
        AppOp::Flags => {
            // Every switch in one transaction: a refusal (stopping accepting
            // other tenants while theirs are assigned) saves none of them.
            let t = SaveAppFlags {
                tenant_id,
                app_id,
                accept_other_tenants: checked(form, ACCEPT_OTHER_TENANTS),
                mfa_required: checked(form, REQUIRE_MFA),
                allow_password_grant: checked(form, ALLOW_PASSWORD_GRANT),
                allow_id_token_implicit: checked(form, ALLOW_ID_TOKEN),
                allow_access_token_implicit: checked(form, ALLOW_ACCESS_TOKEN),
            };
            redirect(st, &actor, &t).await
        }
        AppOp::SecretAdd => {
            let valid_days = match parse_days(field(form, DAYS)) {
                Ok(d) => d,
                Err(err) => return invalid(&err.to_string()),
            };
            // Made before the transaction: nothing slow inside one.
            let t = AddAppSecret {
                tenant_id,
                app_id,
                secret: apps::PreparedSecret::generate(),
                valid_days,
                display_name: maybe(NAME),
            };
            match txn::run(&st.pool, &actor, &t).await {
                Outcome::Done(created) => Outcome::Done(Applied::Reveal(created.secret)),
                Outcome::Refused(r) => Outcome::Refused(r),
                Outcome::Failed(m) => Outcome::Failed(m),
            }
        }
        AppOp::SecretRemove => {
            let key_id = text(KEY_ID);
            redirect(
                st,
                &actor,
                &RemoveAppSecret {
                    tenant_id,
                    app_id,
                    key_id,
                },
            )
            .await
        }
        AppOp::CertificateAdd => {
            let t = AddAppCertificate {
                tenant_id,
                app_id,
                certificate_pem: text(CERT),
                display_name: maybe(NAME),
            };
            redirect(st, &actor, &t).await
        }
        AppOp::CertificateRemove => {
            let key_id = text(KEY_ID);
            redirect(
                st,
                &actor,
                &RemoveAppCertificate {
                    tenant_id,
                    app_id,
                    key_id,
                },
            )
            .await
        }
        AppOp::RedirectUriAdd | AppOp::RedirectUriRemove => {
            let Some(platform) = parse_platform(form) else {
                return invalid(CHOOSE_PLATFORM);
            };
            let uri = text(URI);
            if op == AppOp::RedirectUriAdd {
                let t = AddRedirectUri {
                    tenant_id,
                    app_id,
                    platform,
                    uri,
                };
                redirect(st, &actor, &t).await
            } else {
                let t = RemoveRedirectUri {
                    tenant_id,
                    app_id,
                    platform,
                    uri,
                };
                redirect(st, &actor, &t).await
            }
        }
        AppOp::IdentifierUriAdd => {
            let uri = text(URI);
            redirect(st, &actor, &AddIdentifierUri { tenant_id, app_id, uri }).await
        }
        AppOp::IdentifierUriRemove => {
            let uri = text(URI);
            redirect(st, &actor, &RemoveIdentifierUri { tenant_id, app_id, uri }).await
        }
        AppOp::ScopeAdd => {
            let Some(consent) = ScopeConsent::parse(field(form, CONSENT)) else {
                return invalid("choose who can consent to that scope");
            };
            let t = AddAppScope {
                tenant_id,
                app_id,
                value: text(VALUE),
                consent,
                display_name: maybe(DISPLAY_NAME),
            };
            redirect(st, &actor, &t).await
        }
        AppOp::RoleAdd => {
            let member_types: Vec<MemberType> = MemberType::ALL
                .iter()
                .copied()
                .filter(|t| checked(form, &member_field(*t)))
                .collect();
            let t = AddAppRole {
                tenant_id,
                app_id,
                value: text(VALUE),
                member_types,
                display_name: maybe(DISPLAY_NAME),
                description: maybe(DESCRIPTION),
            };
            redirect(st, &actor, &t).await
        }
        AppOp::Assign => {
            let typed = field(form, PRINCIPAL).trim();
            // `user:` and `group:` name the kind in the name itself, whatever the
            // select says.
            let (picked, name) = match typed.split_once(':') {
                Some(("user", rest)) => (Some(PrincipalType::User), rest.trim()),
                Some(("group", rest)) => (Some(PrincipalType::Group), rest.trim()),
                _ => (PrincipalType::parse(field(form, PRINCIPAL_TYPE)), typed),
            };
            let principal = match picked {
                Some(PrincipalType::User) => Principal::User(name.to_string()),
                Some(PrincipalType::Group) => Principal::Group(name.to_string()),
                _ => return invalid("choose a user or a group"),
            };
            let t = AssignApp {
                tenant_id,
                app_id,
                principal,
                roles: ticked,
            };
            redirect(st, &actor, &t).await
        }
        AppOp::Unassign => {
            let assignment_id = text(ASSIGNMENT);
            let t = UnassignApp {
                tenant_id,
                app_id,
                assignment_id,
            };
            redirect(st, &actor, &t).await
        }
        AppOp::RoleAssign => {
            // People are assigned with `Assign`; this grants a role to a client
            // application.
            let Some(PrincipalType::ServicePrincipal) = PrincipalType::parse(field(form, PRINCIPAL_TYPE)) else {
                return invalid("a role is granted this way to an application only; assign users and groups above");
            };
            let t = GrantAppRole {
                tenant_id,
                app_id,
                role: text(ROLE),
                client_app_id: text(PRINCIPAL),
            };
            redirect(st, &actor, &t).await
        }
        AppOp::RoleUnassign => {
            let assignment_id = text(ASSIGNMENT);
            let t = RevokeAppRole {
                tenant_id,
                app_id,
                assignment_id,
            };
            redirect(st, &actor, &t).await
        }
        AppOp::AuthApiGrant | AppOp::AuthApiRevoke => {
            let Some(permission) = crate::auth_api::AuthApiPermission::parse(field(form, PERMISSION)) else {
                return invalid("choose a permission");
            };
            if op == AppOp::AuthApiGrant {
                let t = GrantAuthApiPermission {
                    tenant_id,
                    app_id,
                    permission,
                };
                redirect(st, &actor, &t).await
            } else {
                let t = RevokeAuthApiPermission {
                    tenant_id,
                    app_id,
                    permission,
                };
                redirect(st, &actor, &t).await
            }
        }
    }
}

/// Refused when the form names no platform, or one outside the closed set.
const CHOOSE_PLATFORM: &str = "choose a platform";

/// The platform named by the form. A value outside the closed set is refused,
/// never defaulted: the rules get weaker from `web` to `publicClient`.
fn parse_platform(form: &Params) -> Option<RedirectPlatform> {
    RedirectPlatform::parse(field(form, PLATFORM))
}

/// A secret lifetime in days. `apps::add_secret` holds the range; this only has
/// to turn the text box into a number without panicking on anything typed in it.
fn parse_days(raw: &str) -> anyhow::Result<i64> {
    raw.parse::<i64>()
        .map_err(|_| anyhow::anyhow!("the number of days must be a whole number"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txn::Need;

    #[test]
    fn operations_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for op in AppOp::ALL {
            assert!(seen.insert(op.as_str()), "two operations are both {}", op.as_str());
            assert_eq!(AppOp::parse(op.as_str()), Some(*op));
        }
        assert_eq!(AppOp::parse("something_else"), None);
        assert_eq!(AppOp::parse(""), None);
    }

    /// The division of labour the module comment promises: credentials are
    /// `App:Rotate`, assignments are `Assignment:Write`, the rest is `App:Write`.
    #[test]
    fn credentials_and_assignments_need_their_own_action() {
        for op in [
            AppOp::SecretAdd,
            AppOp::SecretRemove,
            AppOp::CertificateAdd,
            AppOp::CertificateRemove,
        ] {
            assert_eq!(op.action(), APP_ROTATE, "{op:?}");
        }
        for op in [AppOp::RoleAssign, AppOp::RoleUnassign] {
            assert_eq!(op.action(), ASSIGNMENT_WRITE, "{op:?}");
        }
        for op in [
            AppOp::Flags,
            AppOp::RedirectUriAdd,
            AppOp::RedirectUriRemove,
            AppOp::IdentifierUriAdd,
            AppOp::IdentifierUriRemove,
            AppOp::ScopeAdd,
            AppOp::RoleAdd,
        ] {
            assert_eq!(op.action(), APP_WRITE, "{op:?}");
        }
    }

    /// Every operation runs its own kind of transaction (and so records its own
    /// event), and the page asks for the same action the transaction needs.
    #[test]
    fn every_operation_runs_its_own_transaction_with_the_same_action() {
        let mut seen = std::collections::HashSet::new();
        for op in AppOp::ALL {
            assert!(seen.insert(op.kind().info().event.as_str()), "{op:?} shares an event");
            assert_eq!(op.kind().info().need, Need::Action(op.action()), "{op:?}");
        }
    }

    #[test]
    fn a_lifetime_that_is_not_a_number_is_refused_rather_than_defaulted() {
        assert!(parse_days("not a number").is_err());
        assert!(parse_days("").is_err());
        assert_eq!(parse_days("30").unwrap(), 30);
    }
}
