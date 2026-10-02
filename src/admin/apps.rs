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

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, TenantTab, audited, checked, chrome, field, optional, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{APP_READ, APP_ROTATE, APP_WRITE, ASSIGNMENT_READ, ASSIGNMENT_WRITE};
use crate::apps::{self, Application, MemberType, Principal, RedirectPlatform, ScopeConsent};
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::rbac::Action;
use crate::tenant::Tenant;
use crate::util::now;

/// What a post to an application's page asks for.
///
/// An enum rather than a bare string so a new operation cannot be added without
/// deciding which action authorizes it and which event records it.
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
}

impl AppOp {
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
            Self::Assign | Self::Unassign | Self::RoleAssign | Self::RoleUnassign => ASSIGNMENT_WRITE,
            Self::Flags
            | Self::RedirectUriAdd
            | Self::RedirectUriRemove
            | Self::IdentifierUriAdd
            | Self::IdentifierUriRemove
            | Self::ScopeAdd
            | Self::RoleAdd => APP_WRITE,
        }
    }

    fn event(self) -> Event {
        match self {
            Self::Flags => Event::AdminAppFlags,
            Self::SecretAdd => Event::AdminAppSecretAdd,
            Self::SecretRemove => Event::AdminAppSecretRemove,
            Self::CertificateAdd => Event::AdminAppKeyAdd,
            Self::CertificateRemove => Event::AdminAppKeyRemove,
            Self::RedirectUriAdd => Event::AdminAppRedirectUriAdd,
            Self::RedirectUriRemove => Event::AdminAppRedirectUriRemove,
            Self::IdentifierUriAdd => Event::AdminAppIdentifierUriAdd,
            Self::IdentifierUriRemove => Event::AdminAppIdentifierUriRemove,
            Self::ScopeAdd => Event::AdminAppScopeAdd,
            Self::RoleAdd => Event::AdminAppRoleAdd,
            Self::Assign => Event::AdminAppAssign,
            Self::Unassign => Event::AdminAppUnassign,
            Self::RoleAssign => Event::AdminAppRoleAssign,
            Self::RoleUnassign => Event::AdminAppRoleUnassign,
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
const PRINCIPAL: &str = "principal";
const PRINCIPAL_TYPE: &str = "principal_type";
const ASSIGNMENT: &str = "assignment";
const ALLOW_PASSWORD_GRANT: &str = "allow_password_grant";
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
    let name = field(&form, NAME);
    if name.is_empty() {
        return list(
            &st,
            &ctx,
            tenant,
            Some("An application needs a display name."),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    match apps::create(&st.pool, tenant, name).await {
        Ok(created) => {
            audited(
                &st,
                &ctx,
                &tenant.id,
                Event::AdminAppCreate,
                Some(&created.application.app_id),
                json!({ "displayName": crate::routes::audit::clip(name) }),
            )
            .await;
            view::see_other(&app_url(st.public_url.base(), tenant, &created.application))
        }
        Err(err) => list(&st, &ctx, tenant, Some(&err.to_string()), StatusCode::BAD_REQUEST).await,
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
    detail(&st, &ctx, tenant, &app, Page::default(), StatusCode::OK).await
}

/// What a render of the application page needs beyond the application itself.
#[derive(Default)]
struct Page<'a> {
    error: Option<&'a str>,
    /// A value that exists only in this response: a freshly created secret.
    reveal: Option<&'a str>,
}

async fn detail(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    app: &Application,
    page: Page<'_>,
    status: StatusCode,
) -> Response {
    let base = st.public_url.base();
    let url = app_url(base, tenant, app);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_write = ctx.can_in(APP_WRITE, tenant);
    let may_rotate = ctx.can_in(APP_ROTATE, tenant);
    let may_assign = ctx.can_in(ASSIGNMENT_WRITE, tenant);
    let may_read_assignments = ctx.can_in(ASSIGNMENT_READ, tenant);

    let secrets = apps::secrets(&st.pool, app).await.unwrap_or_default();
    let certificates = apps::key_credentials(&st.pool, app).await.unwrap_or_default();
    let redirect_uris = apps::redirect_uris(&st.pool, app).await.unwrap_or_default();
    let identifier_uris = apps::identifier_uris(&st.pool, app).await.unwrap_or_default();
    let scopes = apps::scopes(&st.pool, app).await.unwrap_or_default();
    let roles = apps::roles(&st.pool, app).await.unwrap_or_default();

    let facts = format!(
        r#"<dl class="facts"><dt>Application (client) id</dt><dd>{app_id}</dd>
<dt>Object id</dt><dd>{id}</dd><dt>Tenant</dt><dd>{tenant_name}</dd></dl>
<p class="muted"><a href="{flow}">Test a sign-in flow with this application</a>, which says what the
flow needs before it runs anything.</p>"#,
        app_id = e(&app.app_id),
        id = e(&app.id),
        tenant_name = e(&tenant.name),
        flow = e(&format!(
            "{base}/admin/tenants/{}/flow?{}={}",
            tenant.id,
            crate::flowtest::APP_FIELD,
            app.app_id
        )),
    );

    let flags = flags_form(&url, &csrf, app, may_write);
    let secrets = secrets_section(&url, &csrf, &secrets, may_rotate);
    let certificates = certificates_section(&url, &csrf, &certificates, may_rotate);
    let redirects = redirect_section(&url, &csrf, &redirect_uris, may_write);
    let identifiers = identifier_section(&url, &csrf, &identifier_uris, may_write);
    let scopes_html = scope_section(&url, &csrf, &scopes, may_write);
    let roles_html = role_section(&url, &csrf, &roles, may_write);
    let assignments = if may_read_assignments {
        let assigned = apps::assignments(&st.pool, &tenant.id, app).await.unwrap_or_default();
        let granted = apps::role_assignments(&st.pool, &tenant.id, app)
            .await
            .unwrap_or_default();
        format!(
            "{}{}",
            assignment_section(&url, &csrf, &assigned, &roles, tenant, may_assign),
            application_roles_section(&url, &csrf, &granted, &roles, may_assign)
        )
    } else {
        String::new()
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

    let body = format!(
        r#"<h1>{name}</h1><p class="sub">{tenant_name} &middot; application registration</p>
{reveal}{error}{facts}{flags}{secrets}{certificates}{redirects}{identifiers}{scopes_html}{roles_html}{assignments}"#,
        name = e(&app.display_name),
        tenant_name = e(&tenant.name),
        error = view::error_block(page.error),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Apps)),
        status,
        &app.display_name,
        &body,
    )
}

fn flags_form(url: &str, csrf: &str, app: &Application, may_write: bool) -> String {
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
        r#"<h2>Grants</h2><form method="post" action="{url}">{csrf}
<input type="hidden" name="{op_field}" value="{op}">
{password}{id_token}{access_token}{save}</form>"#,
        url = e(url),
        op_field = AppOp::FIELD,
        op = AppOp::Flags.as_str(),
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
                    remove_button(url, csrf, AppOp::SecretRemove, KEY_ID, &s.key_id, "Delete")
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
                    remove_button(url, csrf, AppOp::CertificateRemove, KEY_ID, &c.key_id, "Delete")
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
fn assignment_section(
    url: &str,
    csrf: &str,
    assignments: &[apps::Assignment],
    roles: &[apps::AppRole],
    tenant: &Tenant,
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
                    who = e(&a.principal_name),
                    boxes = role_boxes(&user_roles, &a.roles),
                )
            } else {
                String::new()
            };
            format!(
                "<tr><td>{who}</td><td>{kind}</td><td>{held}{change}</td><td>{remove}</td></tr>",
                who = e(&a.principal_name),
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
<label for="assign_principal">Name in {tenant_name}</label>
<input id="assign_principal" name="{PRINCIPAL}" type="text" required autocapitalize="none" spellcheck="false">
{boxes}
<div class="actions"><button type="submit">Assign</button></div></form>"#,
                url = e(url),
                op_field = AppOp::FIELD,
                op = AppOp::Assign.as_str(),
                tenant_name = e(&tenant.name),
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

// ---- writes ----

/// What one operation did, for the audit row and for what to render next.
struct Outcome {
    details: serde_json::Value,
    /// A value that must be shown exactly once, so the response is the page
    /// itself rather than a redirect to it.
    reveal: Option<String>,
}

impl Outcome {
    fn plain(details: serde_json::Value) -> Self {
        Self { details, reveal: None }
    }
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
    match apply(&st, tenant, &app, op, &form, &ticked).await {
        Ok(outcome) => {
            audited(&st, &ctx, &tenant.id, op.event(), Some(&app.app_id), outcome.details).await;
            match &outcome.reveal {
                // The one deliberate exception to "303 after a post": the value
                // lives in this response and nowhere else.
                Some(secret) => {
                    let page = Page {
                        error: None,
                        reveal: Some(secret),
                    };
                    // Re-read the application: the flags may have changed.
                    let app = apps::find_in_tenant(&st.pool, tenant, &app_key).await.unwrap_or(app);
                    detail(&st, &ctx, tenant, &app, page, StatusCode::OK).await
                }
                None => view::see_other(&app_url(st.public_url.base(), tenant, &app)),
            }
        }
        Err(err) => {
            let message = err.to_string();
            let page = Page {
                error: Some(&message),
                reveal: None,
            };
            detail(&st, &ctx, tenant, &app, page, StatusCode::BAD_REQUEST).await
        }
    }
}

/// Carry out one operation. Every branch calls into [`crate::apps`]; nothing
/// about an application is decided here.
async fn apply(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    op: AppOp,
    form: &Params,
    ticked: &[String],
) -> anyhow::Result<Outcome> {
    match op {
        AppOp::Flags => {
            let password = checked(form, ALLOW_PASSWORD_GRANT);
            let id_token = checked(form, ALLOW_ID_TOKEN);
            let access_token = checked(form, ALLOW_ACCESS_TOKEN);
            apps::set_password_grant_allowed(&st.pool, app, password).await?;
            apps::set_implicit_allowed(&st.pool, app, id_token, access_token).await?;
            Ok(Outcome::plain(json!({
                "allowPasswordGrant": password,
                "allowIdTokenImplicit": id_token,
                "allowAccessTokenImplicit": access_token,
            })))
        }
        AppOp::SecretAdd => {
            let days = parse_days(field(form, DAYS))?;
            let created = apps::add_secret(&st.pool, app, optional(form, NAME), days).await?;
            // The key id and the expiry, never the value and never a prefix of it.
            Ok(Outcome {
                details: json!({ "keyId": created.key_id, "endsAt": created.end_at }),
                reveal: Some(created.secret),
            })
        }
        AppOp::SecretRemove => {
            let key_id = field(form, KEY_ID);
            apps::remove_secret(&st.pool, app, key_id).await?;
            Ok(Outcome::plain(json!({ "keyId": key_id })))
        }
        AppOp::CertificateAdd => {
            let pem = field(form, CERT);
            // The same refusal the CLI makes: a pasted key pair would store the
            // private key in `cert_der` and the administrator would never know.
            if pem.contains("PRIVATE KEY") {
                anyhow::bail!("that is a private key; paste only the certificate");
            }
            let key_id = apps::add_key_credential(&st.pool, app, pem, optional(form, NAME)).await?;
            Ok(Outcome::plain(json!({ "keyId": key_id })))
        }
        AppOp::CertificateRemove => {
            let key_id = field(form, KEY_ID);
            if !apps::remove_key_credential(&st.pool, app, key_id).await? {
                anyhow::bail!("no certificate with that thumbprint is registered");
            }
            Ok(Outcome::plain(json!({ "keyId": key_id })))
        }
        AppOp::RedirectUriAdd => {
            let (platform, uri) = (parse_platform(form)?, field(form, URI));
            apps::add_redirect_uri(&st.pool, app, platform, uri).await?;
            Ok(Outcome::plain(
                json!({ "platform": platform.as_str(), "uri": crate::routes::audit::clip(uri) }),
            ))
        }
        AppOp::RedirectUriRemove => {
            let (platform, uri) = (parse_platform(form)?, field(form, URI));
            if !apps::remove_redirect_uri(&st.pool, app, platform, uri).await? {
                anyhow::bail!("that redirect URI is not registered under that platform");
            }
            Ok(Outcome::plain(
                json!({ "platform": platform.as_str(), "uri": crate::routes::audit::clip(uri) }),
            ))
        }
        AppOp::IdentifierUriAdd => {
            let uri = field(form, URI);
            apps::add_identifier_uri(&st.pool, app, uri).await?;
            Ok(Outcome::plain(json!({ "uri": crate::routes::audit::clip(uri) })))
        }
        AppOp::IdentifierUriRemove => {
            let uri = field(form, URI);
            apps::remove_identifier_uri(&st.pool, app, uri).await?;
            Ok(Outcome::plain(json!({ "uri": crate::routes::audit::clip(uri) })))
        }
        AppOp::ScopeAdd => {
            let value = field(form, VALUE);
            let Some(consent) = ScopeConsent::parse(field(form, CONSENT)) else {
                anyhow::bail!("choose who can consent to that scope");
            };
            let display = optional(form, DISPLAY_NAME).unwrap_or(value);
            let id = apps::add_scope(&st.pool, app, value, display, consent).await?;
            Ok(Outcome::plain(
                json!({ "id": id, "value": crate::routes::audit::clip(value), "consent": consent.as_str() }),
            ))
        }
        AppOp::RoleAdd => {
            let value = field(form, VALUE);
            let types: Vec<MemberType> = MemberType::ALL
                .iter()
                .copied()
                .filter(|t| checked(form, &member_field(*t)))
                .collect();
            let display = optional(form, DISPLAY_NAME).unwrap_or(value);
            let id = apps::add_role(&st.pool, app, value, display, optional(form, DESCRIPTION), &types).await?;
            Ok(Outcome::plain(json!({
                "id": id,
                "value": crate::routes::audit::clip(value),
                "allowedMemberTypes": types.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            })))
        }
        AppOp::Assign => {
            let name = field(form, PRINCIPAL);
            let (kind, principal) = match PrincipalType::parse(field(form, PRINCIPAL_TYPE)) {
                Some(PrincipalType::User) => (PrincipalType::User, Principal::User(name.to_string())),
                Some(PrincipalType::Group) => (PrincipalType::Group, Principal::Group(name.to_string())),
                _ => anyhow::bail!("choose a user or a group"),
            };
            // `assign` resolves the principal within this tenant and checks each
            // role, so neither is decided here.
            let id = apps::assign(&st.pool, tenant, app, &principal, ticked).await?;
            Ok(Outcome::plain(json!({
                "assignmentId": id,
                "principalType": kind.as_str(),
                "principal": crate::routes::audit::clip(name),
                "roles": ticked.iter().map(|r| crate::routes::audit::clip(r)).collect::<Vec<_>>(),
            })))
        }
        AppOp::Unassign => {
            let id = field(form, ASSIGNMENT);
            if !apps::unassign(&st.pool, &tenant.id, app, id).await? {
                anyhow::bail!("that assignment no longer exists");
            }
            Ok(Outcome::plain(json!({ "assignmentId": id })))
        }
        AppOp::RoleAssign => {
            let role = field(form, ROLE);
            let name = field(form, PRINCIPAL);
            // People are assigned with `Assign`; this grants a role to a client
            // application.
            let Some(kind @ PrincipalType::ServicePrincipal) = PrincipalType::parse(field(form, PRINCIPAL_TYPE)) else {
                anyhow::bail!("a role is granted this way to an application only; assign users and groups above");
            };
            let principal = Principal::App(name.to_string());
            // `assign_role` resolves the principal within this tenant and checks
            // the role's allowed member types, so neither is decided here.
            apps::assign_role(&st.pool, tenant, app, role, &principal).await?;
            Ok(Outcome::plain(json!({
                "role": crate::routes::audit::clip(role),
                "principalType": kind.as_str(),
                "principal": crate::routes::audit::clip(name),
            })))
        }
        AppOp::RoleUnassign => {
            let id = field(form, ASSIGNMENT);
            if !apps::remove_role_assignment(&st.pool, &tenant.id, app, id).await? {
                anyhow::bail!("that role assignment no longer exists");
            }
            Ok(Outcome::plain(json!({ "assignmentId": id })))
        }
    }
}

/// The platform named by the form. A value outside the closed set is refused,
/// never defaulted: the rules get weaker from `web` to `publicClient`.
fn parse_platform(form: &Params) -> anyhow::Result<RedirectPlatform> {
    RedirectPlatform::parse(field(form, PLATFORM)).ok_or_else(|| anyhow::anyhow!("choose a platform"))
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

    /// Every operation records a distinct event, so the audit trail can tell
    /// which one happened.
    #[test]
    fn every_operation_records_its_own_event() {
        let mut seen = std::collections::HashSet::new();
        for op in AppOp::ALL {
            assert!(
                seen.insert(op.event().as_str()),
                "{:?} shares an event with another operation",
                op
            );
        }
    }

    #[test]
    fn a_lifetime_that_is_not_a_number_is_refused_rather_than_defaulted() {
        assert!(parse_days("not a number").is_err());
        assert!(parse_days("").is_err());
        assert_eq!(parse_days("30").unwrap(), 30);
    }
}
