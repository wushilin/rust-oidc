//! The console's routes: the router, the chrome around every page, sign-in,
//! assume/leave and the platform's role bindings. Each section lives in its own
//! module beside this one; this module holds only what is common to all of them.
//!
//! Every handler has the same shape: take an [`AdminContext`], `require` one
//! action, check the CSRF token on a write, do the work through a domain module,
//! audit it, redirect. `require` comes *before* any lookup, so an unauthorized
//! caller never learns whether what they named exists.

use std::collections::HashMap;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::session;
use crate::admin::users as user_pages;
use crate::admin::view::{self, Chrome, Tab};
use crate::admin::{
    APP_READ, APP_WRITE, AUDIT_READ, BINDING_READ, GROUP_READ, KEY_READ, TENANT_ASSUME, TENANT_READ, USER_READ,
};
use crate::admin::{apps as app_pages, audit as audit_pages, flow as flow_pages, groups as group_pages};
use crate::admin::{keys as key_pages, settings as settings_pages, tenants as tenant_pages};
use crate::db::{Actor, Event};
use crate::routes::audit::{self, Channel, SignInReason};
use crate::tenant::{self, Tenant};
use crate::users::{self, AuthResult};

/// Form fields, parsed the same way the sign-in flow parses them.
pub type Params = HashMap<String, String>;

pub fn parse_form(raw: &[u8]) -> Params {
    url::form_urlencoded::parse(raw).into_owned().collect()
}

/// A field as a trimmed `&str`, empty when absent.
pub fn field<'a>(form: &'a Params, name: &str) -> &'a str {
    form.get(name).map(|v| v.trim()).unwrap_or_default()
}

/// A field as `Option`, so an empty box clears a column rather than storing "".
pub fn optional<'a>(form: &'a Params, name: &str) -> Option<&'a str> {
    Some(field(form, name)).filter(|v| !v.is_empty())
}

/// An HTML checkbox submits its value only when ticked.
pub fn checked(form: &Params, name: &str) -> bool {
    form.contains_key(name)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(index))
        .route("/admin/home", get(home))
        .route("/admin/find", get(crate::admin::find::page))
        .route("/admin/signin", post(signin))
        .route("/admin/signout", post(signout))
        // Platform pages. No `{tenant}` segment: a platform-scope grant covers
        // every tenant, so there is no scope comparison for a URL key to reach.
        .route("/admin/tenants", get(tenant_pages::page).post(tenant_pages::post))
        .route("/admin/keys", get(key_pages::page).post(key_pages::post))
        .route(
            "/admin/bindings",
            get(crate::admin::platform_roles::page).post(crate::admin::platform_roles::post),
        )
        .route("/admin/assume/{tenant}", post(assume))
        .route("/admin/leave", post(leave))
        // One tenant's sections.
        .route("/admin/tenants/{tenant}/users", get(user_pages::list_page))
        .route(
            "/admin/tenants/{tenant}/users/new",
            get(user_pages::new_page).post(user_pages::create_user),
        )
        .route(
            "/admin/tenants/{tenant}/users/{user}",
            get(user_pages::detail_page).post(user_pages::detail_post),
        )
        .route(
            "/admin/tenants/{tenant}/groups",
            get(group_pages::list_page).post(group_pages::create_group),
        )
        .route(
            "/admin/tenants/{tenant}/groups/{group}",
            get(group_pages::detail_page).post(group_pages::detail_post),
        )
        .route(
            "/admin/tenants/{tenant}/apps",
            get(app_pages::list_page).post(app_pages::create_app),
        )
        .route(
            "/admin/tenants/{tenant}/apps/{app}",
            get(app_pages::detail_page).post(app_pages::detail_post),
        )
        .route(
            "/admin/tenants/{tenant}/roles",
            get(crate::admin::roles::page).post(crate::admin::roles::post),
        )
        .route(
            "/admin/tenants/{tenant}/settings",
            get(settings_pages::page).post(settings_pages::post),
        )
        .route("/admin/tenants/{tenant}/audit", get(audit_pages::page))
        .route(
            "/admin/tenants/{tenant}/flow",
            get(flow_pages::page).post(flow_pages::post),
        )
        // The flow tester's callback. One fixed path, with no `{tenant}` segment,
        // because it has to be registered as a redirect URI: the pending row names
        // the tenant, and the guard is applied to that.
        .route(
            crate::flowtest::CALLBACK_PATH,
            get(flow_pages::callback).post(flow_pages::callback),
        )
}

/// A tab at the platform level: about the deployment, not about one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformTab {
    Tenants,
    Keys,
    Roles,
    /// The find-by-id page: at the platform level, but not one of its tabs.
    Find,
}

/// A tab inside a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantTab {
    Users,
    Groups,
    Apps,
    Roles,
    Flow,
    Settings,
    Audit,
}

impl TenantTab {
    /// In the order the sections are usually worked in.
    pub const ALL: &'static [TenantTab] = &[
        Self::Users,
        Self::Groups,
        Self::Apps,
        Self::Roles,
        Self::Flow,
        Self::Settings,
        Self::Audit,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::Apps => "Applications",
            Self::Roles => "Roles",
            Self::Flow => "Flow tester",
            Self::Settings => "Settings",
            Self::Audit => "Audit log",
        }
    }

    /// The last segment of its URL, under `/admin/tenants/{tenant}/`.
    pub fn path(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Groups => "groups",
            Self::Apps => "apps",
            Self::Roles => "roles",
            Self::Flow => "flow",
            Self::Settings => "settings",
            Self::Audit => "audit",
        }
    }

    /// The action that lets someone open it. A tab is shown only with it.
    fn action(self) -> crate::rbac::Action {
        match self {
            Self::Users => USER_READ,
            Self::Groups => GROUP_READ,
            Self::Apps => APP_READ,
            // The tester signs in and registers test clients: a tool for whoever
            // administers applications, not something to view.
            Self::Flow => APP_WRITE,
            Self::Roles => BINDING_READ,
            Self::Settings => TENANT_READ,
            Self::Audit => AUDIT_READ,
        }
    }
}

/// Where a page is, which decides the tabs around it and the tenant shown.
#[derive(Clone, Copy)]
pub enum At<'a> {
    /// A page about the deployment. No tenant is in view unless one is assumed.
    Platform(PlatformTab),
    /// A page about one tenant: its tabs, and its name in the corner.
    Tenant(&'a Tenant, TenantTab),
}

/// Where the first tab an administrator may open in `tenant` leads, if any.
pub fn tenant_home(base: &str, ctx: &AdminContext, tenant: &Tenant) -> Option<String> {
    TenantTab::ALL
        .iter()
        .find(|t| ctx.can_in(t.action(), tenant))
        .map(|t| format!("{base}/admin/tenants/{}/{}", tenant.id, t.path()))
}

/// The chrome for a page: who is signed in, which tenant is in view, and the tabs
/// that go with where the page is.
///
/// The tabs follow the page, not the session. Outside a tenant only the
/// platform's own tabs are shown; a tenant's tabs appear on that tenant's pages,
/// built for that tenant. Nothing is offered for a tenant nobody has opened.
pub fn chrome<'a>(st: &'a AppState, ctx: &'a AdminContext, at: At<'a>) -> Chrome<'a> {
    let base = st.public_url.base();
    let tenants_url = format!("{base}/admin/tenants");
    match at {
        At::Platform(active) => {
            let mut tabs = vec![Tab {
                label: "Tenants",
                href: tenants_url,
                active: active == PlatformTab::Tenants,
            }];
            if ctx.can(KEY_READ, On::Platform) {
                tabs.push(Tab {
                    label: "Signing keys",
                    href: format!("{base}/admin/keys"),
                    active: active == PlatformTab::Keys,
                });
            }
            if ctx.can(BINDING_READ, On::Platform) {
                tabs.push(Tab {
                    label: "All roles",
                    href: format!("{base}/admin/bindings"),
                    active: active == PlatformTab::Roles,
                });
            }
            Chrome {
                base,
                upn: &ctx.user.upn,
                csrf: &ctx.csrf,
                tenant: ctx.acting_tenant.as_ref().map(|t| t.name.as_str()),
                assumed: ctx.acting_tenant.is_some(),
                up: None,
                tabs,
            }
        }
        At::Tenant(tenant, active) => {
            let assumed = ctx.acting_tenant.as_ref().is_some_and(|a| a.id == tenant.id);
            let tabs = TenantTab::ALL
                .iter()
                .filter(|t| ctx.can_in(t.action(), tenant))
                .map(|t| Tab {
                    label: t.label(),
                    href: format!("{base}/admin/tenants/{}/{}", tenant.id, t.path()),
                    active: *t == active,
                })
                .collect();
            Chrome {
                base,
                upn: &ctx.user.upn,
                csrf: &ctx.csrf,
                tenant: Some(&tenant.name),
                assumed,
                // An assumed tenant is left with Leave, beside its name; offering
                // a second way out that keeps it assumed would only confuse.
                up: (!assumed).then_some(tenants_url),
                tabs,
            }
        }
    }
}

/// Audit a console mutation. The actor is always the signed-in administrator,
/// never the assumed tenant's identity: that is the whole point of recording an
/// assume as its own event.
pub async fn audited(
    st: &AppState,
    ctx: &AdminContext,
    tenant_id: &str,
    event: Event,
    target: Option<&str>,
    details: serde_json::Value,
) {
    audit::record(st, tenant_id, Actor::Id(&ctx.user.id), event, target, details).await;
}

// ---- sign-in ----

/// The console's sign-in message, identical for every failure: an unknown
/// account, a wrong password, a disabled account and a locked one are not
/// distinguished, so the form cannot be used to enumerate administrators.
const SIGN_IN_FAILED: &str = "That account or password is not correct.";

/// Shown when the sign-in form carried no valid nonce. Deliberately not the same
/// message as a bad password: this is a stale tab or a cross-site post, and
/// telling someone their password is wrong when it was never checked is a lie.
const SIGN_IN_EXPIRED: &str = "That sign-in form is no longer valid. Please try again.";

/// Render the sign-in page with a fresh login nonce and set its cookie.
///
/// Every path that shows this form goes through here, so the form always carries
/// a nonce the next post can be checked against.
fn sign_in_page(st: &AppState, upn: &str, error: Option<&str>) -> Response {
    let (cookie, token) = session::new_login_nonce();
    let mut resp = view::sign_in(st.public_url.base(), upn, error, &token);
    resp.headers_mut().append(
        axum::http::header::SET_COOKIE,
        session::set_login_nonce(&st.public_url, &cookie, session::LOGIN_NONCE_LIFETIME_SECS),
    );
    resp
}

/// Where a signed-in administrator starts. Someone with a platform-wide view
/// starts at the list of tenants with no tenant in view; someone whose roles are
/// all inside tenants starts in their own.
async fn home(ctx: AdminContext, State(st): State<AppState>) -> Response {
    let base = st.public_url.base();
    let platform_wide = ctx.can(TENANT_READ, On::Platform);
    let own = if platform_wide {
        ctx.acting_tenant.as_ref()
    } else {
        Some(&ctx.home_tenant)
    };
    let target = own
        .and_then(|t| tenant_home(base, &ctx, t))
        .unwrap_or_else(|| format!("{base}/admin/tenants"));
    view::see_other(&target)
}

async fn index(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match session::find(&st.pool, &headers).await {
        Ok(Some(_)) => view::see_other(&format!("{}/admin/home", st.public_url.base())),
        Ok(None) => sign_in_page(&st, "", None),
        Err(e) => {
            tracing::error!("admin session lookup failed: {e}");
            view::server_error()
        }
    }
}

async fn signin(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let form = parse_form(&body);
    // Before anything else: this form must be one we served. The session-derived
    // CSRF token cannot cover sign-in, because there is no session yet, so the
    // sign-in page hands out a single-purpose nonce instead. Without this check a
    // third-party page could post attacker-controlled credentials and leave the
    // victim signed in as the attacker.
    if !session::login_nonce_ok(&headers, field(&form, session::CSRF_FIELD)) {
        return sign_in_page(&st, "", Some(SIGN_IN_EXPIRED));
    }
    let upn = field(&form, "upn");
    let password = field(&form, "password");
    let base = st.public_url.base();

    // The account's own tenant is the one owning its UPN suffix. A suffix no
    // tenant has verified cannot be an account here, and writes nothing: there is
    // no tenant to attribute the attempt to, and the space of invented suffixes
    // is unbounded.
    let Some((_, domain)) = upn.rsplit_once('@') else {
        return sign_in_page(&st, upn, Some(SIGN_IN_FAILED));
    };
    let home = match tenant::resolve(&st.pool, domain).await {
        Ok(Some(t)) => t,
        Ok(None) => return sign_in_page(&st, upn, Some(SIGN_IN_FAILED)),
        Err(e) => {
            tracing::error!("tenant lookup failed during console sign-in: {e}");
            return view::server_error();
        }
    };

    let outcome = users::authenticate_traced(&st.pool, &home, upn, password).await;
    let (result, trace) = match outcome {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("console sign-in failed: {e}");
            return view::server_error();
        }
    };
    let AuthResult::Ok(user) = result else {
        sign_in_failed(&st, &home, upn, &result, &trace).await;
        return sign_in_page(&st, upn, Some(SIGN_IN_FAILED));
    };

    let cookie = match session::create(&st.pool, &user.id, &home.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("console session could not be created: {e}");
            return view::server_error();
        }
    };
    audit::record(
        &st,
        &home.id,
        Actor::Id(&user.id),
        Event::AdminSignIn,
        Some(&user.id),
        json!({ "via": Channel::Console.as_str(), "upn": audit::clip(&user.upn) }),
    )
    .await;

    let mut resp = view::see_other(&format!("{base}/admin/home"));
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, &cookie, session::ADMIN_SESSION_LIFETIME_SECS),
    );
    // The nonce has done its job; a spent one must not authorise a second post.
    resp.headers_mut()
        .append(header::SET_COOKIE, session::clear_login_nonce(&st.public_url));
    resp
}

/// Audit a refused console sign-in, capping the one failure whose key space an
/// attacker chooses. Mirrors [`audit::sign_in_failure`], which cannot be reused
/// as-is because it records an OAuth `client_id` and the console is not one.
async fn sign_in_failed(st: &AppState, home: &Tenant, upn: &str, result: &AuthResult, trace: &users::AuthTrace) {
    use crate::ratelimit::{Hit, Limit};

    let reason = match (result, trace.user_id.is_some()) {
        (AuthResult::Ok(_), _) => return,
        (AuthResult::Locked, _) => SignInReason::Locked,
        (AuthResult::Disabled, _) => SignInReason::Disabled,
        (AuthResult::InvalidCredentials, true) => SignInReason::BadPassword,
        (AuthResult::InvalidCredentials, false) => SignInReason::UnknownUser,
    };
    // A name this tenant does not have is never a legitimate sign-in, and every
    // invented one is another row; cap those per tenant per window. The response
    // is unaffected, so this is not an enumeration oracle.
    if reason == SignInReason::UnknownUser {
        match st.limits.hit(Limit::UnknownUser, &home.id) {
            Hit::Under => {}
            Hit::Reached => audit::throttled(st, &home.id, None, Limit::UnknownUser).await,
            Hit::AlreadyOver(_) => return,
        }
    }
    let mut details = json!({ "reason": reason.as_str(), "via": Channel::Console.as_str() });
    // The submitted name is only safe to record once it resolved to an account:
    // otherwise it may be anything at all, including a password typed into the
    // wrong box.
    if trace.user_id.is_some() {
        details["upn"] = audit::clip(upn).into();
    }
    let actor = Actor::from(trace.user_id.as_deref());
    audit::record(
        st,
        &home.id,
        actor,
        Event::AdminSignInFailed,
        trace.user_id.as_deref(),
        details,
    )
    .await;
    if trace.lockout_triggered {
        audit::record(
            st,
            &home.id,
            actor,
            Event::Lockout,
            trace.user_id.as_deref(),
            json!({ "via": Channel::Console.as_str() }),
        )
        .await;
    }
}

async fn signout(ctx: AdminContext, State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    audited(
        &st,
        &ctx,
        &ctx.home_tenant.id,
        Event::AdminSignOut,
        Some(&ctx.user.id),
        json!({}),
    )
    .await;
    if let Err(e) = session::end(&st.pool, &headers).await {
        tracing::error!("console sign-out failed: {e}");
        return view::server_error();
    }
    let mut resp = view::see_other(&format!("{}/admin", st.public_url.base()));
    resp.headers_mut()
        .append(header::SET_COOKIE, session::clear_cookie(&st.public_url));
    resp
}

// ---- assume and leave ----

async fn assume(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    // Authorization first: an administrator who may not assume learns nothing
    // about which tenants exist, so a disabled, deleted and imaginary tenant all
    // look the same to them.
    if let Err(resp) = ctx.require(TENANT_ASSUME, On::Platform) {
        return resp;
    }
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(target) = ctx.tenant(&key) else {
        return view::not_found();
    };
    if let Err(e) = session::set_acting_tenant(&st.pool, &ctx.cookie_hash, Some(&target.id)).await {
        tracing::error!("assume failed: {e}");
        return view::server_error();
    }
    audited(
        &st,
        &ctx,
        &target.id,
        Event::AdminTenantAssume,
        Some(&target.id),
        json!({ "tenant": target.name }),
    )
    .await;
    // Assuming a tenant is going into it: land on its first section rather than
    // back on the list with one more click to make.
    let base = st.public_url.base();
    let into = tenant_home(base, &ctx, target).unwrap_or_else(|| format!("{base}/admin/tenants"));
    view::see_other(&into)
}

async fn leave(ctx: AdminContext, State(st): State<AppState>, body: Bytes) -> Response {
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    if let Some(left) = &ctx.acting_tenant {
        if let Err(e) = session::set_acting_tenant(&st.pool, &ctx.cookie_hash, None).await {
            tracing::error!("leave failed: {e}");
            return view::server_error();
        }
        audited(
            &st,
            &ctx,
            &left.id,
            Event::AdminTenantLeave,
            Some(&left.id),
            json!({ "tenant": left.name }),
        )
        .await;
    }
    view::see_other(&format!("{}/admin/tenants", st.public_url.base()))
}

// ---- who the administrators are ----
