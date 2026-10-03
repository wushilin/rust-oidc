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
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::session;
use crate::admin::users as user_pages;
use crate::admin::view::{self, Chrome, Tab};
use crate::admin::{APP_READ, APP_WRITE, AUDIT_READ, BINDING_READ, GROUP_READ, KEY_READ, TENANT_READ, USER_READ};
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
        .route(
            "/admin/find",
            get(crate::admin::find::page).post(crate::admin::find::post),
        )
        .route("/admin/signin", post(signin))
        .route("/admin/signout", post(signout))
        // Platform pages. No `{tenant}` segment: a platform-scope grant covers
        // every tenant, so there is no scope comparison for a URL key to reach.
        .route("/admin/tenants", get(tenant_pages::page).post(tenant_pages::post))
        .route("/admin/keys", get(key_pages::page).post(key_pages::post))
        .route("/admin/configuration", get(crate::admin::configuration::page))
        .route(
            "/admin/bindings",
            get(crate::admin::platform_roles::page).post(crate::admin::platform_roles::post),
        )
        // One tenant's sections.
        .route(
            "/admin/tenants/{tenant}/users",
            get(user_pages::list_page).post(user_pages::list_post),
        )
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
            "/admin/tenants/{tenant}/apps/{app}/{section}",
            get(app_pages::section_page),
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
    Configuration,
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
    /// A page about the deployment. No tenant is in view.
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
                    label: "Global roles",
                    href: format!("{base}/admin/bindings"),
                    active: active == PlatformTab::Roles,
                });
            }
            if ctx.can(TENANT_READ, On::Platform) {
                tabs.push(Tab {
                    label: "Configuration",
                    href: format!("{base}/admin/configuration"),
                    active: active == PlatformTab::Configuration,
                });
            }
            Chrome {
                base,
                upn: &ctx.user.upn,
                csrf: &ctx.csrf,
                tenant: None,
                up: None,
                tabs,
            }
        }
        At::Tenant(tenant, active) => {
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
                up: Some(tenants_url),
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
    let own = (!platform_wide).then_some(&ctx.home_tenant);
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
    if let Some(
        op @ (crate::html::LoginOp::MfaVerify | crate::html::LoginOp::MfaEnroll | crate::html::LoginOp::ChangePassword),
    ) = crate::html::LoginOp::parse(field(&form, OP_FIELD))
    {
        return console_second_step(&st, &form, op).await;
    }
    let upn = field(&form, "upn");
    let password = field(&form, "password");

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

    // A second step, where the account or the console needs one.
    match crate::mfa::step(&st.pool, &home, &user.id, crate::mfa::At::Console).await {
        Ok(crate::mfa::Step::Done) => console_finish(&st, &home, &user, false).await,
        Ok(step) => console_start_mfa(&st, &home, &user, step).await,
        Err(e) => {
            tracing::error!("MFA lookup failed during console sign-in: {e}");
            view::server_error()
        }
    }
}

/// The form field naming what a sign-in form asks for.
const OP_FIELD: &str = "op";
/// The tenant a console second step belongs to: the administrator's own.
const MFA_TENANT_FIELD: &str = "tenant";

async fn console_start_mfa(st: &AppState, home: &Tenant, user: &users::User, step: crate::mfa::Step) -> Response {
    use crate::mfa::Purpose;
    let purpose = if step == crate::mfa::Step::Enroll {
        Purpose::Enroll
    } else {
        Purpose::Verify
    };
    match crate::mfa::begin(&st.pool, &home.id, &user.id, purpose).await {
        Ok(ticket) => {
            let secret = if purpose == Purpose::Enroll {
                crate::mfa::pending(&st.pool, &ticket, &home.id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.enroll_secret)
            } else {
                None
            };
            console_mfa_page(st, home, &user.upn, purpose, &ticket, secret.as_deref(), None)
        }
        Err(e) => {
            tracing::error!("MFA could not start during console sign-in: {e}");
            view::server_error()
        }
    }
}

/// The second-step page of a console sign-in, carrying a fresh login nonce: the
/// form is posted before there is a session to derive a CSRF token from.
fn console_mfa_page(
    st: &AppState,
    home: &Tenant,
    upn: &str,
    purpose: crate::mfa::Purpose,
    ticket: &str,
    secret: Option<&str>,
    error: Option<&str>,
) -> Response {
    let (cookie, token) = session::new_login_nonce();
    let hidden = format!(
        r#"{}<input type="hidden" name="{MFA_TENANT_FIELD}" value="{}">"#,
        view::csrf_input(&token),
        view::e(&home.id)
    );
    let action = format!("{}/admin/signin", st.public_url.base());
    let mut resp = match (purpose, secret) {
        (crate::mfa::Purpose::Enroll, Some(secret)) => crate::html::mfa_enroll(&crate::html::MfaEnroll {
            tenant_name: &home.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: OP_FIELD,
            op: crate::html::LoginOp::MfaEnroll.as_str(),
            ticket,
            qr_svg: &crate::mfa::qr_svg(&crate::mfa::otpauth_uri(secret, &home.name, upn)),
            secret,
            issuer: &home.name,
            error,
        }),
        _ => crate::html::mfa_verify(&crate::html::MfaVerify {
            tenant_name: &home.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: OP_FIELD,
            op: crate::html::LoginOp::MfaVerify.as_str(),
            ticket,
            error,
        }),
    };
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_login_nonce(&st.public_url, &cookie, session::LOGIN_NONCE_LIFETIME_SECS),
    );
    resp
}

const MFA_EXPIRED: &str = "That sign-in has expired or had too many wrong codes. Please sign in again.";
const MFA_WRONG: &str = "That code didn't work. Check the time on your phone, wait for a new code and try again.";

async fn console_second_step(st: &AppState, form: &Params, op: crate::html::LoginOp) -> Response {
    use crate::mfa::Purpose;
    let ticket = field(form, crate::html::MFA_TICKET);
    let typed = field(form, crate::html::MFA_CODE);
    let home = match tenant::resolve(&st.pool, field(form, MFA_TENANT_FIELD)).await {
        Ok(Some(t)) => t,
        _ => return sign_in_page(st, "", Some(MFA_EXPIRED)),
    };
    let Ok(Some(waiting)) = crate::mfa::pending(&st.pool, ticket, &home.id).await else {
        return sign_in_page(st, "", Some(MFA_EXPIRED));
    };
    let user = match users::find(&st.pool, &home.id, &waiting.user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return sign_in_page(st, "", Some(MFA_EXPIRED)),
    };
    let fits = match op {
        crate::html::LoginOp::MfaEnroll => waiting.purpose == Purpose::Enroll,
        crate::html::LoginOp::ChangePassword => {
            matches!(
                waiting.purpose,
                Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa
            )
        }
        _ => waiting.purpose == Purpose::Verify,
    };
    if !fits {
        return sign_in_page(st, "", Some(MFA_EXPIRED));
    }
    match waiting.purpose {
        Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa => {
            let new = field(form, crate::html::NEW_PASSWORD);
            let confirm = field(form, crate::html::CONFIRM_PASSWORD);
            let refused = if new != confirm {
                Some("The passwords don't match.".to_string())
            } else {
                users::change_password(&st.pool, &home, &user.id, new, users::PasswordSetBy::User)
                    .await
                    .err()
                    .map(|e| e.to_string())
            };
            if let Some(message) = refused {
                return console_change_page(st, &home, &user.upn, ticket, Some(&message));
            }
            let _ = crate::mfa::finish(&st.pool, ticket).await;
            audit::record(
                st,
                &home.id,
                Actor::Id(&user.id),
                crate::db::Event::PasswordChanged,
                Some(&user.id),
                json!({ "via": Channel::Console.as_str() }),
            )
            .await;
            console_session(st, &home, &user).await
        }
        Purpose::Verify => match crate::mfa::check(&st.pool, &user.id, typed).await {
            Ok(Some(factor)) => {
                let _ = crate::mfa::finish(&st.pool, ticket).await;
                audit::record(
                    st,
                    &home.id,
                    Actor::Id(&user.id),
                    crate::db::Event::MfaVerified,
                    Some(&user.id),
                    json!({ "via": Channel::Console.as_str(), "factor": factor.as_str() }),
                )
                .await;
                console_finish(st, &home, &user, true).await
            }
            Ok(None) => {
                audit::record(
                    st,
                    &home.id,
                    Actor::Id(&user.id),
                    crate::db::Event::MfaFailed,
                    Some(&user.id),
                    json!({ "via": Channel::Console.as_str() }),
                )
                .await;
                match crate::mfa::failed_attempt(&st.pool, ticket).await {
                    Ok(true) => console_mfa_page(st, &home, &user.upn, Purpose::Verify, ticket, None, Some(MFA_WRONG)),
                    _ => sign_in_page(st, &user.upn, Some(MFA_EXPIRED)),
                }
            }
            Err(e) => {
                tracing::error!("MFA check failed during console sign-in: {e}");
                view::server_error()
            }
        },
        Purpose::Enroll => {
            let secret = waiting.enroll_secret.unwrap_or_default();
            if !crate::mfa::verify_new(&secret, typed) {
                return match crate::mfa::failed_attempt(&st.pool, ticket).await {
                    Ok(true) => console_mfa_page(
                        st,
                        &home,
                        &user.upn,
                        Purpose::Enroll,
                        ticket,
                        Some(&secret),
                        Some(MFA_WRONG),
                    ),
                    _ => sign_in_page(st, &user.upn, Some(MFA_EXPIRED)),
                };
            }
            let codes = match crate::mfa::enroll(&st.pool, &user.id, &secret).await {
                Ok(codes) => codes,
                Err(e) => {
                    tracing::error!("MFA enrolment failed during console sign-in: {e}");
                    return view::server_error();
                }
            };
            let _ = crate::mfa::finish(&st.pool, ticket).await;
            let _ = users::end_sessions(&st.pool, &user.id).await;
            audit::record(
                st,
                &home.id,
                Actor::Id(&user.id),
                crate::db::Event::MfaEnrolled,
                Some(&user.id),
                json!({ "via": Channel::Console.as_str() }),
            )
            .await;
            let mut resp = crate::html::mfa_enrolled(&home.name, &codes, &format!("{}/admin", st.public_url.base()));
            resp.headers_mut()
                .append(header::SET_COOKIE, session::clear_login_nonce(&st.public_url));
            resp
        }
    }
}

/// After the password (and second factor, if any): a new password first if the
/// account must choose one, then the console session.
async fn console_finish(st: &AppState, home: &Tenant, user: &users::User, after_mfa: bool) -> Response {
    if users::must_change_password(&st.pool, &user.id).await.unwrap_or(false) {
        return match crate::mfa::begin(
            &st.pool,
            &home.id,
            &user.id,
            crate::mfa::Purpose::change_password(after_mfa),
        )
        .await
        {
            Ok(ticket) => console_change_page(st, home, &user.upn, &ticket, None),
            Err(e) => {
                tracing::error!("password change could not start during console sign-in: {e}");
                view::server_error()
            }
        };
    }
    console_session(st, home, user).await
}

fn console_change_page(st: &AppState, home: &Tenant, upn: &str, ticket: &str, error: Option<&str>) -> Response {
    let (cookie, token) = session::new_login_nonce();
    let hidden = format!(
        r#"{}<input type="hidden" name="{MFA_TENANT_FIELD}" value="{}">"#,
        view::csrf_input(&token),
        view::e(&home.id)
    );
    let mut resp = crate::html::change_password(&crate::html::ChangePassword {
        tenant_name: &home.name,
        upn,
        action: &format!("{}/admin/signin", st.public_url.base()),
        hidden: &hidden,
        op_field: OP_FIELD,
        op: crate::html::LoginOp::ChangePassword.as_str(),
        ticket,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_login_nonce(&st.public_url, &cookie, session::LOGIN_NONCE_LIFETIME_SECS),
    );
    resp
}

/// The console session for an administrator who has signed in, all steps done.
async fn console_session(st: &AppState, home: &Tenant, user: &users::User) -> Response {
    let base = st.public_url.base();
    let cookie = match session::create(&st.pool, &user.id, &home.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("console session could not be created: {e}");
            return view::server_error();
        }
    };
    audit::record(
        st,
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

// ---- who the administrators are ----
