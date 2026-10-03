//! Device authorization grant (RFC 8628), in Entra's shape.
//!
//! The device POSTs to `/{tenant}/oauth2/v2.0/devicecode` and polls the token
//! endpoint while the user approves at `/{tenant}/oauth2/deviceauth`.

use std::collections::HashMap;
use std::fmt;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sqlx::Row;

use super::audit::{self, Actor, Channel, Event};
use crate::AppState;
use crate::access;
use crate::apps::{self, Application};
use crate::claims::Amr;
use crate::error::{AadError, Aadsts, no_store};
use crate::mfa::{self, Purpose};
use crate::ratelimit::{Hit, Limit};
use crate::session::{self, CSRF_COOKIE};
use crate::tenant::{self, Tenant};
use crate::users::AuthResult;
use crate::util::{b64url, now, random_bytes, sha256_hex};
use crate::{html, scopes, users};

/// How long a device code stays valid, as in Entra.
pub const DEVICE_CODE_LIFETIME: i64 = 900;
/// Minimum seconds between polls; a faster device gets `slow_down`.
pub const POLL_INTERVAL: i64 = 5;
/// How long past `expires_at` a row is kept, so a device that polls just after
/// expiry still gets `expired_token` rather than an unknown-code error.
const DEVICE_CODE_RETENTION: i64 = DEVICE_CODE_LIFETIME;
const USER_CODE_LEN: usize = 8;
/// Digits and letters that cannot be confused when read off a screen.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";

/// State of a device code. Stored as the strings in `migrations/0003`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Approved,
    Denied,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

impl fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the user just submitted on a device page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceOp {
    /// The code-entry form.
    Code,
    /// The sign-in form (same field names as the authorize login page).
    Login,
    Approve,
    Deny,
    /// The code at the second step of the sign-in.
    MfaVerify,
    /// The code that confirms a new authenticator.
    MfaEnroll,
    /// A new password, chosen because the old one must be replaced.
    ChangePassword,
}

impl DeviceOp {
    fn parse(raw: Option<&str>) -> Option<Self> {
        match raw {
            Some("code") => Some(Self::Code),
            Some("login") => Some(Self::Login),
            Some("approve") => Some(Self::Approve),
            Some("deny") => Some(Self::Deny),
            Some(raw) if raw == html::LoginOp::MfaVerify.as_str() => Some(Self::MfaVerify),
            Some(raw) if raw == html::LoginOp::MfaEnroll.as_str() => Some(Self::MfaEnroll),
            Some(raw) if raw == html::LoginOp::ChangePassword.as_str() => Some(Self::ChangePassword),
            _ => None,
        }
    }
}

type Params = HashMap<String, String>;

fn parse_form(raw: &[u8]) -> Params {
    url::form_urlencoded::parse(raw).into_owned().collect()
}

fn get<'a>(p: &'a Params, name: &str) -> Option<&'a str> {
    p.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

fn new_user_code() -> String {
    let bytes = random_bytes(USER_CODE_LEN);
    bytes
        .iter()
        .map(|b| USER_CODE_ALPHABET[*b as usize % USER_CODE_ALPHABET.len()] as char)
        .collect()
}

/// User codes are compared case-insensitively and without the display dash.
fn normalize_user_code(raw: &str) -> String {
    raw.trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn deviceauth_url(st: &AppState, tenant_id: &str) -> String {
    st.public_url.tenant_url(tenant_id, "oauth2/deviceauth")
}

// ---- POST /{tenant}/oauth2/v2.0/devicecode ----

pub async fn devicecode(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = parse_form(&body);
    match issue_device_code(&st, &tenant_key, &params).await {
        Ok(resp) => resp,
        Err(err) => err.correlate(&headers).into_response(),
    }
}

async fn issue_device_code(st: &AppState, tenant_key: &str, params: &Params) -> Result<Response, AadError> {
    let tenant = tenant::resolve(&st.pool, tenant_key)
        .await?
        .ok_or_else(|| AadError::tenant_not_found(tenant_key))?;
    let client_id = get(params, "client_id").ok_or_else(|| AadError::missing_parameter("client_id"))?;

    // A device code is only useful to a client that exists in this tenant.
    let app = apps::find(&st.pool, client_id).await?;
    let sp = match &app {
        Some(app) => apps::service_principal(&st.pool, &tenant.id, &app.app_id).await?,
        None => None,
    };
    let (Some(app), Some(sp)) = (app, sp) else {
        return Err(AadError::app_not_found(client_id, &tenant.id));
    };
    if !sp.enabled {
        return Err(AadError::app_disabled(&app.app_id, &app.display_name));
    }

    // Every device authorization request inserts a `device_codes` row and an
    // audit row, and the device is a public client with no secret to check, so
    // the request itself is the thing to bound. Keyed per application: a flood
    // against one application cannot stop another's devices enrolling.
    //
    // One atomic count-and-decide rather than a check followed by a count: two
    // concurrent requests could each pass a separate check and both be served,
    // putting the bucket one over its allowance.
    let key = crate::ratelimit::app_key(&tenant.id, &app.app_id);
    match st.limits.hit(Limit::DeviceCodeRequest, &key) {
        Hit::Under => {}
        Hit::Reached => audit::throttled(st, &tenant.id, Some(&app.app_id), Limit::DeviceCodeRequest).await,
        Hit::AlreadyOver(retry) => return Err(AadError::throttled(retry)),
    }

    let scope = get(params, "scope").unwrap_or("openid");
    // Reject an unusable scope now rather than after the user has signed in.
    scopes::resolve(&st.pool, &tenant, scope).await?;

    let device_code = b64url(&random_bytes(48));
    let user_code = new_user_code();
    let ts = now();
    let expires_at = ts + DEVICE_CODE_LIFETIME;
    // Best effort, like the client-assertion jti prune: a failure must not block issuing.
    if let Err(e) = prune_expired(&st.pool, ts).await {
        tracing::warn!("device code prune failed: {e}");
    }
    sqlx::query(crate::db::q(
        &st.pool,
        "INSERT INTO device_codes (device_code_hash, user_code, tenant_id, client_app_id, scope, status,
                                   interval_secs, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(sha256_hex(device_code.as_bytes()))
    .bind(&user_code)
    .bind(&tenant.id)
    .bind(&app.app_id)
    .bind(scope)
    .bind(DeviceStatus::Pending.as_str())
    .bind(POLL_INTERVAL)
    .bind(ts)
    .bind(expires_at)
    .execute(&st.pool)
    .await?;

    // The user code is what approves this request, so it stays out of the log.
    let details = json!({ "clientId": app.app_id, "scope": audit::clip(scope) });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&app.app_id),
        Event::DeviceCodeIssued,
        None,
        details,
    )
    .await;

    let verification_uri = deviceauth_url(st, &tenant.id);
    let mut resp = (
        StatusCode::OK,
        Json(json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
            "expires_in": DEVICE_CODE_LIFETIME,
            "interval": POLL_INTERVAL,
            "message": format!("To sign in, use a web browser to open the page {verification_uri} and enter the code {user_code} to authenticate."),
        })),
    )
        .into_response();
    no_store(resp.headers_mut());
    Ok(resp)
}

/// Delete device codes that expired more than [`DEVICE_CODE_RETENTION`] ago.
/// Idempotent, and cheap: a range delete on the `expires_at` index.
pub(crate) async fn prune_expired(pool: &crate::db::DbPool, ts: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(crate::db::q(pool, "DELETE FROM device_codes WHERE expires_at < ?"))
        .bind(ts - DEVICE_CODE_RETENTION)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

// ---- GET|POST /{tenant}/oauth2/deviceauth ----

struct Pending {
    user_code: String,
    client: Application,
    scope: String,
}

async fn load_pending(st: &AppState, tenant: &Tenant, user_code: &str) -> anyhow::Result<Option<Pending>> {
    let row = sqlx::query(crate::db::q(
        &st.pool,
        "SELECT user_code, client_app_id, scope FROM device_codes
         WHERE user_code = ? AND tenant_id = ? AND status = ? AND expires_at > ? AND redeemed_at IS NULL",
    ))
    .bind(user_code)
    .bind(&tenant.id)
    .bind(DeviceStatus::Pending.as_str())
    .bind(now())
    .fetch_optional(&st.pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let client_app_id: String = row.get("client_app_id");
    let Some(client) = apps::find(&st.pool, &client_app_id).await? else {
        return Ok(None);
    };
    Ok(Some(Pending {
        user_code: row.get("user_code"),
        client,
        scope: row.get("scope"),
    }))
}

pub async fn deviceauth_get(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Ok(Some(tenant)) = tenant::resolve(&st.pool, &tenant_key).await else {
        return html::error(None, "That sign-in request is not valid.");
    };
    match get(&query, "user_code") {
        // A prefilled code (verification_uri_complete) goes straight on.
        Some(code) => step_after_code(&st, &tenant, &headers, &normalize_user_code(code)).await,
        None => code_entry(&st, &tenant, None, ""),
    }
}

pub async fn deviceauth_post(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Ok(Some(tenant)) = tenant::resolve(&st.pool, &tenant_key).await else {
        return html::error(None, "That sign-in request is not valid.");
    };

    // Double-submit CSRF check, as on the authorize pages.
    let csrf_ok = match (session::cookie(&headers, CSRF_COOKIE), form.get("csrf")) {
        (Some(c), Some(f)) => crate::util::ct_eq(&c, f),
        _ => false,
    };
    if !csrf_ok {
        return code_entry(&st, &tenant, Some("Your session expired. Please try again."), "");
    }

    // `request` carries the user code between steps.
    let user_code = normalize_user_code(
        get(&form, "user_code")
            .or_else(|| get(&form, "request"))
            .unwrap_or_default(),
    );

    match DeviceOp::parse(form.get("op").map(String::as_str)) {
        Some(DeviceOp::Code) => step_after_code(&st, &tenant, &headers, &user_code).await,
        Some(DeviceOp::Login) => match sign_in(&st, &tenant, &headers, &form, &user_code).await {
            Ok(resp) => resp,
            Err(resp) => resp,
        },
        Some(op @ (DeviceOp::MfaVerify | DeviceOp::MfaEnroll | DeviceOp::ChangePassword)) => {
            second_step(&st, &tenant, &headers, &form, &user_code, op).await
        }
        Some(DeviceOp::Approve) => decide(&st, &tenant, &headers, &user_code, DeviceStatus::Approved).await,
        Some(DeviceOp::Deny) => decide(&st, &tenant, &headers, &user_code, DeviceStatus::Denied).await,
        None => code_entry(&st, &tenant, None, &user_code),
    }
}

fn code_entry(st: &AppState, tenant: &Tenant, error: Option<&str>, user_code: &str) -> Response {
    let csrf = session::new_token();
    let mut resp = html::device_code_entry(&html::DeviceCodeForm {
        tenant_name: Some(&tenant.name),
        action: &deviceauth_url(st, &tenant.id),
        csrf: &csrf,
        user_code,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// After a code is supplied: sign in if needed, otherwise ask for approval.
async fn step_after_code(st: &AppState, tenant: &Tenant, headers: &HeaderMap, user_code: &str) -> Response {
    let pending = match load_pending(st, tenant, user_code).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return code_entry(st, tenant, Some("That code is not valid or has expired."), "");
        }
        Err(_) => return html::error(Some(&tenant.name), "Something went wrong. Please try again."),
    };
    match session::find(&st.pool, headers, &tenant.id).await {
        Ok(Some(s)) => {
            if let Err(refused) = gate(st, tenant, &pending, &s.user_id).await {
                return refused;
            }
            match second_step_needed(st, tenant, &pending, &s.user_id, &s.amr).await {
                Some(step) => start_mfa(st, tenant, &pending, &s.user_id, step).await,
                None => approval_page(st, tenant, &pending, &s.user_id).await,
            }
        }
        _ => login_page(st, tenant, &pending, "", None),
    }
}

/// Whether this user may use the client at all ([`access::decide`]); the page
/// saying why not, if not.
async fn gate(st: &AppState, tenant: &Tenant, pending: &Pending, user_id: &str) -> Result<(), Response> {
    let failed = |e: anyhow::Error| html::error(Some(&tenant.name), &AadError::from(e).description());
    let user = users::find_by_id(&st.pool, user_id)
        .await
        .map_err(failed)?
        .ok_or_else(|| login_page(st, tenant, pending, "", None))?;
    let sp = apps::service_principal(&st.pool, &tenant.id, &pending.client.app_id)
        .await
        .map_err(failed)?
        .ok_or_else(|| html::error(Some(&tenant.name), "That application is not available."))?;
    let decision = access::decide(&st.pool, tenant, &sp, &user).await.map_err(failed)?;
    match decision.refusal {
        None => Ok(()),
        Some(refusal) => Err(html::error(
            Some(&tenant.name),
            &format!(
                "AADSTS{}: {}",
                refusal.aadsts().code(),
                refusal.message(&pending.client.display_name, &tenant.name, &decision.home.name)
            ),
        )),
    }
}

/// The second step this user still needs before approving for this client, if
/// any: none once the session has one.
async fn second_step_needed(
    st: &AppState,
    tenant: &Tenant,
    pending: &Pending,
    user_id: &str,
    amr: &[String],
) -> Option<mfa::Step> {
    if amr.iter().any(|m| m == Amr::Mfa.as_str()) {
        return None;
    }
    let sp = apps::service_principal(&st.pool, &tenant.id, &pending.client.app_id)
        .await
        .ok()
        .flatten()?;
    // Their own tenant's MFA rules, for an account of another tenant too.
    let user = users::find_by_id(&st.pool, user_id).await.ok().flatten()?;
    let home = access::home_of(&st.pool, &user).await.ok().flatten()?;
    match mfa::step(&st.pool, &home, user_id, mfa::At::App(&sp)).await {
        Ok(mfa::Step::Done) | Err(_) => None,
        Ok(step) => Some(step),
    }
}

async fn start_mfa(st: &AppState, tenant: &Tenant, pending: &Pending, user_id: &str, step: mfa::Step) -> Response {
    let purpose = if step == mfa::Step::Enroll {
        Purpose::Enroll
    } else {
        Purpose::Verify
    };
    let user = match users::find_by_id(&st.pool, user_id).await {
        Ok(Some(u)) => u,
        _ => return login_page(st, tenant, pending, "", None),
    };
    match mfa::begin(&st.pool, &tenant.id, user_id, purpose).await {
        Ok(ticket) => {
            let secret = if purpose == Purpose::Enroll {
                mfa::pending(&st.pool, &ticket, &tenant.id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.enroll_secret)
            } else {
                None
            };
            mfa_page(
                st,
                tenant,
                pending,
                &user.upn,
                purpose,
                &ticket,
                secret.as_deref(),
                None,
            )
        }
        Err(e) => html::error(Some(&tenant.name), &AadError::from(e).description()),
    }
}

#[allow(clippy::too_many_arguments)]
fn mfa_page(
    st: &AppState,
    tenant: &Tenant,
    pending: &Pending,
    upn: &str,
    purpose: Purpose,
    ticket: &str,
    secret: Option<&str>,
    error: Option<&str>,
) -> Response {
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        html::escape(&pending.user_code)
    );
    let action = deviceauth_url(st, &tenant.id);
    let mut resp = match (purpose, secret) {
        (Purpose::Enroll, Some(secret)) => html::mfa_enroll(&html::MfaEnroll {
            tenant_name: &tenant.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: "op",
            op: html::LoginOp::MfaEnroll.as_str(),
            ticket,
            qr_svg: &mfa::qr_svg(&mfa::otpauth_uri(secret, &tenant.name, upn)),
            secret,
            error,
        }),
        _ => html::mfa_verify(&html::MfaVerify {
            tenant_name: &tenant.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: "op",
            op: html::LoginOp::MfaVerify.as_str(),
            ticket,
            error,
        }),
    };
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

const MFA_EXPIRED: &str = "That sign-in has expired or had too many wrong codes. Please sign in again.";
const MFA_WRONG: &str = "That code didn't work. Check the time on your phone, wait for a new code and try again.";

async fn second_step(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    form: &Params,
    user_code: &str,
    op: DeviceOp,
) -> Response {
    let pending = match load_pending(st, tenant, user_code).await {
        Ok(Some(p)) => p,
        _ => return code_entry(st, tenant, Some("That code is not valid or has expired."), ""),
    };
    let ticket = get(form, html::MFA_TICKET).unwrap_or_default().to_string();
    let typed = get(form, html::MFA_CODE).unwrap_or_default().to_string();
    let Ok(Some(waiting)) = mfa::pending(&st.pool, &ticket, &tenant.id).await else {
        return login_page(st, tenant, &pending, "", Some(MFA_EXPIRED));
    };
    let user = match users::find_by_id(&st.pool, &waiting.user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return login_page(st, tenant, &pending, "", Some(MFA_EXPIRED)),
    };
    let Ok(Some(home)) = access::home_of(&st.pool, &user).await else {
        return login_page(st, tenant, &pending, "", Some(MFA_EXPIRED));
    };
    let fits = match op {
        DeviceOp::MfaEnroll => waiting.purpose == Purpose::Enroll,
        DeviceOp::ChangePassword => {
            matches!(
                waiting.purpose,
                Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa
            )
        }
        _ => waiting.purpose == Purpose::Verify,
    };
    if !fits {
        return login_page(st, tenant, &pending, "", Some(MFA_EXPIRED));
    }
    match waiting.purpose {
        Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa => {
            let new = get(form, html::NEW_PASSWORD).unwrap_or_default();
            let confirm = get(form, html::CONFIRM_PASSWORD).unwrap_or_default();
            let refused = if new != confirm {
                Some("The passwords don't match.".to_string())
            } else {
                users::change_password(&st.pool, &home, &user.id, new, users::PasswordSetBy::User)
                    .await
                    .err()
                    .map(|e| e.to_string())
            };
            if let Some(message) = refused {
                return change_page(st, tenant, &pending, &user.upn, &ticket, Some(&message));
            }
            let _ = mfa::finish(&st.pool, &ticket).await;
            audit::record(
                st,
                &tenant.id,
                Actor::Id(&user.id),
                Event::PasswordChanged,
                Some(&user.id),
                json!({ "via": Channel::Device.as_str() }),
            )
            .await;
            let mut amr = vec![Amr::Pwd.as_str()];
            if waiting.purpose == Purpose::ChangePasswordAfterMfa {
                amr.push(Amr::Mfa.as_str());
            }
            establish(st, tenant, headers, &pending, &user, &amr)
                .await
                .unwrap_or_else(|r| r)
        }
        Purpose::Verify => match mfa::check(&st.pool, &user.id, &typed).await {
            Ok(Some(factor)) => {
                let _ = mfa::finish(&st.pool, &ticket).await;
                audit::record(
                    st,
                    &tenant.id,
                    Actor::Id(&user.id),
                    Event::MfaVerified,
                    Some(&user.id),
                    json!({ "via": Channel::Device.as_str(), "factor": factor.as_str() }),
                )
                .await;
                finish_sign_in(st, tenant, headers, &pending, &user, true)
                    .await
                    .unwrap_or_else(|r| r)
            }
            Ok(None) => {
                super::authorize::wrong_code(st, &tenant.id, &user.id, Channel::Device).await;
                match mfa::failed_attempt(&st.pool, &ticket).await {
                    Ok(true) => mfa_page(
                        st,
                        tenant,
                        &pending,
                        &user.upn,
                        Purpose::Verify,
                        &ticket,
                        None,
                        Some(MFA_WRONG),
                    ),
                    _ => login_page(st, tenant, &pending, "", Some(MFA_EXPIRED)),
                }
            }
            Err(e) => html::error(Some(&tenant.name), &AadError::from(e).description()),
        },
        Purpose::Enroll => {
            let secret = waiting.enroll_secret.unwrap_or_default();
            if !mfa::verify_new(&secret, &typed) {
                return match mfa::failed_attempt(&st.pool, &ticket).await {
                    Ok(true) => mfa_page(
                        st,
                        tenant,
                        &pending,
                        &user.upn,
                        Purpose::Enroll,
                        &ticket,
                        Some(&secret),
                        Some(MFA_WRONG),
                    ),
                    _ => login_page(st, tenant, &pending, "", Some(MFA_EXPIRED)),
                };
            }
            let codes = match mfa::enroll(&st.pool, &user.id, &secret).await {
                Ok(codes) => codes,
                Err(e) => return html::error(Some(&tenant.name), &AadError::from(e).description()),
            };
            let _ = mfa::finish(&st.pool, &ticket).await;
            let _ = users::end_sessions(&st.pool, &user.id).await;
            audit::record(
                st,
                &tenant.id,
                Actor::Id(&user.id),
                Event::MfaEnrolled,
                Some(&user.id),
                json!({ "via": Channel::Device.as_str() }),
            )
            .await;
            let again = format!("{}?user_code={}", deviceauth_url(st, &tenant.id), pending.user_code);
            let mut resp = html::mfa_enrolled(&tenant.name, &codes, &again);
            resp.headers_mut().append(
                header::SET_COOKIE,
                session::clear_cookie(&st.public_url, session::SESSION_COOKIE),
            );
            resp
        }
    }
}

fn login_page(st: &AppState, tenant: &Tenant, pending: &Pending, upn: &str, error: Option<&str>) -> Response {
    let csrf = session::new_token();
    let mut resp = html::login(&html::LoginForm {
        tenant_name: &tenant.name,
        client_name: &pending.client.display_name,
        action: &deviceauth_url(st, &tenant.id),
        csrf: &csrf,
        request: &pending.user_code,
        upn,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

async fn approval_page(st: &AppState, tenant: &Tenant, pending: &Pending, user_id: &str) -> Response {
    let user = match users::find_by_id(&st.pool, user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return login_page(st, tenant, pending, "", None),
    };
    let granted = match scopes::resolve(&st.pool, tenant, &pending.scope).await {
        Ok(grant) => grant.granted,
        Err(_) => Vec::new(),
    };
    let csrf = session::new_token();
    let mut resp = html::device_approval(&html::DeviceApproval {
        tenant_name: &tenant.name,
        client_name: &pending.client.display_name,
        action: &deviceauth_url(st, &tenant.id),
        csrf: &csrf,
        request: &pending.user_code,
        user_code: &pending.user_code,
        upn: &user.upn,
        scopes: &granted,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

async fn sign_in(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    form: &Params,
    user_code: &str,
) -> Result<Response, Response> {
    let pending = match load_pending(st, tenant, user_code).await {
        Ok(Some(p)) => p,
        _ => {
            return Err(code_entry(
                st,
                tenant,
                Some("That code is not valid or has expired."),
                "",
            ));
        }
    };
    let upn = get(form, "upn").unwrap_or_default();
    let password = get(form, "password").unwrap_or_default();
    let sp = apps::service_principal(&st.pool, &tenant.id, &pending.client.app_id)
        .await
        .ok()
        .flatten();
    let (outcome, trace) = match access::authenticate(&st.pool, tenant, sp.as_ref(), upn, password).await {
        Ok(o) => o,
        Err(e) => return Err(html::error(Some(&tenant.name), &AadError::from(e).description())),
    };
    audit::sign_in_failure(
        st,
        &tenant.id,
        upn,
        &outcome,
        &trace,
        Channel::Device,
        &pending.client.app_id,
    )
    .await;
    let user = match outcome {
        AuthResult::Ok(user) => user,
        AuthResult::InvalidCredentials => {
            let hint = tenant::not_ours_hint(
                &st.pool,
                tenant,
                upn,
                sp.as_ref().is_some_and(|sp| sp.accept_other_tenants),
            )
            .await;
            return Err(login_page(
                st,
                tenant,
                &pending,
                upn,
                Some(
                    hint.as_deref()
                        .unwrap_or("Your account or password is incorrect. (AADSTS50126)"),
                ),
            ));
        }
        AuthResult::Locked => {
            return Err(login_page(
                st,
                tenant,
                &pending,
                upn,
                Some("Your account is temporarily locked. (AADSTS50053)"),
            ));
        }
        AuthResult::Disabled => {
            return Err(login_page(
                st,
                tenant,
                &pending,
                upn,
                Some("Your account has been disabled. (AADSTS50057)"),
            ));
        }
    };

    gate(st, tenant, &pending, &user.id).await?;
    // A second step, where one is needed, before there is any session.
    if let Some(step) = second_step_needed(st, tenant, &pending, &user.id, &[]).await {
        return Ok(start_mfa(st, tenant, &pending, &user.id, step).await);
    }
    finish_sign_in(st, tenant, headers, &pending, &user, false).await
}

/// After the password (and second factor, if any): a new password first if the
/// account must choose one, then the session and the approval page.
async fn finish_sign_in(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    pending: &Pending,
    user: &users::User,
    after_mfa: bool,
) -> Result<Response, Response> {
    if users::must_change_password(&st.pool, &user.id).await.unwrap_or(false) {
        return match mfa::begin(&st.pool, &tenant.id, &user.id, Purpose::change_password(after_mfa)).await {
            Ok(ticket) => Ok(change_page(st, tenant, pending, &user.upn, &ticket, None)),
            Err(e) => Err(html::error(Some(&tenant.name), &AadError::from(e).description())),
        };
    }
    let amr: &[&str] = if after_mfa {
        &[Amr::Pwd.as_str(), Amr::Mfa.as_str()]
    } else {
        &[Amr::Pwd.as_str()]
    };
    establish(st, tenant, headers, pending, user, amr).await
}

fn change_page(
    st: &AppState,
    tenant: &Tenant,
    pending: &Pending,
    upn: &str,
    ticket: &str,
    error: Option<&str>,
) -> Response {
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        html::escape(&pending.user_code)
    );
    let mut resp = html::change_password(&html::ChangePassword {
        tenant_name: &tenant.name,
        upn,
        action: &deviceauth_url(st, &tenant.id),
        hidden: &hidden,
        op_field: "op",
        op: html::LoginOp::ChangePassword.as_str(),
        ticket,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// Start a browser session for the signed-in user and show the approval page.
async fn establish(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    pending: &Pending,
    user: &users::User,
    amr: &[&str],
) -> Result<Response, Response> {
    // Start a browser session so the next code does not ask again.
    let lifetime = tenant.settings.session_lifetime_secs;
    let cookie = session::create(&st.pool, headers, &tenant.id, &user.id, amr, lifetime)
        .await
        .map_err(|e| html::error(Some(&tenant.name), &AadError::from(e).description()))?;
    let details = json!({ "via": Channel::Device.as_str(), "clientId": pending.client.app_id });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user.id),
        Event::SignIn,
        Some(&user.id),
        details,
    )
    .await;
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user.id),
        Event::SessionCreate,
        Some(&user.id),
        json!({}),
    )
    .await;

    // Show the approval page as the newly signed-in user.
    let mut headers = headers.clone();
    if session::cookie(&headers, session::SESSION_COOKIE).as_deref() != Some(cookie.as_str()) {
        headers.append(
            header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("{}={cookie}", session::SESSION_COOKIE)).expect("ascii"),
        );
    }
    let mut resp = approval_page(st, tenant, pending, &user.id).await;
    let h = resp.headers_mut();
    h.append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, session::SESSION_COOKIE, &cookie, lifetime),
    );
    Ok(resp)
}

async fn decide(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    user_code: &str,
    status: DeviceStatus,
) -> Response {
    let pending = match load_pending(st, tenant, user_code).await {
        Ok(Some(p)) => p,
        _ => return code_entry(st, tenant, Some("That code is not valid or has expired."), ""),
    };
    let Ok(Some(s)) = session::find(&st.pool, headers, &tenant.id).await else {
        return login_page(st, tenant, &pending, "", None);
    };
    if status == DeviceStatus::Approved
        && let Err(refused) = gate(st, tenant, &pending, &s.user_id).await
    {
        return refused;
    }
    if status == DeviceStatus::Approved
        && let Some(step) = second_step_needed(st, tenant, &pending, &s.user_id, &s.amr).await
    {
        return start_mfa(st, tenant, &pending, &s.user_id, step).await;
    }
    let client_id = pending.client.app_id.as_str();
    if status == DeviceStatus::Denied {
        let denied = sqlx::query(crate::db::q(
            &st.pool,
            "UPDATE device_codes SET status = ? WHERE user_code = ? AND tenant_id = ?",
        ))
        .bind(DeviceStatus::Denied.as_str())
        .bind(&pending.user_code)
        .bind(&tenant.id)
        .execute(&st.pool)
        .await;
        if denied.is_ok_and(|r| r.rows_affected() > 0) {
            let details = json!({ "clientId": client_id });
            audit::record(
                st,
                &tenant.id,
                Actor::Id(&s.user_id),
                Event::DeviceDenied,
                None,
                details,
            )
            .await;
        }
        return html::device_result(
            Some(&tenant.name),
            "Sign-in cancelled",
            "You can close this window and return to your device.",
        );
    }
    let amr = serde_json::to_string(&s.amr).unwrap_or_else(|_| "[]".into());
    let updated = sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE device_codes SET status = ?, user_id = ?, auth_time = ?, amr = ?
         WHERE user_code = ? AND tenant_id = ? AND status = ?",
    ))
    .bind(DeviceStatus::Approved.as_str())
    .bind(&s.user_id)
    .bind(s.auth_time)
    .bind(amr)
    .bind(&pending.user_code)
    .bind(&tenant.id)
    .bind(DeviceStatus::Pending.as_str())
    .execute(&st.pool)
    .await;
    match updated {
        Ok(r) if r.rows_affected() == 1 => {
            let details = json!({ "clientId": client_id });
            audit::record(
                st,
                &tenant.id,
                Actor::Id(&s.user_id),
                Event::DeviceApproved,
                None,
                details,
            )
            .await;
            html::device_result(
                Some(&tenant.name),
                "You're all set",
                "You can close this window and return to your device.",
            )
        }
        _ => code_entry(st, tenant, Some("That code is not valid or has expired."), ""),
    }
}

// ---- grant: urn:ietf:params:oauth:grant-type:device_code ----

/// Redeem a device code. Public clients poll without a secret, so the device
/// code itself is the credential; a confidential client still has to prove it.
pub(super) async fn device_code_grant(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Response, AadError> {
    let device_code = get(params, "device_code").ok_or_else(|| AadError::missing_parameter("device_code"))?;
    let client_id = get(params, "client_id").ok_or_else(|| AadError::missing_parameter("client_id"))?;
    let hash = sha256_hex(device_code.as_bytes());

    let bad_code = || {
        AadError::invalid_grant(
            Aadsts::DeviceCodeInvalidOrRedeemed,
            "AADSTS70018: Invalid verification code due to an invalid or already redeemed device code.",
        )
    };

    let row = sqlx::query(crate::db::q(
        &st.pool,
        "SELECT user_code, client_app_id, scope, status, user_id, auth_time, amr,
                interval_secs, expires_at, last_polled_at, redeemed_at
         FROM device_codes WHERE device_code_hash = ? AND tenant_id = ?",
    ))
    .bind(&hash)
    .bind(&tenant.id)
    .fetch_optional(&st.pool)
    .await?;
    let row = row.ok_or_else(bad_code)?;

    let client_app_id: String = row.get("client_app_id");
    if !client_app_id.eq_ignore_ascii_case(client_id) {
        return Err(bad_code());
    }
    if row.get::<Option<i64>, _>("redeemed_at").is_some() {
        return Err(bad_code());
    }
    let ts = now();
    if row.get::<i64, _>("expires_at") <= ts {
        return Err(AadError::device_code_expired());
    }

    // Rate-limit polling, as RFC 8628 requires.
    let interval: i64 = row.get("interval_secs");
    let too_fast = row
        .get::<Option<i64>, _>("last_polled_at")
        .is_some_and(|last| ts - last < interval);
    sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE device_codes SET last_polled_at = ? WHERE device_code_hash = ?",
    ))
    .bind(ts)
    .bind(&hash)
    .execute(&st.pool)
    .await?;

    let status = DeviceStatus::parse(row.get::<String, _>("status").as_str()).ok_or_else(bad_code)?;
    match status {
        DeviceStatus::Denied => return Err(AadError::authorization_declined()),
        DeviceStatus::Pending => {
            return Err(if too_fast {
                AadError::slow_down()
            } else {
                AadError::authorization_pending()
            });
        }
        DeviceStatus::Approved => {}
    }

    // Approved: claim the code before issuing, so a racing poll cannot reuse it.
    let claimed = sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE device_codes SET redeemed_at = ? WHERE device_code_hash = ? AND redeemed_at IS NULL",
    ))
    .bind(ts)
    .bind(&hash)
    .execute(&st.pool)
    .await?;
    if claimed.rows_affected() != 1 {
        return Err(bad_code());
    }

    let user_id: String = row.get::<Option<String>, _>("user_id").ok_or_else(bad_code)?;
    let details = json!({ "clientId": client_app_id });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user_id),
        Event::DeviceRedeemed,
        None,
        details,
    )
    .await;
    let scope: String = row.get("scope");
    let auth_time: i64 = row.get::<Option<i64>, _>("auth_time").unwrap_or(ts);
    let amr: Vec<String> = row
        .get::<Option<String>, _>("amr")
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| vec![Amr::Pwd.as_str().to_string()]);
    let grant = scopes::resolve(&st.pool, tenant, &scope).await?;

    super::user_grants::issue(
        st,
        tenant,
        headers,
        params,
        &client_app_id,
        &user_id,
        &grant,
        None,
        crate::claims::Azpacr::None,
        super::user_grants::Family {
            id: b64url(&random_bytes(16)),
            code_hash: Some(hash),
            platform: apps::RedirectPlatform::PublicClient,
            auth_time,
            amr,
            spa_expires_at: None,
            rotation: false,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert(pool: &crate::db::DbPool, tenant: &str, hash: &str, expires_at: i64) {
        sqlx::query(crate::db::q(
            pool,
            "INSERT INTO device_codes (device_code_hash, user_code, tenant_id, client_app_id, scope, status,
                                       interval_secs, created_at, expires_at)
             VALUES (?, ?, ?, 'app', 'openid', 'pending', 5, 0, ?)",
        ))
        .bind(hash)
        .bind(hash)
        .bind(tenant)
        .bind(expires_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn hashes(pool: &crate::db::DbPool) -> Vec<String> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT device_code_hash FROM device_codes ORDER BY device_code_hash")
                .fetch_all(pool)
                .await
                .unwrap();
        rows.into_iter().map(|r| r.0).collect()
    }

    #[tokio::test]
    async fn prune_removes_long_expired_codes_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::db::connect(&format!("sqlite://{}", dir.path().join("t.db").display()))
            .await
            .unwrap();
        let t = crate::tenant::create(&pool, "Contoso", "contoso.test", false)
            .await
            .unwrap();
        let ts = 1_000_000;
        insert(&pool, &t.id, "old", ts - DEVICE_CODE_RETENTION - 1).await;
        insert(&pool, &t.id, "just-expired", ts - 1).await;
        insert(&pool, &t.id, "live", ts + DEVICE_CODE_LIFETIME).await;

        assert_eq!(prune_expired(&pool, ts).await.unwrap(), 1);
        assert_eq!(hashes(&pool).await, ["just-expired", "live"]);
        assert_eq!(prune_expired(&pool, ts).await.unwrap(), 0, "idempotent");
        // Once past the retention window the recently expired code goes too; the live one never does.
        assert_eq!(prune_expired(&pool, ts + DEVICE_CODE_RETENTION).await.unwrap(), 1);
        assert_eq!(hashes(&pool).await, ["live"]);
    }
}
