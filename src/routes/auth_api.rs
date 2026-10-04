//! `POST /{tenant}/api/v1/authenticate`: the Auth API's credential check.
//!
//! An application holding the [`AuthApiPermission::CredentialsVerify`]
//! permission (granted by an administrator, see [`crate::auth_api`]) sends a
//! user's name, password and authenticator code, and learns whether they are
//! right; on success it also gets the user's profile, groups and the roles they
//! hold on the calling application. For login prompts that cannot run a browser
//! flow, such as Linux PAM.
//!
//! The caller authenticates with an app-only access token for the Auth API
//! (client credentials, `{AUTH_API_APP_ID}/.default`).
//!
//! What it never does:
//!
//! - **Check a user not assigned to the calling application**, directly or
//!   through a group. Checked before the password, so an application cannot even
//!   move the lockout counter of a user it has no business with.
//! - **Accept a password alone.** The user must have an authenticator and send a
//!   fresh code from it; a recovery code is refused. Without this the endpoint
//!   would confirm passwords.
//! - **Say why a check failed.** Every failure about the user is the same answer,
//!   byte for byte, so the endpoint cannot be used to learn which accounts exist,
//!   which are disabled, or whether a password was right. The reason goes to the
//!   audit log.
//!
//! Wrong passwords count toward the account's lockout, as at sign-in. Checks are
//! limited per calling application and per account ([`Limit::CredentialCheck`],
//! [`Limit::CredentialCheckAccount`]).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::apps::{self, Application, ServicePrincipal};
use crate::auth_api::{AUTH_API_APP_ID, AuthApiPermission};
use crate::claims::{Acr, Amr, IdType};
use crate::db::{Actor, Event};
use crate::error::AadError;
use crate::ratelimit::{Hit, Limit, app_key};
use crate::routes::audit::{self, Channel, SignInReason, clip};
use crate::tenant::{self, Tenant};
use crate::users::{self, AuthResult, User};

/// The one answer to every failed check about the user.
const FAILED_CODE: &str = "invalid_credentials";
const FAILED_MESSAGE: &str = "The user name, password or code is not valid.";

/// What the caller sends.
#[derive(Deserialize)]
struct Check {
    upn: String,
    password: String,
    otp: String,
}

fn caller_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// RFC 6750: a missing or bad token is 401 with a challenge.
fn invalid_token(description: &str) -> Response {
    let mut resp = caller_error(StatusCode::UNAUTHORIZED, "invalid_token", description);
    let challenge = format!(r#"Bearer error="invalid_token", error_description="{description}""#);
    if let Ok(v) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// RFC 6750: a good token without the permission is 403.
fn not_permitted() -> Response {
    caller_error(
        StatusCode::FORBIDDEN,
        "insufficient_scope",
        "The application does not hold the Auth API permission Credentials.Verify.",
    )
}

fn failed() -> Response {
    Json(json!({ "result": false, "code": FAILED_CODE, "msg": FAILED_MESSAGE })).into_response()
}

/// The calling application, from its access token: for the Auth API, of this
/// tenant, an application (not a user), holding Credentials.Verify both in the
/// token and still now.
async fn caller(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> Result<(Application, ServicePrincipal), Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::trim)
        .ok_or_else(|| {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            resp
        })?;
    let claims = st
        .keys
        .verify(token)
        .await
        .map_err(|_| invalid_token("The access token is invalid or expired."))?;
    let claim = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or_default();
    if claim("aud") != AUTH_API_APP_ID || claim("idtyp") != IdType::App.as_str() {
        return Err(invalid_token(
            "The access token was not issued to an application for the Auth API.",
        ));
    }
    if claim("tid") != tenant.id || claim("iss") != st.public_url.issuer(&tenant.id) {
        return Err(invalid_token("The access token was issued for another tenant."));
    }
    let permission = AuthApiPermission::CredentialsVerify;
    let in_token = claims
        .get("roles")
        .and_then(Value::as_array)
        .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some(permission.as_str())));
    if !in_token {
        return Err(not_permitted());
    }
    let app = apps::find_in_tenant(&st.pool, tenant, claim("azp"))
        .await
        .map_err(|_| invalid_token("The calling application no longer exists."))?;
    let sp = match apps::service_principal(&st.pool, &tenant.id, &app.app_id).await {
        Ok(Some(sp)) if sp.enabled => sp,
        Ok(_) => return Err(invalid_token("The calling application is disabled.")),
        Err(e) => return Err(AadError::from(e).into_response()),
    };
    // The grant is checked on every call, so revoking it stops the application
    // at once rather than when its token expires.
    match crate::auth_api::holds(&st.pool, &sp.id, permission).await {
        Ok(true) => Ok((app, sp)),
        Ok(false) => Err(not_permitted()),
        Err(e) => Err(AadError::from(e).into_response()),
    }
}

/// Record a failure that happened after the account resolved.
async fn record_failure(st: &AppState, tenant: &Tenant, user: &User, app: &Application, reason: SignInReason) {
    let details = json!({
        "reason": reason.as_str(),
        "via": Channel::AuthApi.as_str(),
        "clientId": app.app_id,
        "upn": clip(&user.upn),
    });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user.id),
        Event::SignInFailed,
        Some(&user.id),
        details,
    )
    .await;
}

pub async fn authenticate(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tenant = match tenant::resolve(&st.pool, &tenant_key).await {
        Ok(Some(t)) => t,
        Ok(None) => return caller_error(StatusCode::NOT_FOUND, "invalid_tenant", "There is no such tenant."),
        Err(e) => return AadError::from(e).into_response(),
    };
    let (app, sp) = match caller(&st, &tenant, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    // Per calling application: it has authenticated, so a refusal tells it
    // nothing about any user.
    match st.limits.hit(Limit::CredentialCheck, &app_key(&tenant.id, &app.app_id)) {
        Hit::Under => {}
        Hit::Reached => audit::throttled(&st, &tenant.id, Some(&app.app_id), Limit::CredentialCheck).await,
        Hit::AlreadyOver(retry) => return AadError::throttled(retry).into_response(),
    }
    let Ok(check) = serde_json::from_slice::<Check>(&body) else {
        return caller_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The body must be a JSON object with the strings upn, password and otp.",
        );
    };
    match verify(&st, &tenant, &app, &sp, &check).await {
        Ok(Some(user)) => succeeded(&st, &tenant, &app, &sp, &user).await,
        Ok(None) => failed(),
        Err(e) => AadError::from(e).into_response(),
    }
}

/// The checks, in order. `None` is a failure, already recorded.
async fn verify(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    sp: &ServicePrincipal,
    check: &Check,
) -> anyhow::Result<Option<User>> {
    // Who it names, before any password is weighed.
    if let Some(user) = users::find_by_upn(&st.pool, &tenant.id, &check.upn).await? {
        // Per account: only real accounts have a bucket. Tripping it keeps the
        // generic answer, or the limit would say which accounts exist.
        if st.limits.check(Limit::CredentialCheckAccount, &user.id).is_some() {
            record_failure(st, tenant, &user, app, SignInReason::Throttled).await;
            return Ok(None);
        }
        if let Hit::Reached = st.limits.hit(Limit::CredentialCheckAccount, &user.id) {
            audit::throttled(st, &tenant.id, Some(&app.app_id), Limit::CredentialCheckAccount).await;
        }
        if !apps::user_is_assigned(&st.pool, &sp.id, &user.id).await? {
            record_failure(st, tenant, &user, app, SignInReason::NotAssigned).await;
            return Ok(None);
        }
        if crate::mfa::enrolled_at(&st.pool, &user.id).await?.is_none() {
            record_failure(st, tenant, &user, app, SignInReason::NoAuthenticator).await;
            return Ok(None);
        }
    }
    // The password, held to lockout as at sign-in. An unknown name is checked
    // too (against a dummy hash), so it takes as long as a known one.
    let (result, trace) = users::authenticate_traced(&st.pool, tenant, &check.upn, &check.password).await?;
    let user = match result {
        AuthResult::Ok(user) => user,
        other => {
            audit::sign_in_failure(
                st,
                &tenant.id,
                &check.upn,
                &other,
                &trace,
                Channel::AuthApi,
                &app.app_id,
            )
            .await;
            return Ok(None);
        }
    };
    if users::must_change_password(&st.pool, &user.id).await? {
        record_failure(st, tenant, &user, app, SignInReason::MustChangePassword).await;
        return Ok(None);
    }
    if !crate::mfa::check_authenticator_code(&st.pool, &user.id, &check.otp).await? {
        record_failure(st, tenant, &user, app, SignInReason::BadCode).await;
        return Ok(None);
    }
    Ok(Some(user))
}

async fn succeeded(st: &AppState, tenant: &Tenant, app: &Application, sp: &ServicePrincipal, user: &User) -> Response {
    let groups = match crate::groups::for_user(&st.pool, &user.id).await {
        Ok(g) => g,
        Err(e) => return AadError::from(e).into_response(),
    };
    let roles = match apps::app_roles_for_user(&st.pool, &sp.id, &user.id).await {
        Ok(r) => r,
        Err(e) => return AadError::from(e).into_response(),
    };
    let details = json!({ "via": Channel::AuthApi.as_str(), "clientId": app.app_id });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user.id),
        Event::SignIn,
        Some(&user.id),
        details,
    )
    .await;
    let amr = [Amr::Pwd.as_str(), Amr::Mfa.as_str()];
    Json(json!({
        "result": true,
        "oid": user.id,
        "tid": tenant.id,
        "preferred_username": user.upn,
        "name": user.display_name.clone().unwrap_or_else(|| user.upn.clone()),
        "given_name": user.given_name,
        "family_name": user.family_name,
        "email": user.email,
        "groups": groups.iter().map(|g| json!({ "id": g.id, "name": g.name })).collect::<Vec<_>>(),
        "app_roles": roles.iter().map(|r| json!({ "id": r.id, "value": r.value })).collect::<Vec<_>>(),
        "amr": amr,
        "acr": Acr::Mfa.as_str(),
    }))
    .into_response()
}
