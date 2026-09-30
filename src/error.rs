//! Protocol errors in Entra ID's wire format:
//!
//! ```json
//! { "error": "invalid_client",
//!   "error_description": "AADSTS7000215: Invalid client secret provided. ... Trace ID: ... Correlation ID: ... Timestamp: ...",
//!   "error_codes": [7000215], "timestamp": "2026-09-29 10:00:00Z",
//!   "trace_id": "...", "correlation_id": "..." }
//! ```

use axum::Json;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::util::new_guid;

const TIMESTAMP: &[FormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]Z");

#[derive(Debug)]
pub struct AadError {
    pub status: StatusCode,
    pub error: &'static str,
    pub code: u32,
    pub message: String,
    pub correlation_id: Option<String>,
    /// Seconds for the `Retry-After` header. Only a throttled response sets it.
    pub retry_after: Option<u64>,
}

impl AadError {
    pub fn new(status: StatusCode, error: &'static str, code: u32, message: impl Into<String>) -> Self {
        Self {
            status,
            error,
            code,
            message: message.into(),
            correlation_id: None,
            retry_after: None,
        }
    }

    /// Echo the caller's `client-request-id` header, as Entra does.
    pub fn correlate(mut self, headers: &HeaderMap) -> Self {
        self.correlation_id = client_request_id(headers);
        self
    }

    pub fn missing_parameter(name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            900144,
            format!("The request body must contain the following parameter: '{name}'."),
        )
    }

    pub fn invalid_request(code: u32, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", code, message)
    }

    pub fn tenant_not_found(tenant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_tenant",
            90002,
            format!(
                "Tenant '{tenant}' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud."
            ),
        )
    }

    pub fn unsupported_grant_type(grant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            70003,
            format!("The app requested an unsupported grant type '{grant}'."),
        )
    }

    pub fn app_not_found(app_id: &str, tenant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            700016,
            format!(
                "Application with identifier '{app_id}' was not found in the directory '{tenant}'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant."
            ),
        )
    }

    pub fn app_disabled(app_id: &str, name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            7000112,
            format!("Application '{app_id}'({name}) is disabled."),
        )
    }

    pub fn missing_client_credential() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            7000218,
            "The request body must contain the following parameter: 'client_assertion' or 'client_secret'.",
        )
    }

    pub fn invalid_client_secret(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            7000215,
            format!(
                "Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '{app_id}'."
            ),
        )
    }

    pub fn expired_client_secret(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            7000222,
            format!("The provided client secret keys for app '{app_id}' are expired."),
        )
    }

    /// A client assertion that is malformed, wrongly targeted, expired, or not
    /// signed by a certificate registered on the app. Deliberately one error for
    /// all of these, so a caller cannot probe which part was wrong.
    pub fn invalid_client_assertion() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            700027,
            "AADSTS700027: The client assertion is not valid. Check that it is signed with a certificate registered on the application, names the application as both issuer and subject, targets this token endpoint as its audience, and has not expired.",
        )
    }

    pub fn replayed_client_assertion() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            700028,
            "AADSTS700028: The client assertion has already been used. Each assertion must carry a unique 'jti'.",
        )
    }

    pub fn expired_client_certificate(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            700024,
            format!("The certificate credential used by app '{app_id}' is outside its validity period."),
        )
    }

    /// The assertion presented to the on-behalf-of grant is not a user token this
    /// server issued for the calling application.
    pub fn invalid_obo_assertion() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            500133,
            "AADSTS500133: The assertion is not valid for the on-behalf-of flow. It must be an unexpired user access token issued by this service whose audience is the calling application.",
        )
    }

    /// ROPC attempted against an app that has not been opted in.
    pub fn password_grant_not_allowed(app_id: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            700034,
            format!(
                "The resource owner password credentials grant is not enabled for application '{app_id}'. Enable it deliberately, or use the authorization code flow instead."
            ),
        )
    }

    pub fn invalid_scope(code: u32, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", code, message)
    }

    pub fn resource_not_found(resource: &str, tenant_name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_resource",
            500011,
            format!(
                "The resource principal named {resource} was not found in the tenant named {tenant_name}. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have sent your authentication request to the wrong tenant."
            ),
        )
    }

    // ---- device authorization grant (RFC 8628) polling responses ----

    /// The user has not finished signing in yet; the device should keep polling.
    pub fn authorization_pending() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            70016,
            "AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling.",
        )
    }

    /// The device polled faster than the advertised interval.
    pub fn slow_down() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "slow_down",
            70016,
            "AADSTS70016: OAuth 2.0 device flow error. Polling too frequently. Wait for the interval before retrying.",
        )
    }

    /// The user declined on the approval page.
    pub fn authorization_declined() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "authorization_declined",
            70017,
            "AADSTS70017: OAuth 2.0 device flow error. The end user denied the authorization request.",
        )
    }

    /// The device code lived longer than its lifetime.
    pub fn device_code_expired() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
            70019,
            "AADSTS70019: Verification code expired. The user did not complete sign-in in time; restart the flow.",
        )
    }

    pub fn invalid_grant(code: u32, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", code, message)
    }

    /// `error_description` for redirects and error pages:
    /// `AADSTS{code}: {message} Trace ID: ... Correlation ID: ... Timestamp: ...`
    pub fn description(&self) -> String {
        let timestamp = time::OffsetDateTime::now_utc().format(TIMESTAMP).unwrap_or_default();
        let correlation_id = self.correlation_id.clone().unwrap_or_else(new_guid);
        format!(
            "AADSTS{}: {} Trace ID: {} Correlation ID: {correlation_id} Timestamp: {timestamp}",
            self.code,
            self.message,
            new_guid()
        )
    }

    /// Too many requests on one of the buckets in [`crate::ratelimit`].
    ///
    /// The observable shape follows Entra: `429 Too Many Requests` with a
    /// `Retry-After` header (learn.microsoft.com, "Understanding client and
    /// server throttling in MSAL.NET", fetched 30 Sep 2026), which is what MSAL
    /// already knows how to handle.
    ///
    /// `temporarily_unavailable` is Entra's own documented code for this
    /// condition: its token-endpoint and authorize-endpoint error tables both
    /// list it as "The server is temporarily too busy to handle the request"
    /// (v2-oauth2-auth-code-flow, fetched 30 Sep 2026).
    ///
    /// The AADSTS **number** is not verified. 90055 is Entra's
    /// `TenantThrottlingError` ("There are too many incoming requests"), whose
    /// first sentence is quoted here, but its documented cause (a blocked
    /// tenant) is narrower than this, and Entra does not say which number
    /// accompanies its 429. Same caveat as AADSTS700054 — see
    /// `docs/decisions-log.md`.
    pub fn throttled(retry_after: crate::ratelimit::RetryAfter) -> Self {
        let mut err = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            90055,
            "There are too many incoming requests. Retry after the interval in the Retry-After header.",
        );
        err.retry_after = Some(retry_after.0);
        err
    }

    pub fn server_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            50000,
            "There was an error issuing a token or an issue with our sign-in service.",
        )
    }
}

impl From<anyhow::Error> for AadError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(error = ?err, "internal error");
        Self::server_error()
    }
}

impl From<sqlx::Error> for AadError {
    fn from(err: sqlx::Error) -> Self {
        anyhow::Error::from(err).into()
    }
}

impl IntoResponse for AadError {
    fn into_response(self) -> Response {
        let trace_id = new_guid();
        let correlation_id = self.correlation_id.clone().unwrap_or_else(new_guid);
        let timestamp = time::OffsetDateTime::now_utc().format(TIMESTAMP).unwrap_or_default();
        let body = json!({
            "error": self.error,
            "error_description": format!(
                "AADSTS{}: {} Trace ID: {trace_id} Correlation ID: {correlation_id} Timestamp: {timestamp}",
                self.code, self.message
            ),
            "error_codes": [self.code],
            "timestamp": timestamp,
            "trace_id": trace_id,
            "correlation_id": correlation_id,
        });
        let mut resp = (self.status, Json(body)).into_response();
        let headers = resp.headers_mut();
        no_store(headers);
        if let Ok(v) = HeaderValue::from_str(&trace_id) {
            headers.insert("x-ms-request-id", v);
        }
        if let Some(id) = self.correlation_id.and_then(|c| HeaderValue::from_str(&c).ok()) {
            headers.insert("client-request-id", id);
        }
        if let Some(secs) = self.retry_after {
            headers.insert(axum::http::header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}

pub fn client_request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("client-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_string)
}

pub fn no_store(headers: &mut HeaderMap) {
    headers.insert("cache-control", HeaderValue::from_static("no-store, no-cache"));
    headers.insert("pragma", HeaderValue::from_static("no-cache"));
}
