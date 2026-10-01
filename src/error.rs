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

/// The `error` value of an OAuth 2.0 / OIDC error response.
///
/// Entra's own set. Its authorize-endpoint and token-endpoint error tables
/// (v2-oauth2-auth-code-flow, fetched 30 Sep 2026) list `invalid_request`,
/// `unauthorized_client`, `access_denied`, `unsupported_response_type`,
/// `server_error`, `temporarily_unavailable`, `invalid_resource`,
/// `login_required`, `interaction_required`, `invalid_grant`, `invalid_client`,
/// `unsupported_grant_type`, `consent_required` and `invalid_scope`. The
/// device-flow polling values are RFC 8628's, which Entra implements.
///
/// Only the values this server actually emits are here: adding one it never
/// sends would be a list of aspirations rather than a description of the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    /// Entra's extension, not in RFC 6749.
    InvalidResource,
    /// Entra's extension: the tenant in the path does not exist.
    InvalidTenant,
    /// **Entra's spelling, not the RFC's.** RFC 6749 says
    /// `unsupported_response_type`; Entra's implicit-flow documentation says
    /// `unsupported_response`, and we follow Entra (decision 10).
    UnsupportedResponse,
    AccessDenied,
    LoginRequired,
    RequestNotSupported,
    RequestUriNotSupported,
    ServerError,
    /// Entra's documented code for "the server is temporarily too busy to handle
    /// the request", which is what our rate limiter means.
    TemporarilyUnavailable,
    // -- RFC 8628 device authorization grant polling --
    AuthorizationPending,
    /// Entra's spelling. RFC 8628 says `access_denied` for a declined request;
    /// Entra returns `authorization_declined` and so do we.
    AuthorizationDeclined,
    SlowDown,
    ExpiredToken,
}

impl OAuthError {
    pub const ALL: &'static [OAuthError] = &[
        Self::InvalidRequest,
        Self::InvalidClient,
        Self::InvalidGrant,
        Self::UnauthorizedClient,
        Self::UnsupportedGrantType,
        Self::InvalidScope,
        Self::InvalidResource,
        Self::InvalidTenant,
        Self::UnsupportedResponse,
        Self::AccessDenied,
        Self::LoginRequired,
        Self::RequestNotSupported,
        Self::RequestUriNotSupported,
        Self::ServerError,
        Self::TemporarilyUnavailable,
        Self::AuthorizationPending,
        Self::AuthorizationDeclined,
        Self::SlowDown,
        Self::ExpiredToken,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidResource => "invalid_resource",
            Self::InvalidTenant => "invalid_tenant",
            Self::UnsupportedResponse => "unsupported_response",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::AuthorizationPending => "authorization_pending",
            Self::AuthorizationDeclined => "authorization_declined",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
        }
    }
}

/// Every AADSTS number this server puts in `error_codes` and in the
/// `AADSTS{n}:` prefix of `error_description`.
///
/// Entra pairs a number with each failure, and clients, log searches and
/// Microsoft's own support articles are written against the numbers, so they are
/// part of the wire contract, not decoration. Collected here so the set is
/// visible in one place, so a number cannot be reused for two unrelated
/// conditions by accident, and so the ones that are **our guess** rather than a
/// verified Entra pairing are marked as such instead of looking equally
/// authoritative in a call site.
///
/// Two conditions share 70016 on purpose: Entra's 70016 is the whole device-flow
/// error family ("OAuth 2.0 device flow error"), which covers both
/// `authorization_pending` and `slow_down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aadsts {
    // ---- request shape ----
    /// A required parameter is missing or a parameter is not a valid value.
    MissingOrInvalidParameter,
    /// A parameter we do not support was supplied (`request`, `request_uri`), or
    /// `prompt`/`max_age` was not a value we accept.
    UnsupportedParameter,
    /// `code_challenge_method` was not `S256` or `plain`.
    InvalidCodeChallenge,
    /// A SPA redeeming a code must use PKCE.
    PkceRequired,
    /// `code_verifier` did not match the stored `code_challenge`.
    CodeVerifierMismatch,
    /// A request arrived with an `Origin` header on a non-SPA client.
    CrossOriginNotPermitted,
    /// A SPA's grant was redeemed without an `Origin` header.
    SpaRequiresCrossOrigin,
    /// The authorization code or refresh token could not be found or parsed.
    MalformedRequest,
    /// A `scope` naming more than one resource.
    MultipleResourcesInScope,
    /// A client-credentials `scope` without the `/.default` suffix.
    DefaultScopeRequired,

    // ---- tenant and application ----
    TenantNotFound,
    ApplicationNotFound,
    ApplicationDisabled,
    /// The `redirect_uri` is not one registered on the application.
    RedirectUriMismatch,
    /// A grant issued in one tenant was presented to another.
    WrongTenantForGrant,
    /// The grant was issued to a different client than the one presenting it.
    GrantIssuedToDifferentClient,

    // ---- client authentication ----
    MissingClientCredential,
    InvalidClientSecret,
    ExpiredClientSecret,
    InvalidClientAssertion,
    ReplayedClientAssertion,
    ExpiredClientCertificate,
    /// Both `client_secret_basic` and `client_secret_post` were presented.
    MultipleClientAuthMethods,
    /// `client_assertion_type` was not the RFC 7523 JWT bearer URN.
    UnsupportedAssertionType,

    // ---- user authentication ----
    /// Wrong username or password. Never distinguishes the two.
    InvalidUsernameOrPassword,
    AccountLocked,
    AccountDisabled,
    /// `prompt=none` but nobody is signed in.
    SilentSignInFailed,
    /// The app requires assignment and this user has none.
    NotAssigned,
    /// The user pressed Deny on the consent page. **Our guess**: 65004 is the
    /// number Entra documents for a declined consent, not verified against a
    /// live tenant.
    ConsentDeclined,

    // ---- grants ----
    UnsupportedGrantType,
    PasswordGrantNotAllowed,
    /// The grant was revoked (a replayed code kills its family).
    GrantRevoked,
    /// An authorization code presented twice.
    AuthorizationCodeAlreadyRedeemed,
    /// A code or refresh token that went unused past its inactivity window.
    GrantExpiredThroughInactivity,
    /// A refresh token that went unused past its inactivity window.
    RefreshTokenExpired,
    /// A SPA refresh token past its fixed 24h lifetime.
    SpaRefreshTokenExpired,
    /// `requested_token_use` was not `on_behalf_of`.
    InvalidRequestedTokenUse,
    /// The on-behalf-of assertion is not a token we issued for this client.
    InvalidOboAssertion,

    // ---- scopes and resources ----
    InvalidScope,
    ResourceNotFound,

    // ---- responses ----
    /// `response_type` is not enabled on this app registration.
    ///
    /// The message is quoted from Microsoft's implicit-flow documentation; **the
    /// number is our closest match, not a verified pairing** (decision 16).
    ResponseTypeNotAllowed,

    // ---- device authorization grant ----
    /// Entra's whole device-flow error family: `authorization_pending` and
    /// `slow_down` both carry it.
    DeviceFlowError,
    DeviceAuthorizationDeclined,
    DeviceCodeExpired,
    /// A device code that is unknown or has already been redeemed.
    DeviceCodeInvalidOrRedeemed,

    // ---- server ----
    ServerError,
    /// `TenantThrottlingError`. **Not a verified pairing:** Entra documents this
    /// number for a blocked tenant, and does not say which number accompanies
    /// its 429 (decision 31).
    Throttled,
}

impl Aadsts {
    pub const ALL: &'static [Aadsts] = &[
        Self::MissingOrInvalidParameter,
        Self::UnsupportedParameter,
        Self::InvalidCodeChallenge,
        Self::PkceRequired,
        Self::CodeVerifierMismatch,
        Self::CrossOriginNotPermitted,
        Self::SpaRequiresCrossOrigin,
        Self::MalformedRequest,
        Self::MultipleResourcesInScope,
        Self::DefaultScopeRequired,
        Self::TenantNotFound,
        Self::ApplicationNotFound,
        Self::ApplicationDisabled,
        Self::RedirectUriMismatch,
        Self::WrongTenantForGrant,
        Self::GrantIssuedToDifferentClient,
        Self::MissingClientCredential,
        Self::InvalidClientSecret,
        Self::ExpiredClientSecret,
        Self::InvalidClientAssertion,
        Self::ReplayedClientAssertion,
        Self::ExpiredClientCertificate,
        Self::MultipleClientAuthMethods,
        Self::UnsupportedAssertionType,
        Self::InvalidUsernameOrPassword,
        Self::AccountLocked,
        Self::AccountDisabled,
        Self::SilentSignInFailed,
        Self::NotAssigned,
        Self::ConsentDeclined,
        Self::UnsupportedGrantType,
        Self::PasswordGrantNotAllowed,
        Self::GrantRevoked,
        Self::AuthorizationCodeAlreadyRedeemed,
        Self::GrantExpiredThroughInactivity,
        Self::RefreshTokenExpired,
        Self::SpaRefreshTokenExpired,
        Self::InvalidRequestedTokenUse,
        Self::InvalidOboAssertion,
        Self::InvalidScope,
        Self::ResourceNotFound,
        Self::ResponseTypeNotAllowed,
        Self::DeviceFlowError,
        Self::DeviceAuthorizationDeclined,
        Self::DeviceCodeExpired,
        Self::DeviceCodeInvalidOrRedeemed,
        Self::ServerError,
        Self::Throttled,
    ];

    pub fn code(self) -> u32 {
        match self {
            Self::MissingOrInvalidParameter => 900144,
            Self::UnsupportedParameter => 90023,
            Self::InvalidCodeChallenge => 501491,
            Self::PkceRequired => 9002325,
            Self::CodeVerifierMismatch => 501481,
            Self::CrossOriginNotPermitted => 9002326,
            Self::SpaRequiresCrossOrigin => 9002327,
            Self::MalformedRequest => 9002313,
            Self::MultipleResourcesInScope => 28000,
            Self::DefaultScopeRequired => 1002012,
            Self::TenantNotFound => 90002,
            Self::ApplicationNotFound => 700016,
            Self::ApplicationDisabled => 7000112,
            Self::RedirectUriMismatch => 50011,
            Self::WrongTenantForGrant => 700005,
            Self::GrantIssuedToDifferentClient => 70000,
            Self::MissingClientCredential => 7000218,
            Self::InvalidClientSecret => 7000215,
            Self::ExpiredClientSecret => 7000222,
            Self::InvalidClientAssertion => 700027,
            Self::ReplayedClientAssertion => 700028,
            Self::ExpiredClientCertificate => 700024,
            Self::MultipleClientAuthMethods => 50148,
            Self::UnsupportedAssertionType => 700021,
            Self::InvalidUsernameOrPassword => 50126,
            Self::AccountLocked => 50053,
            Self::AccountDisabled => 50057,
            Self::SilentSignInFailed => 50058,
            Self::NotAssigned => 50105,
            Self::ConsentDeclined => 65004,
            Self::UnsupportedGrantType => 70003,
            Self::PasswordGrantNotAllowed => 700034,
            Self::GrantRevoked => 50173,
            Self::AuthorizationCodeAlreadyRedeemed => 54005,
            Self::GrantExpiredThroughInactivity => 70008,
            Self::RefreshTokenExpired => 700082,
            Self::SpaRefreshTokenExpired => 700084,
            Self::InvalidRequestedTokenUse => 500131,
            Self::InvalidOboAssertion => 500133,
            Self::InvalidScope => 70011,
            Self::ResourceNotFound => 500011,
            Self::ResponseTypeNotAllowed => 700054,
            Self::DeviceFlowError => 70016,
            Self::DeviceAuthorizationDeclined => 70017,
            Self::DeviceCodeExpired => 70019,
            Self::DeviceCodeInvalidOrRedeemed => 70018,
            Self::ServerError => 50000,
            Self::Throttled => 90055,
        }
    }
}

#[derive(Debug)]
pub struct AadError {
    pub status: StatusCode,
    pub error: OAuthError,
    pub code: Aadsts,
    pub message: String,
    pub correlation_id: Option<String>,
    /// Seconds for the `Retry-After` header. Only a throttled response sets it.
    pub retry_after: Option<u64>,
}

impl AadError {
    pub fn new(status: StatusCode, error: OAuthError, code: Aadsts, message: impl Into<String>) -> Self {
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
            OAuthError::InvalidRequest,
            Aadsts::MissingOrInvalidParameter,
            format!("The request body must contain the following parameter: '{name}'."),
        )
    }

    pub fn invalid_request(code: Aadsts, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, OAuthError::InvalidRequest, code, message)
    }

    pub fn tenant_not_found(tenant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidTenant,
            Aadsts::TenantNotFound,
            format!(
                "Tenant '{tenant}' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud."
            ),
        )
    }

    pub fn unsupported_grant_type(grant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::UnsupportedGrantType,
            Aadsts::UnsupportedGrantType,
            format!("The app requested an unsupported grant type '{grant}'."),
        )
    }

    pub fn app_not_found(app_id: &str, tenant: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::UnauthorizedClient,
            Aadsts::ApplicationNotFound,
            format!(
                "Application with identifier '{app_id}' was not found in the directory '{tenant}'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant."
            ),
        )
    }

    pub fn app_disabled(app_id: &str, name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::UnauthorizedClient,
            Aadsts::ApplicationDisabled,
            format!("Application '{app_id}'({name}) is disabled."),
        )
    }

    pub fn missing_client_credential() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::MissingClientCredential,
            "The request body must contain the following parameter: 'client_assertion' or 'client_secret'.",
        )
    }

    pub fn invalid_client_secret(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::InvalidClientSecret,
            format!(
                "Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '{app_id}'."
            ),
        )
    }

    pub fn expired_client_secret(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::ExpiredClientSecret,
            format!("The provided client secret keys for app '{app_id}' are expired."),
        )
    }

    /// A client assertion that is malformed, wrongly targeted, expired, or not
    /// signed by a certificate registered on the app. Deliberately one error for
    /// all of these, so a caller cannot probe which part was wrong.
    pub fn invalid_client_assertion() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::InvalidClientAssertion,
            "AADSTS700027: The client assertion is not valid. Check that it is signed with a certificate registered on the application, names the application as both issuer and subject, targets this token endpoint as its audience, and has not expired.",
        )
    }

    pub fn replayed_client_assertion() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::ReplayedClientAssertion,
            "AADSTS700028: The client assertion has already been used. Each assertion must carry a unique 'jti'.",
        )
    }

    pub fn expired_client_certificate(app_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            OAuthError::InvalidClient,
            Aadsts::ExpiredClientCertificate,
            format!("The certificate credential used by app '{app_id}' is outside its validity period."),
        )
    }

    /// The assertion presented to the on-behalf-of grant is not a user token this
    /// server issued for the calling application.
    pub fn invalid_obo_assertion() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidGrant,
            Aadsts::InvalidOboAssertion,
            "AADSTS500133: The assertion is not valid for the on-behalf-of flow. It must be an unexpired user access token issued by this service whose audience is the calling application.",
        )
    }

    /// ROPC attempted against an app that has not been opted in.
    pub fn password_grant_not_allowed(app_id: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::UnauthorizedClient,
            Aadsts::PasswordGrantNotAllowed,
            format!(
                "The resource owner password credentials grant is not enabled for application '{app_id}'. Enable it deliberately, or use the authorization code flow instead."
            ),
        )
    }

    pub fn invalid_scope(code: Aadsts, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, OAuthError::InvalidScope, code, message)
    }

    pub fn resource_not_found(resource: &str, tenant_name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidResource,
            Aadsts::ResourceNotFound,
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
            OAuthError::AuthorizationPending,
            Aadsts::DeviceFlowError,
            "AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling.",
        )
    }

    /// The device polled faster than the advertised interval.
    pub fn slow_down() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::SlowDown,
            Aadsts::DeviceFlowError,
            "AADSTS70016: OAuth 2.0 device flow error. Polling too frequently. Wait for the interval before retrying.",
        )
    }

    /// The user declined on the approval page.
    pub fn authorization_declined() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::AuthorizationDeclined,
            Aadsts::DeviceAuthorizationDeclined,
            "AADSTS70017: OAuth 2.0 device flow error. The end user denied the authorization request.",
        )
    }

    /// The device code lived longer than its lifetime.
    pub fn device_code_expired() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            OAuthError::ExpiredToken,
            Aadsts::DeviceCodeExpired,
            "AADSTS70019: Verification code expired. The user did not complete sign-in in time; restart the flow.",
        )
    }

    pub fn invalid_grant(code: Aadsts, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, OAuthError::InvalidGrant, code, message)
    }

    /// `error_description` for redirects and error pages:
    /// `AADSTS{code}: {message} Trace ID: ... Correlation ID: ... Timestamp: ...`
    pub fn description(&self) -> String {
        let timestamp = time::OffsetDateTime::now_utc().format(TIMESTAMP).unwrap_or_default();
        let correlation_id = self.correlation_id.clone().unwrap_or_else(new_guid);
        format!(
            "AADSTS{}: {} Trace ID: {} Correlation ID: {correlation_id} Timestamp: {timestamp}",
            self.code.code(),
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
            OAuthError::TemporarilyUnavailable,
            Aadsts::Throttled,
            "There are too many incoming requests. Retry after the interval in the Retry-After header.",
        );
        err.retry_after = Some(retry_after.0);
        err
    }

    pub fn server_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthError::ServerError,
            Aadsts::ServerError,
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
            "error": self.error.as_str(),
            "error_description": format!(
                "AADSTS{}: {} Trace ID: {trace_id} Correlation ID: {correlation_id} Timestamp: {timestamp}",
                self.code.code(), self.message
            ),
            "error_codes": [self.code.code()],
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
