//! `POST /{tenant}/oauth2/v2.0/token`

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use super::audit::{self, Actor, ClientFailures, Event, Reason};
use crate::AppState;
use crate::apps::{self, Application, SecretCheck, ServicePrincipal};
use crate::claims::Azpacr;
use crate::error::{AadError, Aadsts, no_store};
use crate::ratelimit::{Limit, app_key};
use crate::tenant::{self, Tenant};
use crate::util::{b64url, ct_eq, now, random_bytes};

pub async fn token(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let mut resp = match handle(&st, &tenant_key, &headers, &params).await {
        Ok(resp) => resp,
        Err(err) => err.correlate(&headers).into_response(),
    };
    // SPAs redeem codes cross-origin. Like Entra, allow the origins of the
    // client's registered SPA redirect URIs (for errors too, so they are readable).
    if let Some(origin) = allowed_spa_origin(&st, &headers, &params).await {
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    resp
}

/// CORS preflight for the token endpoint.
pub async fn preflight(headers: HeaderMap) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    if let Some(origin) = headers.get(header::ORIGIN) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    }
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    if let Some(req) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, req.clone());
    }
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    resp
}

async fn allowed_spa_origin(
    st: &AppState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Option<HeaderValue> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    let app = apps::find(&st.pool, param(params, "client_id")?).await.ok()??;
    let uris = apps::redirect_uris(&st.pool, &app).await.ok()?;
    uris.iter()
        .filter(|(platform, _)| *platform == apps::RedirectPlatform::Spa)
        .filter_map(|(_, uri)| url::Url::parse(uri).ok())
        .any(|u| u.origin().ascii_serialization() == origin)
        .then(|| HeaderValue::from_str(origin).ok())?
}

async fn handle(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Response, AadError> {
    let tenant = tenant::resolve(&st.pool, tenant_key)
        .await?
        .ok_or_else(|| AadError::tenant_not_found(tenant_key))?;

    let grant_type = param(params, "grant_type").ok_or_else(|| AadError::missing_parameter("grant_type"))?;
    match GrantType::parse(grant_type) {
        Some(GrantType::ClientCredentials) => client_credentials(st, &tenant, headers, params).await,
        Some(GrantType::AuthorizationCode) => {
            super::user_grants::authorization_code(st, &tenant, headers, params).await
        }
        Some(GrantType::RefreshToken) => super::user_grants::refresh_token(st, &tenant, headers, params).await,
        Some(GrantType::DeviceCode) => super::device::device_code_grant(st, &tenant, headers, params).await,
        Some(GrantType::JwtBearer) => super::user_grants::on_behalf_of(st, &tenant, headers, params).await,
        Some(GrantType::Password) => super::user_grants::password(st, &tenant, headers, params).await,
        None => Err(AadError::unsupported_grant_type(grant_type)),
    }
}

/// The `grant_type` values this server accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    ClientCredentials,
    AuthorizationCode,
    RefreshToken,
    DeviceCode,
    /// On-behalf-of (RFC 7523 assertion grant).
    JwtBearer,
    /// Resource owner password credentials, opt-in per app.
    Password,
}

impl GrantType {
    pub const DEVICE_CODE: &'static str = "urn:ietf:params:oauth:grant-type:device_code";
    pub const JWT_BEARER: &'static str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientCredentials => "client_credentials",
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::DeviceCode => Self::DEVICE_CODE,
            Self::JwtBearer => Self::JWT_BEARER,
            Self::Password => "password",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "client_credentials" => Some(Self::ClientCredentials),
            "authorization_code" => Some(Self::AuthorizationCode),
            "refresh_token" => Some(Self::RefreshToken),
            Self::DEVICE_CODE => Some(Self::DeviceCode),
            Self::JWT_BEARER => Some(Self::JwtBearer),
            "password" => Some(Self::Password),
            _ => None,
        }
    }
}

pub(super) fn param<'a>(params: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    params.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

// ---- client authentication ----

pub struct AuthenticatedClient {
    pub app: Application,
    pub sp: ServicePrincipal,
    /// How the client proved itself, reported as `azpacr`.
    pub azpacr: Azpacr,
}

/// Client authentication methods this server accepts at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

/// Clock skew tolerated on a client assertion's `exp`/`nbf`, in seconds.
const ASSERTION_CLOCK_SKEW: u64 = 10;
/// Longest a client assertion may remain valid, in seconds.
const MAX_ASSERTION_LIFETIME: i64 = 600;

impl ClientAuthMethod {
    /// RFC 7523 client assertion type for `private_key_jwt`.
    pub const ASSERTION_TYPE: &'static str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// client_secret_basic (RFC 6749 §2.3.1, form-urlencoded inside Basic) or client_secret_post.
fn client_credentials_from_request(
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<(String, Option<String>), AadError> {
    let basic = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")));
    if let Some(encoded) = basic {
        let invalid = || {
            AadError::invalid_request(
                Aadsts::MissingOrInvalidParameter,
                "The Authorization header is not a valid Basic credential.",
            )
        };
        let decoded = STANDARD.decode(encoded.trim()).map_err(|_| invalid())?;
        let decoded = String::from_utf8(decoded).map_err(|_| invalid())?;
        let (id, secret) = decoded.split_once(':').ok_or_else(invalid)?;
        let (id, secret) = (form_decode(id), form_decode(secret));
        if param(params, "client_secret").is_some() {
            return Err(AadError::invalid_request(
                Aadsts::MultipleClientAuthMethods,
                "The client must use only one method to authenticate (client_secret_basic or client_secret_post).",
            ));
        }
        if let Some(body_id) = param(params, "client_id")
            && !body_id.eq_ignore_ascii_case(&id)
        {
            return Err(AadError::invalid_request(
                Aadsts::MissingOrInvalidParameter,
                "The client_id in the body does not match the Authorization header.",
            ));
        }
        return Ok((id, Some(secret)));
    }
    let id = param(params, "client_id").ok_or_else(|| AadError::missing_parameter("client_id"))?;
    Ok((id.to_string(), param(params, "client_secret").map(str::to_string)))
}

/// Decode one application/x-www-form-urlencoded value.
fn form_decode(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub(super) async fn authenticate_confidential_client(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<AuthenticatedClient, AadError> {
    // A client assertion replaces the secret entirely (private_key_jwt).
    if let Some(assertion) = param(params, "client_assertion") {
        return authenticate_with_assertion(st, tenant, params, assertion).await;
    }
    let (client_id, secret) = client_credentials_from_request(headers, params)?;
    let app = apps::find(&st.pool, &client_id).await?;
    let sp = match &app {
        Some(app) => apps::service_principal(&st.pool, &tenant.id, &app.app_id).await?,
        None => None,
    };
    let failures = ClientFailures {
        st,
        tenant_id: &tenant.id,
        event: Event::TokenClientAuthFailed,
        claimed: &client_id,
    };
    // An app registered elsewhere but with no service principal in this tenant is
    // still a known app, so audit its real id rather than the claimed string.
    let registered = app.as_ref().map(|a| a.app_id.clone());
    let (Some(app), Some(sp)) = (app, sp) else {
        return Err(failures
            .fail(
                registered.as_deref(),
                Reason::UnknownClient,
                AadError::app_not_found(&client_id, &tenant.id),
            )
            .await);
    };
    // Refuse before the secret is looked up and compared. A client secret is
    // stored as a plain SHA-256 (it is a ~200-bit random value, so a slow hash
    // adds nothing), which makes the saving here a query rather than a lot of
    // CPU -- the real reason for the guard is that a refused request must not
    // reach the audit write either. Checked only once the client id has
    // resolved, so a throttled application never affects any other.
    if let Some(retry) = st
        .limits
        .check(Limit::ClientAuthFailure, &app_key(&tenant.id, &app.app_id))
    {
        return Err(AadError::throttled(retry));
    }
    let Some(secret) = secret else {
        return Err(failures
            .fail(
                Some(&app.app_id),
                Reason::MissingSecret,
                AadError::missing_client_credential(),
            )
            .await);
    };
    match apps::verify_secret(&st.pool, &app, &secret).await? {
        SecretCheck::Valid => {}
        SecretCheck::Expired => {
            return Err(failures
                .fail(
                    Some(&app.app_id),
                    Reason::ExpiredSecret,
                    AadError::expired_client_secret(&app.app_id),
                )
                .await);
        }
        SecretCheck::Invalid => {
            return Err(failures
                .fail(
                    Some(&app.app_id),
                    Reason::InvalidSecret,
                    AadError::invalid_client_secret(&app.app_id),
                )
                .await);
        }
    }
    if !sp.enabled {
        let err = AadError::app_disabled(&app.app_id, &app.display_name);
        return Err(failures.fail(Some(&app.app_id), Reason::AppDisabled, err).await);
    }
    Ok(AuthenticatedClient {
        app,
        sp,
        azpacr: Azpacr::ClientSecret,
    })
}

/// Read `iss` from an unverified assertion payload, to locate the client.
/// The assertion is fully verified afterwards; nothing here is trusted.
fn unverified_issuer(assertion: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("iss")?.as_str().map(str::to_string)
}

/// Verify a `private_key_jwt` client assertion (RFC 7523) signed with the key of
/// a certificate registered on the app. Entra identifies the certificate by the
/// `x5t` header; `kid` is accepted as well.
async fn authenticate_with_assertion(
    st: &AppState,
    tenant: &Tenant,
    params: &HashMap<String, String>,
    assertion: &str,
) -> Result<AuthenticatedClient, AadError> {
    let assertion_type =
        param(params, "client_assertion_type").ok_or_else(|| AadError::missing_parameter("client_assertion_type"))?;
    if assertion_type != ClientAuthMethod::ASSERTION_TYPE {
        return Err(AadError::invalid_request(
            Aadsts::UnsupportedAssertionType,
            format!(
                "Client assertion type '{assertion_type}' is not supported. Expected '{}'.",
                ClientAuthMethod::ASSERTION_TYPE
            ),
        ));
    }

    // Before the client is known the claimed id is only data (and unverified).
    let claimed = param(params, "client_id")
        .map(str::to_string)
        .unwrap_or_else(|| unverified_issuer(assertion).unwrap_or_default());
    let rejections = ClientFailures {
        st,
        tenant_id: &tenant.id,
        event: Event::TokenAssertionRejected,
        claimed: &claimed,
    };

    let Ok(header) = jsonwebtoken::decode_header(assertion) else {
        return Err(rejections
            .fail(None, Reason::MalformedAssertion, AadError::invalid_client_assertion())
            .await);
    };
    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(rejections
            .fail(None, Reason::MalformedAssertion, AadError::invalid_client_assertion())
            .await);
    }
    let Some(thumbprint) = header.x5t.or(header.kid) else {
        return Err(rejections
            .fail(None, Reason::MalformedAssertion, AadError::invalid_client_assertion())
            .await);
    };

    // The assertion's issuer identifies the client when client_id is absent. This
    // reads the payload WITHOUT verifying it, so it is only used to find which
    // app to check against; every claim is verified against that app's key below.
    let issuer = unverified_issuer(assertion).unwrap_or_default();
    let client_id = match param(params, "client_id") {
        Some(id) => id.to_string(),
        None if !issuer.is_empty() => issuer.clone(),
        None => return Err(AadError::missing_parameter("client_id")),
    };

    let app = apps::find(&st.pool, &client_id).await?;
    let sp = match &app {
        Some(app) => apps::service_principal(&st.pool, &tenant.id, &app.app_id).await?,
        None => None,
    };
    let (Some(app), Some(sp)) = (app, sp) else {
        return Err(rejections
            .fail(
                None,
                Reason::UnknownClient,
                AadError::app_not_found(&client_id, &tenant.id),
            )
            .await);
    };

    // Refuse before the signature check. Unlike the secret path this one really
    // is expensive -- an RSA verification per attempt -- so a throttled caller
    // must not be able to buy it. Both paths count into the same per-application
    // bucket, since both are client authentication for the same application.
    if let Some(retry) = st
        .limits
        .check(Limit::ClientAuthFailure, &app_key(&tenant.id, &app.app_id))
    {
        return Err(AadError::throttled(retry));
    }

    // Only a certificate registered on this app can sign for it.
    let ts = now();
    let credentials = apps::key_credentials(&st.pool, &app).await?;
    let presented = apps::normalize_thumbprint(&thumbprint);
    let Some(credential) = credentials
        .iter()
        .find(|c| ct_eq(&apps::normalize_thumbprint(&c.key_id), &presented))
    else {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::UnknownKey,
                AadError::invalid_client_assertion(),
            )
            .await);
    };
    if !credential.is_current(ts) {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::ExpiredCertificate,
                AadError::expired_client_certificate(&app.app_id),
            )
            .await);
    }

    // `aud` is the token endpoint; the issuer is also accepted, as Entra does.
    let token_endpoint = st.public_url.tenant_url(&tenant.id, "oauth2/v2.0/token");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[token_endpoint.as_str(), st.public_url.issuer(&tenant.id).as_str()]);
    validation.set_issuer(&[app.app_id.as_str()]);
    validation.required_spec_claims = ["exp", "aud", "iss", "sub"].iter().map(|c| c.to_string()).collect();
    // The library default is a full minute, which is far too generous for a
    // single-use credential; allow only real clock skew.
    validation.leeway = ASSERTION_CLOCK_SKEW;
    let key = jsonwebtoken::DecodingKey::from_rsa_raw_components(&credential.n, &credential.e);
    let Ok(decoded) = jsonwebtoken::decode::<Value>(assertion, &key, &validation) else {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::InvalidAssertion,
                AadError::invalid_client_assertion(),
            )
            .await);
    };
    let claims = decoded.claims;

    // RFC 7523: the subject is the client itself.
    if claims["sub"].as_str() != Some(app.app_id.as_str()) {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::SubjectMismatch,
                AadError::invalid_client_assertion(),
            )
            .await);
    }
    // A jti may be presented only once while the assertion is still valid.
    let Some(jti) = claims["jti"].as_str() else {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::MissingJti,
                AadError::invalid_client_assertion(),
            )
            .await);
    };
    let exp = claims["exp"].as_i64().unwrap_or(ts);
    // Bound how long one assertion stays usable, and so how long the jti must be
    // remembered. Entra likewise expects short-lived assertions.
    if exp > ts + MAX_ASSERTION_LIFETIME {
        return Err(rejections
            .fail(
                Some(&app.app_id),
                Reason::LifetimeTooLong,
                AadError::invalid_client_assertion(),
            )
            .await);
    }
    let _ = sqlx::query(crate::db::q(
        &st.pool,
        "DELETE FROM client_assertion_jti WHERE expires_at <= ?",
    ))
    .bind(ts)
    .execute(&st.pool)
    .await;
    // The primary key makes the insert the atomic "first use" test: a unique
    // violation is a replay, any other error is a real failure.
    let first_use = crate::db::inserted(
        sqlx::query(crate::db::q(
            &st.pool,
            "INSERT INTO client_assertion_jti (jti, client_app_id, expires_at) VALUES (?, ?, ?)",
        ))
        .bind(jti)
        .bind(&app.app_id)
        .bind(exp)
        .execute(&st.pool)
        .await,
    )?;
    if !first_use {
        // The jti is an identifier the client chose, not a credential; the
        // signed assertion itself is never logged.
        let details = json!({ "clientId": app.app_id, "jti": audit::clip(jti) });
        audit::record(
            st,
            &tenant.id,
            Actor::Id(&app.app_id),
            Event::TokenAssertionReplayed,
            Some(&app.app_id),
            details,
        )
        .await;
        return Err(AadError::replayed_client_assertion());
    }

    if !sp.enabled {
        let err = AadError::app_disabled(&app.app_id, &app.display_name);
        return Err(rejections.fail(Some(&app.app_id), Reason::AppDisabled, err).await);
    }
    Ok(AuthenticatedClient {
        app,
        sp,
        azpacr: Azpacr::Certificate,
    })
}

// ---- grant: client_credentials ----

async fn client_credentials(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Response, AadError> {
    let client = authenticate_confidential_client(st, tenant, headers, params).await?;

    let scope = param(params, "scope").ok_or_else(|| AadError::missing_parameter("scope"))?;
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    if scopes.len() != 1 {
        return Err(AadError::invalid_scope(
            Aadsts::InvalidScope,
            format!("The provided value for the input parameter 'scope' is not valid. The scope {scope} is not valid."),
        ));
    }
    let Some(resource) = scopes[0].strip_suffix("/.default") else {
        return Err(AadError::invalid_scope(
            Aadsts::DefaultScopeRequired,
            format!(
                "The provided value for scope {scope} is not valid. Client credential flows must have a scope value with /.default suffixed to the resource identifier (application ID URI)."
            ),
        ));
    };
    let (resource_app, resource_sp) = apps::resolve_resource(&st.pool, &tenant.id, resource)
        .await?
        .ok_or_else(|| AadError::resource_not_found(resource, &tenant.name))?;

    let roles = apps::app_roles_for_service_principal(&st.pool, &resource_sp.id, &client.sp.id).await?;

    let iat = now();
    let lifetime = tenant.settings.access_token_lifetime_secs;
    let mut claims = Map::new();
    claims.insert("aud".into(), json!(resource_app.app_id));
    claims.insert("iss".into(), json!(st.public_url.issuer(&tenant.id)));
    claims.insert("iat".into(), json!(iat));
    claims.insert("nbf".into(), json!(iat));
    claims.insert("exp".into(), json!(iat + lifetime));
    claims.insert("azp".into(), json!(client.app.app_id));
    claims.insert("azpacr".into(), json!(client.azpacr.as_str()));
    claims.insert("idtyp".into(), json!(crate::claims::IdType::App.as_str()));
    claims.insert("oid".into(), json!(client.sp.id));
    if !roles.is_empty() {
        claims.insert("roles".into(), json!(roles));
    }
    claims.insert("sub".into(), json!(client.sp.id));
    claims.insert("tid".into(), json!(tenant.id));
    claims.insert("uti".into(), json!(b64url(&random_bytes(16))));
    claims.insert("ver".into(), json!("2.0"));

    let access_token = st.keys.sign(&Value::Object(claims)).await?;
    let details = json!({
        "grant": GrantType::ClientCredentials.as_str(),
        "clientId": client.app.app_id,
        "resource": resource_app.app_id,
        "azpacr": client.azpacr.as_str(),
    });
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&client.app.app_id),
        Event::TokenIssued,
        Some(&resource_app.app_id),
        details,
    )
    .await;
    let mut resp = Json(json!({
        "token_type": "Bearer",
        "expires_in": lifetime,
        "ext_expires_in": lifetime,
        "access_token": access_token,
    }))
    .into_response();
    no_store(resp.headers_mut());
    if let Some(id) = crate::error::client_request_id(headers).and_then(|c| c.parse().ok()) {
        resp.headers_mut().insert("client-request-id", id);
    }
    Ok(resp)
}
