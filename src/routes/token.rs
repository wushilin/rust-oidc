//! `POST /{tenant}/oauth2/v2.0/token`

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::apps::{self, Application, SecretCheck, ServicePrincipal};
use crate::error::{AadError, no_store};
use crate::tenant::{self, Tenant};
use crate::util::{b64url, now, random_bytes};

pub async fn token(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle(&st, &tenant_key, &headers, &body).await {
        Ok(resp) => resp,
        Err(err) => err.correlate(&headers).into_response(),
    }
}

async fn handle(st: &AppState, tenant_key: &str, headers: &HeaderMap, body: &[u8]) -> Result<Response, AadError> {
    let params: HashMap<String, String> = url::form_urlencoded::parse(body).into_owned().collect();

    let tenant = tenant::resolve(&st.pool, tenant_key)
        .await?
        .ok_or_else(|| AadError::tenant_not_found(tenant_key))?;

    let grant_type = param(&params, "grant_type").ok_or_else(|| AadError::missing_parameter("grant_type"))?;
    match grant_type {
        "client_credentials" => client_credentials(st, &tenant, headers, &params).await,
        other => Err(AadError::unsupported_grant_type(other)),
    }
}

fn param<'a>(params: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    params.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

// ---- client authentication ----

pub struct AuthenticatedClient {
    pub app: Application,
    pub sp: ServicePrincipal,
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
        let invalid = || AadError::invalid_request(900144, "The Authorization header is not a valid Basic credential.");
        let decoded = STANDARD.decode(encoded.trim()).map_err(|_| invalid())?;
        let decoded = String::from_utf8(decoded).map_err(|_| invalid())?;
        let (id, secret) = decoded.split_once(':').ok_or_else(invalid)?;
        let (id, secret) = (form_decode(id), form_decode(secret));
        if param(params, "client_secret").is_some() {
            return Err(AadError::invalid_request(
                50148,
                "The client must use only one method to authenticate (client_secret_basic or client_secret_post).",
            ));
        }
        if let Some(body_id) = param(params, "client_id")
            && !body_id.eq_ignore_ascii_case(&id)
        {
            return Err(AadError::invalid_request(
                900144,
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

async fn authenticate_confidential_client(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<AuthenticatedClient, AadError> {
    let (client_id, secret) = client_credentials_from_request(headers, params)?;
    let app = apps::find(&st.pool, &client_id).await?;
    let sp = match &app {
        Some(app) => apps::service_principal(&st.pool, &tenant.id, &app.app_id).await?,
        None => None,
    };
    let (Some(app), Some(sp)) = (app, sp) else {
        return Err(AadError::app_not_found(&client_id, &tenant.id));
    };
    let secret = secret.ok_or_else(AadError::missing_client_credential)?;
    match apps::verify_secret(&st.pool, &app, &secret).await? {
        SecretCheck::Valid => {}
        SecretCheck::Expired => return Err(AadError::expired_client_secret(&app.app_id)),
        SecretCheck::Invalid => return Err(AadError::invalid_client_secret(&app.app_id)),
    }
    if !sp.enabled {
        return Err(AadError::app_disabled(&app.app_id, &app.display_name));
    }
    Ok(AuthenticatedClient { app, sp })
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
            70011,
            format!("The provided value for the input parameter 'scope' is not valid. The scope {scope} is not valid."),
        ));
    }
    let Some(resource) = scopes[0].strip_suffix("/.default") else {
        return Err(AadError::invalid_scope(
            1002012,
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
    claims.insert("azpacr".into(), json!("1"));
    claims.insert("idtyp".into(), json!("app"));
    claims.insert("oid".into(), json!(client.sp.id));
    if !roles.is_empty() {
        claims.insert("roles".into(), json!(roles));
    }
    claims.insert("sub".into(), json!(client.sp.id));
    claims.insert("tid".into(), json!(tenant.id));
    claims.insert("uti".into(), json!(b64url(&random_bytes(16))));
    claims.insert("ver".into(), json!("2.0"));

    let access_token = st.keys.sign(&Value::Object(claims)).await?;
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
