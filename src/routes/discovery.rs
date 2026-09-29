use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::AppState;
use crate::error::AadError;
use crate::tenant;

/// `GET /{tenant}/v2.0/.well-known/openid-configuration`
///
/// Like Entra, the tenant may be addressed by GUID or verified domain, but the
/// document always uses the tenant GUID in the issuer and endpoints.
pub async fn openid_configuration(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, AadError> {
    let tenant = tenant::resolve(&st.pool, &tenant_key)
        .await?
        .ok_or_else(|| AadError::tenant_not_found(&tenant_key).correlate(&headers))?;
    let tid = tenant.id.as_str();
    let url = &st.public_url;

    Ok(Json(json!({
        "token_endpoint": url.tenant_url(tid, "oauth2/v2.0/token"),
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "jwks_uri": url.tenant_url(tid, "discovery/v2.0/keys"),
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "issuer": url.issuer(tid),
        "request_uri_parameter_supported": false,
        "userinfo_endpoint": format!("{}/oidc/userinfo", url.base()),
        "authorization_endpoint": url.tenant_url(tid, "oauth2/v2.0/authorize"),
        "end_session_endpoint": url.tenant_url(tid, "oauth2/v2.0/logout"),
        "http_logout_supported": false,
        "frontchannel_logout_supported": false,
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "nbf", "auth_time", "nonce", "ver", "tid", "oid",
            "uti", "azp", "azpacr", "idtyp", "name", "preferred_username", "upn", "email",
            "given_name", "family_name", "roles", "groups", "wids", "scp", "amr"
        ],
        "tenant_region_scope": null,
        "cloud_instance_name": url.host(),
    })))
}

/// `GET /{tenant}/discovery/v2.0/keys`
///
/// Keys are shared by all tenants. Like Entra's v2 key set, each key carries
/// the tenant's issuer; `common` gets the `{tenantid}` template.
pub async fn keys(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, AadError> {
    let issuer = if tenant_key.eq_ignore_ascii_case("common") {
        st.public_url.issuer("{tenantid}")
    } else {
        let tenant = tenant::resolve(&st.pool, &tenant_key)
            .await?
            .ok_or_else(|| AadError::tenant_not_found(&tenant_key).correlate(&headers))?;
        st.public_url.issuer(&tenant.id)
    };
    let keys = st.keys.published().await?;
    let jwks: Vec<_> = keys.iter().map(|k| k.jwk(Some(issuer.clone()))).collect();
    Ok(Json(json!({ "keys": jwks })))
}
