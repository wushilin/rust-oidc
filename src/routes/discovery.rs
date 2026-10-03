use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use serde_json::{Value, json};

use super::authorize::Prompt;
use super::token::{ClientAuthMethod, GrantType};
use crate::AppState;
use crate::error::AadError;
use crate::tenant;

/// An address an integrating application is configured with. Named once, so the
/// discovery document and the console's Configuration page cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Issuer,
    Discovery,
    Authorization,
    Token,
    DeviceAuthorization,
    Jwks,
    UserInfo,
    EndSession,
}

impl Endpoint {
    pub const ALL: &'static [Endpoint] = &[
        Self::Issuer,
        Self::Discovery,
        Self::Authorization,
        Self::Token,
        Self::DeviceAuthorization,
        Self::Jwks,
        Self::UserInfo,
        Self::EndSession,
    ];

    /// What it is called where people configure things.
    pub fn label(self) -> &'static str {
        match self {
            Self::Issuer => "Issuer",
            Self::Discovery => "OpenID Connect discovery document",
            Self::Authorization => "Authorization endpoint",
            Self::Token => "Token endpoint",
            Self::DeviceAuthorization => "Device authorization endpoint",
            Self::Jwks => "Signing keys (JWKS)",
            Self::UserInfo => "UserInfo endpoint",
            Self::EndSession => "Sign-out endpoint",
        }
    }

    /// Its name in the discovery document. The document does not list itself.
    pub fn metadata_key(self) -> Option<&'static str> {
        match self {
            Self::Issuer => Some("issuer"),
            Self::Discovery => None,
            Self::Authorization => Some("authorization_endpoint"),
            Self::Token => Some("token_endpoint"),
            Self::DeviceAuthorization => Some("device_authorization_endpoint"),
            Self::Jwks => Some("jwks_uri"),
            Self::UserInfo => Some("userinfo_endpoint"),
            Self::EndSession => Some("end_session_endpoint"),
        }
    }

    /// The address for tenant `tid`: an id, a domain, or a placeholder.
    pub fn url(self, url: &crate::config::PublicUrl, tid: &str) -> String {
        match self {
            Self::Issuer => url.issuer(tid),
            Self::Discovery => url.tenant_url(tid, "v2.0/.well-known/openid-configuration"),
            Self::Authorization => url.tenant_url(tid, "oauth2/v2.0/authorize"),
            Self::Token => url.tenant_url(tid, "oauth2/v2.0/token"),
            Self::DeviceAuthorization => url.tenant_url(tid, "oauth2/v2.0/devicecode"),
            Self::Jwks => url.tenant_url(tid, "discovery/v2.0/keys"),
            // One for every tenant: the token says whose it is.
            Self::UserInfo => format!("{}/oidc/userinfo", url.base()),
            Self::EndSession => url.tenant_url(tid, "oauth2/v2.0/logout"),
        }
    }
}

pub const SIGNING_ALGORITHMS: &[&str] = &["RS256"];
pub const RESPONSE_MODES: &[&str] = &["query", "fragment", "form_post"];
/// Exactly what Entra advertises. Its documentation additionally demonstrates
/// bare `token` (the silent-refresh iframe), which it does not advertise and
/// neither do we -- the mismatch is reproduced deliberately.
pub const RESPONSE_TYPES: &[&str] = &["code", "id_token", "code id_token", "id_token token"];
pub const SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];
pub const CODE_CHALLENGE_METHODS: &[&str] = &["S256", "plain"];
pub const CLIENT_AUTH_METHODS: &[ClientAuthMethod] = &[
    ClientAuthMethod::ClientSecretPost,
    ClientAuthMethod::ClientSecretBasic,
    ClientAuthMethod::PrivateKeyJwt,
];
pub const GRANT_TYPES: &[GrantType] = &[
    GrantType::AuthorizationCode,
    GrantType::RefreshToken,
    GrantType::ClientCredentials,
    GrantType::DeviceCode,
    GrantType::JwtBearer,
    GrantType::Password,
];

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

    let at = |endpoint: Endpoint| endpoint.url(url, tid);
    Ok(Json(json!({
        "token_endpoint": at(Endpoint::Token),
        "token_endpoint_auth_methods_supported": CLIENT_AUTH_METHODS.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
        "jwks_uri": at(Endpoint::Jwks),
        "response_modes_supported": RESPONSE_MODES,
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": SIGNING_ALGORITHMS,
        "response_types_supported": RESPONSE_TYPES,
        "scopes_supported": SCOPES,
        "device_authorization_endpoint": at(Endpoint::DeviceAuthorization),
        "grant_types_supported": GRANT_TYPES.iter().map(|g| g.as_str()).collect::<Vec<_>>(),
        "code_challenge_methods_supported": CODE_CHALLENGE_METHODS,
        "prompt_values_supported": Prompt::SUPPORTED.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "acr_values_supported": crate::claims::Acr::ALL.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "issuer": at(Endpoint::Issuer),
        "request_uri_parameter_supported": false,
        "userinfo_endpoint": at(Endpoint::UserInfo),
        "authorization_endpoint": at(Endpoint::Authorization),
        "end_session_endpoint": at(Endpoint::EndSession),
        "http_logout_supported": false,
        "frontchannel_logout_supported": false,
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "nbf", "auth_time", "nonce", "ver", "tid", "oid",
            "uti", "azp", "azpacr", "idtyp", "name", "preferred_username", "upn", "email",
            "given_name", "family_name", "roles", "role_ids", "groups", "group_ids", "wids", "scp",
            "acr", "amr", "idp", "acct"
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
