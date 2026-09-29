//! Token endpoint grants for signed-in users: `authorization_code` and `refresh_token`.
//!
//! Client authentication follows Entra's platform rules, decided by the
//! redirect URI the code was issued to:
//! - `web`: confidential client; must authenticate (secret); no browser Origin.
//! - `spa`: public client; must be a cross-origin (CORS) request; PKCE required.
//! - `publicClient`: public client; no secret; no browser Origin.

use std::collections::HashMap;

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, json};
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use super::token::{authenticate_confidential_client, param};
use crate::AppState;
use crate::apps::{self, Application, PLATFORM_SPA, PLATFORM_WEB};
use crate::claims::{self, SignIn};
use crate::error::{AadError, no_store};
use crate::scopes::{self, Grant};
use crate::tenant::Tenant;
use crate::users;
use crate::util::{b64url, ct_eq, new_guid, now, random_bytes, sha256_hex};

/// Entra: refresh tokens issued to SPAs have a fixed 24 hour lifetime.
const SPA_REFRESH_LIFETIME: i64 = 86_400;

type Params = HashMap<String, String>;

/// Authenticate the client according to the platform the grant was issued to.
/// Returns `azpacr`.
async fn authenticate_for_platform(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
    platform: &str,
    expected_client: &str,
) -> Result<&'static str, AadError> {
    let has_origin = headers.contains_key("origin");
    if platform == PLATFORM_SPA {
        if !has_origin {
            return Err(AadError::invalid_request(
                9002327,
                "Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests.",
            ));
        }
    } else if has_origin {
        return Err(AadError::invalid_request(
            9002326,
            "Cross-origin token redemption is permitted only for the 'Single-Page Application' client-type.",
        ));
    }
    if platform == PLATFORM_WEB {
        let client = authenticate_confidential_client(st, tenant, headers, params).await?;
        if !client.app.app_id.eq_ignore_ascii_case(expected_client) {
            return Err(AadError::invalid_grant(
                70000,
                "The provided grant was issued to a different client.",
            ));
        }
        return Ok("1");
    }
    let client_id = param(params, "client_id").ok_or_else(|| AadError::missing_parameter("client_id"))?;
    if !client_id.eq_ignore_ascii_case(expected_client) {
        return Err(AadError::invalid_grant(
            70000,
            "The provided grant was issued to a different client.",
        ));
    }
    Ok("0")
}

#[derive(FromRow)]
struct CodeRow {
    code_hash: String,
    tenant_id: String,
    client_app_id: String,
    redirect_uri: String,
    platform: String,
    user_id: String,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    auth_time: i64,
    amr: String,
    expires_at: i64,
    redeemed_at: Option<i64>,
}

pub async fn authorization_code(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Response, AadError> {
    let code = param(params, "code").ok_or_else(|| AadError::missing_parameter("code"))?;
    let row: Option<CodeRow> = sqlx::query_as(
        "SELECT code_hash, tenant_id, client_app_id, redirect_uri, platform, user_id, scope, nonce, code_challenge,
                code_challenge_method, auth_time, amr, expires_at, redeemed_at
         FROM auth_codes WHERE code_hash = ?",
    )
    .bind(sha256_hex(code.as_bytes()))
    .fetch_optional(&st.pool)
    .await?;
    let row =
        row.ok_or_else(|| AadError::invalid_grant(70000, "The provided value for the 'code' parameter is not valid."))?;
    if row.tenant_id != tenant.id {
        return Err(AadError::invalid_grant(
            700005,
            "Provided Authorization Code is intended to use against other tenant, thus rejected.",
        ));
    }
    let azpacr = authenticate_for_platform(st, tenant, headers, params, &row.platform, &row.client_app_id).await?;

    if row.redeemed_at.is_some() {
        revoke_code_family(st, &row.code_hash).await?;
        return Err(AadError::invalid_grant(
            54005,
            "OAuth2 Authorization code was already redeemed, please retry with a new valid code or use an existing refresh token.",
        ));
    }
    if row.expires_at <= now() {
        return Err(AadError::invalid_grant(
            70008,
            "The provided authorization code or refresh token has expired due to inactivity. Send a new interactive authorization request for this user and resource.",
        ));
    }
    let redirect_uri = param(params, "redirect_uri").unwrap_or_default();
    if redirect_uri != row.redirect_uri {
        return Err(AadError::invalid_grant(
            50011,
            "The redirect URI in the token request does not match the one used in the authorization request.",
        ));
    }
    if let Some(challenge) = &row.code_challenge {
        let verifier = param(params, "code_verifier").unwrap_or_default();
        let expected = match row.code_challenge_method.as_deref() {
            Some("S256") => URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            _ => verifier.to_string(),
        };
        if verifier.is_empty() || !ct_eq(&expected, challenge) {
            return Err(AadError::invalid_grant(
                501481,
                "The Code_Verifier does not match the code_challenge supplied in the authorization request.",
            ));
        }
    }
    // Single use, race-safe: only one redemption can flip redeemed_at.
    let res = sqlx::query("UPDATE auth_codes SET redeemed_at = ? WHERE code_hash = ? AND redeemed_at IS NULL")
        .bind(now())
        .bind(&row.code_hash)
        .execute(&st.pool)
        .await?;
    if res.rows_affected() != 1 {
        return Err(AadError::invalid_grant(
            54005,
            "OAuth2 Authorization code was already redeemed.",
        ));
    }

    let grant = scopes::resolve(&st.pool, tenant, &row.scope).await?;
    let amr: Vec<String> = serde_json::from_str(&row.amr).unwrap_or_default();
    let family = Family {
        id: new_guid(),
        code_hash: Some(row.code_hash.clone()),
        platform: row.platform.clone(),
        auth_time: row.auth_time,
        amr,
        spa_expires_at: None,
    };
    issue(
        st,
        tenant,
        headers,
        params,
        &row.client_app_id,
        &row.user_id,
        &grant,
        row.nonce.as_deref(),
        azpacr,
        family,
    )
    .await
}

#[derive(FromRow)]
struct RefreshRow {
    token_hash: String,
    family_id: String,
    tenant_id: String,
    client_app_id: String,
    platform: String,
    user_id: String,
    scope: String,
    auth_time: i64,
    amr: String,
    expires_at: i64,
    used_at: Option<i64>,
    revoked_at: Option<i64>,
}

pub async fn refresh_token(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Response, AadError> {
    let token = param(params, "refresh_token").ok_or_else(|| AadError::missing_parameter("refresh_token"))?;
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT token_hash, family_id, tenant_id, client_app_id, platform, user_id, scope, auth_time, amr,
                expires_at, used_at, revoked_at
         FROM refresh_tokens WHERE token_hash = ?",
    )
    .bind(sha256_hex(token.as_bytes()))
    .fetch_optional(&st.pool)
    .await?;
    let row =
        row.ok_or_else(|| AadError::invalid_grant(9002313, "Invalid request. Request is malformed or invalid."))?;
    if row.tenant_id != tenant.id {
        return Err(AadError::invalid_grant(
            700005,
            "Provided refresh token is intended to use against other tenant, thus rejected.",
        ));
    }
    let azpacr = authenticate_for_platform(st, tenant, headers, params, &row.platform, &row.client_app_id).await?;

    let revoked = || AadError::invalid_grant(50173, "The provided grant has expired due to it being revoked.");
    if row.revoked_at.is_some() {
        return Err(revoked());
    }
    if row.used_at.is_some() {
        // A rotated token was replayed: assume theft and revoke the chain.
        revoke_family(st, &row.family_id).await?;
        return Err(revoked());
    }
    if row.expires_at <= now() {
        return Err(if row.platform == PLATFORM_SPA {
            AadError::invalid_grant(
                700084,
                "The refresh token was issued to a single page app (SPA), and therefore has a fixed, limited lifetime of 1.00:00:00, which cannot be extended. It is now expired and a new sign in request must be sent by the SPA to the sign in page.",
            )
        } else {
            AadError::invalid_grant(700082, "The refresh token has expired due to inactivity.")
        });
    }
    let res = sqlx::query("UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL")
        .bind(now())
        .bind(&row.token_hash)
        .execute(&st.pool)
        .await?;
    if res.rows_affected() != 1 {
        revoke_family(st, &row.family_id).await?;
        return Err(revoked());
    }

    // Like Entra, a refresh token may be used for any resource: `scope` may differ
    // from the original request. Without `scope`, reuse the original.
    let scope = param(params, "scope").unwrap_or(&row.scope);
    let grant = scopes::resolve(&st.pool, tenant, scope).await?;
    let family = Family {
        id: row.family_id.clone(),
        code_hash: None,
        platform: row.platform.clone(),
        auth_time: row.auth_time,
        amr: serde_json::from_str(&row.amr).unwrap_or_default(),
        spa_expires_at: (row.platform == PLATFORM_SPA).then_some(row.expires_at),
    };
    issue(
        st,
        tenant,
        headers,
        params,
        &row.client_app_id,
        &row.user_id,
        &grant,
        None,
        azpacr,
        family,
    )
    .await
}

struct Family {
    id: String,
    code_hash: Option<String>,
    platform: String,
    auth_time: i64,
    amr: Vec<String>,
    /// SPA refresh tokens keep the family's original expiry.
    spa_expires_at: Option<i64>,
}

#[allow(clippy::too_many_arguments)]
async fn issue(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
    client_app_id: &str,
    user_id: &str,
    grant: &Grant,
    nonce: Option<&str>,
    azpacr: &str,
    family: Family,
) -> Result<Response, AadError> {
    let user = users::find(&st.pool, &tenant.id, user_id)
        .await?
        .filter(|u| u.enabled)
        .ok_or_else(|| AadError::invalid_grant(50057, "The user account is disabled."))?;
    let client: Application = apps::find(&st.pool, client_app_id)
        .await?
        .ok_or_else(|| AadError::app_not_found(client_app_id, &tenant.id))?;
    let sign_in = SignIn {
        tenant: tenant.clone(),
        user: user.clone(),
        client,
        auth_time: family.auth_time,
        amr: family.amr.clone(),
    };
    let issued = claims::issue(st, &sign_in, grant, nonce, azpacr).await?;

    let mut body = Map::new();
    body.insert("token_type".into(), json!("Bearer"));
    body.insert("scope".into(), json!(grant.granted.join(" ")));
    body.insert("expires_in".into(), json!(issued.expires_in));
    body.insert("ext_expires_in".into(), json!(issued.expires_in));
    body.insert("access_token".into(), json!(issued.access_token));

    // Entra issues a refresh token when offline_access was requested; on refresh
    // it always returns a new one (we rotate).
    if grant.has("offline_access") || family.code_hash.is_none() {
        let refresh = b64url(&random_bytes(48));
        let ts = now();
        let expires_at = family.spa_expires_at.unwrap_or(
            ts + if family.platform == PLATFORM_SPA {
                SPA_REFRESH_LIFETIME
            } else {
                tenant.settings.refresh_token_lifetime_secs
            },
        );
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, family_id, code_hash, tenant_id, client_app_id, platform, user_id,
                                         scope, auth_time, amr, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(sha256_hex(refresh.as_bytes()))
        .bind(&family.id)
        .bind(&family.code_hash)
        .bind(&tenant.id)
        .bind(client_app_id)
        .bind(&family.platform)
        .bind(&user.id)
        .bind(grant.granted.join(" "))
        .bind(family.auth_time)
        .bind(serde_json::to_string(&family.amr).map_err(anyhow::Error::from)?)
        .bind(ts)
        .bind(expires_at)
        .execute(&st.pool)
        .await?;
        body.insert("refresh_token".into(), json!(refresh));
    }
    if let Some(id_token) = issued.id_token {
        body.insert("id_token".into(), json!(id_token));
    }
    if param(params, "client_info") == Some("1") {
        body.insert("client_info".into(), json!(claims::client_info(&user)));
    }
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    no_store(resp.headers_mut());
    if let Some(id) = crate::error::client_request_id(headers).and_then(|c| c.parse().ok()) {
        resp.headers_mut().insert("client-request-id", id);
    }
    Ok(resp)
}

async fn revoke_family(st: &AppState, family_id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
        .bind(now())
        .bind(family_id)
        .execute(&st.pool)
        .await?;
    Ok(())
}

/// A replayed authorization code revokes the refresh tokens it produced (RFC 6749 §4.1.2).
async fn revoke_code_family(st: &AppState, code_hash: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE revoked_at IS NULL
         AND family_id IN (SELECT family_id FROM refresh_tokens WHERE code_hash = ?)",
    )
    .bind(now())
    .bind(code_hash)
    .execute(&st.pool)
    .await?;
    Ok(())
}
