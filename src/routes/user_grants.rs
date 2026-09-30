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

use super::audit::{self, Channel, Event};
use super::token::{GrantType, authenticate_confidential_client, param};
use crate::AppState;
use crate::apps::{self, Application, PLATFORM_SPA, PLATFORM_WEB};
use crate::claims::{self, Amr, Azpacr, IdType, SignIn};
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
) -> Result<Azpacr, AadError> {
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
        // A web client may authenticate with a secret or a certificate.
        return Ok(client.azpacr);
    }
    let client_id = param(params, "client_id").ok_or_else(|| AadError::missing_parameter("client_id"))?;
    if !client_id.eq_ignore_ascii_case(expected_client) {
        return Err(AadError::invalid_grant(
            70000,
            "The provided grant was issued to a different client.",
        ));
    }
    Ok(Azpacr::None)
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
    let row: Option<CodeRow> = sqlx::query_as(crate::db::q(
        &st.pool,
        "SELECT code_hash, tenant_id, client_app_id, redirect_uri, platform, user_id, scope, nonce, code_challenge,
                code_challenge_method, auth_time, amr, expires_at, redeemed_at
         FROM auth_codes WHERE code_hash = ?",
    ))
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
        // Only the outcome and identifiers: never the code itself, nor its hash.
        let details = json!({ "clientId": row.client_app_id });
        audit::record(
            st,
            &tenant.id,
            &row.user_id,
            Event::TokenCodeReplayed,
            Some(&row.client_app_id),
            details,
        )
        .await;
        revoke_code_family(st, tenant, &row.user_id, &row.code_hash).await?;
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
    let res = sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE auth_codes SET redeemed_at = ? WHERE code_hash = ? AND redeemed_at IS NULL",
    ))
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
        rotation: false,
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
    let row: Option<RefreshRow> = sqlx::query_as(crate::db::q(
        &st.pool,
        "SELECT token_hash, family_id, tenant_id, client_app_id, platform, user_id, scope, auth_time, amr,
                expires_at, used_at, revoked_at
         FROM refresh_tokens WHERE token_hash = ?",
    ))
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
        revoke_family(st, tenant, &row.user_id, &row.family_id, RevokeCause::RefreshReuse).await?;
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
    let res = sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
    ))
    .bind(now())
    .bind(&row.token_hash)
    .execute(&st.pool)
    .await?;
    if res.rows_affected() != 1 {
        revoke_family(st, tenant, &row.user_id, &row.family_id, RevokeCause::RefreshReuse).await?;
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
        rotation: true,
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

pub(super) struct Family {
    pub(super) id: String,
    pub(super) code_hash: Option<String>,
    pub(super) platform: String,
    pub(super) auth_time: i64,
    pub(super) amr: Vec<String>,
    /// SPA refresh tokens keep the family's original expiry.
    pub(super) spa_expires_at: Option<i64>,
    /// True when rotating an existing refresh token, which always yields a new
    /// one even if `offline_access` is not asked for again.
    pub(super) rotation: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn issue(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
    client_app_id: &str,
    user_id: &str,
    grant: &Grant,
    nonce: Option<&str>,
    azpacr: Azpacr,
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
    if grant.has("offline_access") || family.rotation {
        let refresh = b64url(&random_bytes(48));
        let ts = now();
        let expires_at = family.spa_expires_at.unwrap_or(
            ts + if family.platform == PLATFORM_SPA {
                SPA_REFRESH_LIFETIME
            } else {
                tenant.settings.refresh_token_lifetime_secs
            },
        );
        sqlx::query(crate::db::q(
            &st.pool,
            "INSERT INTO refresh_tokens (token_hash, family_id, code_hash, tenant_id, client_app_id, platform, user_id,
                                         scope, auth_time, amr, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
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
    let details = json!({
        "grant": param(params, "grant_type").and_then(GrantType::parse).map(GrantType::as_str),
        "clientId": client_app_id,
        "resource": grant.resource.audience(),
        "scope": grant.granted.join(" "),
        "refreshToken": body.contains_key("refresh_token"),
        "familyId": family.id,
    });
    audit::record(
        st,
        &tenant.id,
        &user.id,
        Event::TokenIssued,
        Some(client_app_id),
        details,
    )
    .await;
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

/// Why a refresh-token family was revoked, recorded as `cause`.
#[derive(Clone, Copy)]
enum RevokeCause {
    /// A rotated refresh token was presented again.
    RefreshReuse,
    /// The authorization code that started the family was redeemed twice.
    CodeReplay,
}

impl RevokeCause {
    fn as_str(self) -> &'static str {
        match self {
            Self::RefreshReuse => "refresh_reuse",
            Self::CodeReplay => "code_replay",
        }
    }
}

async fn revoke_family(
    st: &AppState,
    tenant: &Tenant,
    user_id: &str,
    family_id: &str,
    cause: RevokeCause,
) -> anyhow::Result<()> {
    let res = sqlx::query(crate::db::q(
        &st.pool,
        "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
    ))
    .bind(now())
    .bind(family_id)
    .execute(&st.pool)
    .await?;
    // Nothing revoked means nothing changed, so no event. The family id names
    // a chain of tokens; it cannot be used as one.
    if res.rows_affected() > 0 {
        let details = json!({ "familyId": family_id, "cause": cause.as_str(), "tokens": res.rows_affected() });
        audit::record(
            st,
            &tenant.id,
            user_id,
            Event::RefreshFamilyRevoked,
            Some(user_id),
            details,
        )
        .await;
    }
    Ok(())
}

/// A replayed authorization code revokes the refresh tokens it produced (RFC 6749 §4.1.2).
/// Two statements rather than one self-referencing UPDATE: MySQL refuses to update a
/// table the same statement selects from (error 1093). Revocation is idempotent and
/// monotonic, so splitting it loses nothing.
async fn revoke_code_family(st: &AppState, tenant: &Tenant, user_id: &str, code_hash: &str) -> anyhow::Result<()> {
    let engine = crate::db::engine_of(&st.pool);
    let families: Vec<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT DISTINCT family_id FROM refresh_tokens WHERE code_hash = ?",
    ))
    .bind(code_hash)
    .fetch_all(&st.pool)
    .await?;
    for (id,) in families {
        revoke_family(st, tenant, user_id, &id, RevokeCause::CodeReplay).await?;
    }
    Ok(())
}

// ---- grant: urn:ietf:params:oauth:grant-type:jwt-bearer (on-behalf-of) ----

/// The only `requested_token_use` value Entra defines for this grant.
pub const REQUESTED_TOKEN_USE_OBO: &str = "on_behalf_of";

/// Exchange the user token a middle-tier API received for a token to a
/// downstream API, keeping the same user and how they authenticated.
pub async fn on_behalf_of(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Response, AadError> {
    // The middle tier must prove who it is; the user token alone is not enough.
    let client = authenticate_confidential_client(st, tenant, headers, params).await?;

    let requested =
        param(params, "requested_token_use").ok_or_else(|| AadError::missing_parameter("requested_token_use"))?;
    if requested != REQUESTED_TOKEN_USE_OBO {
        return Err(AadError::invalid_request(
            500131,
            format!(
                "The value '{requested}' for 'requested_token_use' is not valid. Expected '{REQUESTED_TOKEN_USE_OBO}'."
            ),
        ));
    }

    let assertion = param(params, "assertion").ok_or_else(|| AadError::missing_parameter("assertion"))?;
    let claims = st
        .keys
        .verify(assertion)
        .await
        .map_err(|_| AadError::invalid_obo_assertion())?;
    let claim = |name: &str| {
        claims
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };

    // The assertion has to be a user token this server issued, for this tenant,
    // and addressed to the very app that is now presenting it. Without the
    // audience check any API could replay a token meant for someone else.
    if claim("iss") != st.public_url.issuer(&tenant.id) || claim("tid") != tenant.id {
        return Err(AadError::invalid_obo_assertion());
    }
    if !claim("aud").eq_ignore_ascii_case(&client.app.app_id) {
        return Err(AadError::invalid_obo_assertion());
    }
    if claim("idtyp") != IdType::User.as_str() {
        return Err(AadError::invalid_obo_assertion());
    }
    let user_id = claim("oid");
    if user_id.is_empty() {
        return Err(AadError::invalid_obo_assertion());
    }

    let scope = param(params, "scope").ok_or_else(|| AadError::missing_parameter("scope"))?;
    let grant = scopes::resolve(&st.pool, tenant, scope).await?;

    // Carry the original sign-in forward, so the downstream API sees how and when
    // the user actually authenticated rather than the time of this exchange.
    let auth_time = claims
        .get("auth_time")
        .or_else(|| claims.get("iat"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(now);
    let amr: Vec<String> = claims
        .get("amr")
        .and_then(serde_json::Value::as_array)
        .map(|vs| {
            vs.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![Amr::Pwd.as_str().to_string()]);

    issue(
        st,
        tenant,
        headers,
        params,
        &client.app.app_id,
        &user_id,
        &grant,
        None,
        client.azpacr,
        Family {
            id: b64url(&random_bytes(16)),
            code_hash: None,
            platform: PLATFORM_WEB.to_string(),
            auth_time,
            amr,
            spa_expires_at: None,
            rotation: false,
        },
    )
    .await
}

// ---- grant: password (resource owner password credentials) ----

/// ROPC. Off unless the app is opted in: the client sees the user's password,
/// so it cannot support MFA and should be a last resort for legacy clients.
pub async fn password(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Response, AadError> {
    let client = authenticate_confidential_client(st, tenant, headers, params).await?;
    if !client.app.allow_password_grant {
        return Err(AadError::password_grant_not_allowed(&client.app.app_id));
    }

    let username = param(params, "username").ok_or_else(|| AadError::missing_parameter("username"))?;
    let password = param(params, "password").ok_or_else(|| AadError::missing_parameter("password"))?;
    let scope = param(params, "scope").ok_or_else(|| AadError::missing_parameter("scope"))?;

    let (outcome, trace) = users::authenticate_traced(&st.pool, tenant, username, password).await?;
    audit::sign_in_failure(
        st,
        &tenant.id,
        username,
        &outcome,
        &trace,
        Channel::Ropc,
        &client.app.app_id,
    )
    .await;
    let user = match outcome {
        users::AuthResult::Ok(user) => {
            // The browser and device flows both audit a successful sign-in; without
            // this one, a password verified through ROPC leaves only `token.issued`,
            // so "when did this user last authenticate" is unanswerable for a client
            // that uses the password grant. No session is created, so no
            // `session.create` belongs here.
            let details = serde_json::json!({
                "via": Channel::Ropc.as_str(),
                "clientId": client.app.app_id,
            });
            audit::record(st, &tenant.id, &user.id, Event::SignIn, Some(&user.id), details).await;
            user
        }
        // An unknown user and a wrong password give the same answer, so the token
        // endpoint cannot be used to discover which accounts exist.
        users::AuthResult::InvalidCredentials => {
            return Err(AadError::invalid_grant(
                50126,
                "AADSTS50126: Error validating credentials due to invalid username or password.",
            ));
        }
        users::AuthResult::Locked => {
            return Err(AadError::invalid_grant(
                50053,
                "AADSTS50053: The account is temporarily locked because of too many failed sign-in attempts.",
            ));
        }
        users::AuthResult::Disabled => {
            return Err(AadError::invalid_grant(
                50057,
                "AADSTS50057: The user account is disabled.",
            ));
        }
    };

    let grant = scopes::resolve(&st.pool, tenant, scope).await?;
    let ts = now();
    issue(
        st,
        tenant,
        headers,
        params,
        &client.app.app_id,
        &user.id,
        &grant,
        None,
        client.azpacr,
        Family {
            id: b64url(&random_bytes(16)),
            code_hash: None,
            platform: PLATFORM_WEB.to_string(),
            auth_time: ts,
            amr: vec![Amr::Pwd.as_str().to_string()],
            spa_expires_at: None,
            rotation: false,
        },
    )
    .await
}
