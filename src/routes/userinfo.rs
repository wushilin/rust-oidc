//! `GET|POST /oidc/userinfo`, Entra's UserInfo endpoint (Entra hosts it on
//! Microsoft Graph). Accepts the "Graph" access token issued when a client asks
//! for OIDC scopes without naming an API.

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::scopes::GRAPH_APP_ID;
use crate::{tenant, users};

fn unauthorized(description: &str) -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid_token", "error_description": description })),
    )
        .into_response();
    let challenge = format!(r#"Bearer error="invalid_token", error_description="{description}""#);
    if let Ok(v) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

pub async fn userinfo(State(st): State<AppState>, method: Method, headers: HeaderMap, body: Bytes) -> Response {
    // RFC 6750: bearer token in the Authorization header, or (POST) in the form body.
    let from_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(|t| t.trim().to_string());
    let from_body = (method == Method::POST)
        .then(|| {
            url::form_urlencoded::parse(&body)
                .into_owned()
                .collect::<HashMap<String, String>>()
                .remove("access_token")
        })
        .flatten();
    let token = match (from_header, from_body) {
        (Some(t), None) | (None, Some(t)) => t,
        (Some(_), Some(_)) => return unauthorized("The access token must be sent in exactly one place."),
        (None, None) => {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return resp;
        }
    };

    let claims = match st.keys.verify(&token).await {
        Ok(c) => c,
        Err(_) => return unauthorized("The access token is invalid or expired."),
    };
    let str_claim = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    let (tid, oid, aud) = (str_claim("tid"), str_claim("oid"), str_claim("aud"));
    if aud != GRAPH_APP_ID || str_claim("idtyp") != "user" {
        return unauthorized("The access token was not issued for the UserInfo endpoint.");
    }
    let Ok(Some(t)) = tenant::resolve(&st.pool, &tid).await else {
        return unauthorized("The access token's tenant is not valid.");
    };
    if str_claim("iss") != st.public_url.issuer(&t.id) {
        return unauthorized("The access token's issuer is not valid.");
    }
    let Ok(Some(user)) = users::find(&st.pool, &t.id, &oid).await else {
        return unauthorized("The user no longer exists.");
    };
    if !user.enabled {
        return unauthorized("The user account is disabled.");
    }
    let scopes: Vec<&str> = claims
        .get("scp")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split(' ')
        .collect();

    // Same fields as Entra's UserInfo response.
    let mut out = Map::new();
    out.insert("sub".into(), json!(str_claim("sub")));
    if scopes.contains(&"profile") {
        out.insert(
            "name".into(),
            json!(user.display_name.clone().unwrap_or_else(|| user.upn.clone())),
        );
        if let Some(v) = &user.family_name {
            out.insert("family_name".into(), json!(v));
        }
        if let Some(v) = &user.given_name {
            out.insert("given_name".into(), json!(v));
        }
    }
    if scopes.contains(&"email")
        && let Some(email) = &user.email
    {
        out.insert("email".into(), json!(email));
    }
    let mut resp = Json(Value::Object(out)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
