//! `GET|POST /{tenant}/oauth2/v2.0/logout` (RP-initiated logout).
//!
//! Ends this browser's session in the tenant. Redirects to
//! `post_logout_redirect_uri` only if it is a registered redirect URI of the
//! client (named by `client_id` or by the `aud` of `id_token_hint`).

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::audit::{self, Actor, Channel, Event};
use crate::AppState;
use crate::apps;
use crate::html;
use crate::session::{self, SESSION_COOKIE};
use crate::tenant;

pub async fn logout(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw = if method == Method::POST {
        body.to_vec()
    } else {
        query.unwrap_or_default().into_bytes()
    };
    let params: HashMap<String, String> = url::form_urlencoded::parse(&raw).into_owned().collect();
    let get = |k: &str| params.get(k).map(String::as_str).filter(|v| !v.is_empty());

    let Ok(Some(tenant)) = tenant::resolve(&st.pool, &tenant_key).await else {
        return html::signed_out(None);
    };
    let signed_in = session::find(&st.pool, &headers, &tenant.id).await.ok().flatten();
    if let Err(e) = session::end(&st.pool, &headers, &tenant.id).await {
        tracing::error!(error = ?e, "ending session failed");
    }

    // The hint may be expired; only its signature and issuer matter here.
    let hinted_client = match get("id_token_hint") {
        Some(hint) => match st.keys.verify_ignoring_expiry(hint).await {
            Ok(claims) if claims.get("iss").and_then(Value::as_str) == Some(&st.public_url.issuer(&tenant.id)) => {
                claims.get("aud").and_then(Value::as_str).map(str::to_string)
            }
            _ => None,
        },
        None => None,
    };
    let client_id = get("client_id").map(str::to_string).or(hinted_client);
    // Resolve the claimed id once. `client_id` is caller text until it names a
    // real app in this tenant, so only the registered id is ever audited -- the
    // same rule the token endpoint applies to a claimed client id.
    let registered = match &client_id {
        Some(id) => apps::find(&st.pool, id)
            .await
            .ok()
            .flatten()
            .filter(|app| app.tenant_id == tenant.id),
        None => None,
    };

    let mut target = None;
    if let (Some(uri), Some(app)) = (get("post_logout_redirect_uri"), &registered)
        && let Ok(Some(_)) = apps::match_redirect_uri(&st.pool, app, uri).await
        && let Ok(mut url) = url::Url::parse(uri)
    {
        if let Some(state) = get("state") {
            url.query_pairs_mut().append_pair("state", state);
        }
        target = Some(url);
    }

    // Only a real session ending is an event; anonymous hits on this endpoint are noise.
    if let Some(s) = signed_in {
        let details = serde_json::json!({
            "via": Channel::EndSession.as_str(),
            "clientId": registered.as_ref().map(|app| app.app_id.clone()),
            "redirected": target.is_some(),
        });
        audit::record(
            &st,
            &tenant.id,
            Actor::Id(&s.user_id),
            Event::SessionEnd,
            Some(&s.user_id),
            details,
        )
        .await;
    }
    let mut resp = match target {
        Some(url) => {
            let mut r = StatusCode::FOUND.into_response();
            if let Ok(v) = HeaderValue::from_str(url.as_str()) {
                r.headers_mut().insert(header::LOCATION, v);
            }
            r
        }
        None => html::signed_out(Some(&tenant.name)),
    };
    // Other tenants' sessions share the cookie, so only drop it when none remain.
    if session::cookie(&headers, SESSION_COOKIE).is_some()
        && !session::has_any(&st.pool, &headers).await.unwrap_or(true)
    {
        resp.headers_mut().append(
            header::SET_COOKIE,
            session::clear_cookie(&st.public_url, SESSION_COOKIE),
        );
    }
    resp
}
