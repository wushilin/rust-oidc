//! The server's front door, at the public URL's own path (`/rust-oidc`).
//!
//! Every page a user signs in to is a tenant's, and nothing in a bare URL says
//! which tenant. So the front door asks for the UPN and password, finds the
//! tenant owning the UPN's suffix (as the console's sign-in does), and hands the
//! form, unchanged, to that tenant's My Account sign-in with a 307, which keeps
//! the method and body. Everything after the password (a second factor, a new
//! password, lockout, the audit row) is My Account's, done once, there.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::html;
use crate::session::{self, CSRF_COOKIE};
use crate::tenant;

/// Shown for a UPN whose suffix no tenant owns: the same words My Account uses
/// for a wrong password, so the front door says nothing My Account would not.
const SIGN_IN_FAILED: &str = "Your account or password is incorrect. (AADSTS50126)";

fn action(st: &AppState) -> String {
    format!("{}/", st.public_url.base())
}

fn sign_in_page(st: &AppState, upn: &str, error: Option<&str>) -> Response {
    let csrf = session::new_token();
    let mut resp = html::login(&html::LoginForm {
        tenant_name: None,
        client_name: "My account",
        action: &action(st),
        csrf: &csrf,
        request: "",
        upn,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// `GET /`: the sign-in form.
pub async fn page(State(st): State<AppState>) -> Response {
    sign_in_page(&st, "", None)
}

/// `POST /`: on to the UPN's tenant. Nothing is checked or written here; the
/// CSRF token and the password are My Account's to check.
pub async fn post(State(st): State<AppState>, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let upn = form.get("upn").map(|u| u.trim()).unwrap_or_default();
    let Some((_, domain)) = upn.rsplit_once('@') else {
        return sign_in_page(&st, upn, Some(SIGN_IN_FAILED));
    };
    let tenant = match tenant::resolve(&st.pool, domain).await {
        Ok(Some(t)) => t,
        Ok(None) => return sign_in_page(&st, upn, Some(SIGN_IN_FAILED)),
        Err(e) => {
            tracing::error!("tenant lookup failed at the front door: {e}");
            return html::error(None, "Something went wrong. Please try again.");
        }
    };
    let target = st.public_url.tenant_url(&tenant.id, "myaccount");
    let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
    if let Ok(v) = HeaderValue::from_str(&target) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// `/admin/` is the console's sign-in too.
pub async fn admin_slash(State(st): State<AppState>) -> Response {
    let mut resp = StatusCode::PERMANENT_REDIRECT.into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("{}/admin", st.public_url.base())) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}
