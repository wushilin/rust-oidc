//! `GET|POST /{tenant}/oauth2/v2.0/authorize` and the sign-in form it renders.
//!
//! Validation order follows Entra/OIDC: problems with the client or the
//! redirect URI are shown on an error page (never redirected, to avoid open
//! redirects); everything after that is reported to the client's redirect URI.

// Pages (login form, error page) travel in `Err`; boxing them buys nothing here.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::apps::{self, Application, PLATFORM_SPA, ServicePrincipal};
use crate::error::AadError;
use crate::html;
use crate::scopes;
use crate::session::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::tenant::{self, Tenant};
use crate::users::{self, AuthResult, User};
use crate::util::{b64url, ct_eq, now, random_bytes, sha256_hex};

pub const CODE_LIFETIME: i64 = 600;

type Params = HashMap<String, String>;

fn parse(raw: &[u8]) -> Params {
    let mut map = Params::new();
    for (k, v) in url::form_urlencoded::parse(raw) {
        map.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    map
}

fn get<'a>(p: &'a Params, name: &str) -> Option<&'a str> {
    p.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

fn is_openid_request(p: &Params) -> bool {
    get(p, "scope").is_some_and(|s| s.split_whitespace().any(|x| x == "openid"))
}

pub async fn authorize(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // OIDC Core 3.1.2.1: authorize must accept GET and POST (form body).
    let raw = if method == Method::POST {
        body.to_vec()
    } else {
        query.unwrap_or_default().into_bytes()
    };
    let params = parse(&raw);
    let request = String::from_utf8_lossy(&raw).into_owned();
    match run(&st, &tenant_key, &headers, &params, &request, Interaction::None).await {
        Ok(resp) | Err(resp) => resp,
    }
}

/// What the user just did on one of our pages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Interaction {
    None,
    /// Signed in with a password just now.
    SignedIn,
    /// Picked the existing account on the account picker.
    ChoseAccount,
}

/// A validated request, ready to be answered at the client's redirect URI.
struct Validated {
    tenant: Tenant,
    client: Application,
    sp: ServicePrincipal,
    redirect_uri: url::Url,
    platform: String,
    response_mode: ResponseMode,
    state: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

impl Validated {
    /// Deliver `params` to the client's redirect URI.
    fn respond(&self, mut params: Vec<(&str, String)>) -> Response {
        if let Some(state) = &self.state {
            params.push(("state", state.clone()));
        }
        let mut url = self.redirect_uri.clone();
        match self.response_mode {
            ResponseMode::Query => {
                url.query_pairs_mut()
                    .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())));
                redirect(url.as_str())
            }
            ResponseMode::Fragment => {
                let fragment = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())))
                    .finish();
                url.set_fragment(Some(&fragment));
                redirect(url.as_str())
            }
            ResponseMode::FormPost => html::form_post(&url, &params),
        }
    }

    fn error(&self, err: AadError) -> Response {
        let error = err.error.to_string();
        self.respond(vec![("error", error), ("error_description", err.description())])
    }
}

fn redirect(location: &str) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Validation that must not redirect: tenant, client, redirect URI.
async fn validate_client(
    st: &AppState,
    tenant_key: &str,
    params: &Params,
) -> Result<(Tenant, Application, ServicePrincipal, url::Url, String), Response> {
    let page_error = |tenant: Option<&str>, err: AadError| html::error(tenant, &err.description());
    let internal = |e: anyhow::Error| page_error(None, AadError::from(e));

    let tenant = tenant::resolve(&st.pool, tenant_key)
        .await
        .map_err(internal)?
        .ok_or_else(|| page_error(None, AadError::tenant_not_found(tenant_key)))?;
    let tn = Some(tenant.name.as_str());

    let client_id = get(params, "client_id").ok_or_else(|| page_error(tn, AadError::missing_parameter("client_id")))?;
    let app = apps::find(&st.pool, client_id).await.map_err(internal)?;
    let sp = match &app {
        Some(app) => apps::service_principal(&st.pool, &tenant.id, &app.app_id)
            .await
            .map_err(internal)?,
        None => None,
    };
    let (Some(app), Some(sp)) = (app, sp) else {
        return Err(page_error(tn, AadError::app_not_found(client_id, &tenant.id)));
    };

    let registered = apps::redirect_uris(&st.pool, &app).await.map_err(internal)?;
    let requested = match get(params, "redirect_uri") {
        Some(uri) => uri.to_string(),
        // Entra falls back to the only registered URI when none is given. OIDC
        // Core makes redirect_uri mandatory, so only plain OAuth requests get that.
        None if registered.len() == 1 && !is_openid_request(params) => registered[0].1.clone(),
        None => return Err(page_error(tn, AadError::missing_parameter("redirect_uri"))),
    };
    let platform = registered
        .iter()
        .find(|(_, uri)| apps::redirect_uri_matches(uri, &requested))
        .map(|(p, _)| p.clone());
    let (Some(platform), Ok(url)) = (platform, url::Url::parse(&requested)) else {
        return Err(page_error(
            tn,
            AadError::invalid_request(
                50011,
                format!(
                    "The redirect URI '{requested}' specified in the request does not match the redirect URIs configured for the application '{}'. Make sure the redirect URI sent in the request matches one added to your application in the Azure portal.",
                    app.app_id
                ),
            ),
        ));
    };
    Ok((tenant, app, sp, url, platform))
}

async fn run(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    interaction: Interaction,
) -> Result<Response, Response> {
    let (tenant, client, sp, redirect_uri, platform) = validate_client(st, tenant_key, params).await?;

    let response_mode = match get(params, "response_mode") {
        None | Some("query") => ResponseMode::Query,
        Some("fragment") => ResponseMode::Fragment,
        Some("form_post") => ResponseMode::FormPost,
        Some(other) => {
            let v = Validated {
                tenant,
                client,
                sp,
                redirect_uri,
                platform,
                response_mode: ResponseMode::Query,
                state: get(params, "state").map(str::to_string),
            };
            return Ok(v.error(AadError::invalid_request(
                900144,
                format!("The response_mode '{other}' is not supported."),
            )));
        }
    };
    let v = Validated {
        tenant,
        client,
        sp,
        redirect_uri,
        platform,
        response_mode,
        state: get(params, "state").map(str::to_string),
    };

    match continue_authorize(st, headers, params, request, interaction, &v).await {
        Ok(resp) => Ok(resp),
        Err(Step::Redirect(err)) => Ok(v.error(err)),
        Err(Step::Page(resp)) => Ok(resp),
    }
}

enum Step {
    /// Report an OAuth error to the client.
    Redirect(AadError),
    /// Show a page (login form, account picker, error page).
    Page(Response),
}

impl From<AadError> for Step {
    fn from(e: AadError) -> Self {
        Step::Redirect(e)
    }
}

impl From<anyhow::Error> for Step {
    fn from(e: anyhow::Error) -> Self {
        Step::Redirect(AadError::from(e))
    }
}

struct Prompt {
    none: bool,
    login: bool,
    select_account: bool,
}

async fn continue_authorize(
    st: &AppState,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    interaction: Interaction,
    v: &Validated,
) -> Result<Response, Step> {
    if get(params, "request").is_some() {
        return Err(AadError::new(
            StatusCode::BAD_REQUEST,
            "request_not_supported",
            90023,
            "The 'request' parameter is not supported.",
        )
        .into());
    }
    if get(params, "request_uri").is_some() {
        return Err(AadError::new(
            StatusCode::BAD_REQUEST,
            "request_uri_not_supported",
            90023,
            "The 'request_uri' parameter is not supported.",
        )
        .into());
    }
    match get(params, "response_type") {
        None => return Err(AadError::missing_parameter("response_type").into()),
        Some("code") => {}
        Some(other) => {
            return Err(AadError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                700054,
                format!("response_type '{other}' is not enabled for the application."),
            )
            .into());
        }
    }
    let scope = get(params, "scope").ok_or_else(|| AadError::missing_parameter("scope"))?;
    let grant = scopes::resolve(&st.pool, &v.tenant, scope).await?;

    let code_challenge = get(params, "code_challenge");
    let method = get(params, "code_challenge_method");
    if let Some(challenge) = code_challenge {
        if !matches!(method, None | Some("S256") | Some("plain")) {
            return Err(AadError::invalid_request(
                501491,
                "Invalid size of Code_Challenge parameter. Only 'S256' and 'plain' are supported code_challenge_method values.",
            )
            .into());
        }
        if challenge.len() < 43 || challenge.len() > 128 {
            return Err(AadError::invalid_request(501491, "Invalid size of Code_Challenge parameter.").into());
        }
    } else if v.platform == PLATFORM_SPA {
        return Err(AadError::invalid_request(
            9002325,
            "Proof Key for Code Exchange is required for cross-origin authorization code redemption.",
        )
        .into());
    }

    let mut prompt = Prompt {
        none: false,
        login: false,
        select_account: false,
    };
    for p in get(params, "prompt").unwrap_or_default().split_whitespace() {
        match p {
            "none" => prompt.none = true,
            "login" => prompt.login = true,
            "select_account" => prompt.select_account = true,
            "consent" | "create" => {} // apps are admin-consented; no sign-up here
            other => {
                return Err(AadError::invalid_request(90023, format!("Invalid prompt value '{other}'.")).into());
            }
        }
    }
    if prompt.none && (prompt.login || prompt.select_account) {
        return Err(AadError::invalid_request(90023, "prompt=none cannot be combined with other values.").into());
    }
    let max_age = match get(params, "max_age") {
        Some(s) => Some(
            s.parse::<i64>()
                .map_err(|_| AadError::invalid_request(90023, "Invalid max_age value."))?,
        ),
        None => None,
    };
    let login_hint = get(params, "login_hint");

    if !v.sp.enabled {
        return Err(AadError::app_disabled(&v.client.app_id, &v.client.display_name).into());
    }

    // ---- who is the user? ----
    let session = session::find(&st.pool, headers, &v.tenant.id).await?;
    let user = match &session {
        Some(s) => users::find(&st.pool, &v.tenant.id, &s.user_id).await?,
        None => None,
    };
    let fresh = interaction == Interaction::SignedIn;
    let mut needs_login = user.is_none();
    if !fresh {
        needs_login |= prompt.login;
        if let (Some(max_age), Some(s)) = (max_age, &session) {
            needs_login |= now() - s.auth_time > max_age;
        }
        if let (Some(hint), Some(u)) = (login_hint, &user) {
            needs_login |= crate::util::fold(hint) != crate::util::fold(&u.upn);
        }
    }
    if needs_login {
        if prompt.none {
            return Err(AadError::new(
                StatusCode::BAD_REQUEST,
                "login_required",
                50058,
                "A silent sign-in request was sent but no user is signed in.",
            )
            .into());
        }
        return Err(Step::Page(login_page(
            st,
            v,
            request,
            login_hint.unwrap_or_default(),
            None,
        )));
    }
    let (session, user) = (session.expect("checked"), user.expect("checked"));

    if prompt.select_account && interaction == Interaction::None {
        return Err(Step::Page(account_picker(st, v, request, &user)));
    }

    if v.sp.app_role_assignment_required && !apps::user_is_assigned(&st.pool, &v.sp.id, &user.id).await? {
        let err = AadError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            50105,
            format!(
                "Your administrator has configured the application {} ('{}') to block users unless they are specifically granted ('assigned') access to the application.",
                v.client.display_name, v.client.app_id
            ),
        );
        return Err(Step::Page(html::error(Some(&v.tenant.name), &err.description())));
    }

    // ---- issue the code ----
    let code = b64url(&random_bytes(48));
    let ts = now();
    sqlx::query(
        crate::db::sql_stmt(crate::db::engine_of(&st.pool), "INSERT INTO auth_codes (code_hash, tenant_id, client_app_id, redirect_uri, platform, user_id, scope, nonce,
                                 code_challenge, code_challenge_method, auth_time, amr, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
    )
    .bind(sha256_hex(code.as_bytes()))
    .bind(&v.tenant.id)
    .bind(&v.client.app_id)
    // Empty when the client omitted redirect_uri; then the token request may omit it too.
    .bind(get(params, "redirect_uri").unwrap_or_default())
    .bind(&v.platform)
    .bind(&user.id)
    .bind(grant.granted.join(" "))
    .bind(get(params, "nonce"))
    .bind(code_challenge)
    .bind(code_challenge.map(|_| method.unwrap_or("plain")))
    .bind(session.auth_time)
    .bind(serde_json::to_string(&session.amr).map_err(anyhow::Error::from)?)
    .bind(ts)
    .bind(ts + CODE_LIFETIME)
    .execute(&st.pool)
    .await
    .map_err(anyhow::Error::from)?;

    let mut out = vec![("code", code)];
    if get(params, "client_info") == Some("1") {
        out.push(("client_info", crate::claims::client_info(&user)));
    }
    Ok(v.respond(out))
}

fn form_action(st: &AppState, v: &Validated) -> String {
    st.public_url.tenant_url(&v.tenant.id, "login")
}

/// Render the login page and set a fresh CSRF cookie for it.
fn login_page(st: &AppState, v: &Validated, request: &str, upn: &str, error: Option<&str>) -> Response {
    let csrf = session::new_token();
    let mut resp = html::login(&html::LoginForm {
        tenant_name: &v.tenant.name,
        client_name: &v.client.display_name,
        action: &form_action(st, v),
        csrf: &csrf,
        request,
        upn,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

fn account_picker(st: &AppState, v: &Validated, request: &str, user: &User) -> Response {
    let csrf = session::new_token();
    let mut resp = html::account_picker(&html::AccountPicker {
        tenant_name: &v.tenant.name,
        client_name: &v.client.display_name,
        action: &form_action(st, v),
        csrf: &csrf,
        request,
        upn: &user.upn,
        display_name: user.display_name.as_deref().unwrap_or(&user.upn),
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// `POST /{tenant}/login` — the sign-in form and account picker submit here.
/// The original authorize request travels in the `request` field and is
/// validated again from scratch.
pub async fn login(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = parse(&body);
    let request = form.get("request").cloned().unwrap_or_default();
    let params = parse(request.as_bytes());

    let v = match validate_client(&st, &tenant_key, &params).await {
        Ok((tenant, client, sp, redirect_uri, platform)) => Validated {
            tenant,
            client,
            sp,
            redirect_uri,
            platform,
            response_mode: ResponseMode::Query,
            state: None,
        },
        Err(page) => return page,
    };

    // Double-submit CSRF check: the form must echo the cookie set with the page.
    let csrf_ok = match (session::cookie(&headers, CSRF_COOKIE), form.get("csrf")) {
        (Some(c), Some(f)) => ct_eq(&c, f),
        _ => false,
    };
    if !csrf_ok {
        return login_page(
            &st,
            &v,
            &request,
            "",
            Some("Your session expired. Please sign in again."),
        );
    }

    let result = match form.get("op").map(String::as_str) {
        Some("continue") => run(&st, &tenant_key, &headers, &params, &request, Interaction::ChoseAccount).await,
        Some("other") => return login_page(&st, &v, &request, "", None),
        _ => {
            let upn = form.get("upn").map(|s| s.trim().to_string()).unwrap_or_default();
            let password = form.get("password").cloned().unwrap_or_default();
            let outcome = match users::authenticate(&st.pool, &v.tenant, &upn, &password).await {
                Ok(o) => o,
                Err(e) => return html::error(Some(&v.tenant.name), &AadError::from(e).description()),
            };
            let message = match outcome {
                AuthResult::Ok(user) => {
                    return match signed_in(&st, &tenant_key, &headers, &params, &request, &v, &user).await {
                        Ok(resp) | Err(resp) => resp,
                    };
                }
                AuthResult::InvalidCredentials => {
                    "Your account or password is incorrect. (AADSTS50126: Error validating credentials due to invalid username or password.)"
                }
                AuthResult::Locked => {
                    "Your account is temporarily locked to prevent unauthorized use. Try again later. (AADSTS50053)"
                }
                AuthResult::Disabled => "Your account has been disabled. (AADSTS50057: The user account is disabled.)",
            };
            return login_page(&st, &v, &request, &upn, Some(message));
        }
    };
    match result {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn signed_in(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    user: &User,
) -> Result<Response, Response> {
    let amr = ["pwd"];
    let lifetime = v.tenant.settings.session_lifetime_secs;
    let cookie = session::create(&st.pool, headers, &v.tenant.id, &user.id, &amr, lifetime)
        .await
        .map_err(|e| html::error(Some(&v.tenant.name), &AadError::from(e).description()))?;

    // Continue the original request as the newly signed-in user.
    let mut headers = headers.clone();
    let existing = session::cookie(&headers, SESSION_COOKIE);
    if existing.as_deref() != Some(cookie.as_str()) {
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={cookie}")).expect("ascii"),
        );
    }
    let mut resp = run(st, tenant_key, &headers, params, request, Interaction::SignedIn).await?;
    let h = resp.headers_mut();
    h.append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, SESSION_COOKIE, &cookie, lifetime),
    );
    h.append(header::SET_COOKIE, session::clear_cookie(&st.public_url, CSRF_COOKIE));
    Ok(resp)
}
