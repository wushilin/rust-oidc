//! `GET|POST /{tenant}/oauth2/v2.0/authorize` and the sign-in form it renders.
//!
//! Validation order follows Entra/OIDC: problems with the client or the
//! redirect URI are shown on an error page (never redirected, to avoid open
//! redirects); everything after that is reported to the client's redirect URI.

use crate::routes::audit::SignInReason;
use crate::users::Attempt;
use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::audit::{self, Actor, Channel, Event};
use crate::AppState;
use crate::access;
use crate::admin::routes::Settled;
use crate::apps::{self, Application, RedirectPlatform, ServicePrincipal};
use crate::claims::{self, Acr, Amr, Azpacr};
use crate::error::{AadError, Aadsts, OAuthError};
use crate::html;
use crate::mfa::{self, Purpose};
use crate::scopes;
use crate::session::{self, CSRF_COOKIE, KeepSignedIn, MFA_DEVICE_COOKIE, SESSION_COOKIE};
use crate::tenant::{self, Tenant, TenantSettings};
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
    /// Pressed Allow on the consent page.
    Consented,
    /// Pressed Deny on it.
    ConsentDenied,
}

/// A validated request, ready to be answered at the client's redirect URI.
struct Validated {
    tenant: Tenant,
    client: Application,
    sp: ServicePrincipal,
    redirect_uri: url::Url,
    platform: RedirectPlatform,
    response_mode: ResponseMode,
    state: Option<String>,
}

/// The response types Entra accepts.
///
/// An enum of whole combinations rather than three booleans, so every decision that
/// depends on what the response carries -- the default response mode, whether a nonce
/// is required, which hash claims bind the ID token -- is an exhaustive match the
/// compiler checks. Any combination not listed is refused: Entra advertises
/// `code`, `id_token`, `code id_token` and `id_token token`, and its documentation
/// additionally demonstrates bare `token`.
///
/// Public because the admin console's flow tester offers the same closed set on a
/// form and has to spell each one back into a request; there is one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    IdToken,
    Token,
    CodeIdToken,
    IdTokenToken,
}

impl ResponseType {
    pub const ALL: &'static [ResponseType] = &[
        Self::Code,
        Self::IdToken,
        Self::Token,
        Self::CodeIdToken,
        Self::IdTokenToken,
    ];

    /// The canonical spelling, which is what `response_types_supported` publishes
    /// and what the flow tester puts in a request.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::IdToken => "id_token",
            Self::Token => "token",
            Self::CodeIdToken => "code id_token",
            Self::IdTokenToken => "id_token token",
        }
    }

    /// Order-insensitive: the value is a space-delimited *set*, and Entra's own docs
    /// spell the hybrid type both ways round.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts: Vec<&str> = raw.split_whitespace().collect();
        parts.sort_unstable();
        parts.dedup();
        match parts.as_slice() {
            ["code"] => Some(Self::Code),
            ["id_token"] => Some(Self::IdToken),
            ["token"] => Some(Self::Token),
            ["code", "id_token"] => Some(Self::CodeIdToken),
            ["id_token", "token"] => Some(Self::IdTokenToken),
            _ => None,
        }
    }

    pub fn has_code(self) -> bool {
        matches!(self, Self::Code | Self::CodeIdToken)
    }

    pub fn has_id_token(self) -> bool {
        matches!(self, Self::IdToken | Self::CodeIdToken | Self::IdTokenToken)
    }

    pub fn has_access_token(self) -> bool {
        matches!(self, Self::Token | Self::IdTokenToken)
    }

    /// Whether a token travels in the response itself, rather than only a code.
    pub fn is_front_channel(self) -> bool {
        self.has_id_token() || self.has_access_token()
    }
}

/// Entra's answer when the app registration has not enabled front-channel tokens.
/// The error value and message are quoted from Microsoft's implicit-flow
/// documentation; the AADSTS number is our closest match, not a verified pairing.
fn response_type_not_allowed() -> AadError {
    AadError::new(
        StatusCode::BAD_REQUEST,
        OAuthError::UnsupportedResponse,
        Aadsts::ResponseTypeNotAllowed,
        "The provided value for the input parameter 'response_type' is not allowed for this client. Expected value is 'code'",
    )
}

/// Where the authorize response is delivered. Public for the same reason
/// [`ResponseType`] is: the console's flow tester offers the same three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

impl ResponseMode {
    pub const ALL: &'static [ResponseMode] = &[Self::Query, Self::Fragment, Self::FormPost];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }

    /// `None` for a mode this server does not implement, which is a caller error
    /// reported as such, never defaulted: a token must not fall back to a query
    /// string because the mode was misspelled.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|m| m.as_str() == raw)
    }
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
        let error = err.error.as_str().to_string();
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
) -> Result<(Tenant, Application, ServicePrincipal, url::Url, RedirectPlatform), Response> {
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
        .map(|(p, _)| *p);
    let (Some(platform), Ok(url)) = (platform, url::Url::parse(&requested)) else {
        return Err(page_error(
            tn,
            AadError::invalid_request(
                Aadsts::RedirectUriMismatch,
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

    // Entra defaults the response mode to fragment when an ID token is involved, and
    // a token must never travel in a query string: it would be logged by proxies and
    // leak through Referer. Parsed leniently -- continue_authorize reports a bad value.
    let front_channel = get(params, "response_type")
        .and_then(ResponseType::parse)
        .is_some_and(ResponseType::is_front_channel);
    let requested_mode = get(params, "response_mode");
    let response_mode = match requested_mode.map(ResponseMode::parse) {
        Some(Some(ResponseMode::Query)) if front_channel => {
            let v = Validated {
                tenant,
                client,
                sp,
                redirect_uri,
                platform,
                // Report it through the mode this request should have used.
                response_mode: ResponseMode::Fragment,
                state: get(params, "state").map(str::to_string),
            };
            return Ok(v.error(AadError::invalid_request(
                Aadsts::MissingOrInvalidParameter,
                "The response_mode 'query' cannot be used with a response_type that returns a token.",
            )));
        }
        None if front_channel => ResponseMode::Fragment,
        None | Some(Some(ResponseMode::Query)) => ResponseMode::Query,
        Some(Some(mode)) => mode,
        Some(None) => {
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
                Aadsts::MissingOrInvalidParameter,
                format!(
                    "The response_mode '{}' is not supported.",
                    requested_mode.unwrap_or_default()
                ),
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

/// A `prompt` value on the authorize endpoint.
///
/// Entra documents exactly four: *"Valid values are `login`, `none`, `consent`,
/// and `select_account`"* (v2-oauth2-auth-code-flow, fetched 30 Sep 2026). Those
/// four are what [`Prompt::SUPPORTED`] advertises in discovery.
///
/// [`Prompt::Create`] is a fifth we accept and ignore. It is real in Entra, but on
/// **External ID** tenants (`*.ciamlogin.com`) with a self-service sign-up user
/// flow, not on the workforce v2 endpoint this server clones; what a workforce
/// tenant does with it is not documented and we have not captured it. Since this
/// server has no sign-up at all, accepting and ignoring it sends the caller to the
/// sign-in page, which is the least surprising of the options available. It is
/// deliberately not advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
    Create,
}

impl Prompt {
    pub const ALL: &'static [Prompt] = &[
        Self::None,
        Self::Login,
        Self::Consent,
        Self::SelectAccount,
        Self::Create,
    ];

    /// What `prompt_values_supported` advertises: Entra's documented four.
    pub const SUPPORTED: &'static [Prompt] = &[Self::None, Self::Login, Self::Consent, Self::SelectAccount];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
            Self::Create => "create",
        }
    }

    /// A value from the query string. `None` is a caller error, not something to
    /// tolerate: an unrecognised `prompt` is rejected with AADSTS90023, as Entra
    /// rejects one.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }
}

/// The prompts one request asked for.
///
/// `consent` shows the consent page even though nothing here requires it: apps
/// are treated as consented by an administrator, so the page appears only when a
/// client asks for it. `create` is accepted and has no effect, since there is no
/// sign-up.
#[derive(Debug, Default, Clone, Copy)]
pub struct PromptSet {
    pub none: bool,
    pub login: bool,
    pub select_account: bool,
    pub consent: bool,
}

impl PromptSet {
    /// Parse the space-delimited `prompt` parameter.
    pub fn parse(raw: &str) -> Result<Self, AadError> {
        let mut set = Self::default();
        for word in raw.split_whitespace() {
            match Prompt::parse(word) {
                Some(Prompt::None) => set.none = true,
                Some(Prompt::Login) => set.login = true,
                Some(Prompt::SelectAccount) => set.select_account = true,
                Some(Prompt::Consent) => set.consent = true,
                // Accepted, no effect: there is no sign-up.
                Some(Prompt::Create) => {}
                None => {
                    return Err(AadError::invalid_request(
                        Aadsts::UnsupportedParameter,
                        format!("Invalid prompt value '{word}'."),
                    ));
                }
            }
        }
        if set.none && (set.login || set.select_account || set.consent) {
            return Err(AadError::invalid_request(
                Aadsts::UnsupportedParameter,
                "prompt=none cannot be combined with other values.",
            ));
        }
        Ok(set)
    }
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
            OAuthError::RequestNotSupported,
            Aadsts::UnsupportedParameter,
            "The 'request' parameter is not supported.",
        )
        .into());
    }
    if get(params, "request_uri").is_some() {
        return Err(AadError::new(
            StatusCode::BAD_REQUEST,
            OAuthError::RequestUriNotSupported,
            Aadsts::UnsupportedParameter,
            "The 'request_uri' parameter is not supported.",
        )
        .into());
    }
    let response_type = match get(params, "response_type") {
        None => return Err(AadError::missing_parameter("response_type").into()),
        Some(raw) => match ResponseType::parse(raw) {
            Some(rt) => rt,
            None => return Err(response_type_not_allowed().into()),
        },
    };
    // Entra gates front-channel tokens per app registration, both off by default.
    if (response_type.has_id_token() && !v.client.allow_id_token_implicit)
        || (response_type.has_access_token() && !v.client.allow_access_token_implicit)
    {
        return Err(response_type_not_allowed().into());
    }
    // Required whenever an ID token comes back through the browser: it is what binds
    // the token to this request, and there is no code exchange to do it instead.
    let nonce = get(params, "nonce");
    if response_type.has_id_token() && nonce.is_none() {
        return Err(AadError::missing_parameter("nonce").into());
    }
    let scope = get(params, "scope").ok_or_else(|| AadError::missing_parameter("scope"))?;
    let grant = scopes::resolve(&st.pool, &v.tenant, scope).await?;
    if response_type.has_id_token() && !grant.has("openid") {
        return Err(AadError::invalid_request(
            Aadsts::MissingOrInvalidParameter,
            "The scope must include 'openid' when the response_type requests an id_token.",
        )
        .into());
    }

    let code_challenge = get(params, "code_challenge");
    let method = get(params, "code_challenge_method");
    if let Some(challenge) = code_challenge {
        if !matches!(method, None | Some("S256") | Some("plain")) {
            return Err(AadError::invalid_request(Aadsts::InvalidCodeChallenge,
                "Invalid size of Code_Challenge parameter. Only 'S256' and 'plain' are supported code_challenge_method values.",
            )
            .into());
        }
        if challenge.len() < 43 || challenge.len() > 128 {
            return Err(AadError::invalid_request(
                Aadsts::InvalidCodeChallenge,
                "Invalid size of Code_Challenge parameter.",
            )
            .into());
        }
    } else if v.platform == RedirectPlatform::Spa && response_type.has_code() {
        return Err(AadError::invalid_request(
            Aadsts::PkceRequired,
            "Proof Key for Code Exchange is required for cross-origin authorization code redemption.",
        )
        .into());
    }

    let prompt = PromptSet::parse(get(params, "prompt").unwrap_or_default())?;

    let max_age = match get(params, "max_age") {
        Some(s) => Some(
            s.parse::<i64>()
                .map_err(|_| AadError::invalid_request(Aadsts::UnsupportedParameter, "Invalid max_age value."))?,
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
        // Of this tenant, or of another one signed in here (see `access`).
        Some(s) => users::find_by_id(&st.pool, &s.user_id).await?,
        None => None,
    };
    let fresh = interaction == Interaction::SignedIn;
    // With `prompt=login consent` the sign-in page comes first and the consent
    // page second, so by the time the consent answer arrives the user has already
    // re-authenticated for this request. Honour that -- but only if the session
    // really is that recent, so posting a consent answer cannot be used to dodge
    // `prompt=login` on an old session.
    let answered_consent = matches!(interaction, Interaction::Consented | Interaction::ConsentDenied)
        && session
            .as_ref()
            .is_some_and(|s| now() - s.auth_time <= CONSENT_REAUTH_WINDOW);
    let mut needs_login = user.is_none();
    if !fresh {
        needs_login |= prompt.login && !answered_consent;
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
                OAuthError::LoginRequired,
                Aadsts::SilentSignInFailed,
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

    // ---- may this user use this application at all? ----
    let decision = access::decide(&st.pool, &v.tenant, &v.sp, &user).await?;
    if let Some(refusal) = decision.refusal {
        return Err(Step::Page(refused_page(v, &decision.home, refusal)));
    }

    // ---- a second factor, where one is needed and this session has none ----
    if !session.amr.iter().any(|m| m == Amr::Mfa.as_str()) {
        let step = mfa::step(&st.pool, &decision.home, &user.id, mfa::At::App(&v.sp)).await?;
        let step = stepped_up(step, params);
        if step != mfa::Step::Done {
            if prompt.none {
                let (code, what) = match step {
                    mfa::Step::Enroll => (
                        Aadsts::MfaRegistrationRequired,
                        "The user must set up multi-factor authentication.",
                    ),
                    _ => (Aadsts::MfaRequired, "The user must use multi-factor authentication."),
                };
                return Err(AadError::new(StatusCode::BAD_REQUEST, OAuthError::InteractionRequired, code, what).into());
            }
            return Err(Step::Page(start_mfa(st, v, request, &user, step, session.keep).await));
        }
    }

    if prompt.select_account && interaction == Interaction::None {
        return Err(Step::Page(account_picker(st, v, request, &user)));
    }

    // ---- consent, when the client asked for it ----
    if prompt.consent {
        match interaction {
            Interaction::Consented => {
                let details = serde_json::json!({ "clientId": v.client.app_id, "scope": grant.granted.join(" ") });
                audit::record(
                    st,
                    &v.tenant.id,
                    Actor::Id(&user.id),
                    Event::ConsentGranted,
                    Some(&v.client.app_id),
                    details,
                )
                .await;
            }
            Interaction::ConsentDenied => {
                let details = serde_json::json!({ "clientId": v.client.app_id, "scope": grant.granted.join(" ") });
                audit::record(
                    st,
                    &v.tenant.id,
                    Actor::Id(&user.id),
                    Event::ConsentDenied,
                    Some(&v.client.app_id),
                    details,
                )
                .await;
                return Err(AadError::new(
                    StatusCode::FORBIDDEN,
                    OAuthError::AccessDenied,
                    Aadsts::ConsentDeclined,
                    "The user declined to consent to access the app.",
                )
                .into());
            }
            _ => return Err(Step::Page(consent_page(st, v, request, &user, &grant).await)),
        }
    }

    // ---- issue ----
    let ts = now();
    let mut out: Vec<(&str, String)> = Vec::new();

    let code = if response_type.has_code() {
        let code = b64url(&random_bytes(48));
        sqlx::query(crate::db::q(
            &st.pool,
            "INSERT INTO auth_codes (code_hash, tenant_id, client_app_id, redirect_uri, platform, user_id, scope, nonce,
                                     code_challenge, code_challenge_method, auth_time, amr, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(sha256_hex(code.as_bytes()))
        .bind(&v.tenant.id)
        .bind(&v.client.app_id)
        // Empty when the client omitted redirect_uri; then the token request may omit it too.
        .bind(get(params, "redirect_uri").unwrap_or_default())
        .bind(v.platform.as_str())
        .bind(&user.id)
        .bind(grant.granted.join(" "))
        .bind(nonce)
        .bind(code_challenge)
        .bind(code_challenge.map(|_| method.unwrap_or("plain")))
        .bind(session.auth_time)
        .bind(serde_json::to_string(&session.amr).map_err(anyhow::Error::from)?)
        .bind(ts)
        .bind(ts + CODE_LIFETIME)
        .execute(&st.pool)
        .await
        .map_err(anyhow::Error::from)?;
        out.push(("code", code.clone()));
        Some(code)
    } else {
        None
    };

    if response_type.is_front_channel() {
        let sign_in = claims::SignIn {
            tenant: v.tenant.clone(),
            user: user.clone(),
            client: v.client.clone(),
            auth_time: session.auth_time,
            amr: session.amr.clone(),
        };
        // A front-channel client presents no credential at all, so azpacr is "0".
        // The implicit grant issues no refresh token, so nothing is recorded for
        // rotation -- a hybrid response's code still redeems normally and gets one.
        let issued = claims::issue(
            st,
            &sign_in,
            &grant,
            nonce,
            Azpacr::None,
            claims::FrontChannel {
                code: code.as_deref(),
                with_access_token: response_type.has_access_token(),
            },
        )
        .await
        .map_err(|e| Step::from(AadError::from(e)))?;
        if response_type.has_access_token() {
            out.push(("access_token", issued.access_token));
            out.push(("token_type", "Bearer".to_string()));
            out.push(("expires_in", issued.expires_in.to_string()));
            out.push(("scope", grant.scp.join(" ")));
        }
        // Only when it was asked for: an `openid` scope on a bare `token` request
        // would otherwise hand back an ID token the client never requested.
        if response_type.has_id_token()
            && let Some(id_token) = issued.id_token
        {
            out.push(("id_token", id_token));
        }
    }

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
        tenant_name: Some(&v.tenant.name),
        client_name: &v.client.display_name,
        action: &form_action(st, v),
        csrf: &csrf,
        request,
        upn,
        error,
        offer_keep_signed_in: v.tenant.settings.allow_keep_signed_in,
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

/// How long after a sign-in a consent answer still counts as part of that same
/// exchange, for `prompt=login consent`. Invented: ten minutes, the lifetime of
/// the pages involved.
const CONSENT_REAUTH_WINDOW: i64 = 600;

/// The consent page for this request: the application, and every scope it will
/// be granted, each with what it means.
async fn consent_page(
    st: &AppState,
    v: &Validated,
    request: &str,
    user: &User,
    grant: &crate::scopes::Grant,
) -> Response {
    let mut items: Vec<html::ConsentItem> = grant
        .oidc
        .iter()
        .map(|s| html::ConsentItem {
            scope: s.to_string(),
            description: crate::scopes::oidc_description(s).to_string(),
        })
        .collect();
    // A resource's own scopes carry the display name its owner gave them.
    if let crate::scopes::Resource::App { app, .. } = &grant.resource {
        let named = apps::scopes(&st.pool, app).await.unwrap_or_default();
        for value in &grant.scp {
            let description = named
                .iter()
                .find(|s| s.value == *value)
                .map(|s| s.display_name.clone())
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| format!("Access {} as you", app.display_name));
            items.push(html::ConsentItem {
                scope: format!("{} ({})", value, app.display_name),
                description,
            });
        }
    }
    let csrf = session::new_token();
    let mut resp = html::consent(&html::Consent {
        tenant_name: &v.tenant.name,
        client_name: &v.client.display_name,
        action: &form_action(st, v),
        csrf: &csrf,
        request,
        upn: &user.upn,
        items: &items,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// The page for a user who may not use this application, saying why.
fn refused_page(v: &Validated, home: &Tenant, refusal: access::Refusal) -> Response {
    let err = AadError::new(
        StatusCode::FORBIDDEN,
        OAuthError::AccessDenied,
        refusal.aadsts(),
        refusal.message(&v.client.display_name, &v.tenant.name, &home.name),
    );
    html::error(Some(&v.tenant.name), &err.description())
}

/// Start the second step of a sign-in: a code, or setting an authenticator up.
/// The second step, raised to what the application asked for with `acr_values`.
///
/// An account with an authenticator is always asked for a code, so asking for
/// [`Acr::Mfa`] changes only an account without one: it sets one up now, exactly
/// as when its tenant or the application requires MFA. A session that already
/// has a second factor never gets here.
fn stepped_up(step: mfa::Step, params: &Params) -> mfa::Step {
    let wants_mfa = get(params, ACR_VALUES).and_then(Acr::requested) == Some(Acr::Mfa);
    if step == mfa::Step::Done && wants_mfa {
        mfa::Step::Enroll
    } else {
        step
    }
}

/// The authorize parameter an application asks for a level of authentication with.
const ACR_VALUES: &str = "acr_values";

/// What this request asks of a remembered browser: `prompt=login` wants the user
/// now, `max_age` wants authentication no older than it. An unparseable value is
/// reported when the request continues; here it simply remembers nothing.
fn freshness(params: &Params) -> mfa::Freshness {
    let prompt = PromptSet::parse(get(params, "prompt").unwrap_or_default());
    mfa::Freshness {
        forced: prompt.is_err() || prompt.is_ok_and(|p| p.login),
        max_age: get(params, "max_age").and_then(|m| m.parse().ok()),
    }
}

async fn start_mfa(
    st: &AppState,
    v: &Validated,
    request: &str,
    user: &User,
    step: mfa::Step,
    keep: KeepSignedIn,
) -> Response {
    let purpose = match step {
        mfa::Step::Enroll => Purpose::Enroll,
        _ => Purpose::Verify,
    };
    match mfa::begin(&st.pool, &v.tenant.id, &user.id, purpose, keep).await {
        Ok(ticket) => {
            let secret = match purpose {
                Purpose::Enroll => mfa::pending(&st.pool, &ticket, &v.tenant.id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.enroll_secret),
                _ => None,
            };
            let home = access::home_of(&st.pool, user).await.ok().flatten();
            let issuer = home.as_ref().map_or(v.tenant.name.as_str(), |t| t.name.as_str());
            let enroll = secret.as_deref().map(|s| (s, issuer));
            let offer = home.as_ref().is_some_and(|h| may_remember(h, &v.tenant));
            mfa_page(st, v, request, &user.upn, purpose, &ticket, enroll, offer, None)
        }
        Err(e) => html::error(Some(&v.tenant.name), &AadError::from(e).description()),
    }
}

/// "Set up an authenticator?", with its own ticket so the answer carries on the
/// sign-in the password made.
async fn suggest_mfa(st: &AppState, v: &Validated, request: &str, user: &User, keep: KeepSignedIn) -> Response {
    let ticket = match mfa::begin(&st.pool, &v.tenant.id, &user.id, Purpose::Suggest, keep).await {
        Ok(t) => t,
        Err(e) => return html::error(Some(&v.tenant.name), &AadError::from(e).description()),
    };
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        html::escape(request)
    );
    let mut resp = html::mfa_suggest(&html::MfaSuggest {
        tenant_name: &v.tenant.name,
        upn: &user.upn,
        action: &form_action(st, v),
        hidden: &hidden,
        op_field: "op",
        ticket: &ticket,
        snooze_days: TenantSettings::MFA_SETUP_SNOOZE_SECS / SECS_PER_DAY,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

const SECS_PER_DAY: i64 = 86_400;

/// The last part of a sign-in whose password (and second factor, if any) are
/// done: a new password first if the account must choose one, then the session.
#[allow(clippy::too_many_arguments)]
async fn finish_sign_in(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    user: &User,
    after_mfa: bool,
    keep: KeepSignedIn,
) -> Response {
    match users::must_change_password(&st.pool, &user.id).await {
        Ok(true) => {
            return match mfa::begin(
                &st.pool,
                &v.tenant.id,
                &user.id,
                Purpose::change_password(after_mfa),
                keep,
            )
            .await
            {
                Ok(ticket) => change_page(st, v, request, &user.upn, &ticket, None),
                Err(e) => html::error(Some(&v.tenant.name), &AadError::from(e).description()),
            };
        }
        Ok(false) => {}
        Err(e) => return html::error(Some(&v.tenant.name), &AadError::from(e).description()),
    }
    let amr: &[&str] = if after_mfa {
        &[Amr::Pwd.as_str(), Amr::Mfa.as_str()]
    } else {
        &[Amr::Pwd.as_str()]
    };
    match signed_in(st, tenant_key, headers, params, request, v, user, amr, keep).await {
        Ok(resp) | Err(resp) => resp,
    }
}

/// The change-password page for this request.
fn change_page(st: &AppState, v: &Validated, request: &str, upn: &str, ticket: &str, error: Option<&str>) -> Response {
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        html::escape(request)
    );
    let mut resp = html::change_password(&html::ChangePassword {
        tenant_name: &v.tenant.name,
        upn,
        action: &form_action(st, v),
        hidden: &hidden,
        op_field: "op",
        op: html::LoginOp::ChangePassword.as_str(),
        ticket,
        error,
    });
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

/// The second-step page for this request, with a fresh CSRF cookie for its form.
#[allow(clippy::too_many_arguments)]
fn mfa_page(
    st: &AppState,
    v: &Validated,
    request: &str,
    upn: &str,
    purpose: Purpose,
    ticket: &str,
    // The secret being set up, and the name of the account's own tenant, which
    // the authenticator app lists it under.
    enroll: Option<(&str, &str)>,
    // Offer "Don't ask again on this device": the account's own tenant allows it.
    offer_remember_device: bool,
    error: Option<&str>,
) -> Response {
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        html::escape(request)
    );
    let action = form_action(st, v);
    let mut resp = match (purpose, enroll) {
        (Purpose::Enroll, Some((secret, issuer))) => {
            let uri = mfa::otpauth_uri(secret, issuer, upn);
            html::mfa_enroll(&html::MfaEnroll {
                tenant_name: &v.tenant.name,
                upn,
                action: &action,
                hidden: &hidden,
                op_field: "op",
                op: html::LoginOp::MfaEnroll.as_str(),
                ticket,
                qr_svg: &mfa::qr_svg(&uri),
                secret,
                issuer,
                error,
            })
        }
        _ => html::mfa_verify(&html::MfaVerify {
            tenant_name: &v.tenant.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: "op",
            op: html::LoginOp::MfaVerify.as_str(),
            ticket,
            error,
            offer_remember_device,
        }),
    };
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, &csrf, 3600),
    );
    resp
}

const MFA_EXPIRED: &str = "That sign-in has expired or had too many wrong codes. Please sign in again.";
const MFA_WRONG: &str = "That code didn't work. Check the time on your phone, wait for a new code and try again.";

/// The code posted at a second step: check it, and finish the sign-in.
#[allow(clippy::too_many_arguments)]
async fn second_step(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    form: &HashMap<String, String>,
    op: html::LoginOp,
) -> Response {
    let ticket = form.get(html::MFA_TICKET).cloned().unwrap_or_default();
    let typed = form.get(html::MFA_CODE).cloned().unwrap_or_default();
    let pending = match mfa::pending(&st.pool, &ticket, &v.tenant.id).await {
        Ok(Some(p)) => p,
        Ok(None) => return login_page(st, v, request, "", Some(MFA_EXPIRED)),
        Err(e) => return html::error(Some(&v.tenant.name), &AadError::from(e).description()),
    };
    // A code page after a wrong password: never a sign-in, whatever is posted.
    if !pending.password_right {
        if pending.purpose != Purpose::Verify || op != html::LoginOp::MfaVerify {
            return login_page(st, v, request, "", Some(MFA_EXPIRED));
        }
        return unverified_second_step(st, request, v, &ticket, &pending, &typed).await;
    }
    let user = match users::find_by_id(&st.pool, &pending.user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return login_page(st, v, request, "", Some(MFA_EXPIRED)),
    };
    // Their own tenant's password rules, for an account of another tenant too.
    let Ok(Some(home)) = access::home_of(&st.pool, &user).await else {
        return login_page(st, v, request, "", Some(MFA_EXPIRED));
    };
    let fits = match op {
        html::LoginOp::MfaEnroll => pending.purpose == Purpose::Enroll,
        html::LoginOp::MfaSetupNow | html::LoginOp::MfaSetupLater => pending.purpose == Purpose::Suggest,
        html::LoginOp::ChangePassword => {
            matches!(
                pending.purpose,
                Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa
            )
        }
        _ => pending.purpose == Purpose::Verify,
    };
    if !fits {
        return login_page(st, v, request, "", Some(MFA_EXPIRED));
    }
    match pending.purpose {
        // "Set up an authenticator?": now goes on to setting one up, as when one
        // is required; "Not now" carries on with the sign-in the password made.
        Purpose::Suggest => {
            let _ = mfa::finish(&st.pool, &ticket).await;
            if op == html::LoginOp::MfaSetupNow {
                return start_mfa(st, v, request, &user, mfa::Step::Enroll, pending.keep).await;
            }
            if let Err(e) = mfa::snooze_setup(&st.pool, &user.id).await {
                // Not remembering the answer only means asking again next time.
                tracing::error!("snoozing the authenticator suggestion failed: {e}");
            }
            finish_sign_in(st, tenant_key, headers, params, request, v, &user, false, pending.keep).await
        }
        Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa => {
            let new = form.get(html::NEW_PASSWORD).cloned().unwrap_or_default();
            let confirm = form.get(html::CONFIRM_PASSWORD).cloned().unwrap_or_default();
            let refused = if new != confirm {
                Some("The passwords don't match.".to_string())
            } else {
                let changed = super::change_own_password(st, &home, &user.id, &new, Channel::Authorize).await;
                match super::settle_own(changed, &v.tenant.name) {
                    Settled::Done(()) => None,
                    Settled::Refused(message) => Some(message),
                    Settled::Respond(resp) => return resp,
                }
            };
            if let Some(message) = refused {
                return change_page(st, v, request, &user.upn, &ticket, Some(&message));
            }
            let _ = mfa::finish(&st.pool, &ticket).await;
            let mut amr = vec![Amr::Pwd.as_str()];
            if pending.purpose == Purpose::ChangePasswordAfterMfa {
                amr.push(Amr::Mfa.as_str());
            }
            match signed_in(st, tenant_key, headers, params, request, v, &user, &amr, pending.keep).await {
                Ok(resp) | Err(resp) => resp,
            }
        }
        Purpose::Verify => match mfa::check(&st.pool, &user.id, &typed).await {
            Ok(Some(factor)) => {
                let _ = mfa::finish(&st.pool, &ticket).await;
                // Both factors right: the count the password left alone is cleared.
                if let Err(e) = users::settle_attempt(&st.pool, &user.id, Attempt::Succeeded).await {
                    return html::error(Some(&v.tenant.name), &AadError::from(e).description());
                }
                let device = remember_if_asked(st, headers, form, &user, &home).await;
                audit::record(
                    st,
                    &v.tenant.id,
                    Actor::Id(&user.id),
                    Event::MfaVerified,
                    Some(&user.id),
                    serde_json::json!({
                        "via": Channel::Authorize.as_str(),
                        "factor": factor.as_str(),
                        "rememberDevice": device.is_some(),
                    }),
                )
                .await;
                let resp = finish_sign_in(st, tenant_key, headers, params, request, v, &user, true, pending.keep).await;
                with_device_cookie(st, resp, device)
            }
            Ok(None) => {
                wrong_code(st, &v.tenant.id, &user.id, Channel::Authorize).await;
                // A right password with a wrong code: what lockout is for.
                match users::settle_attempt(&st.pool, &user.id, Attempt::Failed).await {
                    Ok(true) => {
                        let details = serde_json::json!({
                            "via": Channel::Authorize.as_str(),
                            "clientId": v.client.app_id,
                        });
                        audit::record(
                            st,
                            &v.tenant.id,
                            Actor::Id(&user.id),
                            Event::Lockout,
                            Some(&user.id),
                            details,
                        )
                        .await;
                    }
                    Ok(false) => {}
                    Err(e) => return html::error(Some(&v.tenant.name), &AadError::from(e).description()),
                }
                match mfa::failed_attempt(&st.pool, &ticket).await {
                    Ok(true) => mfa_page(
                        st,
                        v,
                        request,
                        &user.upn,
                        Purpose::Verify,
                        &ticket,
                        None,
                        may_remember(&home, &v.tenant),
                        Some(MFA_WRONG),
                    ),
                    _ => login_page(st, v, request, "", Some(MFA_EXPIRED)),
                }
            }
            Err(e) => html::error(Some(&v.tenant.name), &AadError::from(e).description()),
        },
        Purpose::Enroll => {
            let secret = pending.enroll_secret.unwrap_or_default();
            if !mfa::verify_new(&secret, &typed) {
                return match mfa::failed_attempt(&st.pool, &ticket).await {
                    Ok(true) => mfa_page(
                        st,
                        v,
                        request,
                        &user.upn,
                        Purpose::Enroll,
                        &ticket,
                        Some((&secret, &home.name)),
                        false,
                        Some(MFA_WRONG),
                    ),
                    _ => login_page(st, v, request, "", Some(MFA_EXPIRED)),
                };
            }
            // Then signed out, everywhere (by the same transaction), and back in
            // through the front door.
            let enrolled =
                super::enroll_own_authenticator(st, &home.id, &user.id, &secret, Channel::Authorize, false).await;
            let codes = match super::settle_own(enrolled, &v.tenant.name) {
                Settled::Done(codes) => codes,
                Settled::Refused(message) => return login_page(st, v, request, "", Some(&message)),
                Settled::Respond(resp) => return resp,
            };
            let _ = mfa::finish(&st.pool, &ticket).await;
            let again = format!(
                "{}?{}",
                st.public_url.tenant_url(&v.tenant.id, "oauth2/v2.0/authorize"),
                request
            );
            let mut resp = html::mfa_enrolled(&v.tenant.name, &codes, &again);
            let h = resp.headers_mut();
            h.append(
                header::SET_COOKIE,
                session::clear_cookie(&st.public_url, SESSION_COOKIE),
            );
            h.append(header::SET_COOKIE, session::clear_cookie(&st.public_url, CSRF_COOKIE));
            resp
        }
    }
}

/// Record a wrong code at a second step.
pub(crate) async fn wrong_code(st: &AppState, tenant_id: &str, user_id: &str, via: Channel) {
    audit::record(
        st,
        tenant_id,
        Actor::Id(user_id),
        Event::MfaFailed,
        Some(user_id),
        serde_json::json!({ "via": via.as_str() }),
    )
    .await;
}

/// Remember this browser for the account's second factor, if the box was ticked
/// and the account's own tenant allows it. The device cookie value to set, if any.
pub(crate) async fn remember_if_asked(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
    user: &User,
    home: &Tenant,
) -> Option<String> {
    if !html::ticked(form, html::REMEMBER_DEVICE) {
        return None;
    }
    let existing = session::cookie(headers, MFA_DEVICE_COOKIE);
    match mfa::remember_device(&st.pool, existing.as_deref(), &user.id, home).await {
        Ok(device) => device,
        Err(e) => {
            // Not remembering is the safe failure: the next sign-in asks again.
            tracing::error!("remembering a device failed: {e}");
            None
        }
    }
}

/// Put the remembered-device cookie on whatever the sign-in answers with.
pub(crate) fn with_device_cookie(st: &AppState, mut resp: Response, device: Option<String>) -> Response {
    if let Some(device) = device {
        resp.headers_mut().append(
            header::SET_COOKIE,
            session::set_cookie(
                &st.public_url,
                MFA_DEVICE_COOKIE,
                &device,
                TenantSettings::REMEMBER_MFA_SECS,
            ),
        );
    }
    resp
}

/// Whether "Don't ask again on this device" is offered and trusted for a sign-in
/// of an account of `home` to `resource`: the account's own tenant allows it, and
/// neither tenant enforces MFA, which asks for a code at every sign-in.
pub(crate) fn may_remember(home: &Tenant, resource: &Tenant) -> bool {
    home.settings.remembers_mfa() && !resource.settings.enforces_mfa()
}

/// Whether this browser may skip `user`'s code this time, signing in to
/// `resource`. A failure to look is treated as "no": the user is asked for the code.
pub(crate) async fn device_remembered(
    st: &AppState,
    headers: &HeaderMap,
    user: &User,
    home: &Tenant,
    resource: &Tenant,
    freshness: mfa::Freshness,
) -> bool {
    if !may_remember(home, resource) {
        return false;
    }
    let device = session::cookie(headers, MFA_DEVICE_COOKIE);
    matches!(
        mfa::remembered(&st.pool, device.as_deref(), &user.id, home, freshness).await,
        Ok(mfa::Remembered::Yes)
    )
}

/// Record a second factor satisfied by a remembered browser.
pub(crate) async fn audit_remembered(st: &AppState, tenant_id: &str, user: &User, via: Channel) {
    audit::record(
        st,
        tenant_id,
        Actor::Id(&user.id),
        Event::MfaVerified,
        Some(&user.id),
        serde_json::json!({ "via": via.as_str(), "factor": mfa::Factor::RememberedDevice.as_str() }),
    )
    .await;
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

    let op = form.get("op").and_then(|raw| html::LoginOp::parse(raw));
    let result = match op {
        Some(html::LoginOp::Continue) => {
            run(&st, &tenant_key, &headers, &params, &request, Interaction::ChoseAccount).await
        }
        Some(html::LoginOp::Other) => return login_page(&st, &v, &request, "", None),
        Some(
            op @ (html::LoginOp::MfaVerify
            | html::LoginOp::MfaEnroll
            | html::LoginOp::ChangePassword
            | html::LoginOp::MfaSetupNow
            | html::LoginOp::MfaSetupLater),
        ) => {
            return second_step(&st, &tenant_key, &headers, &params, &request, &v, &form, op).await;
        }
        Some(html::LoginOp::ConsentAccept) => {
            run(&st, &tenant_key, &headers, &params, &request, Interaction::Consented).await
        }
        Some(html::LoginOp::ConsentDeny) => {
            run(
                &st,
                &tenant_key,
                &headers,
                &params,
                &request,
                Interaction::ConsentDenied,
            )
            .await
        }
        None => {
            let upn = form.get("upn").map(|s| s.trim().to_string()).unwrap_or_default();
            let password = form.get("password").cloned().unwrap_or_default();
            return password_step(
                &st,
                &tenant_key,
                &headers,
                &params,
                &request,
                &v,
                &form,
                &upn,
                &password,
            )
            .await;
        }
    };
    match result {
        Ok(resp) | Err(resp) => resp,
    }
}

/// The AADSTS50126 answer to a wrong password, the same whatever else was wrong.
const BAD_CREDENTIALS: &str = "Your account or password is incorrect. (AADSTS50126: Error validating credentials due to invalid username or password.)";

/// The password page posted: the first step of a sign-in.
///
/// A right password that will be asked for a code settles nothing yet: the code
/// does. Where MFA is enforced, a wrong password leads to the same code page
/// (as does a name that names no account), and the attempt counts toward
/// lockout only when exactly one of the two is right (decision 55). Everywhere
/// else a wrong password counts at once, as before.
#[allow(clippy::too_many_arguments)]
async fn password_step(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    form: &HashMap<String, String>,
    upn: &str,
    password: &str,
) -> Response {
    let fail = |e: anyhow::Error| html::error(Some(&v.tenant.name), &AadError::from(e).description());
    let (outcome, mut trace) =
        match access::authenticate_deferred(&st.pool, &v.tenant, Some(&v.sp), upn, password).await {
            Ok(o) => o,
            Err(e) => return fail(e),
        };
    let keep = KeepSignedIn::chosen(&v.tenant, html::ticked(form, html::KEEP_SIGNED_IN));
    match outcome {
        AuthResult::Ok(user) => {
            let home = match access::home_of(&st.pool, &user).await {
                Ok(Some(h)) => h,
                Ok(None) => return fail(anyhow::anyhow!("the account's tenant is gone")),
                Err(e) => return fail(e),
            };
            let step = match mfa::step(&st.pool, &home, &user.id, mfa::At::App(&v.sp)).await {
                Ok(step) => stepped_up(step, params),
                Err(e) => return fail(e),
            };
            let remembered = step == mfa::Step::Verify
                && device_remembered(st, headers, &user, &home, &v.tenant, freshness(params)).await;
            // A code comes next: the counter waits for it, and so does whether
            // the account may use this application (which a refusal now would
            // say only to someone with the right password). The authorize
            // request is decided again, in full, once the code is right.
            if step == mfa::Step::Verify && !remembered {
                return start_mfa(st, v, request, &user, step, keep).await;
            }
            // The password is all this sign-in asks: it settles the count now.
            if let Err(e) = users::settle_attempt(&st.pool, &user.id, Attempt::Succeeded).await {
                return fail(e);
            }
            // May they use this application? Answered before setting an
            // authenticator up, so nobody does that only to be refused.
            let decision = match access::decide(&st.pool, &v.tenant, &v.sp, &user).await {
                Ok(d) => d,
                Err(e) => return fail(e),
            };
            if let Some(refusal) = decision.refusal {
                return refused_page(v, &decision.home, refusal);
            }
            if remembered {
                audit_remembered(st, &v.tenant.id, &user, Channel::Authorize).await;
                return finish_sign_in(st, tenant_key, headers, params, request, v, &user, true, keep).await;
            }
            if step != mfa::Step::Done {
                return start_mfa(st, v, request, &user, step, keep).await;
            }
            // Nothing requires a second factor: offer one, where the account's
            // own tenant asks for that.
            if mfa::suggest_setup(&st.pool, &decision.home, &user.id)
                .await
                .unwrap_or(false)
            {
                return suggest_mfa(st, v, request, &user, keep).await;
            }
            finish_sign_in(st, tenant_key, headers, params, request, v, &user, false, keep).await
        }
        AuthResult::InvalidCredentials => {
            if let Some(hint) = tenant::not_ours_hint(&st.pool, &v.tenant, upn, v.sp.accept_other_tenants).await {
                audit::sign_in_failure(
                    st,
                    &v.tenant.id,
                    upn,
                    &outcome,
                    &trace,
                    Channel::Authorize,
                    &v.client.app_id,
                )
                .await;
                return login_page(st, v, request, upn, Some(&hint));
            }
            match unverified_code_page(st, headers, params, request, v, trace.user_id.as_deref(), upn, keep).await {
                Ok(Some(page)) => {
                    // Audited when the code decides why it failed. An unknown name
                    // has nothing for the code to decide, so it is audited now.
                    if trace.user_id.is_none() {
                        audit::sign_in_failure(
                            st,
                            &v.tenant.id,
                            upn,
                            &outcome,
                            &trace,
                            Channel::Authorize,
                            &v.client.app_id,
                        )
                        .await;
                    }
                    page
                }
                Ok(None) => {
                    // No code to wait for: the wrong password counts now.
                    if let Some(id) = trace.user_id.as_deref() {
                        trace.lockout_triggered = match users::settle_attempt(&st.pool, id, Attempt::Failed).await {
                            Ok(locked) => locked,
                            Err(e) => return fail(e),
                        };
                    }
                    audit::sign_in_failure(
                        st,
                        &v.tenant.id,
                        upn,
                        &outcome,
                        &trace,
                        Channel::Authorize,
                        &v.client.app_id,
                    )
                    .await;
                    login_page(st, v, request, upn, Some(BAD_CREDENTIALS))
                }
                Err(e) => fail(e),
            }
        }
        AuthResult::Locked => {
            audit::sign_in_failure(
                st,
                &v.tenant.id,
                upn,
                &outcome,
                &trace,
                Channel::Authorize,
                &v.client.app_id,
            )
            .await;
            login_page(
                st,
                v,
                request,
                upn,
                Some("Your account is temporarily locked to prevent unauthorized use. Try again later. (AADSTS50053)"),
            )
        }
        AuthResult::Disabled => {
            audit::sign_in_failure(
                st,
                &v.tenant.id,
                upn,
                &outcome,
                &trace,
                Channel::Authorize,
                &v.client.app_id,
            )
            .await;
            login_page(
                st,
                v,
                request,
                upn,
                Some("Your account has been disabled. (AADSTS50057: The user account is disabled.)"),
            )
        }
    }
}

/// After a wrong password, where MFA is enforced for the sign-in: the code page a
/// right password would have led to. `None` elsewhere, or where it would not
/// have led to one (a remembered browser is never trusted under Enforced, so
/// that leaves an account still to set an authenticator up), and the wrong
/// password counts at once.
///
/// Only under Enforced, because only there can every name get the page: an
/// unknown name (`user_id` `None`) is given it too, as nearly every account of
/// such a tenant has an authenticator. In a Permissive tenant most accounts may
/// have none, so a code page after a wrong password would say "this account
/// exists and has an authenticator", where today an unknown name and a wrong
/// password read the same.
#[allow(clippy::too_many_arguments)]
async fn unverified_code_page(
    st: &AppState,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    user_id: Option<&str>,
    upn: &str,
    keep: KeepSignedIn,
) -> anyhow::Result<Option<Response>> {
    let (shown_upn, home) = match user_id {
        Some(id) => {
            let Some(user) = users::find_by_id(&st.pool, id).await? else {
                return Ok(None);
            };
            let Some(home) = access::home_of(&st.pool, &user).await? else {
                return Ok(None);
            };
            let enforced = home.settings.enforces_mfa() || v.tenant.settings.enforces_mfa();
            if !enforced
                || mfa::step(&st.pool, &home, &user.id, mfa::At::App(&v.sp)).await? != mfa::Step::Verify
                || device_remembered(st, headers, &user, &home, &v.tenant, freshness(params)).await
            {
                return Ok(None);
            }
            (user.upn, home)
        }
        None if v.tenant.settings.enforces_mfa() => (upn.to_string(), v.tenant.clone()),
        None => return Ok(None),
    };
    let ticket = mfa::begin_unverified(&st.pool, &v.tenant.id, user_id, keep).await?;
    let offer = may_remember(&home, &v.tenant);
    Ok(Some(mfa_page(
        st,
        v,
        request,
        &shown_upn,
        Purpose::Verify,
        &ticket,
        None,
        offer,
        None,
    )))
}

/// A code posted on a page shown after a wrong password. It never signs anyone
/// in, and it answers a wrong code exactly as a right password's page would.
/// A right code makes the attempt count toward lockout (the code is in the
/// caller's hands); a wrong one does not (someone holding neither factor).
#[allow(clippy::too_many_arguments)]
async fn unverified_second_step(
    st: &AppState,
    request: &str,
    v: &Validated,
    ticket: &str,
    pending: &mfa::Pending,
    typed: &str,
) -> Response {
    let fail = |e: anyhow::Error| html::error(Some(&v.tenant.name), &AadError::from(e).description());
    let user = if pending.user_id.is_empty() {
        None
    } else {
        match users::find_by_id(&st.pool, &pending.user_id).await {
            Ok(u) => u,
            Err(e) => return fail(e),
        }
    };
    let offer = match &user {
        Some(u) => match access::home_of(&st.pool, u).await {
            Ok(Some(home)) => may_remember(&home, &v.tenant),
            _ => false,
        },
        None => may_remember(&v.tenant, &v.tenant),
    };
    let code_right = match &user {
        Some(u) => match mfa::check(&st.pool, &u.id, typed).await {
            Ok(factor) => factor.is_some(),
            Err(e) => return fail(e),
        },
        None => false,
    };
    if code_right && let Some(u) = &user {
        let _ = mfa::finish(&st.pool, ticket).await;
        let locked = match users::settle_attempt(&st.pool, &u.id, Attempt::Failed).await {
            Ok(locked) => locked,
            Err(e) => return fail(e),
        };
        audit::known_sign_in_failure(
            st,
            &v.tenant.id,
            &u.id,
            &u.upn,
            SignInReason::BadPassword,
            Channel::Authorize,
            Some(&v.client.app_id),
            locked,
        )
        .await;
        return login_page(st, v, request, &u.upn, Some(BAD_CREDENTIALS));
    }
    if let Some(u) = &user {
        audit::known_sign_in_failure(
            st,
            &v.tenant.id,
            &u.id,
            &u.upn,
            SignInReason::BadPasswordAndCode,
            Channel::Authorize,
            Some(&v.client.app_id),
            false,
        )
        .await;
    }
    let upn = user.as_ref().map(|u| u.upn.clone()).unwrap_or_default();
    match mfa::failed_attempt(&st.pool, ticket).await {
        Ok(true) => mfa_page(
            st,
            v,
            request,
            &upn,
            Purpose::Verify,
            ticket,
            None,
            offer,
            Some(MFA_WRONG),
        ),
        _ => login_page(st, v, request, "", Some(MFA_EXPIRED)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn signed_in(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    params: &Params,
    request: &str,
    v: &Validated,
    user: &User,
    amr: &[&str],
    keep: KeepSignedIn,
) -> Result<Response, Response> {
    let session::Created { cookie, max_age } = session::create(&st.pool, headers, &v.tenant, &user.id, amr, keep)
        .await
        .map_err(|e| html::error(Some(&v.tenant.name), &AadError::from(e).description()))?;
    let details = serde_json::json!({ "via": Channel::Authorize.as_str(), "clientId": v.client.app_id });
    audit::record(
        st,
        &v.tenant.id,
        Actor::Id(&user.id),
        Event::SignIn,
        Some(&user.id),
        details,
    )
    .await;
    audit::record(
        st,
        &v.tenant.id,
        Actor::Id(&user.id),
        Event::SessionCreate,
        Some(&user.id),
        serde_json::json!({ "keepSignedIn": keep.is_kept() }),
    )
    .await;

    // Continue the original request as the newly signed-in user.
    let mut headers = headers.clone();
    let existing = session::cookie(&headers, SESSION_COOKIE);
    if existing.as_deref() != Some(cookie.as_str()) {
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={cookie}")).expect("ascii"),
        );
    }
    // The session cookie goes on whatever comes next, a page as much as a redirect.
    // It used to be attached only to a redirect, which was harmless while the only
    // page that could follow a sign-in was an error; the consent page follows one
    // and then needs the browser to still be signed in when it is answered.
    let outcome = run(st, tenant_key, &headers, params, request, Interaction::SignedIn).await;
    let (Ok(mut resp) | Err(mut resp)) = outcome;
    // A following page brings its own CSRF cookie for its own form; only clear the
    // sign-in form's when nothing replaced it.
    let csrf_prefix = format!("{CSRF_COOKIE}=");
    let sets_csrf = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.starts_with(&csrf_prefix)));
    let h = resp.headers_mut();
    h.append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, SESSION_COOKIE, &cookie, max_age),
    );
    if !sets_csrf {
        h.append(header::SET_COOKIE, session::clear_cookie(&st.public_url, CSRF_COOKIE));
    }
    Ok(resp)
}
