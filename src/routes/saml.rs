//! The SAML endpoints: `/{tenant}/saml2` (sign-in and Single Logout, as in Entra)
//! and the application's federation metadata.
//!
//! A SAML sign-in shares every step of the browser sign-in with OIDC (password,
//! second factor, assignment, session) through `authorize`. Its request travels
//! between those pages as the raw request string, and is read and checked again
//! at every step, so nothing a page posts can change what was validated.
//!
//! An IdP-initiated sign-in is started only from the signed-in user's own app
//! gallery, which records a single-use ticket for that user and application;
//! `/saml2` itself does not accept one.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::audit::{self, Actor, Channel, Event};
use crate::AppState;
use crate::apps::{self, Application, ServicePrincipal};
use crate::claims::{Acr, Amr};
use crate::error::{AadError, Aadsts, OAuthError};
use crate::groups;
use crate::html;
use crate::saml::{
    self, CLAIM_AUTHN_METHODS, CLAIM_DISPLAY_NAME, CLAIM_GROUPS, CLAIM_IDENTITY_PROVIDER, CLAIM_OBJECT_ID, CLAIM_ROLE,
    CLAIM_TENANT, Participant, SamlConfig,
};
use crate::saml_protocol::{self as protocol, AssertionAttribute, AuthnRequest, SamlError, SamlQuery, Signer};
use crate::session::{self, SESSION_COOKIE, Session};
use crate::tenant::{self, Tenant};
use crate::users::User;
use crate::util::{now, sha256_hex};

pub(super) const SAML_REQUEST: &str = protocol::PARAM_REQUEST;
const SAML_RESPONSE: &str = protocol::PARAM_RESPONSE;
const RELAY_STATE: &str = protocol::PARAM_RELAY_STATE;
/// Marks a sign-in started from the app gallery; its value is the launch ticket.
pub(super) const IDP_INITIATED: &str = "saml_launch";
/// The request string as received, kept beside the parsed parameters because a
/// Redirect signature covers its exact octets. Always set from the request
/// itself by [`normalized`], never taken from a form.
const RAW_REQUEST: &str = "saml_raw";
/// `login_hint`, the one query parameter Entra reads beside the SAML message.
const LOGIN_HINT: &str = "login_hint";
/// Binds a logout in progress to the browser it started in.
const LOGOUT_COOKIE: &str = "saml_logout";
const LOGOUT_COOKIE_SECS: i64 = 600;

const METADATA_CONTENT_TYPE: &str = "application/samlmetadata+xml";

type Params = HashMap<String, String>;

fn get<'a>(p: &'a Params, name: &str) -> Option<&'a str> {
    p.get(name).map(String::as_str).filter(|v| !v.is_empty())
}

/// Whether these parameters are a SAML sign-in rather than an OAuth one.
pub(super) fn is_saml(params: &Params) -> bool {
    get(params, SAML_REQUEST).is_some() || get(params, IDP_INITIATED).is_some()
}

/// The parameters of a SAML sign-in, rebuilt from the request alone: whatever
/// else was in it (`client_id`, `prompt`, ...) is dropped, and `prompt` and
/// `acr_values` are what the AuthnRequest itself says. A request whose SAML
/// parameters do not parse keeps only its marker, and [`resolve`] refuses it.
pub(super) fn normalized(params: Params, raw: &str) -> Params {
    if !is_saml(&params) {
        return params;
    }
    let mut out = Params::new();
    out.insert(RAW_REQUEST.to_string(), raw.to_string());
    if let Some(hint) = get(&params, LOGIN_HINT) {
        out.insert(LOGIN_HINT.to_string(), hint.to_string());
    }
    if let Some(message) = get(&params, SAML_REQUEST) {
        out.insert(SAML_REQUEST.to_string(), message.to_string());
        if let Some(request) = SamlQuery::parse(raw)
            .ok()
            .filter(|q| q.param == SAML_REQUEST)
            .and_then(|q| protocol::decode_message(&q.message).ok())
            .and_then(|xml| AuthnRequest::parse(&xml).ok())
        {
            if request.force_authn {
                out.insert("prompt".into(), "login".into());
            } else if request.is_passive {
                out.insert("prompt".into(), "none".into());
            }
            if request.authn_contexts.iter().any(|c| c == protocol::AC_MFA) {
                out.insert("acr_values".into(), Acr::Mfa.as_str().into());
            }
        }
    } else if let Some(ticket) = get(&params, IDP_INITIATED) {
        out.insert(IDP_INITIATED.to_string(), ticket.to_string());
    }
    out
}

/// A validated SAML sign-in, carried beside the application it is for.
pub(super) struct SamlCall {
    /// `None` for an IdP-initiated sign-in.
    pub request: Option<AuthnRequest>,
    /// The gallery launch this sign-in is, if it is one.
    pub launch: Option<String>,
    /// The request's signature was verified.
    pub signed: bool,
    pub config: SamlConfig,
    pub idp_entity: String,
    pub relay_state: Option<String>,
    /// The Reply URL exactly as registered: `Recipient` and `Destination` must
    /// match it to the byte, and parsing a URL can normalize it.
    pub reply_url: String,
}

/// Where a sign-in restarts after a step that signs the user out.
pub(super) fn restart_url(st: &AppState, tenant_id: &str, params: &Params, request: &str) -> String {
    if get(params, IDP_INITIATED).is_some() {
        st.public_url.tenant_url(tenant_id, "myaccount")
    } else {
        format!("{}?{request}", sso_url(st, tenant_id))
    }
}

/// This server's SAML entity id for a tenant, shaped like Entra's.
pub(crate) fn idp_entity_id(st: &AppState, tenant_id: &str) -> String {
    st.public_url.tenant_url(tenant_id, "")
}

/// The sign-in and logout endpoint of a tenant.
pub(crate) fn sso_url(st: &AppState, tenant_id: &str) -> String {
    st.public_url.tenant_url(tenant_id, "saml2")
}

fn page(tenant: Option<&Tenant>, message: &str) -> Response {
    html::error(tenant.map(|t| t.name.as_str()), message)
}

fn internal(tenant: Option<&Tenant>, e: anyhow::Error) -> Response {
    page(tenant, &AadError::from(e).description())
}

/// What a signed message must also satisfy: addressed to this tenant's endpoint
/// (the bindings require `Destination` on a signed message), and recent.
fn signed_message_ok(
    st: &AppState,
    tenant_key: &str,
    tenant: &Tenant,
    destination: Option<&str>,
    issue_instant: Option<i64>,
) -> Result<(), &'static str> {
    if !destination.is_some_and(|d| d == sso_url(st, &tenant.id) || d == sso_url(st, tenant_key)) {
        return Err("The signed request's Destination is not this endpoint.");
    }
    if !protocol::is_fresh(issue_instant, now()) {
        return Err("The signed request has expired.");
    }
    Ok(())
}

/// Check the message's signature, and say whether one was verified.
///
/// An application requiring signatures must send one. Otherwise a signature is
/// checked when the application has a certificate to check it with: a message
/// that claims to be signed and is not must not pass. Without a certificate it
/// cannot be checked, and is treated as unsigned.
async fn check_signature(
    st: &AppState,
    app: &Application,
    config: &SamlConfig,
    query: &SamlQuery,
) -> Result<bool, SamlError> {
    let xml = protocol::decode_message(&query.message)?;
    let detached = query.is_signed();
    let enveloped = !detached && crate::saml_dsig::carries_signature(&xml);
    if !detached && !enveloped {
        return if config.require_signed_requests {
            Err(SamlError::requester("The request is not signed."))
        } else {
            Ok(false)
        };
    }
    let certificates: Vec<Vec<u8>> = saml::verification_certificates(&st.pool, app)
        .await
        .map_err(|_| refused("The verification certificates could not be read."))?
        .into_iter()
        .filter(|c| c.not_after > now())
        .map(|c| c.cert_der)
        .collect();
    if certificates.is_empty() && !config.require_signed_requests {
        return Ok(false);
    }
    let allow_sha1 = config.signing_algorithm == protocol::SigningAlgorithm::Sha1;
    if detached {
        query.verify(&certificates, allow_sha1)?;
    } else {
        crate::saml_dsig::verify(&xml, &certificates, allow_sha1)?;
    }
    Ok(true)
}

fn refused(message: &str) -> SamlError {
    SamlError {
        status: protocol::STATUS_RESPONDER,
        sub_status: None,
        message: message.to_string(),
    }
}

/// Resolve and validate a SAML sign-in: its tenant, application, Reply URL and
/// signature. A problem before a registered Reply URL is known is a page: an
/// answer is never sent anywhere the application did not register.
pub(super) async fn resolve(
    st: &AppState,
    tenant_key: &str,
    params: &Params,
) -> Result<(Tenant, Application, ServicePrincipal, url::Url, SamlCall), Response> {
    let tenant = tenant::resolve(&st.pool, tenant_key)
        .await
        .map_err(|e| internal(None, e))?
        .ok_or_else(|| page(None, &AadError::tenant_not_found(tenant_key).description()))?;
    let t = Some(&tenant);

    let (app, request, query, launch) = if get(params, SAML_REQUEST).is_some() {
        // Read from the raw request, the only form its signature covers.
        let query = SamlQuery::parse(get(params, RAW_REQUEST).unwrap_or_default())
            .ok()
            .filter(|q| q.param == SAML_REQUEST)
            .ok_or_else(|| page(t, "The SAML parameters are malformed or repeated."))?;
        let xml = protocol::decode_message(&query.message).map_err(|e| page(t, &e.message))?;
        let request = AuthnRequest::parse(&xml).map_err(|e| page(t, &e.message))?;
        let app = saml::find_by_identifier(&st.pool, &tenant.id, &request.issuer)
            .await
            .map_err(|e| internal(t, e))?
            .ok_or_else(|| page(t, &AadError::app_not_found(&request.issuer, &tenant.id).description()))?;
        (app, Some(request), Some(query), None)
    } else {
        let expired = || page(t, "That launch has expired. Open the application again from My apps.");
        let ticket = get(params, IDP_INITIATED).unwrap_or_default();
        let launch = saml::launch_ticket(&st.pool, ticket, &tenant.id)
            .await
            .map_err(|e| internal(t, e))?
            .ok_or_else(expired)?;
        let app = saml::application_by_object_id(&st.pool, &launch.application_id)
            .await
            .map_err(|e| internal(t, e))?
            .filter(|a| a.tenant_id == tenant.id)
            .ok_or_else(expired)?;
        (app, None, None, Some(ticket.to_string()))
    };
    let sp = apps::service_principal(&st.pool, &tenant.id, &app.app_id)
        .await
        .map_err(|e| internal(t, e))?
        .ok_or_else(|| page(t, &AadError::app_not_found(&app.app_id, &tenant.id).description()))?;
    let config = saml::config(&st.pool, &app)
        .await
        .map_err(|e| internal(t, e))?
        .filter(|c| c.enabled && c.is_configured())
        .ok_or_else(|| page(t, "SAML single sign-on is not set up for this application."))?;

    let reply_url = config
        .reply_url_for(
            request.as_ref().and_then(|r| r.acs_url.as_deref()),
            request.as_ref().and_then(|r| r.acs_index),
        )
        .map(str::to_string)
        .ok_or_else(|| {
            page(
                t,
                &AadError::invalid_request(
                    Aadsts::RedirectUriMismatch,
                    "The reply URL specified in the request does not match the reply URLs configured for the application.",
                )
                .description(),
            )
        })?;
    let reply = url::Url::parse(&reply_url).map_err(|e| internal(t, e.into()))?;

    // As in Entra, requiring verification rules out IdP-initiated sign-in: there
    // is no signed request to verify.
    if request.is_none() && config.require_signed_requests {
        return Err(page(
            t,
            "This application requires signed requests, so it must be opened from its own sign-in page.",
        ));
    }
    let mut signed = false;
    if let (Some(request), Some(query)) = (&request, &query) {
        signed = check_signature(st, &app, &config, query)
            .await
            .map_err(|e| page(t, &e.message))?;
        if signed {
            signed_message_ok(
                st,
                tenant_key,
                &tenant,
                request.destination.as_deref(),
                request.issue_instant,
            )
            .map_err(|m| page(t, m))?;
        }
    }

    let relay_state = query
        .as_ref()
        .and_then(|q| q.relay_state.clone())
        .or_else(|| config.relay_state.clone());
    let idp_entity = idp_entity_id(st, &tenant.id);
    Ok((
        tenant,
        app,
        sp,
        reply,
        SamlCall {
            request,
            launch,
            signed,
            config,
            idp_entity,
            relay_state,
            reply_url,
        },
    ))
}

fn post_back(reply: &url::Url, response: String, relay_state: Option<&str>) -> Response {
    let mut fields = vec![(SAML_RESPONSE, response)];
    if let Some(relay) = relay_state {
        fields.push((RELAY_STATE, relay.to_string()));
    }
    html::form_post(reply, &fields)
}

/// A protocol failure, posted to the application's registered Reply URL.
pub(super) fn error_answer(call: &SamlCall, reply: &url::Url, error: &SamlError) -> Response {
    let in_response_to = call.request.as_ref().map(|r| r.id.as_str());
    match protocol::error_response(&call.idp_entity, &call.reply_url, in_response_to, error, now()) {
        Ok(response) => post_back(reply, response, call.relay_state.as_deref()),
        Err(e) => internal(None, e),
    }
}

/// An OAuth-shaped failure from the shared sign-in steps, as a SAML status.
pub(super) fn from_aad(err: &AadError) -> SamlError {
    let sub_status = match err.error {
        OAuthError::LoginRequired | OAuthError::InteractionRequired => Some(protocol::STATUS_NO_PASSIVE),
        OAuthError::AccessDenied => Some(protocol::STATUS_AUTHN_FAILED),
        _ => None,
    };
    SamlError {
        status: protocol::STATUS_RESPONDER,
        sub_status,
        message: err.description(),
    }
}

/// The class the assertion states, and whether the request's can be met: a
/// requested class this sign-in satisfies is echoed, else the strongest used.
fn authn_context(requested: &[String], declaration: bool, amr: &[String]) -> Result<&'static str, SamlError> {
    let unmet = || SamlError {
        status: protocol::STATUS_RESPONDER,
        sub_status: Some(protocol::STATUS_NO_AUTHN_CONTEXT),
        message: "The requested authentication context cannot be satisfied.".into(),
    };
    if declaration {
        return Err(unmet());
    }
    let mfa = amr.iter().any(|m| m == Amr::Mfa.as_str());
    let strongest = if mfa { protocol::AC_MFA } else { protocol::AC_PASSWORD };
    if requested.is_empty() {
        return Ok(strongest);
    }
    for class in requested {
        match class.as_str() {
            protocol::AC_MFA if mfa => return Ok(protocol::AC_MFA),
            protocol::AC_PASSWORD => return Ok(protocol::AC_PASSWORD),
            protocol::AC_PASSWORD_PROTECTED => return Ok(protocol::AC_PASSWORD_PROTECTED),
            protocol::AC_UNSPECIFIED => return Ok(strongest),
            _ => {}
        }
    }
    Err(unmet())
}

fn single(name: &str, value: Option<String>) -> Option<AssertionAttribute> {
    value.filter(|v| !v.is_empty()).map(|v| AssertionAttribute {
        name: name.to_string(),
        values: vec![v],
    })
}

/// The assertion's attributes: the configured claims, then Entra's fixed ones.
pub(crate) async fn attributes(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    sp: &ServicePrincipal,
    config: &SamlConfig,
    user: &User,
    amr: &[String],
) -> anyhow::Result<Vec<AssertionAttribute>> {
    // Configured claims cannot use these names (`saml::claim_name_problem`).
    let mut out: Vec<AssertionAttribute> = config
        .claims
        .iter()
        .filter_map(|c| single(&c.name, c.source.of(user, &tenant.id)))
        .collect();
    out.extend(single(CLAIM_TENANT, Some(tenant.id.clone())));
    out.extend(single(CLAIM_OBJECT_ID, Some(user.id.clone())));
    out.extend(single(CLAIM_DISPLAY_NAME, user.display_name.clone()));
    // Where the account is from, so an application can tell a guest from its own.
    out.extend(single(
        CLAIM_IDENTITY_PROVIDER,
        Some(st.public_url.issuer(&user.tenant_id)),
    ));
    out.push(AssertionAttribute {
        name: CLAIM_AUTHN_METHODS.into(),
        values: amr.to_vec(),
    });
    let roles = apps::app_roles_for_user(&st.pool, &sp.id, &user.id).await?;
    if !roles.is_empty() {
        out.push(AssertionAttribute {
            name: CLAIM_ROLE.into(),
            values: roles.into_iter().map(|r| r.value).collect(),
        });
    }
    // Another tenant's groups mean nothing here, as in its tokens.
    let groups = if user.tenant_id == tenant.id {
        groups::for_claim(&st.pool, app.group_membership_claims, Some(&sp.id), &user.id).await?
    } else {
        Vec::new()
    };
    if !groups.is_empty() {
        out.push(AssertionAttribute {
            name: CLAIM_GROUPS.into(),
            values: groups.into_iter().map(|g| g.id).collect(),
        });
    }
    Ok(out)
}

/// Everything the assertion is for.
pub(super) struct Issue<'a> {
    pub tenant: &'a Tenant,
    pub app: &'a Application,
    pub sp: &'a ServicePrincipal,
    pub reply: &'a url::Url,
    pub call: &'a SamlCall,
    pub user: &'a User,
    pub session: &'a Session,
    pub headers: &'a HeaderMap,
}

/// The signed-in, permitted user's assertion, posted to the Reply URL.
pub(super) async fn issue(st: &AppState, i: Issue<'_>) -> Response {
    if let Some(ticket) = &i.call.launch {
        match launch_allowed(st, &i, ticket).await {
            Ok(true) => {}
            Ok(false) => {
                return page(
                    Some(i.tenant),
                    "That launch is no longer valid. Open the application again from My apps.",
                );
            }
            Err(e) => return internal(Some(i.tenant), e),
        }
    }
    let answer = build(st, &i).await;
    match answer {
        Ok(response) => post_back(i.reply, response, i.call.relay_state.as_deref()),
        Err(e) => match e.downcast_ref::<SamlError>() {
            Some(error) => error_answer(i.call, i.reply, error),
            None => {
                tracing::error!(error = ?e, "building a SAML response failed");
                error_answer(i.call, i.reply, &refused("The sign-in could not be completed."))
            }
        },
    }
}

/// Whether this gallery launch stands: the application is still in this user's
/// gallery, and the ticket is theirs and unused. Using it up is the last step.
async fn launch_allowed(st: &AppState, i: &Issue<'_>, ticket: &str) -> anyhow::Result<bool> {
    let listed = saml::gallery(&st.pool, &i.user.tenant_id, &i.user.id)
        .await?
        .into_iter()
        .any(|a| a.app_id == i.app.app_id && a.is_saml && a.sign_on_url.is_none());
    Ok(listed && saml::take_launch_ticket(&st.pool, ticket, &i.tenant.id, &i.app.id, &i.user.id).await?)
}

async fn build(st: &AppState, i: &Issue<'_>) -> anyhow::Result<String> {
    let config = &i.call.config;
    let request = i.call.request.as_ref();
    let requested_contexts: &[String] = request.map_or(&[], |r| r.authn_contexts.as_slice());
    let declaration = request.is_some_and(|r| r.requests_declaration);
    let context = authn_context(requested_contexts, declaration, &i.session.amr)?;
    let key = saml::active_key(&st.pool, i.app)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the application has no active signing certificate"))?;
    let pairwise = st.secrets.pairwise_sub(&i.user.id, &i.app.app_id).await?;
    let (name_id, name_id_format) =
        saml::name_id_for(config, request.and_then(|r| r.name_id_format), i.user, &pairwise)?;
    // Copied into a signed assertion, so only a name this application owns.
    if let Some(qualifier) = request.and_then(|r| r.sp_name_qualifier.as_deref())
        && !config.identifiers.iter().any(|id| id == qualifier)
    {
        return Err(SamlError {
            status: protocol::STATUS_REQUESTER,
            sub_status: Some(protocol::STATUS_INVALID_NAMEID_POLICY),
            message: "SPNameQualifier is not an Identifier of this application.".into(),
        }
        .into());
    }
    if i.call.signed
        && let Some(r) = request
        && !saml::consume_message(&st.pool, &i.app.id, &r.id).await?
    {
        return Err(SamlError {
            status: protocol::STATUS_REQUESTER,
            sub_status: None,
            message: "This signed request has already been used.".into(),
        }
        .into());
    }
    let audience = match request {
        Some(r) => r.issuer.clone(),
        None => config
            .default_identifier()
            .ok_or_else(|| anyhow::anyhow!("no Identifier"))?
            .to_string(),
    };
    let attributes = attributes(st, i.tenant, i.app, i.sp, config, i.user, &i.session.amr).await?;
    let ts = now();
    let session_index = match session::cookie(i.headers, SESSION_COOKIE) {
        Some(cookie) => {
            saml::ensure_participant(
                &st.pool,
                &sha256_hex(cookie.as_bytes()),
                &i.tenant.id,
                i.app,
                &i.user.id,
                &name_id,
                name_id_format,
                i.session.auth_time + i.session.keep.lifetime(i.tenant),
            )
            .await?
        }
        None => protocol::new_id(),
    };
    let input = protocol::AssertionInput {
        idp_entity_id: &i.call.idp_entity,
        audience: &audience,
        recipient: &i.call.reply_url,
        in_response_to: request.map(|r| r.id.as_str()),
        name_id: &name_id,
        name_id_format,
        sp_name_qualifier: request.and_then(|r| r.sp_name_qualifier.as_deref()),
        session_index: &session_index,
        authn_instant: i.session.auth_time,
        authn_context: context,
        attributes: &attributes,
        now: ts,
    };
    let signer = Signer {
        private_key_pem: &key.private_key_pem,
        cert_der: &key.cert_der,
        algorithm: config.signing_algorithm,
    };
    let response = protocol::success_response(
        &input,
        &signer,
        config.signing_option,
        config.encryption_cert.as_deref(),
    )?;
    Ok(response)
}

// ---- the endpoint ----

/// `GET|POST /{tenant}/saml2`: a sign-in request, a logout request, or the
/// answer to a logout request we sent.
pub async fn endpoint(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw = if method == Method::POST {
        String::from_utf8_lossy(&body).into_owned()
    } else {
        query.unwrap_or_default()
    };
    // An IdP-initiated sign-in starts from the app gallery only: without a SAML
    // message there is nothing to answer here.
    let query = match SamlQuery::parse(&raw) {
        Ok(query) => query,
        Err(e) => return page(None, &e.message),
    };
    // A POST's signature is inside the message; query parameters do not count.
    let raw = if method == Method::POST {
        query.without_signature()
    } else {
        raw
    };
    let query = match SamlQuery::parse(&raw) {
        Ok(query) => query,
        Err(e) => return page(None, &e.message),
    };
    if query.param == SAML_RESPONSE {
        return logout_answered(&st, &tenant_key, &headers, &query).await;
    }
    let xml = match protocol::decode_message(&query.message) {
        Ok(xml) => xml,
        Err(e) => return page(None, &e.message),
    };
    let is_logout = protocol::parse_xml(&xml).is_ok_and(|root| root.local == "LogoutRequest");
    if is_logout {
        return logout_requested(&st, &tenant_key, &headers, &xml, &query, method).await;
    }
    let mut params = Params::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        params.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    let params = normalized(params, &raw);
    super::authorize::run_saml(&st, &tenant_key, &headers, &params, &raw).await
}

/// `GET /{tenant}/federationmetadata/2007-06/federationmetadata.xml?appid=..`
pub async fn metadata(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match metadata_xml(&st, &tenant_key, query.get("appid").map(String::as_str)).await {
        Ok(Some(xml)) => {
            let mut resp = (StatusCode::OK, xml).into_response();
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(METADATA_CONTENT_TYPE));
            resp
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "federation metadata failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn metadata_xml(st: &AppState, tenant_key: &str, app_id: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(tenant) = tenant::resolve(&st.pool, tenant_key).await? else {
        return Ok(None);
    };
    let Some(app_id) = app_id else { return Ok(None) };
    let Some(app) = apps::find(&st.pool, app_id).await?.filter(|a| a.tenant_id == tenant.id) else {
        return Ok(None);
    };
    let Some(config) = saml::config(&st.pool, &app).await?.filter(|c| c.enabled) else {
        return Ok(None);
    };
    // The active certificate first, then any others still valid, so an
    // application that reads metadata already trusts the next one at rollover.
    let mut certificates = saml::certificates(&st.pool, &app).await?;
    certificates.retain(|c| c.active || c.not_after > now());
    certificates.sort_by_key(|c| !c.active);
    let der: Vec<Vec<u8>> = certificates.into_iter().map(|c| c.cert_der).collect();
    Ok(Some(protocol::idp_metadata(
        &idp_entity_id(st, &tenant.id),
        &sso_url(st, &tenant.id),
        &der,
        config.require_signed_requests,
    )?))
}

// ---- Single Logout ----

fn redirect(location: &str) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn with_query(url: &str, query: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{query}")
}

/// A signed Redirect-binding message to `url`, from this application's key.
async fn signed_redirect(
    st: &AppState,
    app: &Application,
    config: &SamlConfig,
    url: &str,
    param: &str,
    xml: &str,
    relay_state: Option<&str>,
) -> anyhow::Result<Response> {
    let key = saml::active_key(&st.pool, app)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the application has no active signing certificate"))?;
    let signer = Signer {
        private_key_pem: &key.private_key_pem,
        cert_der: &key.cert_der,
        algorithm: config.signing_algorithm,
    };
    let query = signer.sign_redirect(param, &protocol::encode_redirect(xml)?, relay_state)?;
    Ok(redirect(&with_query(url, &query)))
}

/// Clear the session cookie unless the browser still has a session in another
/// tenant: one cookie serves them all.
async fn clear_cookie_if_last(st: &AppState, headers: &HeaderMap, resp: &mut Response) {
    if session::cookie(headers, SESSION_COOKIE).is_some() && !session::has_any(&st.pool, headers).await.unwrap_or(true)
    {
        resp.headers_mut().append(
            header::SET_COOKIE,
            session::clear_cookie(&st.public_url, SESSION_COOKIE),
        );
    }
}

/// Where a logout ends once every participant has been told.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogoutFinish {
    /// The application that asked, with its request id, to be answered.
    pub initiator: Option<String>,
    pub in_response_to: Option<String>,
    pub relay_state: Option<String>,
    /// Otherwise, a validated address from the OIDC logout endpoint.
    pub final_url: Option<String>,
    /// A participant could not be told, or said it failed.
    #[serde(default)]
    pub partial: bool,
}

/// Tell the next participant, or finish. `browser` is the cookie value that ties
/// this logout to the browser carrying it.
async fn advance(
    st: &AppState,
    tenant: &Tenant,
    mut remaining: Vec<Participant>,
    mut finish: LogoutFinish,
    browser: &str,
) -> anyhow::Result<Response> {
    while let Some(next) = remaining.pop() {
        let target = match saml::application_by_object_id(&st.pool, &next.application_id).await? {
            Some(app) => saml::config(&st.pool, &app)
                .await?
                .filter(|c| c.enabled)
                .and_then(|c| c.logout_url.clone().map(|url| (app, c, url))),
            None => None,
        };
        let Some((app, config, logout_url)) = target else {
            finish.partial = true;
            continue;
        };
        let (xml, id) = protocol::logout_request(
            &idp_entity_id(st, &tenant.id),
            &logout_url,
            &next.name_id,
            next.name_id_format,
            &next.session_index,
            now(),
        )?;
        let hash = sha256_hex(browser.as_bytes());
        let sent = match saml::save_logout_state(&st.pool, &id, &tenant.id, &app.id, &hash, &remaining, &finish).await {
            Ok(()) => signed_redirect(st, &app, &config, &logout_url, SAML_REQUEST, &xml, None).await,
            Err(e) => Err(e),
        };
        // One application that cannot be reached must not stop the others.
        let mut resp = match sent {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(error = ?e, "telling a SAML application about a logout failed");
                finish.partial = true;
                continue;
            }
        };
        resp.headers_mut().append(
            header::SET_COOKIE,
            session::set_cookie(&st.public_url, LOGOUT_COOKIE, browser, LOGOUT_COOKIE_SECS),
        );
        return Ok(resp);
    }
    let mut resp = finished(st, tenant, finish).await?;
    // The cookie is per browser: another tenant's logout may still need it.
    if !saml::logout_in_progress(&st.pool, &sha256_hex(browser.as_bytes())).await? {
        resp.headers_mut()
            .append(header::SET_COOKIE, session::clear_cookie(&st.public_url, LOGOUT_COOKIE));
    }
    Ok(resp)
}

/// The value tying a logout to this browser: the one it already holds, so that
/// logouts in two tenants do not overwrite each other's.
fn logout_browser(headers: &HeaderMap) -> String {
    session::cookie(headers, LOGOUT_COOKIE).unwrap_or_else(session::new_token)
}

/// Answer a logout request at the application's registered Logout URL.
#[allow(clippy::too_many_arguments)]
async fn answer_logout(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    config: &SamlConfig,
    logout_url: &str,
    in_response_to: &str,
    relay_state: Option<&str>,
    status: &str,
    sub_status: Option<&str>,
) -> anyhow::Result<Response> {
    let xml = protocol::logout_response(
        &idp_entity_id(st, &tenant.id),
        logout_url,
        in_response_to,
        status,
        sub_status,
        now(),
    )?;
    signed_redirect(st, app, config, logout_url, SAML_RESPONSE, &xml, relay_state).await
}

async fn finished(st: &AppState, tenant: &Tenant, finish: LogoutFinish) -> anyhow::Result<Response> {
    if let (Some(app_id), Some(in_response_to)) = (&finish.initiator, &finish.in_response_to)
        && let Some(app) = saml::application_by_object_id(&st.pool, app_id).await?
        && let Some(config) = saml::config(&st.pool, &app).await?
        && let Some(logout_url) = config.logout_url.clone()
    {
        let (status, sub_status) = if finish.partial {
            (protocol::STATUS_RESPONDER, Some(protocol::STATUS_PARTIAL_LOGOUT))
        } else {
            (protocol::STATUS_SUCCESS, None)
        };
        return answer_logout(
            st,
            tenant,
            &app,
            &config,
            &logout_url,
            in_response_to,
            finish.relay_state.as_deref(),
            status,
            sub_status,
        )
        .await;
    }
    // With nobody to send a status to, the user is told directly.
    if finish.partial {
        return Ok(html::signed_out_partially(Some(&tenant.name)));
    }
    if let Some(url) = &finish.final_url {
        return Ok(redirect(url));
    }
    Ok(html::signed_out(Some(&tenant.name)))
}

/// A service provider asks to log the user out. As in Entra the NameID is not
/// compared, but only an application this browser's session actually signed in
/// to can end it, and a SessionIndex it sends must be the one it was given.
async fn logout_requested(
    st: &AppState,
    tenant_key: &str,
    headers: &HeaderMap,
    xml: &str,
    query: &SamlQuery,
    method: Method,
) -> Response {
    // Entra's Single Logout is the Redirect binding only.
    if method != Method::GET {
        return page(None, "SAML logout requests use the HTTP-Redirect binding.");
    }
    let tenant = match tenant::resolve(&st.pool, tenant_key).await {
        Ok(Some(t)) => t,
        Ok(None) => return page(None, &AadError::tenant_not_found(tenant_key).description()),
        Err(e) => return internal(None, e),
    };
    let t = Some(&tenant);
    let request = match protocol::LogoutRequest::parse(xml) {
        Ok(r) => r,
        Err(e) => return page(t, &e.message),
    };
    if request.not_on_or_after.is_some_and(|at| at <= now()) {
        return page(t, "The logout request has expired.");
    }
    let app = match saml::find_by_identifier(&st.pool, &tenant.id, &request.issuer).await {
        Ok(Some(app)) => app,
        Ok(None) => return page(t, &AadError::app_not_found(&request.issuer, &tenant.id).description()),
        Err(e) => return internal(t, e),
    };
    let config = match saml::config(&st.pool, &app).await {
        Ok(Some(c)) => c,
        Ok(None) => return page(t, "SAML single sign-on is not set up for this application."),
        Err(e) => return internal(t, e),
    };
    // The logout answer goes only to a registered Logout URL.
    let Some(logout_url) = config.logout_url.clone() else {
        return page(t, "No Logout URL is configured for this application.");
    };
    let signed = match check_signature(st, &app, &config, query).await {
        Ok(signed) => signed,
        Err(e) => return page(t, &e.message),
    };
    if signed
        && let Err(m) = signed_message_ok(
            st,
            tenant_key,
            &tenant,
            request.destination.as_deref(),
            request.issue_instant,
        )
    {
        return page(t, m);
    }
    let signed_in = match session::find(&st.pool, headers, &tenant.id).await {
        Ok(s) => s,
        Err(e) => return internal(t, e),
    };
    let hash = session::cookie(headers, SESSION_COOKIE).map(|c| sha256_hex(c.as_bytes()));
    let held = match (&signed_in, &hash) {
        (Some(s), Some(hash)) => {
            match saml::participant_indexes(&st.pool, hash, &tenant.id, &app.id, &s.user_id).await {
                Ok(held) => held,
                Err(e) => return internal(t, e),
            }
        }
        _ => Vec::new(),
    };
    // The entries this request is about: the SessionIndexes it names, or all of
    // this user's at this application when it names none.
    let matched: Vec<String> = held
        .into_iter()
        .filter(|i| request.session_indexes.is_empty() || request.session_indexes.contains(i))
        .collect();
    let (Some(session), Some(hash), false) = (&signed_in, &hash, matched.is_empty()) else {
        // Nothing of this application's here to end: say so, and end nothing.
        return match answer_logout(
            st,
            &tenant,
            &app,
            &config,
            &logout_url,
            &request.id,
            query.relay_state.as_deref(),
            protocol::STATUS_RESPONDER,
            Some(protocol::STATUS_UNKNOWN_PRINCIPAL),
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => internal(t, e),
        };
    };
    // Used up only by a request that really ends this session, so that someone
    // holding a copy of the URL cannot burn it from another browser.
    if signed {
        match saml::consume_message(&st.pool, &app.id, &request.id).await {
            Ok(true) => {}
            Ok(false) => return page(t, "This signed request has already been used."),
            Err(e) => return internal(t, e),
        }
    }
    let mut participants = match saml::take_participants(&st.pool, hash, &tenant.id).await {
        Ok(p) => p,
        Err(e) => return internal(t, e),
    };
    if let Err(e) = session::end(&st.pool, headers, &tenant.id).await {
        return internal(t, e);
    }
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&session.user_id),
        Event::SessionEnd,
        Some(&session.user_id),
        serde_json::json!({ "via": Channel::SamlLogout.as_str(), "clientId": app.app_id }),
    )
    .await;
    // The application that asked is answered last, not asked again.
    participants.retain(|p| !matched.contains(&p.session_index));
    let finish = LogoutFinish {
        initiator: Some(app.id.clone()),
        in_response_to: Some(request.id),
        relay_state: query.relay_state.clone(),
        final_url: None,
        partial: false,
    };
    match advance(st, &tenant, participants, finish, &logout_browser(headers)).await {
        Ok(mut resp) => {
            clear_cookie_if_last(st, headers, &mut resp).await;
            resp
        }
        Err(e) => internal(t, e),
    }
}

/// A participant answered the logout request we sent it: carry on.
async fn logout_answered(st: &AppState, tenant_key: &str, headers: &HeaderMap, query: &SamlQuery) -> Response {
    let tenant = match tenant::resolve(&st.pool, tenant_key).await {
        Ok(Some(t)) => t,
        Ok(None) => return page(None, &AadError::tenant_not_found(tenant_key).description()),
        Err(e) => return internal(None, e),
    };
    let t = Some(&tenant);
    let parsed = protocol::decode_message(&query.message).and_then(|xml| protocol::LogoutResponse::parse(&xml));
    let response = match parsed {
        Ok(r) => r,
        Err(e) => return page(t, &e.message),
    };
    let Some(id) = response.in_response_to.as_deref() else {
        return page(t, "The logout response does not answer a request.");
    };
    let Some(browser) = session::cookie(headers, LOGOUT_COOKIE) else {
        return page(t, "This browser has no logout in progress.");
    };
    // Who answered is settled first: only the application the request went to,
    // in the browser it went through, can use up the waiting logout.
    let answering = match saml::find_by_identifier_any_mode(&st.pool, &tenant.id, &response.issuer).await {
        Ok(Some(app)) => app,
        Ok(None) => return page(t, "The logout response is not from the application it was sent to."),
        Err(e) => return internal(t, e),
    };
    let config = match saml::config(&st.pool, &answering).await {
        Ok(Some(c)) => c,
        Ok(None) => return page(t, "SAML single sign-on is not set up for this application."),
        Err(e) => return internal(t, e),
    };
    if let Err(e) = check_signature(st, &answering, &config, query).await {
        return page(t, &e.message);
    }
    // A response that names a Destination must name this endpoint, or it is
    // discarded (SAML Core 3.2.2); a signed one must name it (the bindings).
    // Checked before the waiting logout is used up.
    let here = |d: &str| d == sso_url(st, &tenant.id) || d == sso_url(st, tenant_key);
    match response.destination.as_deref() {
        Some(d) if !here(d) => return page(t, "The logout response's Destination is not this endpoint."),
        None if config.require_signed_requests => {
            return page(t, "The signed logout response has no Destination.");
        }
        _ => {}
    }
    let hash = sha256_hex(browser.as_bytes());
    let mut state = match saml::take_logout_state(&st.pool, id, &tenant.id, &answering.id, &hash).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            return page(
                t,
                "The logout response does not answer a request sent to this application.",
            );
        }
        Err(e) => return internal(t, e),
    };
    state.finish.partial |= !response.success;
    match advance(st, &tenant, state.remaining, state.finish, &browser).await {
        Ok(resp) => resp,
        Err(e) => internal(t, e),
    }
}

/// The OIDC logout endpoint ended a session: tell its SAML participants, then
/// go where that endpoint would have gone. `None` when there are none to tell.
pub(super) async fn logout_participants(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    participants: Vec<Participant>,
    final_url: Option<String>,
) -> Option<Response> {
    if participants.is_empty() {
        return None;
    }
    let finish = LogoutFinish {
        initiator: None,
        in_response_to: None,
        relay_state: None,
        final_url,
        partial: false,
    };
    match advance(st, tenant, participants, finish, &logout_browser(headers)).await {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::error!(error = ?e, "SAML logout failed");
            Some(html::signed_out_partially(Some(&tenant.name)))
        }
    }
}
