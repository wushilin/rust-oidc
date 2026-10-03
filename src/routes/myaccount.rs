//! My Account: the user's own page, at `/{tenant}/myaccount`.
//!
//! What a user may do for themselves (2026-10-03): see their profile (only an
//! administrator changes it), change their password knowing the current one,
//! set up an authenticator, replace it after confirming with a code from it or a
//! recovery code, get new recovery codes after confirming with an authenticator
//! code, and sign out everywhere. Forgetting a password is not handled here: that
//! needs mail, which this server does not send.
//!
//! Sign-in is the tenant's own browser session, so a user already signed in to an
//! application is signed in here too, and the same steps apply: a second factor
//! for whoever has one or needs one, and a new password where one must be chosen.
//! The page is script-free like every other.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use serde_json::json;

use super::audit::{self, Actor, Channel, Event};
use crate::AppState;
use crate::admin::routes::Settled;
use crate::claims::Amr;
use crate::error::AadError;
use crate::html::{self, AccountOp, LoginOp};
use crate::mfa::{self, Purpose};
use crate::session::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::tenant::{self, Tenant};
use crate::txn::{
    self,
    ops::self_service::{ReplaceRecoveryCodes, SignOutEverywhere},
};
use crate::users::{self, AuthResult, User};
use crate::util::ct_eq;

type Params = HashMap<String, String>;

/// What a second-step form's `request` field says when the step was started from
/// this page by a signed-in user, rather than as part of signing in.
const VOLUNTARY: &str = "voluntary";
const EXPIRED: &str = "That sign-in has expired or had too many wrong codes. Please sign in again.";
const WRONG_CODE: &str = "That code didn't work. Check the time on your phone, wait for a new code and try again.";

fn url(st: &AppState, tenant: &Tenant) -> String {
    st.public_url.tenant_url(&tenant.id, "myaccount")
}

fn get<'a>(form: &'a Params, name: &str) -> &'a str {
    form.get(name).map(String::as_str).unwrap_or_default()
}

fn fail(tenant: &Tenant, e: anyhow::Error) -> Response {
    html::error(Some(&tenant.name), &AadError::from(e).description())
}

/// The signed-in user of this browser in this tenant, with the methods their
/// session was signed in with.
async fn current(st: &AppState, tenant: &Tenant, headers: &HeaderMap) -> Option<(User, Vec<String>)> {
    let s = session::find(&st.pool, headers, &tenant.id).await.ok()??;
    let user = users::find(&st.pool, &tenant.id, &s.user_id).await.ok()??;
    user.enabled.then_some((user, s.amr))
}

fn with_csrf(mut resp: Response, st: &AppState, csrf: &str) -> Response {
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, CSRF_COOKIE, csrf, 3600),
    );
    resp
}

fn login_page(st: &AppState, tenant: &Tenant, upn: &str, error: Option<&str>) -> Response {
    let csrf = session::new_token();
    let resp = html::login(&html::LoginForm {
        tenant_name: &tenant.name,
        client_name: "My account",
        action: &url(st, tenant),
        csrf: &csrf,
        request: "",
        upn,
        error,
    });
    with_csrf(resp, st, &csrf)
}

struct Shown<'a> {
    notice: Option<&'a str>,
    error: Option<&'a str>,
    new_codes: Option<&'a [String]>,
}

const PLAIN: Shown<'static> = Shown {
    notice: None,
    error: None,
    new_codes: None,
};

async fn dashboard(st: &AppState, tenant: &Tenant, user: &User, shown: Shown<'_>) -> Response {
    let csrf = session::new_token();
    let since = mfa::enrolled_at(&st.pool, &user.id)
        .await
        .unwrap_or(None)
        .map(crate::admin::view::ts);
    let left = mfa::recovery_codes_left(&st.pool, &user.id).await.unwrap_or(0);
    let required = mfa::required(&st.pool, tenant, &user.id, mfa::At::MyAccount)
        .await
        .unwrap_or(false);
    let resp = html::my_account(&html::MyAccount {
        tenant_name: &tenant.name,
        action: &url(st, tenant),
        csrf: &csrf,
        upn: &user.upn,
        display_name: user.display_name.as_deref(),
        given_name: user.given_name.as_deref(),
        family_name: user.family_name.as_deref(),
        email: user.email.as_deref(),
        mfa_since: since.as_deref(),
        recovery_codes_left: left,
        mfa_required: required,
        notice: shown.notice,
        error: shown.error,
        new_codes: shown.new_codes,
    });
    with_csrf(resp, st, &csrf)
}

/// A second-step page (code, authenticator set-up, new password) for this page.
#[allow(clippy::too_many_arguments)]
fn step_page(
    st: &AppState,
    tenant: &Tenant,
    upn: &str,
    purpose: Purpose,
    ticket: &str,
    secret: Option<&str>,
    voluntary: bool,
    error: Option<&str>,
) -> Response {
    let csrf = session::new_token();
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        html::escape(&csrf),
        if voluntary { VOLUNTARY } else { "" }
    );
    let action = url(st, tenant);
    let resp = match (purpose, secret) {
        (Purpose::Enroll, Some(secret)) => html::mfa_enroll(&html::MfaEnroll {
            tenant_name: &tenant.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: "op",
            op: LoginOp::MfaEnroll.as_str(),
            ticket,
            qr_svg: &mfa::qr_svg(&mfa::otpauth_uri(secret, &tenant.name, upn)),
            secret,
            issuer: &tenant.name,
            error,
        }),
        (Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa, _) => {
            html::change_password(&html::ChangePassword {
                tenant_name: &tenant.name,
                upn,
                action: &action,
                hidden: &hidden,
                op_field: "op",
                op: LoginOp::ChangePassword.as_str(),
                ticket,
                error,
            })
        }
        _ => html::mfa_verify(&html::MfaVerify {
            tenant_name: &tenant.name,
            upn,
            action: &action,
            hidden: &hidden,
            op_field: "op",
            op: LoginOp::MfaVerify.as_str(),
            ticket,
            error,
        }),
    };
    with_csrf(resp, st, &csrf)
}

/// Start a pending step for this user and show its page.
async fn start(st: &AppState, tenant: &Tenant, user: &User, purpose: Purpose, voluntary: bool) -> Response {
    match mfa::begin(&st.pool, &tenant.id, &user.id, purpose).await {
        Ok(ticket) => {
            let secret = match purpose {
                Purpose::Enroll => mfa::pending(&st.pool, &ticket, &tenant.id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.enroll_secret),
                _ => None,
            };
            step_page(
                st,
                tenant,
                &user.upn,
                purpose,
                &ticket,
                secret.as_deref(),
                voluntary,
                None,
            )
        }
        Err(e) => fail(tenant, e),
    }
}

fn step_purpose(step: mfa::Step) -> Option<Purpose> {
    match step {
        mfa::Step::Done => None,
        mfa::Step::Verify => Some(Purpose::Verify),
        mfa::Step::Enroll => Some(Purpose::Enroll),
    }
}

/// The steps after the password: a new password if one must be chosen, then the
/// session, and back to the page.
async fn finish(st: &AppState, tenant: &Tenant, headers: &HeaderMap, user: &User, after_mfa: bool) -> Response {
    match users::must_change_password(&st.pool, &user.id).await {
        Ok(true) => return start(st, tenant, user, Purpose::change_password(after_mfa), false).await,
        Ok(false) => {}
        Err(e) => return fail(tenant, e),
    }
    let amr: Vec<&str> = if after_mfa {
        vec![Amr::Pwd.as_str(), Amr::Mfa.as_str()]
    } else {
        vec![Amr::Pwd.as_str()]
    };
    signed_in(st, tenant, headers, user, &amr, PLAIN).await
}

/// Make (or remake) this browser's session and show the page.
async fn signed_in(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    user: &User,
    amr: &[&str],
    shown: Shown<'_>,
) -> Response {
    let lifetime = tenant.settings.session_lifetime_secs;
    let cookie = match session::create(&st.pool, headers, &tenant.id, &user.id, amr, lifetime).await {
        Ok(c) => c,
        Err(e) => return fail(tenant, e),
    };
    audit::record(
        st,
        &tenant.id,
        Actor::Id(&user.id),
        Event::SignIn,
        Some(&user.id),
        json!({ "via": Channel::MyAccount.as_str() }),
    )
    .await;
    let mut resp = dashboard(st, tenant, user, shown).await;
    resp.headers_mut().append(
        header::SET_COOKIE,
        session::set_cookie(&st.public_url, SESSION_COOKIE, &cookie, lifetime),
    );
    resp
}

/// `GET /{tenant}/myaccount`
pub async fn page(State(st): State<AppState>, Path(tenant_key): Path<String>, headers: HeaderMap) -> Response {
    let Ok(Some(tenant)) = tenant::resolve(&st.pool, &tenant_key).await else {
        return html::error(None, "That account page is not valid.");
    };
    let Some((user, amr)) = current(&st, &tenant, &headers).await else {
        return login_page(&st, &tenant, "", None);
    };
    // A session from an application's sign-in still needs a second factor here,
    // where the user has one or needs one.
    if !amr.iter().any(|m| m == Amr::Mfa.as_str()) {
        match mfa::step(&st.pool, &tenant, &user.id, mfa::At::MyAccount).await {
            Ok(step) => {
                if let Some(purpose) = step_purpose(step) {
                    return start(&st, &tenant, &user, purpose, false).await;
                }
            }
            Err(e) => return fail(&tenant, e),
        }
    }
    dashboard(&st, &tenant, &user, PLAIN).await
}

/// `POST /{tenant}/myaccount`: signing in, its further steps, and every action.
pub async fn post(
    State(st): State<AppState>,
    Path(tenant_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form: Params = url::form_urlencoded::parse(&body).into_owned().collect();
    let Ok(Some(tenant)) = tenant::resolve(&st.pool, &tenant_key).await else {
        return html::error(None, "That account page is not valid.");
    };
    let csrf_ok = match (session::cookie(&headers, CSRF_COOKIE), form.get("csrf")) {
        (Some(c), Some(f)) => ct_eq(&c, f),
        _ => false,
    };
    if !csrf_ok {
        return login_page(&st, &tenant, "", Some("Your session expired. Please sign in again."));
    }
    let op = get(&form, "op");
    if let Some(account_op) = AccountOp::parse(op) {
        let Some((user, amr)) = current(&st, &tenant, &headers).await else {
            return login_page(&st, &tenant, "", None);
        };
        return action(&st, &tenant, &headers, &form, &user, &amr, account_op).await;
    }
    match LoginOp::parse(op) {
        Some(op @ (LoginOp::MfaVerify | LoginOp::MfaEnroll | LoginOp::ChangePassword)) => {
            pending_step(&st, &tenant, &headers, &form, op).await
        }
        _ => password(&st, &tenant, &headers, &form).await,
    }
}

/// The sign-in form: the password, then whatever comes after it.
async fn password(st: &AppState, tenant: &Tenant, headers: &HeaderMap, form: &Params) -> Response {
    let upn = get(form, "upn").trim();
    let (outcome, trace) = match users::authenticate_traced(&st.pool, tenant, upn, get(form, "password")).await {
        Ok(o) => o,
        Err(e) => return fail(tenant, e),
    };
    audit::sign_in_failure(st, &tenant.id, upn, &outcome, &trace, Channel::MyAccount, "").await;
    let user = match outcome {
        AuthResult::Ok(user) => user,
        AuthResult::InvalidCredentials => {
            let hint = tenant::not_ours_hint(&st.pool, tenant, upn, false).await;
            return login_page(
                st,
                tenant,
                upn,
                Some(
                    hint.as_deref()
                        .unwrap_or("Your account or password is incorrect. (AADSTS50126)"),
                ),
            );
        }
        AuthResult::Locked => {
            return login_page(
                st,
                tenant,
                upn,
                Some("Your account is temporarily locked. Try again later. (AADSTS50053)"),
            );
        }
        AuthResult::Disabled => {
            return login_page(st, tenant, upn, Some("Your account has been disabled. (AADSTS50057)"));
        }
    };
    match mfa::step(&st.pool, tenant, &user.id, mfa::At::MyAccount).await {
        Ok(step) => match step_purpose(step) {
            Some(purpose) => start(st, tenant, &user, purpose, false).await,
            None => finish(st, tenant, headers, &user, false).await,
        },
        Err(e) => fail(tenant, e),
    }
}

/// A posted code, authenticator set-up or new password.
async fn pending_step(st: &AppState, tenant: &Tenant, headers: &HeaderMap, form: &Params, op: LoginOp) -> Response {
    let ticket = get(form, html::MFA_TICKET);
    let typed = get(form, html::MFA_CODE);
    let voluntary = get(form, "request") == VOLUNTARY;
    let Ok(Some(waiting)) = mfa::pending(&st.pool, ticket, &tenant.id).await else {
        return login_page(st, tenant, "", Some(EXPIRED));
    };
    let user = match users::find(&st.pool, &tenant.id, &waiting.user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return login_page(st, tenant, "", Some(EXPIRED)),
    };
    // A step started from the page belongs to whoever is signed in on it.
    let signed_in_here = current(st, tenant, headers).await;
    if voluntary && signed_in_here.as_ref().is_none_or(|(u, _)| u.id != user.id) {
        return login_page(st, tenant, "", Some(EXPIRED));
    }
    let fits = match op {
        LoginOp::MfaEnroll => waiting.purpose == Purpose::Enroll,
        LoginOp::ChangePassword => matches!(
            waiting.purpose,
            Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa
        ),
        _ => waiting.purpose == Purpose::Verify,
    };
    if !fits {
        return login_page(st, tenant, "", Some(EXPIRED));
    }
    match waiting.purpose {
        Purpose::Verify => match mfa::check(&st.pool, &user.id, typed).await {
            Ok(Some(factor)) => {
                let _ = mfa::finish(&st.pool, ticket).await;
                audit::record(
                    st,
                    &tenant.id,
                    Actor::Id(&user.id),
                    Event::MfaVerified,
                    Some(&user.id),
                    json!({ "via": Channel::MyAccount.as_str(), "factor": factor.as_str() }),
                )
                .await;
                finish(st, tenant, headers, &user, true).await
            }
            Ok(None) => {
                super::authorize::wrong_code(st, &tenant.id, &user.id, Channel::MyAccount).await;
                match mfa::failed_attempt(&st.pool, ticket).await {
                    Ok(true) => step_page(
                        st,
                        tenant,
                        &user.upn,
                        Purpose::Verify,
                        ticket,
                        None,
                        false,
                        Some(WRONG_CODE),
                    ),
                    _ => login_page(st, tenant, "", Some(EXPIRED)),
                }
            }
            Err(e) => fail(tenant, e),
        },
        Purpose::Enroll => {
            let secret = waiting.enroll_secret.unwrap_or_default();
            if !mfa::verify_new(&secret, typed) {
                return match mfa::failed_attempt(&st.pool, ticket).await {
                    Ok(true) => step_page(
                        st,
                        tenant,
                        &user.upn,
                        Purpose::Enroll,
                        ticket,
                        Some(&secret),
                        voluntary,
                        Some(WRONG_CODE),
                    ),
                    _ => login_page(st, tenant, "", Some(EXPIRED)),
                };
            }
            // Set up at sign-in, the transaction also signs them out everywhere.
            let enrolled =
                super::enroll_own_authenticator(st, &tenant.id, &user.id, &secret, Channel::MyAccount, voluntary).await;
            let codes = match super::settle_own(enrolled, &tenant.name) {
                Settled::Done(codes) => codes,
                Settled::Refused(message) => return login_page(st, tenant, "", Some(&message)),
                Settled::Respond(resp) => return resp,
            };
            let _ = mfa::finish(&st.pool, ticket).await;
            if voluntary {
                // Set up from the page: still signed in, now with both methods,
                // and the codes on the page this once.
                let amr = [Amr::Pwd.as_str(), Amr::Mfa.as_str()];
                let shown = Shown {
                    notice: Some(
                        "Your authenticator is set up. You will be asked for a code from it at every sign-in.",
                    ),
                    error: None,
                    new_codes: Some(&codes),
                };
                return signed_in(st, tenant, headers, &user, &amr, shown).await;
            }
            // Set up at sign-in: signed out, and back in with it.
            let mut resp = html::mfa_enrolled(&tenant.name, &codes, &url(st, tenant));
            resp.headers_mut().append(
                header::SET_COOKIE,
                session::clear_cookie(&st.public_url, SESSION_COOKIE),
            );
            resp
        }
        Purpose::ChangePassword | Purpose::ChangePasswordAfterMfa => {
            let new = get(form, html::NEW_PASSWORD);
            let refused = if new != get(form, html::CONFIRM_PASSWORD) {
                Some("The passwords don't match.".to_string())
            } else {
                let changed = super::change_own_password(st, tenant, &user.id, new, Channel::MyAccount).await;
                match super::settle_own(changed, &tenant.name) {
                    Settled::Done(()) => None,
                    Settled::Refused(message) => Some(message),
                    Settled::Respond(resp) => return resp,
                }
            };
            if let Some(message) = refused {
                return step_page(
                    st,
                    tenant,
                    &user.upn,
                    waiting.purpose,
                    ticket,
                    None,
                    false,
                    Some(&message),
                );
            }
            let _ = mfa::finish(&st.pool, ticket).await;
            let mut amr = vec![Amr::Pwd.as_str()];
            if waiting.purpose == Purpose::ChangePasswordAfterMfa {
                amr.push(Amr::Mfa.as_str());
            }
            signed_in(st, tenant, headers, &user, &amr, PLAIN).await
        }
    }
}

/// One of the page's own actions, by the signed-in user.
#[allow(clippy::too_many_arguments)]
async fn action(
    st: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    form: &Params,
    user: &User,
    amr: &[String],
    op: AccountOp,
) -> Response {
    let refuse = |message: &str| {
        let message = message.to_string();
        async move {
            dashboard(
                st,
                tenant,
                user,
                Shown {
                    notice: None,
                    error: Some(&message),
                    new_codes: None,
                },
            )
            .await
        }
    };
    let typed = get(form, html::MFA_CODE);
    match op {
        AccountOp::Password => {
            let current_ok = matches!(
                users::authenticate(&st.pool, tenant, &user.upn, get(form, html::CURRENT_PASSWORD)).await,
                Ok(AuthResult::Ok(_))
            );
            if !current_ok {
                return refuse("Your current password is not right.").await;
            }
            let new = get(form, html::NEW_PASSWORD);
            if new != get(form, html::CONFIRM_PASSWORD) {
                return refuse("The new passwords don't match.").await;
            }
            let changed = super::change_own_password(st, tenant, &user.id, new, Channel::MyAccount).await;
            match super::settle_own(changed, &tenant.name) {
                Settled::Done(()) => {}
                Settled::Refused(message) => return refuse(&message).await,
                Settled::Respond(resp) => return resp,
            }
            // A new password ends every session; this browser stays signed in.
            let amr: Vec<&str> = amr.iter().map(String::as_str).collect();
            let shown = Shown {
                notice: Some("Your password is changed. You have been signed out everywhere else."),
                error: None,
                new_codes: None,
            };
            signed_in(st, tenant, headers, user, &amr, shown).await
        }
        AccountOp::MfaSetup => {
            if mfa::enrolled_at(&st.pool, &user.id).await.unwrap_or(None).is_some() {
                return refuse("You already have an authenticator. To move to a new phone, use New phone below.").await;
            }
            start(st, tenant, user, Purpose::Enroll, true).await
        }
        AccountOp::MfaReplace => match mfa::check(&st.pool, &user.id, typed).await {
            Ok(Some(_)) => start(st, tenant, user, Purpose::Enroll, true).await,
            Ok(None) => {
                super::authorize::wrong_code(st, &tenant.id, &user.id, Channel::MyAccount).await;
                refuse("That code didn't work.").await
            }
            Err(e) => fail(tenant, e),
        },
        AccountOp::RecoveryCodes => {
            // An authenticator code, not a recovery code: new codes are for whoever
            // still has the authenticator.
            let digits = typed.trim().replace(' ', "");
            let is_authenticator_code = digits.len() == 6 && digits.chars().all(|c| c.is_ascii_digit());
            let confirmed = is_authenticator_code
                && matches!(
                    mfa::check(&st.pool, &user.id, &digits).await,
                    Ok(Some(mfa::Factor::Authenticator))
                );
            if !confirmed {
                super::authorize::wrong_code(st, &tenant.id, &user.id, Channel::MyAccount).await;
                return refuse("That code didn't work. Use the six-digit code from your authenticator.").await;
            }
            let replace = ReplaceRecoveryCodes {
                tenant_id: tenant.id.clone(),
                user_id: user.id.clone(),
                codes: mfa::NewRecoveryCodes::generate(),
            };
            let replaced = txn::run(&st.pool, &super::own(&user.id), &replace).await;
            let codes = match super::settle_own(replaced, &tenant.name) {
                Settled::Done(codes) => codes,
                Settled::Refused(message) => return refuse(&message).await,
                Settled::Respond(resp) => return resp,
            };
            dashboard(
                st,
                tenant,
                user,
                Shown {
                    notice: None,
                    error: None,
                    new_codes: Some(&codes),
                },
            )
            .await
        }
        AccountOp::SignOutEverywhere => {
            let sign_out = SignOutEverywhere {
                tenant_id: tenant.id.clone(),
                user_id: user.id.clone(),
            };
            let ended = txn::run(&st.pool, &super::own(&user.id), &sign_out).await;
            match super::settle_own(ended, &tenant.name) {
                Settled::Done(()) => {}
                Settled::Refused(message) => return refuse(&message).await,
                Settled::Respond(resp) => return resp,
            }
            let mut resp = html::signed_out(Some(&tenant.name));
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
