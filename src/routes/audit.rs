//! Audit trail for the HTTP layer.
//!
//! One helper, [`record`], and one enum of event names, [`Event`].
//!
//! Rules every call site follows:
//! - `details` is treated as public: audit rows are shipped to third-party log
//!   systems. Only identifiers, outcomes and reason codes go in. Never a
//!   password, secret, token, code, assertion, cookie or device code, and no
//!   hash or prefix of one either.
//! - A failed write is logged and swallowed. See [`record`].
//! - Attacker-supplied strings (a submitted UPN, a claimed client id) are
//!   clipped by [`clip`] so a hostile request cannot bloat the table.

use serde_json::Value;

use crate::AppState;
use crate::ratelimit::{Hit, Limit, app_key};
use crate::users::{AuthResult, AuthTrace};

/// Longest attacker-supplied string kept in `details`.
const MAX_FIELD_LEN: usize = 128;

/// The audit vocabulary lives in [`crate::db`], beside the `audit` function that
/// writes it, so the CLI and the HTTP layer cannot drift apart. Re-exported here
/// because this is where the HTTP layer reaches for it.
pub use crate::db::{Actor, Event};

/// Where a password was checked, recorded as `via`.
#[derive(Debug, Clone, Copy)]
pub enum Channel {
    /// The browser sign-in form on `/authorize`.
    Authorize,
    /// The sign-in form on the device approval page.
    Device,
    /// The password grant at the token endpoint.
    Ropc,
    /// The RP-initiated logout endpoint.
    EndSession,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Device => "device",
            Self::Ropc => "password_grant",
            Self::EndSession => "end_session",
        }
    }
}

/// Why client authentication failed, recorded as `reason`. Finer than the
/// error the client sees, which is deliberately uniform.
#[derive(Debug, Clone, Copy)]
pub enum Reason {
    UnknownClient,
    MissingSecret,
    InvalidSecret,
    ExpiredSecret,
    AppDisabled,
    MalformedAssertion,
    UnknownKey,
    ExpiredCertificate,
    InvalidAssertion,
    SubjectMismatch,
    MissingJti,
    LifetimeTooLong,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownClient => "unknown_client",
            Self::MissingSecret => "missing_secret",
            Self::InvalidSecret => "invalid_secret",
            Self::ExpiredSecret => "expired_secret",
            Self::AppDisabled => "app_disabled",
            Self::MalformedAssertion => "malformed_assertion",
            Self::UnknownKey => "unknown_key",
            Self::ExpiredCertificate => "expired_certificate",
            Self::InvalidAssertion => "invalid_signature_or_claims",
            Self::SubjectMismatch => "subject_mismatch",
            Self::MissingJti => "missing_jti",
            Self::LifetimeTooLong => "lifetime_too_long",
        }
    }
}

/// Why a password check failed. Distinguishes an unknown account from a wrong
/// password in the log even though the HTTP response cannot tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInReason {
    Locked,
    Disabled,
    BadPassword,
    UnknownUser,
}

impl SignInReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Disabled => "disabled",
            Self::BadPassword => "bad_password",
            Self::UnknownUser => "unknown_user",
        }
    }
}

/// The shape of a client id that did not resolve. Recorded instead of the value
/// itself, which is caller text and may be a credential (see
/// [`ClientFailures::fail`]). One bit of diagnostics, no content: it separates
/// "a well-formed id we do not know" from "something that is not an id at all",
/// which is what a transposed `client_id`/`client_secret` pair looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedShape {
    Guid,
    Other,
}

impl ClaimedShape {
    pub fn of(claimed: &str) -> Self {
        let guid = claimed.len() == 36
            && claimed.chars().enumerate().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => c == '-',
                _ => c.is_ascii_hexdigit(),
            });
        if guid { Self::Guid } else { Self::Other }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Guid => "guid",
            Self::Other => "other",
        }
    }
}

/// Reports failed client authentication for one request. Each `fail` audits
/// and hands an error back, so a call site reads
/// `return Err(failures.fail(.., err).await)`.
///
/// The error is returned untouched **except** when this failure is past its
/// rate-limit allowance, in which case nothing is recorded and the caller is
/// told to back off instead ([`crate::ratelimit`]). That is the one case where
/// auditing changes a response, and it is deliberate: it is what stops an
/// unauthenticated caller appending audit rows indefinitely.
pub struct ClientFailures<'a> {
    pub st: &'a AppState,
    pub tenant_id: &'a str,
    pub event: Event,
    /// The client id as claimed by the request. Unverified caller text, so only
    /// its [`ClaimedShape`] is ever recorded, never the value.
    pub claimed: &'a str,
}

impl ClientFailures<'_> {
    /// `app_id` is the client once it is known to exist and is then the actor;
    /// before that the actor is [`Actor::Anonymous`] and the claimed id is only data.
    pub async fn fail(
        &self,
        app_id: Option<&str>,
        reason: Reason,
        err: crate::error::AadError,
    ) -> crate::error::AadError {
        // Bucket this failure before recording it. An unresolved client id is
        // counted per tenant (never a legitimate request); a resolved one per
        // application, so one application's flood cannot throttle another.
        let (limit, key) = match app_id {
            Some(id) => (Limit::ClientAuthFailure, app_key(self.tenant_id, id)),
            None => (Limit::UnknownClient, self.tenant_id.to_string()),
        };
        let hit = self.st.limits.hit(limit, &key);
        if let Hit::AlreadyOver(retry) = hit {
            // Past the allowance nothing more is recorded -- that is what bounds
            // the table -- and the caller is told to back off instead of being
            // told why its credentials were wrong.
            return crate::error::AadError::throttled(retry);
        }
        // The claimed id is only safe to log once it has resolved to an app,
        // because then it is our own registered value. Before that it is
        // whatever the caller put in the field: a client that transposes
        // client_id and client_secret -- in the body or in the username half of
        // a Basic credential -- would otherwise write its secret here verbatim,
        // and a secret is short enough to survive `clip` intact. Same rule the
        // sign-in path applies to a submitted UPN.
        let mut details = serde_json::json!({ "reason": reason.as_str() });
        match app_id {
            Some(id) => details["clientId"] = id.into(),
            None => details["claimedShape"] = ClaimedShape::of(self.claimed).as_str().into(),
        }
        record(
            self.st,
            self.tenant_id,
            Actor::from(app_id),
            self.event,
            app_id,
            details,
        )
        .await;
        // Recorded *after* this failure's own row, and only by the event that
        // reached the allowance, so the log reads "the last failure, then the
        // throttle" and the refusals that follow add nothing.
        if hit == Hit::Reached {
            throttled(self.st, self.tenant_id, app_id, limit).await;
        }
        err
    }
}

/// Record that a rate-limit bucket reached its allowance. Written exactly once
/// per bucket per window, by the event that trips it.
pub async fn throttled(st: &AppState, tenant_id: &str, app_id: Option<&str>, limit: Limit) {
    let mut details = serde_json::json!({
        "limit": limit.as_str(),
        "allowance": limit.allowance(),
        "windowSeconds": limit.window_secs(),
    });
    if let Some(id) = app_id {
        details["clientId"] = id.into();
    }
    record(st, tenant_id, Actor::from(app_id), Event::Throttled, app_id, details).await;
}

/// The tenant's own verified domain that `value` names after its last `@`, as
/// stored. Anything else, including a lookup failure, yields `None`.
async fn own_domain(st: &AppState, tenant_id: &str, value: &str) -> Option<String> {
    let submitted = crate::util::fold(value.trim().rsplit_once('@')?.1);
    let domains = crate::tenant::domains(&st.pool, tenant_id).await.ok()?;
    domains.into_iter().find(|d| crate::util::fold(d) == submitted)
}

/// Truncate an attacker-controlled string for `details`.
pub fn clip(s: &str) -> String {
    s.chars().take(MAX_FIELD_LEN).collect()
}

/// Append one audit row. Never fails the request: an IdP that stops issuing
/// tokens because its audit table is full or briefly unreachable turns an
/// audit outage into an authentication outage (and a lever for denial of
/// service). The failure is logged at error level so monitoring can alert on
/// it; the request proceeds.
pub async fn record(
    st: &AppState,
    tenant_id: &str,
    actor: Actor<'_>,
    event: Event,
    target: Option<&str>,
    details: Value,
) {
    if let Err(e) = crate::db::audit(&st.pool, Some(tenant_id), actor, event, target, details).await {
        tracing::error!(error = ?e, event = event.as_str(), "audit write failed");
    }
}

/// Audit a failed password check: `auth.sign_in_failed` (with the reason class,
/// which distinguishes an unknown account from a wrong password even though
/// the HTTP response does not) and `auth.lockout` when this attempt tripped it.
/// `client_id` is the OAuth client involved, when known.
pub async fn sign_in_failure(
    st: &AppState,
    tenant_id: &str,
    submitted_upn: &str,
    result: &AuthResult,
    trace: &AuthTrace,
    channel: Channel,
    client_id: &str,
) {
    let reason = match (result, trace.user_id.is_some()) {
        (AuthResult::Ok(_), _) => return,
        (AuthResult::Locked, _) => SignInReason::Locked,
        (AuthResult::Disabled, _) => SignInReason::Disabled,
        (AuthResult::InvalidCredentials, true) => SignInReason::BadPassword,
        (AuthResult::InvalidCredentials, false) => SignInReason::UnknownUser,
    };
    // A sign-in naming an account this tenant does not have can never be a
    // legitimate one, and it is the only failure whose key space is unbounded:
    // every distinct name the attacker invents is another row. Cap those rows
    // per tenant per window.
    //
    // Unlike the token endpoint this does **not** change the response. An
    // unknown account and a wrong password are deliberately indistinguishable to
    // the caller, and returning 429 only for the unknown one would turn the rate
    // limiter into an account-enumeration oracle. The cap applies to the audit
    // row alone.
    if reason == SignInReason::UnknownUser {
        match st.limits.hit(Limit::UnknownUser, tenant_id) {
            Hit::Under => {}
            Hit::Reached => throttled(st, tenant_id, None, Limit::UnknownUser).await,
            Hit::AlreadyOver(_) => return,
        }
    }
    // A known account is the actor; otherwise the submitted name is only data.
    // For the password grant the authenticated client stands in.
    let actor = match trace.user_id.as_deref() {
        Some(id) => Actor::Id(id),
        // For the password grant the authenticated client stands in; elsewhere
        // there is nobody to name.
        None => match channel {
            Channel::Ropc => Actor::Id(client_id),
            _ => Actor::Anonymous,
        },
    };
    // The submitted name is only safe to log when it resolved to an account,
    // because then it is a real UPN. Otherwise it may be anything, including a
    // password typed into the wrong box. The one thing still worth keeping is
    // the domain, and only when it is one of this tenant's own: that is our
    // public data, so it cannot be a fragment of what the user typed.
    let mut details = serde_json::json!({
        "reason": reason.as_str(),
        "via": channel.as_str(),
        "clientId": client_id,
    });
    if trace.user_id.is_some() {
        details["upn"] = clip(submitted_upn).into();
    } else if let Some(domain) = own_domain(st, tenant_id, submitted_upn).await {
        details["domain"] = domain.into();
    }
    record(
        st,
        tenant_id,
        actor,
        Event::SignInFailed,
        trace.user_id.as_deref(),
        details,
    )
    .await;
    if trace.lockout_triggered {
        let details = serde_json::json!({ "via": channel.as_str(), "clientId": client_id });
        record(st, tenant_id, actor, Event::Lockout, trace.user_id.as_deref(), details).await;
    }
}
