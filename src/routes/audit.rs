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
use crate::users::{AuthResult, AuthTrace};

/// Actor for events where no user or client has been identified, such as a
/// failed sign-in for an unknown account. The submitted name goes in `details`.
pub const ANONYMOUS: &str = "anonymous";

/// Longest attacker-supplied string kept in `details`.
const MAX_FIELD_LEN: usize = 128;

/// Audit event names, `area.event`, matching the CLI's `user.create` style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    SignIn,
    SignInFailed,
    Lockout,
    SessionCreate,
    SessionEnd,
    TokenIssued,
    TokenClientAuthFailed,
    TokenAssertionRejected,
    TokenAssertionReplayed,
    TokenCodeReplayed,
    RefreshFamilyRevoked,
    DeviceCodeIssued,
    DeviceApproved,
    DeviceDenied,
    DeviceRedeemed,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "auth.sign_in",
            Self::SignInFailed => "auth.sign_in_failed",
            Self::Lockout => "auth.lockout",
            Self::SessionCreate => "session.create",
            Self::SessionEnd => "session.end",
            Self::TokenIssued => "token.issued",
            Self::TokenClientAuthFailed => "token.client_auth_failed",
            Self::TokenAssertionRejected => "token.assertion_rejected",
            Self::TokenAssertionReplayed => "token.assertion_replayed",
            Self::TokenCodeReplayed => "token.code_replayed",
            Self::RefreshFamilyRevoked => "token.refresh_family_revoked",
            Self::DeviceCodeIssued => "device.code_issued",
            Self::DeviceApproved => "device.approved",
            Self::DeviceDenied => "device.denied",
            Self::DeviceRedeemed => "device.redeemed",
        }
    }
}

/// Where a password was checked, recorded as `via`.
#[derive(Debug, Clone, Copy)]
pub enum Channel {
    /// The browser sign-in form on `/authorize`.
    Authorize,
    /// The sign-in form on the device approval page.
    Device,
    /// The password grant at the token endpoint.
    Ropc,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Device => "device",
            Self::Ropc => "password_grant",
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

/// Reports failed client authentication for one request. Each `fail` audits
/// and hands the error back, so a call site reads
/// `return Err(failures.fail(.., err).await)`. The error is returned
/// untouched, so the audit cannot change any response.
pub struct ClientFailures<'a> {
    pub st: &'a AppState,
    pub tenant_id: &'a str,
    pub event: Event,
    /// The client id as claimed by the request. Unverified, so clipped.
    pub claimed: &'a str,
}

impl ClientFailures<'_> {
    /// `app_id` is the client once it is known to exist and is then the actor;
    /// before that the actor is [`ANONYMOUS`] and the claimed id is only data.
    pub async fn fail(
        &self,
        app_id: Option<&str>,
        reason: Reason,
        err: crate::error::AadError,
    ) -> crate::error::AadError {
        let details = serde_json::json!({ "reason": reason.as_str(), "clientId": clip(self.claimed) });
        record(
            self.st,
            self.tenant_id,
            app_id.unwrap_or(ANONYMOUS),
            self.event,
            app_id,
            details,
        )
        .await;
        err
    }
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
pub async fn record(st: &AppState, tenant_id: &str, actor: &str, event: Event, target: Option<&str>, details: Value) {
    if let Err(e) = crate::db::audit(&st.pool, Some(tenant_id), actor, event.as_str(), target, details).await {
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
        (AuthResult::Locked, _) => "locked",
        (AuthResult::Disabled, _) => "disabled",
        (AuthResult::InvalidCredentials, true) => "bad_password",
        (AuthResult::InvalidCredentials, false) => "unknown_user",
    };
    // A known account is the actor; otherwise the submitted name is only data.
    // For the password grant the authenticated client stands in.
    let actor = trace.user_id.as_deref().unwrap_or(match channel {
        Channel::Ropc => client_id,
        _ => ANONYMOUS,
    });
    let details = serde_json::json!({
        "reason": reason,
        "upn": clip(submitted_upn),
        "via": channel.as_str(),
        "clientId": client_id,
    });
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
