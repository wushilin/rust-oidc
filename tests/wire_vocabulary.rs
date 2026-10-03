//! The two closed sets that go out on the wire in an error response: the OAuth
//! `error` value and the AADSTS number.
//!
//! Both were written out at ~60 call sites as a `&'static str` and a bare `u32`.
//! Clients, log searches and Microsoft's own support articles are written against
//! these values, so they are a contract; the expected lists below are therefore
//! spelled out by hand rather than derived from the enums, which would make the
//! test agree with any change.

use rust_oidc::error::{AadError, Aadsts, OAuthError};
use rust_oidc::routes::Prompt;

/// Every `error` value this server can emit.
const ERRORS: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_resource",
    "invalid_tenant",
    "unsupported_response",
    "access_denied",
    "login_required",
    "interaction_required",
    "request_not_supported",
    "request_uri_not_supported",
    "server_error",
    "temporarily_unavailable",
    "authorization_pending",
    "authorization_declined",
    "slow_down",
    "expired_token",
];

#[test]
fn the_error_values_are_pinned() {
    let actual: Vec<&str> = OAuthError::ALL.iter().map(|e| e.as_str()).collect();
    assert_eq!(
        actual, ERRORS,
        "an `error` value changed. Clients branch on these strings."
    );
}

/// Entra's spelling, not the RFC's: `unsupported_response`, without `_type`.
/// Decision 10 -- this is a deliberate divergence and must not be "fixed".
#[test]
fn the_unsupported_response_type_error_keeps_entras_spelling() {
    assert_eq!(OAuthError::UnsupportedResponse.as_str(), "unsupported_response");
    assert!(
        !OAuthError::ALL
            .iter()
            .any(|e| e.as_str() == "unsupported_response_type"),
        "the RFC spelling must not appear; Entra uses the shorter one"
    );
}

#[test]
fn every_aadsts_number_is_a_plausible_entra_code() {
    for code in Aadsts::ALL {
        let n = code.code();
        assert!(n >= 1000, "{code:?} => {n} is too short to be an AADSTS number");
        assert!(n <= 9_999_999, "{code:?} => {n} is too long");
    }
}

/// Numbers may be shared, but only where Entra shares them. 70016 is Entra's
/// whole device-flow error family, so `authorization_pending` and `slow_down`
/// both carry it -- via one variant, not two.
#[test]
fn no_two_conditions_quietly_claim_the_same_number() {
    let mut seen = std::collections::HashMap::new();
    for code in Aadsts::ALL {
        if let Some(other) = seen.insert(code.code(), code) {
            panic!(
                "{:?} and {:?} both use AADSTS{}. If Entra really shares it, use one \
                 variant at both call sites instead of two.",
                other,
                code,
                code.code()
            );
        }
    }
    assert_eq!(seen.len(), Aadsts::ALL.len());
}

/// The device-flow pair really does share one variant.
#[test]
fn the_device_flow_family_shares_one_variant() {
    assert_eq!(Aadsts::DeviceFlowError.code(), 70016);
    assert_eq!(AadError::authorization_pending().code, Aadsts::DeviceFlowError);
    assert_eq!(AadError::slow_down().code, Aadsts::DeviceFlowError);
    // ...and they are still distinguishable to the client, which is the point.
    assert_ne!(AadError::authorization_pending().error, AadError::slow_down().error);
    assert_eq!(
        AadError::authorization_pending().error,
        OAuthError::AuthorizationPending
    );
    assert_eq!(AadError::slow_down().error, OAuthError::SlowDown);
}

/// The two numbers that are our closest match rather than an observed Entra
/// pairing. Pinned so that "which of these did we guess?" has an answer in code
/// and not only in docs/decisions-log.md (decisions 16 and 31).
#[test]
fn the_unverified_pairings_are_the_two_we_know_about() {
    assert_eq!(Aadsts::ResponseTypeNotAllowed.code(), 700054);
    assert_eq!(Aadsts::Throttled.code(), 90055);
}

/// Throttling: status, error value and header all together, since the three are
/// what MSAL reads.
#[test]
fn a_throttled_error_carries_entras_shape() {
    let err = AadError::throttled(rust_oidc::ratelimit::RetryAfter(42));
    assert_eq!(err.status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(err.error, OAuthError::TemporarilyUnavailable);
    assert_eq!(err.retry_after, Some(42));
}

// ---- prompt ----

/// Entra documents exactly four values, and those four are what discovery
/// advertises. `create` is accepted and ignored but deliberately not advertised.
#[test]
fn the_advertised_prompt_values_are_entras_documented_four() {
    assert_eq!(
        Prompt::SUPPORTED.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ["none", "login", "consent", "select_account"]
    );
    assert!(
        !Prompt::SUPPORTED.contains(&Prompt::Create),
        "`create` is accepted but must not be advertised: it is an External ID \
         feature and this server has no sign-up"
    );
    assert!(Prompt::ALL.contains(&Prompt::Create), "it is still accepted");
}

#[test]
fn prompt_values_round_trip_and_reject_the_unknown() {
    for p in Prompt::ALL {
        assert_eq!(Prompt::parse(p.as_str()), Some(*p));
    }
    assert_eq!(Prompt::parse("Login"), None, "case matters");
    assert_eq!(Prompt::parse("select-account"), None);
    assert_eq!(Prompt::parse(""), None);
}
