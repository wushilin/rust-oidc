//! The `audit_log.action` vocabulary, pinned.
//!
//! `db::Event` is the only source of the values that column can hold. These
//! tests exist because the vocabulary used to live in two places — an enum for
//! the HTTP layer and nineteen bare strings in the CLI — so nothing said what
//! the column could contain and nothing caught a typo in either half.
//!
//! The expected strings below are written out by hand on purpose. Deriving them
//! from `Event::as_str` would make the test agree with any rename, including one
//! that silently splits a deployment's history across two spellings.

use rust_oidc::db::{Actor, Event};

/// Every action this build can write, spelled out. A rename must fail here.
const EXPECTED: &[(&str, &str)] = &[
    ("SignIn", "auth.sign_in"),
    ("SignInFailed", "auth.sign_in_failed"),
    ("Lockout", "auth.lockout"),
    ("SessionCreate", "session.create"),
    ("SessionEnd", "session.end"),
    ("TokenIssued", "token.issued"),
    ("TokenClientAuthFailed", "token.client_auth_failed"),
    ("TokenAssertionRejected", "token.assertion_rejected"),
    ("TokenAssertionReplayed", "token.assertion_replayed"),
    ("TokenCodeReplayed", "token.code_replayed"),
    ("RefreshFamilyRevoked", "token.refresh_family_revoked"),
    ("DeviceCodeIssued", "device.code_issued"),
    ("DeviceApproved", "device.approved"),
    ("DeviceDenied", "device.denied"),
    ("DeviceRedeemed", "device.redeemed"),
    ("Throttled", "security.throttled"),
    ("Bootstrap", "bootstrap"),
    ("TenantCreate", "tenant.create"),
    ("TenantAddDomain", "tenant.add_domain"),
    ("UserCreate", "user.create"),
    ("UserSetPassword", "user.set_password"),
    ("GroupCreate", "group.create"),
    ("GroupAddMember", "group.add_member"),
    ("AppCreate", "app.create"),
    ("AppRedirectUriAdd", "app.redirect_uri.add"),
    ("AppScopeAdd", "app.scope.add"),
    ("AppSecretAdd", "app.secret.add"),
    ("AppSecretRemove", "app.secret.remove"),
    ("AppImplicit", "app.implicit"),
    ("AppPasswordGrant", "app.password_grant"),
    ("AppKeyAdd", "app.key.add"),
    ("AppKeyRemove", "app.key.remove"),
    ("AppRoleAdd", "app.role.add"),
    ("AppRoleAssign", "app.role.assign"),
    ("KeyRotate", "key.rotate"),
    ("AdminSignIn", "admin.sign_in"),
    ("AdminSignInFailed", "admin.sign_in_failed"),
    ("AdminSignOut", "admin.sign_out"),
    ("AdminTenantAssume", "admin.tenant.assume"),
    ("AdminTenantLeave", "admin.tenant.leave"),
    ("AdminUserCreate", "admin.user.create"),
    ("AdminUserUpdate", "admin.user.update"),
    ("AdminUserEnable", "admin.user.enable"),
    ("AdminUserDisable", "admin.user.disable"),
    ("AdminUserReset", "admin.user.reset"),
    ("AdminUserDelete", "admin.user.delete"),
    ("AdminRoleGrant", "admin.role.grant"),
    ("AdminRoleRevoke", "admin.role.revoke"),
];

#[test]
fn every_action_has_its_pinned_wire_value() {
    let actual: Vec<&str> = Event::ALL.iter().map(|e| e.as_str()).collect();
    let expected: Vec<&str> = EXPECTED.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        actual, expected,
        "the audit vocabulary changed. Renaming an action splits a deployment's \
         history across two spellings; adding one means adding it here too."
    );
}

#[test]
fn actions_are_distinct_and_round_trip() {
    let mut seen = std::collections::HashSet::new();
    for event in Event::ALL {
        let value = event.as_str();
        assert!(seen.insert(value), "two events both write {value:?}");
        assert_eq!(Event::parse(value), Some(*event), "{value} does not round-trip");
    }
}

/// An action written by a newer build must not stop this one reading the table.
#[test]
fn an_unknown_action_parses_to_none_rather_than_panicking() {
    assert_eq!(Event::parse("something.from.the.future"), None);
    assert_eq!(Event::parse(""), None);
}

/// `area.event`, so the column can be grouped by area. `bootstrap` is the one
/// documented exception: it predates the convention and rows already carry it.
#[test]
fn actions_follow_the_area_event_shape() {
    for event in Event::ALL {
        let value = event.as_str();
        if value == "bootstrap" {
            continue;
        }
        let Some((area, rest)) = value.split_once('.') else {
            panic!("{value} is not area.event");
        };
        assert!(!area.is_empty() && !rest.is_empty(), "{value} is not area.event");
        assert!(
            value.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "{value} should be lowercase with '.' and '_' only"
        );
    }
}

#[test]
fn actor_spells_out_only_the_two_non_identifiers() {
    assert_eq!(Actor::Cli.as_str(), "cli");
    assert_eq!(Actor::Anonymous.as_str(), "anonymous");
    assert_eq!(Actor::Id("abc").as_str(), "abc");
    // The conversion every call site uses, so `None` can never become an empty
    // actor or the literal string "None".
    assert_eq!(Actor::from(None), Actor::Anonymous);
    assert_eq!(Actor::from(Some("abc")), Actor::Id("abc"));
}
