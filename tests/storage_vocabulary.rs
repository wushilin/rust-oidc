//! The closed sets the database stores, and what happens when a row holds
//! something outside one.
//!
//! These were bare strings until the enums landed. The platform one is not a
//! rename: `authenticate_for_platform` compared strings and fell through to the
//! **public client** branch for anything it did not recognise, which is the
//! weakest of the three rule sets — an unreadable platform meant "no client
//! authentication required". The first test below is that hole.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::apps::{MemberType, RedirectPlatform, ScopeConsent};
use rust_oidc::rbac::{RoleId, Scope};

/// An authorization code whose stored platform this build cannot read must be
/// refused, not treated as a public client that needs no secret.
#[tokio::test]
async fn a_code_with_an_unreadable_platform_is_refused_not_treated_as_public() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();

    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    let done = b.login(&page, &f.upn, &f.password).await;
    assert_eq!(done.status, 302, "{}", done.body);
    let code = done.redirect_params()["code"].clone();

    // Corrupt the platform the grant was issued under. Nothing in the server can
    // write this; a hand-edited row or a newer build's value could.
    let n = sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE auth_codes SET platform = ? WHERE client_app_id = ?",
    ))
    .bind("someFuturePlatform")
    .bind(&f.web.app_id)
    .execute(&s.pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(n, 1, "expected to corrupt exactly one code row");

    // Redeem with NO client secret, as a public client would. Before the enum
    // this succeeded: the unknown platform fell past the `web` branch.
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &f.web.app_id),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_ne!(status, 200, "an unreadable platform must not yield a token: {body}");
    assert!(
        body.get("access_token").is_none(),
        "no token may be issued for a grant we cannot classify: {body}"
    );
}

/// The same row, uncorrupted, does need the secret — so the test above is
/// measuring the platform and not some unrelated refusal.
#[tokio::test]
async fn a_web_code_still_requires_the_client_secret() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let (verifier, challenge) = pkce();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    let done = b.login(&page, &f.upn, &f.password).await;
    let code = done.redirect_params()["code"].clone();

    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", f.web.app_id.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", verifier.as_str()),
    ];
    let (status, body) = s.token(&f.tenant.id, &form).await;
    assert_ne!(status, 200, "a web client with no secret must be refused: {body}");

    let mut with_secret = form.to_vec();
    with_secret.push(("client_secret", f.web.secret.as_str()));
    let (status, body) = s.token(&f.tenant.id, &with_secret).await;
    assert_eq!(status, 200, "with the secret it works: {body}");
}

/// Where the fail-open was reachable, and where it was not.
///
/// `app_redirect_uris.platform` carries `CHECK (platform IN ('web','spa',
/// 'publicClient'))` on all three engines, so an unknown platform can never be
/// stored there and `apps::redirect_uris`'s skip is defence in depth.
/// `auth_codes.platform` and `refresh_tokens.platform` carry **no such check** on
/// any engine — only a comment — which is exactly where the string comparison
/// could fall through to public-client rules. Both halves are asserted so that a
/// future migration dropping the check, or adding one, is noticed here.
#[tokio::test]
async fn the_schema_constrains_the_redirect_platform_but_not_the_grant_platform() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = rust_oidc::apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id)
        .await
        .unwrap();

    // Registered as web by the fixture, and readable as the enum.
    let uris = rust_oidc::apps::redirect_uris(&s.pool, &app).await.unwrap();
    assert!(
        uris.iter().any(|(p, u)| *p == RedirectPlatform::Web && u == REDIRECT),
        "fixture should register {REDIRECT} as web: {uris:?}"
    );

    // The database refuses an unknown platform on a redirect URI.
    let refused = sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE app_redirect_uris SET platform = ? WHERE application_id = ? AND uri = ?",
    ))
    .bind("someFuturePlatform")
    .bind(&app.id)
    .bind(REDIRECT)
    .execute(&s.pool)
    .await;
    assert!(
        refused.is_err(),
        "app_redirect_uris.platform should be constrained by the schema; if this now \
         succeeds a migration dropped the CHECK and redirect_uris()'s skip is the only guard"
    );

    // A grant row is not constrained, which is why the Rust side has to fail closed.
    let (_verifier, challenge) = pkce();
    let b = Browser::new();
    let page = b
        .authorize(
            &s,
            &f.tenant.id,
            &[
                ("client_id", &f.web.app_id),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    b.login(&page, &f.upn, &f.password).await;
    let accepted = sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE auth_codes SET platform = ? WHERE client_app_id = ?",
    ))
    .bind("someFuturePlatform")
    .bind(&f.web.app_id)
    .execute(&s.pool)
    .await;
    assert!(
        accepted.is_ok(),
        "auth_codes.platform has no CHECK, so this documents where the Rust-side \
         guard is load-bearing rather than belt-and-braces"
    );
}

/// A service principal cannot sign in to the console, so it cannot hold a
/// console role. Refused at the door, not left to be ignored downstream.
#[tokio::test]
async fn a_service_principal_cannot_hold_a_console_role() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;

    let refused = bindings::create(
        &s.pool,
        PrincipalType::ServicePrincipal,
        &f.web.sp_id,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await;
    assert!(refused.is_err(), "a service principal binding must be refused");

    // A user is fine, so the refusal is about the principal type.
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .expect("a user may hold a console role");
}

/// Even if such a row were written directly, it must grant nothing.
#[tokio::test]
async fn a_service_principal_binding_written_directly_grants_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;

    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(rust_oidc::util::new_guid())
    .bind(PrincipalType::ServicePrincipal.as_str())
    // The *user's* id under a service-principal type: the nastiest shape, since a
    // query that ignored principal_type would match it.
    .bind(&f.user_id)
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind(rust_oidc::rbac::ScopeKind::All.as_str())
    .bind(rust_oidc::util::now())
    .bind("test")
    .execute(&s.pool)
    .await
    .unwrap();

    let effective = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(
        effective.is_empty(),
        "a ServicePrincipal binding must grant nothing to a user: {}",
        effective.len()
    );
}

// ---- the vocabularies themselves ----

#[tokio::test]
async fn an_app_role_is_only_assignable_to_the_member_types_it_allows() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "orders-api").await;
    let worker = s.app(&t, "billing-worker").await;
    let app = rust_oidc::apps::find_in_tenant(&s.pool, &t, &api.app_id).await.unwrap();

    // User-only role: an application must not be able to hold it.
    rust_oidc::apps::add_role(&s.pool, &app, "Orders.Approve", "Approve", None, &[MemberType::User])
        .await
        .unwrap();
    let refused = rust_oidc::apps::assign_role(
        &s.pool,
        &t,
        &app,
        "Orders.Approve",
        &rust_oidc::apps::Principal::App(worker.app_id.clone()),
    )
    .await;
    assert!(refused.is_err(), "a User-only role must not be assignable to an app");

    // And an Application role is.
    rust_oidc::apps::add_role(&s.pool, &app, "Orders.Sync", "Sync", None, &[MemberType::Application])
        .await
        .unwrap();
    rust_oidc::apps::assign_role(
        &s.pool,
        &t,
        &app,
        "Orders.Sync",
        &rust_oidc::apps::Principal::App(worker.app_id.clone()),
    )
    .await
    .expect("an Application role is assignable to an app");
}

/// `allowed_member_types` is stored as JSON. A value this build does not know is
/// dropped, not matched by accident — the old code did a substring test on the
/// raw JSON text.
#[test]
fn unknown_member_types_are_dropped_rather_than_matched() {
    assert_eq!(
        MemberType::parse_list(r#"["User","Application"]"#),
        vec![MemberType::User, MemberType::Application]
    );
    assert_eq!(MemberType::parse_list(r#"["Device"]"#), vec![]);
    // "ApplicationImpersonation" contains "Application" as a substring; it must
    // not count as one.
    assert_eq!(MemberType::parse_list(r#"["ApplicationImpersonation"]"#), vec![]);
    assert_eq!(MemberType::parse_list("not json"), vec![]);
    assert_eq!(MemberType::parse_list("[]"), vec![]);
}

#[test]
fn every_stored_vocabulary_round_trips_and_rejects_the_unknown() {
    for p in RedirectPlatform::ALL {
        assert_eq!(RedirectPlatform::parse(p.as_str()), Some(*p));
    }
    for c in ScopeConsent::ALL {
        assert_eq!(ScopeConsent::parse(c.as_str()), Some(*c));
    }
    for p in PrincipalType::ALL {
        assert_eq!(PrincipalType::parse(p.as_str()), Some(*p));
    }
    for m in MemberType::ALL {
        assert_eq!(MemberType::parse(m.as_str()), Some(*m));
    }
    assert_eq!(RedirectPlatform::parse("nativeClient"), None);
    assert_eq!(ScopeConsent::parse("user"), None, "case matters, as in Entra");
    assert_eq!(PrincipalType::parse("Device"), None);
    assert_eq!(MemberType::parse("Device"), None);
}

/// The spellings are Entra's and are stored in the database, so they are pinned
/// by hand rather than derived from the enum.
#[test]
fn the_stored_spellings_are_entras() {
    assert_eq!(
        RedirectPlatform::ALL.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ["web", "spa", "publicClient"]
    );
    assert_eq!(
        ScopeConsent::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        ["User", "Admin"]
    );
    assert_eq!(
        PrincipalType::ALL.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ["User", "Group", "ServicePrincipal"]
    );
    assert_eq!(
        MemberType::ALL.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
        ["User", "Application"]
    );
}
