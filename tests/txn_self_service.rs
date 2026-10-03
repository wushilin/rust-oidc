//! A user's changes to their own account, through the engine without HTTP:
//! each completes with its audit row, and each is refused (changing and
//! recording nothing) when it should be.

mod common;

use axum::http::HeaderMap;
use common::*;
use rust_oidc::db::Event;
use rust_oidc::mfa::{self, NewRecoveryCodes};
use rust_oidc::routes::audit::Channel;
use rust_oidc::txn::ops::self_service::{
    ChangeOwnPassword, EnrollAuthenticator, ReplaceRecoveryCodes, SignOutEverywhere,
};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use rust_oidc::users::{self, AuthResult, NewPassword, PasswordSetBy};

const NEW_PASSWORD: &str = "Brand-New-Pass-42";

fn own(user_id: &str) -> Actor {
    Actor::User {
        user_id: user_id.to_string(),
    }
}

/// `(tenant_id, actor, target, details)` of every row of this event.
async fn audit_rows(s: &TestServer, event: Event) -> Vec<(Option<String>, String, Option<String>, String)> {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT tenant_id, actor, target, details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(event.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

async fn sessions(s: &TestServer, user_id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    n
}

async fn sign_in_session(s: &TestServer, f: &UserFixture) {
    rust_oidc::session::create(&s.pool, &HeaderMap::new(), &f.tenant.id, &f.user_id, &["pwd"], 3600)
        .await
        .unwrap();
}

async fn password_works(s: &TestServer, f: &UserFixture, password: &str) -> bool {
    matches!(
        users::authenticate(&s.pool, &f.tenant, &f.upn, password).await.unwrap(),
        AuthResult::Ok(_)
    )
}

async fn change(s: &TestServer, f: &UserFixture, via: Channel) -> ChangeOwnPassword {
    ChangeOwnPassword {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
        password: users::prepare_password(&s.pool, &f.tenant, &f.user_id, NEW_PASSWORD, PasswordSetBy::User)
            .await
            .unwrap(),
        via,
    }
}

fn enroll(f: &UserFixture, secret: &str, voluntary: bool) -> EnrollAuthenticator {
    EnrollAuthenticator {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
        secret: secret.to_string(),
        codes: NewRecoveryCodes::generate(),
        via: Channel::MyAccount,
        voluntary,
    }
}

// ---- change own password ----

#[tokio::test]
async fn a_user_changes_their_own_password_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sign_in_session(&s, &f).await;

    let t = change(&s, &f, Channel::Authorize).await;
    assert_eq!(txn::run(&s.pool, &own(&f.user_id), &t).await, Outcome::Done(()));

    assert!(password_works(&s, &f, NEW_PASSWORD).await);
    assert_eq!(sessions(&s, &f.user_id).await, 0, "a new password ends every session");
    let rows = audit_rows(&s, Event::PasswordChanged).await;
    assert_eq!(rows.len(), 1);
    let (tenant, actor, target, details) = &rows[0];
    assert_eq!(tenant.as_deref(), Some(f.tenant.id.as_str()), "the home tenant's row");
    assert_eq!(actor, &f.user_id, "the user is the actor");
    assert_eq!(target.as_deref(), Some(f.user_id.as_str()));
    let details: serde_json::Value = serde_json::from_str(details).unwrap();
    assert_eq!(details, serde_json::json!({ "via": "authorize" }));
}

#[tokio::test]
async fn nobody_changes_another_users_password() {
    let s = TestServer::start().await;
    let admin = admin_fixture(&s).await;
    let f = user_fixture_in(&s, admin.tenant.clone(), "bob@contoso.com").await;
    let other = user_fixture_in(&s, admin.tenant.clone(), "mallory@contoso.com").await;

    let t = change(&s, &f, Channel::MyAccount).await;
    let outcome = txn::run(&s.pool, &own(&other.user_id), &t).await;
    assert_eq!(outcome, Outcome::Refused(Refusal::NotPermitted));
    // Not even a Global Administrator: a user's own change is theirs alone
    // (an administrator's is Reset password).
    let actor = Actor::Admin {
        user_id: admin.user_id.clone(),
        bindings: rust_oidc::admin::bindings::effective_for_user(&s.pool, &admin.user_id)
            .await
            .unwrap(),
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &t).await,
        Outcome::Refused(Refusal::NotPermitted)
    );
    assert!(!password_works(&s, &f, NEW_PASSWORD).await);
    assert!(audit_rows(&s, Event::PasswordChanged).await.is_empty());
}

#[tokio::test]
async fn a_disabled_account_cannot_change_its_password() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let t = change(&s, &f, Channel::Device).await;
    users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false)
        .await
        .unwrap();

    let outcome = txn::run(&s.pool, &own(&f.user_id), &t).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Conflict(_))), "{outcome:?}");
    users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, true)
        .await
        .unwrap();
    assert!(password_works(&s, &f, &f.password).await, "the old password stands");
    assert!(audit_rows(&s, Event::PasswordChanged).await.is_empty());
}

#[tokio::test]
async fn a_users_own_password_is_never_a_temporary_one() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let t = ChangeOwnPassword {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
        password: NewPassword::for_new_account_as(NEW_PASSWORD, PasswordSetBy::AdminTemporary).unwrap(),
        via: Channel::MyAccount,
    };
    let outcome = txn::run(&s.pool, &own(&f.user_id), &t).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert!(!users::must_change_password(&s.pool, &f.user_id).await.unwrap());
    assert!(audit_rows(&s, Event::PasswordChanged).await.is_empty());
}

// ---- authenticator ----

#[tokio::test]
async fn set_up_at_sign_in_the_user_is_signed_out_everywhere() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sign_in_session(&s, &f).await;
    let secret = mfa::new_secret();

    let codes = txn::run(&s.pool, &own(&f.user_id), &enroll(&f, &secret, false))
        .await
        .into_result()
        .unwrap();
    assert_eq!(codes.len(), mfa::RECOVERY_CODE_COUNT);
    assert!(mfa::enrolled_at(&s.pool, &f.user_id).await.unwrap().is_some());
    assert_eq!(sessions(&s, &f.user_id).await, 0);
    assert_eq!(
        mfa::check(&s.pool, &f.user_id, &codes[0]).await.unwrap(),
        Some(mfa::Factor::RecoveryCode),
        "the codes shown are the codes stored"
    );

    let rows = audit_rows(&s, Event::MfaEnrolled).await;
    assert_eq!(rows.len(), 1);
    let (tenant, actor, target, details) = &rows[0];
    assert_eq!(tenant.as_deref(), Some(f.tenant.id.as_str()));
    assert_eq!(actor, &f.user_id);
    assert_eq!(target.as_deref(), Some(f.user_id.as_str()));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(details).unwrap(),
        serde_json::json!({ "via": "my_account", "voluntary": false })
    );
    // Never the secret, never a code.
    assert!(!details.contains(&secret));
    assert!(codes.iter().all(|c| !details.contains(c.as_str())));
}

#[tokio::test]
async fn set_up_from_my_account_the_session_stays() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sign_in_session(&s, &f).await;
    let outcome = txn::run(&s.pool, &own(&f.user_id), &enroll(&f, &mfa::new_secret(), true)).await;
    assert!(outcome.is_done(), "{outcome:?}");
    assert_eq!(sessions(&s, &f.user_id).await, 1);
}

#[tokio::test]
async fn a_deleted_account_cannot_set_up_an_authenticator() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap();

    let outcome = txn::run(&s.pool, &own(&f.user_id), &enroll(&f, &mfa::new_secret(), false)).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(mfa::enrolled_at(&s.pool, &f.user_id).await.unwrap().is_none());
    assert!(audit_rows(&s, Event::MfaEnrolled).await.is_empty());
}

// ---- recovery codes ----

#[tokio::test]
async fn new_recovery_codes_replace_the_old_ones() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let old = mfa::enroll(&s.pool, &f.user_id, &mfa::new_secret()).await.unwrap();

    let replace = ReplaceRecoveryCodes {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
        codes: NewRecoveryCodes::generate(),
    };
    let new = txn::run(&s.pool, &own(&f.user_id), &replace)
        .await
        .into_result()
        .unwrap();
    assert_eq!(new, replace.codes.plain());
    assert_eq!(mfa::check(&s.pool, &f.user_id, &old[0]).await.unwrap(), None);
    assert_eq!(
        mfa::check(&s.pool, &f.user_id, &new[0]).await.unwrap(),
        Some(mfa::Factor::RecoveryCode)
    );
    let rows = audit_rows(&s, Event::MfaRecoveryCodesReplaced).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, f.user_id);
    assert!(
        new.iter().all(|c| !rows[0].3.contains(c.as_str())),
        "no code in the audit row"
    );
}

#[tokio::test]
async fn recovery_codes_need_an_authenticator() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let replace = ReplaceRecoveryCodes {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
        codes: NewRecoveryCodes::generate(),
    };
    let outcome = txn::run(&s.pool, &own(&f.user_id), &replace).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert_eq!(mfa::recovery_codes_left(&s.pool, &f.user_id).await.unwrap(), 0);
    assert!(audit_rows(&s, Event::MfaRecoveryCodesReplaced).await.is_empty());
}

// ---- sign out everywhere ----

#[tokio::test]
async fn a_user_signs_out_everywhere_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sign_in_session(&s, &f).await;
    sign_in_session(&s, &f).await;

    let t = SignOutEverywhere {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    assert_eq!(txn::run(&s.pool, &own(&f.user_id), &t).await, Outcome::Done(()));
    assert_eq!(sessions(&s, &f.user_id).await, 0);
    let rows = audit_rows(&s, Event::SessionEndEverywhere).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0.as_deref(), Some(f.tenant.id.as_str()));
    assert_eq!(rows[0].1, f.user_id);
    assert_eq!(rows[0].2.as_deref(), Some(f.user_id.as_str()));
}

#[tokio::test]
async fn nobody_signs_another_user_out() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = user_fixture_in(&s, f.tenant.clone(), "mallory@contoso.com").await;
    sign_in_session(&s, &f).await;

    let t = SignOutEverywhere {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    let outcome = txn::run(&s.pool, &own(&other.user_id), &t).await;
    assert_eq!(outcome, Outcome::Refused(Refusal::NotPermitted));
    assert_eq!(sessions(&s, &f.user_id).await, 1);
    assert!(audit_rows(&s, Event::SessionEndEverywhere).await.is_empty());
}

#[tokio::test]
async fn a_user_of_another_tenant_is_not_found_here() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let elsewhere = s.tenant("Fabrikam", "fabrikam.com").await;

    let t = SignOutEverywhere {
        tenant_id: elsewhere.id.clone(),
        user_id: f.user_id.clone(),
    };
    let outcome = txn::run(&s.pool, &own(&f.user_id), &t).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(audit_rows(&s, Event::SessionEndEverywhere).await.is_empty());
}
