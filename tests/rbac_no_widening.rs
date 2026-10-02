//! Two rules that are about more than one tenant at a time: a binding write
//! cannot grant reach the writer does not hold, and the last platform
//! administrator cannot be removed.
//!
//! The first is the rule that makes tenant-scoped delegation safe at all. Without
//! it a Global Administrator scoped to one tenant could simply write themselves a
//! binding at `All` scope, and every other check in the console would then agree
//! that they were entitled to everything.

mod common;

use common::*;
use rust_oidc::admin::authz::{self, RefusedReason};
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{EffectiveBinding, RoleId, Scope};

fn held(role: RoleId, scope: Scope) -> EffectiveBinding {
    EffectiveBinding { role, scope }
}

fn tenants(ids: &[&str]) -> Scope {
    Scope::Tenants(ids.iter().map(|s| s.to_string()).collect())
}

#[test]
fn an_admin_may_grant_within_tenants_they_hold() {
    let me = [held(RoleId::GlobalAdministrator, tenants(&["t1", "t2"]))];
    assert!(authz::may_write_binding(&me, &tenants(&["t1"])));
    assert!(authz::may_write_binding(&me, &tenants(&["t1", "t2"])));
    assert!(authz::may_write_binding(&me, &tenants(&["t2"])));
}

#[test]
fn an_admin_may_not_grant_outside_their_scope() {
    let me = [held(RoleId::GlobalAdministrator, tenants(&["t1"]))];
    assert!(!authz::may_write_binding(&me, &tenants(&["t2"])));
    // A partial overlap is still a widening: t2 is not theirs to give.
    assert!(!authz::may_write_binding(&me, &tenants(&["t1", "t2"])));
}

#[test]
fn only_an_all_scope_principal_may_mint_an_all_scope_binding() {
    let scoped = [held(RoleId::GlobalAdministrator, tenants(&["t1"]))];
    assert!(
        !authz::may_write_binding(&scoped, &Scope::All),
        "this is the escalation the rule exists to stop"
    );
    let global = [held(RoleId::GlobalAdministrator, Scope::All)];
    assert!(authz::may_write_binding(&global, &Scope::All));
}

#[test]
fn a_role_without_rolebinding_write_may_not_grant_at_all() {
    let helpdesk = [held(RoleId::UserAdministrator, Scope::All)];
    assert!(!authz::may_write_binding(&helpdesk, &tenants(&["t1"])));
    assert!(!authz::may_write_binding(&helpdesk, &Scope::All));
}

#[test]
fn an_empty_tenant_scope_is_refused() {
    let global = [held(RoleId::GlobalAdministrator, Scope::All)];
    assert!(
        !authz::may_write_binding(&global, &tenants(&[])),
        "an empty scope grants nothing and is more likely a bug than intent"
    );
}

#[test]
fn holding_nothing_grants_nothing() {
    assert!(!authz::may_write_binding(&[], &Scope::All));
    assert!(!authz::may_write_binding(&[], &tenants(&["t1"])));
}

/// Review Focus 5: it must not be possible to lock every administrator out of the
/// platform. Only an `All`-scope PlatformAdministrator can create or assume a
/// tenant, and the console is web-only, so there is no CLI to repair it.
#[tokio::test]
async fn removing_the_last_platform_binding_is_refused() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let id = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();

    assert_eq!(
        authz::check_delete(&s.pool, &id).await.unwrap_err(),
        RefusedReason::WouldLockOut
    );

    // With a second platform administrator, removal is allowed again.
    let other = rust_oidc::users::create(
        &s.pool,
        &f.tenant,
        rust_oidc::users::NewUser {
            upn: "bob@contoso.com",
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &other,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    assert!(authz::check_delete(&s.pool, &id).await.is_ok());
}

/// The lock-out rule is about the platform role at `All` scope only. Any other
/// binding may be the last of its kind and still be removable.
#[tokio::test]
async fn the_lockout_rule_does_not_block_other_bindings() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let plain = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    assert!(
        authz::check_delete(&s.pool, &plain).await.is_ok(),
        "the last Global Administrator is not a platform lock-out"
    );

    // A tenant-scoped platform binding is not the load-bearing one either: it
    // cannot create or assume a tenant in the first place.
    let scoped = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    assert!(authz::check_delete(&s.pool, &scoped).await.is_ok());
}

/// The other half of the same rule, and the one a first draft missed: a
/// tenant-scoped platform binding must **not** count towards the platform's
/// survival. If the count ignored `scope_kind`, deleting the last `All`-scope
/// binding would look safe because a scoped one existed -- and that scoped one
/// cannot create or assume a tenant, so the platform would be locked out anyway.
///
/// Found by teeth-checking: dropping `scope_kind = 'all'` from the count left
/// every other test in this file passing.
#[tokio::test]
async fn a_tenant_scoped_platform_binding_does_not_keep_the_platform_alive() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let load_bearing = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();

    assert_eq!(
        authz::check_delete(&s.pool, &load_bearing).await.unwrap_err(),
        RefusedReason::WouldLockOut,
        "a tenant-scoped platform binding is not a substitute for the all-scope one"
    );
}

#[tokio::test]
async fn deleting_a_binding_that_does_not_exist_is_not_permitted() {
    let s = TestServer::start().await;
    let _f = user_fixture(&s).await;
    assert_eq!(
        authz::check_delete(&s.pool, "no-such-binding").await.unwrap_err(),
        RefusedReason::NotPermitted
    );
}

/// The one entry point handlers use: it applies both rules, so neither can be
/// forgotten at a call site.
#[tokio::test]
async fn the_combined_delete_applies_both_rules() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;

    // A binding in Fabrikam, and an actor who only holds Contoso.
    let theirs = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![other.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let contoso_only = [held(
        RoleId::GlobalAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )];
    assert_eq!(
        authz::delete(&s.pool, &contoso_only, &theirs).await.unwrap_err(),
        RefusedReason::NotPermitted,
        "an admin scoped to Contoso must not delete a Fabrikam binding"
    );
    // ...and it is still there.
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 1);

    // A global admin may.
    let global = [held(RoleId::GlobalAdministrator, Scope::All)];
    authz::delete(&s.pool, &global, &theirs).await.unwrap();
    assert!(bindings::list_all(&s.pool).await.unwrap().is_empty());
}

/// And the lock-out rule survives the combined path, so a platform admin cannot
/// remove the last platform binding just because they are entitled to write it.
#[tokio::test]
async fn the_combined_delete_still_refuses_a_lockout() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let id = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let global = [held(RoleId::GlobalAdministrator, Scope::All)];
    assert_eq!(
        authz::delete(&s.pool, &global, &id).await.unwrap_err(),
        RefusedReason::WouldLockOut
    );
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 1, "untouched");
}
