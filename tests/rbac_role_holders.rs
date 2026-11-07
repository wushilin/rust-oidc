//! The no-widening rule covers the other ways of taking a role's reach, not
//! only writing its binding: the credentials and standing of an account that
//! holds a role, and the membership of a group that holds one. Whoever could not
//! grant the role cannot reset, disable or delete its holder, nor put anyone
//! (themselves included) into, or take anyone out of, its group.
//!
//! Each test here fails when the guard it covers is removed.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::txn::ops::Account;
use rust_oidc::txn::ops::groups::{AddGroupMember, RemoveGroupMember};
use rust_oidc::txn::ops::users::{DisableUser, ResetPassword, ResetUserMfa, SetUserGroups};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use rust_oidc::users::{self, AuthResult, NewPassword};
use rust_oidc::{groups, mfa};

/// What the console says of an engine refusal on a page that lists them.
const NOT_PERMITTED: &str = "Your roles do not allow this.";

async fn actor(s: &TestServer, user_id: &str) -> Actor {
    Actor::Admin {
        user_id: user_id.to_string(),
        bindings: bindings::effective_for_user(&s.pool, user_id).await.unwrap(),
    }
}

fn refused<T: std::fmt::Debug>(outcome: &Outcome<T>) -> bool {
    matches!(outcome, Outcome::Refused(Refusal::NotPermitted))
}

fn reset(tenant_id: &str, user_id: &str) -> ResetPassword {
    ResetPassword {
        tenant_id: tenant_id.to_string(),
        account: Account::Id(user_id.to_string()),
        password: NewPassword::for_new_account("Brand-New-Pass-1").unwrap(),
    }
}

async fn still_signs_in(s: &TestServer, f: &UserFixture) {
    let outcome = users::authenticate(&s.pool, &f.tenant, &f.upn, &f.password)
        .await
        .unwrap();
    assert!(matches!(outcome, AuthResult::Ok(_)), "the password was changed");
}

/// A User Administrator of the root tenant (help desk) cannot reset the
/// password or the authenticator of the Global Administrator, nor disable them;
/// an account holding no role they can.
#[tokio::test]
async fn a_user_administrator_cannot_take_over_a_global_administrator() {
    let s = TestServer::start().await;
    let ga = admin_fixture(&s).await;
    mfa::enroll(&s.pool, &ga.user_id, &mfa::new_secret()).await.unwrap();
    let helpdesk = user_fixture_in(&s, ga.tenant.clone(), "bea@contoso.com").await;
    bind_in_own_tenant(&s, &helpdesk, RoleId::UserAdministrator).await;
    let nobody = user_fixture_in(&s, ga.tenant.clone(), "carol@contoso.com").await;

    // Through the console.
    let b = signed_in_admin(&s, &helpdesk).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", ga.tenant.id, ga.user_id));
    for form in [
        vec![("op", "mfa_reset")],
        vec![("op", "reset"), ("password", "Brand-New-Pass-1")],
        vec![("op", "disable")],
    ] {
        let page = b.post(&url, &form).await;
        assert_eq!(page.status, 403, "{form:?}: {}", page.body);
    }
    still_signs_in(&s, &ga).await;
    assert!(mfa::enrolled_at(&s.pool, &ga.user_id).await.unwrap().is_some());

    // Through the engine, which is where the rule lives.
    let bea = actor(&s, &helpdesk.user_id).await;
    assert!(refused(
        &txn::run(&s.pool, &bea, &reset(&ga.tenant.id, &ga.user_id)).await
    ));
    let mfa_reset = ResetUserMfa {
        tenant_id: ga.tenant.id.clone(),
        user_id: ga.user_id.clone(),
    };
    assert!(refused(&txn::run(&s.pool, &bea, &mfa_reset).await));
    let disable = DisableUser {
        tenant_id: ga.tenant.id.clone(),
        user_id: ga.user_id.clone(),
    };
    assert!(refused(&txn::run(&s.pool, &bea, &disable).await));

    // An account holding no role: the help desk's job.
    let done = txn::run(&s.pool, &bea, &reset(&ga.tenant.id, &nobody.user_id)).await;
    assert!(matches!(done, Outcome::Done(_)), "{done:?}");
    // The Global Administrator resets the help desk, and the operator anyone.
    let done = txn::run(
        &s.pool,
        &actor(&s, &ga.user_id).await,
        &reset(&ga.tenant.id, &helpdesk.user_id),
    )
    .await;
    assert!(matches!(done, Outcome::Done(_)), "{done:?}");
    let done = txn::run(&s.pool, &Actor::Cli, &reset(&ga.tenant.id, &ga.user_id)).await;
    assert!(matches!(done, Outcome::Done(_)), "{done:?}");
}

/// A role held through a group protects the account the same way.
#[tokio::test]
async fn a_role_held_through_a_group_protects_the_account_too() {
    let s = TestServer::start().await;
    let ga = admin_fixture(&s).await;
    let admins = groups::create(&s.pool, &ga.tenant, "Platform Admins", None)
        .await
        .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &admins,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let member = user_fixture_in(&s, ga.tenant.clone(), "dan@contoso.com").await;
    groups::add_member(&s.pool, &ga.tenant, "Platform Admins", "dan@contoso.com")
        .await
        .unwrap();
    let helpdesk = user_fixture_in(&s, ga.tenant.clone(), "bea@contoso.com").await;
    bind_in_own_tenant(&s, &helpdesk, RoleId::UserAdministrator).await;

    let bea = actor(&s, &helpdesk.user_id).await;
    assert!(refused(
        &txn::run(&s.pool, &bea, &reset(&ga.tenant.id, &member.user_id)).await
    ));
    still_signs_in(&s, &member).await;
}

/// A Groups Administrator (or a Tenant Administrator) of the root tenant cannot
/// put themselves, or anyone, into a group that holds Global Administrator, nor
/// take anyone out of it; a group that holds no role is theirs to manage.
#[tokio::test]
async fn joining_a_group_that_holds_a_role_is_a_binding_write() {
    let s = TestServer::start().await;
    let ga = admin_fixture(&s).await;
    let admins = groups::create(&s.pool, &ga.tenant, "Platform Admins", None)
        .await
        .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &admins,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let staff = groups::create(&s.pool, &ga.tenant, "Staff", None).await.unwrap();
    let mole = user_fixture_in(&s, ga.tenant.clone(), "mole@contoso.com").await;
    bind_in_own_tenant(&s, &mole, RoleId::GroupsAdministrator).await;
    let ta = user_fixture_in(&s, ga.tenant.clone(), "ta@contoso.com").await;
    bind_in_own_tenant(&s, &ta, RoleId::TenantAdministrator).await;

    // Through the console: the group page's "add member", which runs a
    // transaction per name and lists what was refused.
    let b = signed_in_admin(&s, &mole).await;
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/groups/{admins}", ga.tenant.id)),
            &[("op", "member_add"), ("upn", &mole.upn)],
        )
        .await;
    assert!(page.body.contains(NOT_PERMITTED), "{}", page.body);
    let effective = bindings::effective_for_user(&s.pool, &mole.user_id).await.unwrap();
    assert!(
        effective.iter().all(|b| b.scope != Scope::All),
        "the mole became Global Administrator: {effective:?}"
    );

    // Through the engine, by every membership write, as either delegated role.
    for who in [&mole, &ta] {
        let me = actor(&s, &who.user_id).await;
        let add = AddGroupMember {
            tenant_id: ga.tenant.id.clone(),
            group_id: admins.clone(),
            account: Account::Upn(who.upn.clone()),
        };
        assert!(refused(&txn::run(&s.pool, &me, &add).await), "{}", who.upn);
        let set = SetUserGroups {
            tenant_id: ga.tenant.id.clone(),
            user_id: who.user_id.clone(),
            group_ids: vec![admins.clone(), staff.clone()],
        };
        assert!(refused(&txn::run(&s.pool, &me, &set).await), "{}", who.upn);
        assert!(
            groups::for_user(&s.pool, &who.user_id).await.unwrap().is_empty(),
            "nothing of the refused change happened"
        );
        // The ordinary group is theirs.
        let set = SetUserGroups {
            tenant_id: ga.tenant.id.clone(),
            user_id: who.user_id.clone(),
            group_ids: vec![staff.clone()],
        };
        assert!(matches!(txn::run(&s.pool, &me, &set).await, Outcome::Done(_)));
    }

    // The Global Administrator may; and then nobody below may take them out.
    let add = AddGroupMember {
        tenant_id: ga.tenant.id.clone(),
        group_id: admins.clone(),
        account: Account::Upn(ta.upn.clone()),
    };
    assert!(matches!(
        txn::run(&s.pool, &actor(&s, &ga.user_id).await, &add).await,
        Outcome::Done(_)
    ));
    let remove = RemoveGroupMember {
        tenant_id: ga.tenant.id.clone(),
        group_id: admins.clone(),
        user_id: ta.user_id.clone(),
    };
    assert!(refused(
        &txn::run(&s.pool, &actor(&s, &mole.user_id).await, &remove).await
    ));
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/groups/{admins}", ga.tenant.id)),
            &[("op", "member_remove"), ("user", &ta.user_id)],
        )
        .await;
    assert!(page.body.contains(NOT_PERMITTED), "{}", page.body);
    assert!(
        groups::for_user(&s.pool, &ta.user_id)
            .await
            .unwrap()
            .iter()
            .any(|g| g.id == admins),
        "the mole took the Tenant Administrator out of the group"
    );
}

/// A group that holds a tenant role is within a Tenant Administrator's reach,
/// and beyond a Groups Administrator's: the rule is the binding's scope, not
/// "any role at all".
#[tokio::test]
async fn a_group_holding_a_tenant_role_is_within_its_tenant_administrators_reach() {
    let s = TestServer::start().await;
    let ta = tenant_admin_fixture(&s).await;
    let users_admins = groups::create(&s.pool, &ta.tenant, "User admins", None).await.unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &users_admins,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![ta.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let groupie = user_fixture_in(&s, ta.tenant.clone(), "groupie@contoso.com").await;
    bind_in_own_tenant(&s, &groupie, RoleId::GroupsAdministrator).await;

    let add = |upn: &str| AddGroupMember {
        tenant_id: ta.tenant.id.clone(),
        group_id: users_admins.clone(),
        account: Account::Upn(upn.to_string()),
    };
    assert!(refused(
        &txn::run(&s.pool, &actor(&s, &groupie.user_id).await, &add(&groupie.upn)).await
    ));
    assert!(matches!(
        txn::run(&s.pool, &actor(&s, &ta.user_id).await, &add(&groupie.upn)).await,
        Outcome::Done(_)
    ));
}
