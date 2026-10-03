//! Console role grants, signing keys and the flow tester's directory writes, run
//! through the transaction engine without HTTP.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::apps::{self, RedirectPlatform};
use rust_oidc::db::Event;
use rust_oidc::keys::{self, KeyStatus, NewKey};
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::tenant::Tenant;
use rust_oidc::txn::ops::flow::{AddFlowCallback, CreateFlowTestClient};
use rust_oidc::txn::ops::keys::{PruneKeys, RotateKeys};
use rust_oidc::txn::ops::roles::{GrantRole, Principal, RevokeRole, RolePage};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use rust_oidc::{flowtest, users};

async fn admin(s: &TestServer, user_id: &str) -> Actor {
    Actor::Admin {
        user_id: user_id.to_string(),
        bindings: bindings::effective_for_user(&s.pool, user_id).await.unwrap(),
    }
}

/// (tenant_id, actor, target, details) of every row with this event, oldest first.
async fn rows(s: &TestServer, event: Event) -> Vec<(Option<String>, String, Option<String>, String)> {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT tenant_id, actor, target, details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(event.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

async fn account(s: &TestServer, tenant: &Tenant, upn: &str) -> String {
    users::create(
        &s.pool,
        tenant,
        users::NewUser {
            upn,
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap()
}

fn tenant_page(tenant: &Tenant) -> RolePage {
    RolePage::Tenant(tenant.id.clone())
}

// ---- roles ----

#[tokio::test]
async fn a_tenant_role_is_granted_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let bob = account(&s, &f.tenant, "bob@contoso.com").await;
    let actor = admin(&s, &f.user_id).await;

    let grant = GrantRole {
        page: tenant_page(&f.tenant),
        principal: Principal::User("bob@contoso.com".into()),
        role: RoleId::TenantViewer,
    };
    let out = txn::run(&s.pool, &actor, &grant).await.into_result().unwrap();
    assert_eq!(out.principal_id, bob);
    let held = bindings::effective_for_user(&s.pool, &bob).await.unwrap();
    assert!(held.iter().any(|b| b.role == RoleId::TenantViewer));

    let audit = rows(&s, Event::AdminRoleGrant).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(f.tenant.id.as_str()));
    assert_eq!(audit[0].1, f.user_id);
    assert_eq!(audit[0].2.as_deref(), Some(out.binding_id.as_str()));
    assert!(audit[0].3.contains(&bob), "{}", audit[0].3);
}

#[tokio::test]
async fn a_tenant_grant_is_refused_for_an_unknown_name_or_a_global_role() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;

    let nobody = GrantRole {
        page: tenant_page(&f.tenant),
        principal: Principal::User("nobody@contoso.com".into()),
        role: RoleId::TenantViewer,
    };
    let outcome = txn::run(&s.pool, &actor, &nobody).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");

    let global = GrantRole {
        page: tenant_page(&f.tenant),
        principal: Principal::User("alice@contoso.com".into()),
        role: RoleId::GlobalAdministrator,
    };
    let outcome = txn::run(&s.pool, &actor, &global).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert!(rows(&s, Event::AdminRoleGrant).await.is_empty());
}

/// No widening: a tenant administrator grants nothing outside their tenant, and
/// cannot make anybody a Global Administrator.
#[tokio::test]
async fn a_tenant_administrator_cannot_grant_beyond_their_reach() {
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    account(&s, &other, "eve@fabrikam.com").await;
    let f = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;

    let elsewhere = GrantRole {
        page: tenant_page(&other),
        principal: Principal::User("eve@fabrikam.com".into()),
        role: RoleId::TenantAdministrator,
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &elsewhere).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    let global = GrantRole {
        page: RolePage::Global,
        principal: Principal::User("alice@contoso.com".into()),
        role: RoleId::GlobalAdministrator,
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &global).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    assert!(rows(&s, Event::AdminRoleGrant).await.is_empty());
}

/// The command line is not held to no-widening, and a Global Administrator grant
/// belongs to the root tenant's history. A name without a domain takes the root's.
#[tokio::test]
async fn the_command_line_makes_a_global_administrator() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let grant = GrantRole {
        page: RolePage::Global,
        principal: Principal::User("alice".into()),
        role: RoleId::GlobalAdministrator,
    };
    let out = txn::run(&s.pool, &Actor::Cli, &grant).await.into_result().unwrap();
    assert_eq!(out.principal_id, f.user_id);
    let audit = rows(&s, Event::AdminRoleGrant).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(f.tenant.id.as_str()), "the root tenant");
    assert_eq!(audit[0].1, "cli");
}

#[tokio::test]
async fn global_administrator_is_refused_outside_the_root_tenant() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    account(&s, &other, "eve@fabrikam.com").await;
    let actor = admin(&s, &f.user_id).await;
    let grant = GrantRole {
        page: RolePage::Global,
        principal: Principal::User("eve@fabrikam.com".into()),
        role: RoleId::GlobalAdministrator,
    };
    let outcome = txn::run(&s.pool, &actor, &grant).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");

    let group = GrantRole {
        page: RolePage::Global,
        principal: Principal::Group("No such group".into()),
        role: RoleId::GlobalAdministrator,
    };
    let outcome = txn::run(&s.pool, &actor, &group).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(rows(&s, Event::AdminRoleGrant).await.is_empty());
}

#[tokio::test]
async fn a_tenant_role_is_revoked_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let bob = account(&s, &f.tenant, "bob@contoso.com").await;
    let id = bind(
        &s,
        &bob,
        RoleId::TenantViewer,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let actor = admin(&s, &f.user_id).await;

    let revoke = RevokeRole {
        page: tenant_page(&f.tenant),
        binding_id: id.clone(),
    };
    txn::run(&s.pool, &actor, &revoke).await.into_result().unwrap();
    assert!(bindings::effective_for_user(&s.pool, &bob).await.unwrap().is_empty());
    let audit = rows(&s, Event::AdminRoleRevoke).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(f.tenant.id.as_str()));
    assert_eq!(audit[0].2.as_deref(), Some(id.as_str()));

    // Gone now, so no longer listed: refused, and nothing recorded.
    assert_eq!(
        txn::run(&s.pool, &actor, &revoke).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    assert_eq!(rows(&s, Event::AdminRoleRevoke).await.len(), 1);
}

/// A Global Administrator binding is revoked on the Global roles page only.
#[tokio::test]
async fn a_global_binding_is_not_revoked_from_a_tenant_page() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let bob = account(&s, &f.tenant, "bob@contoso.com").await;
    let id = bind(&s, &bob, RoleId::GlobalAdministrator, Scope::All).await;
    let actor = admin(&s, &f.user_id).await;
    let from_tenant = RevokeRole {
        page: tenant_page(&f.tenant),
        binding_id: id.clone(),
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &from_tenant).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    let from_global = RevokeRole {
        page: RolePage::Global,
        binding_id: id,
    };
    txn::run(&s.pool, &actor, &from_global).await.into_result().unwrap();
    let audit = rows(&s, Event::AdminRoleRevoke).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(f.tenant.id.as_str()), "the root tenant");
}

#[tokio::test]
async fn the_last_global_administrator_is_not_revoked() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let id = bindings::list_all(&s.pool).await.unwrap().remove(0).id;
    for actor in [admin(&s, &f.user_id).await, Actor::Cli] {
        let revoke = RevokeRole {
            page: RolePage::Global,
            binding_id: id.clone(),
        };
        let outcome = txn::run(&s.pool, &actor, &revoke).await;
        assert!(
            matches!(outcome, Outcome::Refused(Refusal::RuleBroken(_))),
            "{outcome:?}"
        );
    }
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 1);
    assert!(rows(&s, Event::AdminRoleRevoke).await.is_empty());
}

/// TODO gap 5: two revocations of the last two Global Administrators, run at the
/// same time, leave one. Both lock the administrators first, so they run one
/// after the other and the second sees the first's result.
#[tokio::test]
async fn concurrent_revocations_of_the_last_two_global_administrators_leave_one() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let bob = account(&s, &f.tenant, "bob@contoso.com").await;
    bind(&s, &bob, RoleId::GlobalAdministrator, Scope::All).await;
    let ids: Vec<String> = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(ids.len(), 2);

    let first = RevokeRole {
        page: RolePage::Global,
        binding_id: ids[0].clone(),
    };
    let second = RevokeRole {
        page: RolePage::Global,
        binding_id: ids[1].clone(),
    };
    let (a, b) = tokio::join!(
        txn::run(&s.pool, &Actor::Cli, &first),
        txn::run(&s.pool, &Actor::Cli, &second)
    );
    let outcomes = [a.map_done(), b.map_done()];
    assert_eq!(
        outcomes.iter().filter(|o| o.is_done()).count(),
        1,
        "exactly one completes: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Outcome::Refused(Refusal::RuleBroken(_)))),
        "the other is refused by the rule: {outcomes:?}"
    );
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 1, "one remains");
    assert_eq!(rows(&s, Event::AdminRoleRevoke).await.len(), 1);
}

// ---- signing keys ----

#[tokio::test]
async fn a_rotation_promotes_next_and_publishes_the_key_passed_in() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let before = keys::list(&s.pool).await.unwrap();
    let active = before
        .iter()
        .find(|k| k.status == KeyStatus::Active)
        .unwrap()
        .kid
        .clone();
    let next = before.iter().find(|k| k.status == KeyStatus::Next).unwrap().kid.clone();

    let fresh = NewKey::generate().unwrap();
    let fresh_kid = fresh.kid().to_string();
    let out = txn::run(&s.pool, &actor, &RotateKeys { fresh })
        .await
        .into_result()
        .unwrap();
    assert_eq!(out.rotated.active, next);
    assert_eq!(out.rotated.next.as_deref(), Some(fresh_kid.as_str()));

    let after = keys::list(&s.pool).await.unwrap();
    let status = |kid: &str| after.iter().find(|k| k.kid == kid).unwrap().status;
    assert_eq!(status(&active), KeyStatus::Retired);
    assert_eq!(status(&next), KeyStatus::Active);
    assert_eq!(status(&fresh_kid), KeyStatus::Next);

    let audit = rows(&s, Event::AdminKeyRotate).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].0.as_deref(),
        Some(f.tenant.id.as_str()),
        "the administrator's own tenant"
    );
    assert_eq!(audit[0].1, f.user_id);
}

#[tokio::test]
async fn only_a_platform_administrator_rotates_or_prunes() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let before: Vec<_> = keys::list(&s.pool).await.unwrap().into_iter().map(|k| k.kid).collect();
    let rotate = RotateKeys {
        fresh: NewKey::generate().unwrap(),
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &rotate).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    assert_eq!(
        txn::run(&s.pool, &actor, &PruneKeys { older_than_days: 2 })
            .await
            .map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    let after: Vec<_> = keys::list(&s.pool).await.unwrap().into_iter().map(|k| k.kid).collect();
    assert_eq!(before, after);
    assert!(rows(&s, Event::AdminKeyRotate).await.is_empty());
}

#[tokio::test]
async fn pruning_deletes_old_retired_keys_and_refuses_an_age_under_a_day() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let fresh = NewKey::generate().unwrap();
    txn::run(&s.pool, &actor, &RotateKeys { fresh })
        .await
        .into_result()
        .unwrap();
    // The retired key retired long ago.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE signing_keys SET retired_at = ? WHERE status = ?",
    ))
    .bind(0_i64)
    .bind(KeyStatus::Retired.as_str())
    .execute(&s.pool)
    .await
    .unwrap();

    let outcome = txn::run(&s.pool, &actor, &PruneKeys { older_than_days: 0 }).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert!(rows(&s, Event::AdminKeyPrune).await.is_empty());

    let out = txn::run(&s.pool, &actor, &PruneKeys { older_than_days: 2 })
        .await
        .into_result()
        .unwrap();
    assert_eq!(out.deleted, 1);
    assert!(
        keys::list(&s.pool)
            .await
            .unwrap()
            .iter()
            .all(|k| k.status != KeyStatus::Retired)
    );
    let audit = rows(&s, Event::AdminKeyPrune).await;
    assert_eq!(audit.len(), 1);
    assert!(audit[0].3.contains("\"deleted\":1"), "{}", audit[0].3);
}

// ---- the flow tester ----

#[tokio::test]
async fn the_flow_tester_registers_its_callback_with_an_audit_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let add = AddFlowCallback {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        platform: RedirectPlatform::PublicClient,
        callback: "https://console.example.com/rust-oidc/admin/flow/callback".into(),
    };
    txn::run(&s.pool, &actor, &add).await.into_result().unwrap();
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    let uris = apps::redirect_uris(&s.pool, &app).await.unwrap();
    assert!(uris.iter().any(|(_, u)| *u == add.callback));
    let audit = rows(&s, Event::AdminFlowTestCallbackAdd).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].2.as_deref(), Some(f.web.app_id.as_str()));

    // Twice is refused by the storage layer, and records nothing more.
    let outcome = txn::run(&s.pool, &actor, &add).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert_eq!(rows(&s, Event::AdminFlowTestCallbackAdd).await.len(), 1);
}

#[tokio::test]
async fn the_flow_tester_callback_is_refused_on_another_tenants_application() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let theirs = s.app(&other, "their-app").await;
    let actor = admin(&s, &f.user_id).await;
    let add = AddFlowCallback {
        tenant_id: f.tenant.id.clone(),
        app_id: theirs.app_id,
        platform: RedirectPlatform::PublicClient,
        callback: "https://console.example.com/rust-oidc/admin/flow/callback".into(),
    };
    let outcome = txn::run(&s.pool, &actor, &add).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(rows(&s, Event::AdminFlowTestCallbackAdd).await.is_empty());
}

#[tokio::test]
async fn the_flow_tester_client_is_created_once() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let create = CreateFlowTestClient {
        tenant_id: f.tenant.id.clone(),
        callback: "https://console.example.com/rust-oidc/admin/flow/callback".into(),
    };
    let made = txn::run(&s.pool, &actor, &create).await.into_result().unwrap();
    assert!(made.created);
    assert_eq!(made.application.display_name, flowtest::TEST_CLIENT_NAME);
    let uris = apps::redirect_uris(&s.pool, &made.application).await.unwrap();
    assert_eq!(uris, vec![(RedirectPlatform::PublicClient, create.callback.clone())]);
    let audit = rows(&s, Event::AdminFlowTestClientCreate).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].2.as_deref(), Some(made.application.app_id.as_str()));

    let again = txn::run(&s.pool, &actor, &create).await.into_result().unwrap();
    assert!(!again.created);
    assert_eq!(again.application.app_id, made.application.app_id);
}

#[tokio::test]
async fn the_flow_tester_client_needs_app_write_in_the_tenant() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let create = CreateFlowTestClient {
        tenant_id: f.tenant.id.clone(),
        callback: "https://console.example.com/rust-oidc/admin/flow/callback".into(),
    };
    assert_eq!(
        txn::run(&s.pool, &actor, &create).await.map_done(),
        Outcome::Refused(Refusal::NotPermitted)
    );
    assert!(flowtest::test_client(&s.pool, &f.tenant.id).await.unwrap().is_none());
    assert!(rows(&s, Event::AdminFlowTestClientCreate).await.is_empty());
}
