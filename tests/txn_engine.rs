//! The transaction engine, without HTTP: authorization, all-or-nothing, the
//! audit row inside the transaction, batches, global rules, locks.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::db::Event;
use rust_oidc::txn::ops::Account;
use rust_oidc::txn::ops::users::{CreateUser, DeleteUser, DisableUser, EnableUser};
use rust_oidc::txn::{self, Actor, BatchOutcome, LockTarget, Outcome, Refusal, Txn, TxnKind};
use rust_oidc::users::{self, NewPassword};

async fn admin(s: &TestServer, user_id: &str) -> Actor {
    Actor::Admin {
        user_id: user_id.to_string(),
        bindings: bindings::effective_for_user(&s.pool, user_id).await.unwrap(),
    }
}

async fn audit_rows(s: &TestServer, event: Event) -> Vec<(String, Option<String>, String)> {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, target, details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(event.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

fn create(tenant_id: &str, upn: &str) -> CreateUser {
    CreateUser {
        tenant_id: tenant_id.to_string(),
        upn: upn.to_string(),
        password: NewPassword::for_new_account("Correct-Horse-9").unwrap(),
        display_name: None,
        given_name: None,
        family_name: None,
        email: None,
    }
}

#[tokio::test]
async fn a_completed_transaction_commits_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;

    let out = txn::run(&s.pool, &actor, &create(&f.tenant.id, "bea@contoso.com"))
        .await
        .into_result()
        .unwrap();
    assert!(users::find(&s.pool, &f.tenant.id, &out.id).await.unwrap().is_some());
    let rows = audit_rows(&s, Event::AdminUserCreate).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.user_id, "the actor is the administrator");
    assert_eq!(rows[0].1.as_deref(), Some(out.id.as_str()));
}

#[tokio::test]
async fn a_refused_transaction_changes_and_records_nothing() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;

    // A user name outside the tenant's domain: the storage layer refuses.
    let outcome = txn::run(&s.pool, &actor, &create(&f.tenant.id, "bea@elsewhere.org")).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert!(audit_rows(&s, Event::AdminUserCreate).await.is_empty());
}

#[tokio::test]
async fn the_actor_needs_the_action_at_the_scope() {
    let s = TestServer::start().await;
    let reader = reader_fixture(&s).await;
    let actor = admin(&s, &reader.user_id).await;
    let outcome = txn::run(&s.pool, &actor, &create(&reader.tenant.id, "bea@contoso.com")).await;
    assert_eq!(outcome.map_done(), Outcome::Refused(Refusal::NotPermitted));

    // A tenant administrator cannot act in a tenant that is not theirs.
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let ta = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &ta.user_id).await;
    let outcome = txn::run(&s.pool, &actor, &create(&other.id, "bea@fabrikam.com")).await;
    assert_eq!(outcome.map_done(), Outcome::Refused(Refusal::NotPermitted));
    let outcome = txn::run(&s.pool, &actor, &create(&ta.tenant.id, "bea@contoso.com")).await;
    assert!(outcome.is_done(), "{:?}", outcome.map_done());
}

#[tokio::test]
async fn nobody_disables_or_deletes_their_own_account() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let disable = DisableUser {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    assert!(matches!(
        txn::run(&s.pool, &actor, &disable).await,
        Outcome::Refused(Refusal::Conflict(_))
    ));
    let delete = DeleteUser {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    assert!(matches!(
        txn::run(&s.pool, &actor, &delete).await,
        Outcome::Refused(Refusal::Conflict(_))
    ));
}

#[tokio::test]
async fn the_last_global_administrator_stays_whoever_asks() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    // The command line is not the account, so only the global rule stands in the way.
    let disable = DisableUser {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    let outcome = txn::run(&s.pool, &Actor::Cli, &disable).await;
    assert!(
        matches!(outcome, Outcome::Refused(Refusal::RuleBroken(_))),
        "{outcome:?}"
    );
    assert!(
        users::find(&s.pool, &f.tenant.id, &f.user_id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
    assert!(audit_rows(&s, Event::AdminUserDisable).await.is_empty());
}

/// No audit, no change: a transaction whose audit row cannot be written rolls
/// back entirely.
#[tokio::test]
async fn a_transaction_whose_audit_row_fails_changes_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // Break the audit table: every audit write fails from here on.
    break_audit_log(&s.pool).await;
    let outcome = txn::run(&s.pool, &Actor::Cli, &create(&f.tenant.id, "bea@contoso.com")).await;
    assert!(matches!(outcome, Outcome::Failed(_)), "{:?}", outcome.map_done());
    assert!(
        users::find_by_upn(&s.pool, &f.tenant.id, "bea@contoso.com")
            .await
            .unwrap()
            .is_none(),
        "the account was not created"
    );
}

#[tokio::test]
async fn a_batch_commits_once_and_shares_a_batch_id() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let batch: Vec<Txn> = vec![
        create(&f.tenant.id, "bea@contoso.com").into(),
        create(&f.tenant.id, "cal@contoso.com").into(),
    ];
    let BatchOutcome::Done(outputs) = txn::run_batch(&s.pool, &Actor::Cli, &batch).await else {
        panic!("the batch did not complete");
    };
    assert_eq!(outputs.len(), 2);
    let rows = audit_rows(&s, Event::AdminUserCreate).await;
    assert_eq!(rows.len(), 2);
    let batch_of = |details: &str| serde_json::from_str::<serde_json::Value>(details).unwrap()["batch"].clone();
    assert!(batch_of(&rows[0].2).is_string());
    assert_eq!(batch_of(&rows[0].2), batch_of(&rows[1].2));
    assert_eq!(rows[0].0, "cli");
}

#[tokio::test]
async fn a_batch_that_aborts_part_way_rolls_back_what_ran_before() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let batch: Vec<Txn> = vec![
        create(&f.tenant.id, "bea@contoso.com").into(),
        create(&f.tenant.id, "cal@elsewhere.org").into(),
    ];
    match txn::run_batch(&s.pool, &Actor::Cli, &batch).await {
        BatchOutcome::Aborted { index, outcome } => {
            assert_eq!(index, 1);
            assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))));
        }
        BatchOutcome::Done(_) => panic!("the batch should have aborted"),
    }
    assert!(
        users::find_by_upn(&s.pool, &f.tenant.id, "bea@contoso.com")
            .await
            .unwrap()
            .is_none(),
        "the first transaction of the batch rolled back with the second"
    );
    assert!(audit_rows(&s, Event::AdminUserCreate).await.is_empty());
}

/// Inside a batch the global rules hold only at the end: making somebody else
/// Global Administrator's account usable and then disabling the old one works,
/// in that order, even though the old one is the only one at the start.
#[tokio::test]
async fn global_rules_are_checked_against_the_final_state_of_a_batch() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let second = user_fixture_in(&s, f.tenant.clone(), "bea@contoso.com").await;
    bind(
        &s,
        &second.user_id,
        rust_oidc::rbac::RoleId::GlobalAdministrator,
        rust_oidc::rbac::Scope::All,
    )
    .await;
    users::set_enabled(&s.pool, &f.tenant.id, &second.user_id, false)
        .await
        .unwrap();

    let batch: Vec<Txn> = vec![
        EnableUser {
            tenant_id: f.tenant.id.clone(),
            user_id: second.user_id.clone(),
        }
        .into(),
        DisableUser {
            tenant_id: f.tenant.id.clone(),
            user_id: f.user_id.clone(),
        }
        .into(),
    ];
    match txn::run_batch(&s.pool, &Actor::Cli, &batch).await {
        BatchOutcome::Done(_) => {}
        BatchOutcome::Aborted { index, outcome } => panic!("aborted at {index}: {outcome:?}"),
    }
    // The other order fails at its first step, and changes nothing.
    let batch: Vec<Txn> = vec![
        DisableUser {
            tenant_id: f.tenant.id.clone(),
            user_id: second.user_id.clone(),
        }
        .into(),
        EnableUser {
            tenant_id: f.tenant.id.clone(),
            user_id: f.user_id.clone(),
        }
        .into(),
    ];
    assert!(matches!(
        txn::run_batch(&s.pool, &Actor::Cli, &batch).await,
        BatchOutcome::Aborted { index: 0, .. }
    ));
    assert!(
        users::find(&s.pool, &f.tenant.id, &second.user_id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

/// Locks are taken in one order whatever order they were declared in, which is
/// what rules out two transactions waiting on each other.
#[test]
fn locks_are_taken_in_one_order() {
    let order = txn::lock_order(vec![
        LockTarget::App("a".into()),
        LockTarget::User("b".into()),
        LockTarget::Administrators,
        LockTarget::User("a".into()),
        LockTarget::Tenant("z".into()),
        LockTarget::User("b".into()),
    ]);
    assert_eq!(
        order,
        vec![
            LockTarget::Administrators,
            LockTarget::Tenant("z".into()),
            LockTarget::User("a".into()),
            LockTarget::User("b".into()),
            LockTarget::App("a".into()),
        ]
    );
}

/// A transaction that cannot get its lock in time gives up as `Busy` and
/// changes nothing; it does not wait for ever. On Postgres and MySQL this is the
/// engine's own row lock and lock timeout; on SQLite, the database's write lock
/// and busy timeout.
#[tokio::test]
async fn a_lock_not_granted_in_time_is_busy() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // Another connection holds the Administrators lock, which disabling an
    // account declares.
    let mut holder = s.pool.acquire().await.unwrap();
    let held = hold_administrators_lock(&mut holder).await;

    let disable = DisableUser {
        tenant_id: f.tenant.id.clone(),
        user_id: f.user_id.clone(),
    };
    let started = std::time::Instant::now();
    let outcome = txn::run(&s.pool, &Actor::Cli, &disable).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Busy(_))), "{outcome:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    held.rollback().await.unwrap();
    assert!(
        users::find(&s.pool, &f.tenant.id, &f.user_id)
            .await
            .unwrap()
            .unwrap()
            .enabled,
        "nothing changed"
    );
    assert!(audit_rows(&s, Event::AdminUserDisable).await.is_empty());
}

/// Every kind of transaction is listed once, with a name and its own audit event.
#[test]
fn every_kind_has_a_name_and_its_own_event() {
    let mut events = Vec::new();
    let mut names = Vec::new();
    for kind in TxnKind::ALL {
        let info = kind.info();
        assert!(!info.name.is_empty());
        assert!(!names.contains(&info.name), "{kind:?}: name {} used twice", info.name);
        assert!(
            !events.contains(&info.event),
            "{kind:?}: event {:?} used twice",
            info.event
        );
        names.push(info.name);
        events.push(info.event);
    }
}

#[tokio::test]
async fn an_account_named_by_user_name_is_restored() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap();
    let restore = txn::ops::users::RestoreUser {
        tenant_id: f.tenant.id.clone(),
        account: Account::Upn(f.upn.clone()),
    };
    let id = txn::run(&s.pool, &Actor::Cli, &restore).await.into_result().unwrap();
    assert_eq!(id, f.user_id);
    assert!(users::find(&s.pool, &f.tenant.id, &f.user_id).await.unwrap().is_some());
}

#[tokio::test]
async fn a_user_name_in_use_is_refused_deleted_or_not() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let outcome = txn::run(&s.pool, &Actor::Cli, &create(&f.tenant.id, &f.upn)).await;
    assert!(
        matches!(outcome, Outcome::Refused(Refusal::Invalid(_))),
        "{:?}",
        outcome.map_done()
    );
    users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap();
    let outcome = txn::run(&s.pool, &Actor::Cli, &create(&f.tenant.id, &f.upn)).await;
    match outcome {
        Outcome::Refused(Refusal::Invalid(m)) => assert!(m.contains("restore"), "{m}"),
        other => panic!("{:?}", other.map_done()),
    }
}
