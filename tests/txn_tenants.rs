//! Tenant transactions, run through the engine without HTTP: creating a tenant,
//! renaming, enabling and disabling it, its domain, and its settings.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::db::Event;
use rust_oidc::tenant::{self, TenantSettings};
use rust_oidc::txn::ops::tenants::{
    ChangeTenantDomain, CreateTenant, DisableTenant, EnableTenant, RemoveTenantDomain, RenameTenant, SaveTenantSettings,
};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};

async fn admin(s: &TestServer, user_id: &str) -> Actor {
    Actor::Admin {
        user_id: user_id.to_string(),
        bindings: bindings::effective_for_user(&s.pool, user_id).await.unwrap(),
    }
}

/// (actor, tenant_id, target, details) of every row with this event, oldest first.
async fn rows(s: &TestServer, event: Event) -> Vec<(String, Option<String>, Option<String>, serde_json::Value)> {
    let raw: Vec<(String, Option<String>, Option<String>, String)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, tenant_id, target, details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(event.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap();
    raw.into_iter()
        .map(|(a, t, g, d)| (a, t, g, serde_json::from_str(&d).unwrap()))
        .collect()
}

fn refused<T: std::fmt::Debug>(outcome: Outcome<T>) -> Refusal {
    match outcome {
        Outcome::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn second_domain(s: &TestServer, tenant_id: &str, domain: &str) {
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO tenant_domains (domain, domain_folded, tenant_id, is_default, created_at) VALUES (?, ?, ?, ?, 0)",
    ))
    .bind(domain)
    .bind(domain)
    .bind(tenant_id)
    .bind(false)
    .execute(&s.pool)
    .await
    .unwrap();
}

// ---- create ----

#[tokio::test]
async fn a_tenant_is_created_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let create = CreateTenant {
        name: "Fabrikam".into(),
        domain: "fabrikam.com".into(),
    };
    let created = txn::run(&s.pool, &actor, &create).await.into_result().unwrap();
    assert!(!created.is_root);
    assert_eq!(
        tenant::domains(&s.pool, &created.id).await.unwrap(),
        vec!["fabrikam.com"]
    );
    let rows = rows(&s, Event::AdminTenantCreate).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.user_id);
    assert_eq!(rows[0].1.as_deref(), Some(created.id.as_str()));
    assert_eq!(rows[0].2.as_deref(), Some(created.id.as_str()));
    assert_eq!(rows[0].3["name"], "Fabrikam");
    assert_eq!(rows[0].3["domain"], "fabrikam.com");
}

#[tokio::test]
async fn a_tenant_on_a_domain_already_held_is_refused_and_not_recorded() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let create = CreateTenant {
        name: "Copycat".into(),
        domain: "contoso.com".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &actor, &create).await),
        Refusal::Invalid(_)
    ));
    assert_eq!(tenant::list(&s.pool).await.unwrap().len(), 1);
    assert!(rows(&s, Event::AdminTenantCreate).await.is_empty());
}

/// Every write on the tenants page is platform work: a tenant's own
/// administrator holds `Tenant:Write` in their tenant, and that is not enough.
#[tokio::test]
async fn a_tenant_administrator_does_no_platform_work() {
    let s = TestServer::start().await;
    let ta = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &ta.user_id).await;
    let id = ta.tenant.id.clone();
    let create = CreateTenant {
        name: "Fabrikam".into(),
        domain: "fabrikam.com".into(),
    };
    assert_eq!(refused(txn::run(&s.pool, &actor, &create).await), Refusal::NotPermitted);
    let rename = RenameTenant {
        tenant_id: id.clone(),
        name: "Mine now".into(),
    };
    assert_eq!(refused(txn::run(&s.pool, &actor, &rename).await), Refusal::NotPermitted);
    let disable = DisableTenant { tenant_id: id.clone() };
    assert_eq!(
        refused(txn::run(&s.pool, &actor, &disable).await),
        Refusal::NotPermitted
    );
    let change = ChangeTenantDomain {
        tenant_id: id.clone(),
        domain: "contoso.org".into(),
    };
    assert_eq!(refused(txn::run(&s.pool, &actor, &change).await), Refusal::NotPermitted);
    let stored = tenant::find_for_admin(&s.pool, &id).await.unwrap();
    assert_eq!(stored.name, "Contoso");
    assert!(stored.enabled);
}

// ---- rename ----

#[tokio::test]
async fn a_tenant_is_renamed_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let rename = RenameTenant {
        tenant_id: other.id.clone(),
        name: "Fabrikam Ltd".into(),
    };
    txn::run(&s.pool, &actor, &rename).await.into_result().unwrap();
    assert_eq!(
        tenant::find_for_admin(&s.pool, &other.id).await.unwrap().name,
        "Fabrikam Ltd"
    );
    let rows = rows(&s, Event::AdminTenantRename).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2.as_deref(), Some(other.id.as_str()));
    assert_eq!(rows[0].3["name"], "Fabrikam Ltd");
}

#[tokio::test]
async fn an_empty_name_or_an_unknown_tenant_is_refused() {
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let rename = RenameTenant {
        tenant_id: other.id.clone(),
        name: "   ".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &Actor::Cli, &rename).await),
        Refusal::Invalid(_)
    ));
    // Named by its domain rather than its id: the lock is taken on the id, so
    // only the id names a tenant here.
    let rename = RenameTenant {
        tenant_id: "fabrikam.com".into(),
        name: "Fabrikam Ltd".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &Actor::Cli, &rename).await),
        Refusal::NotFound(_)
    ));
    let rename = RenameTenant {
        tenant_id: rust_oidc::util::new_guid(),
        name: "Nobody".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &Actor::Cli, &rename).await),
        Refusal::Invalid(_)
    ));
    assert_eq!(
        tenant::find_for_admin(&s.pool, &other.id).await.unwrap().name,
        "Fabrikam"
    );
    assert!(rows(&s, Event::AdminTenantRename).await.is_empty());
}

// ---- enable, disable ----

#[tokio::test]
async fn a_tenant_is_disabled_and_enabled_again_each_with_its_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let disable = DisableTenant {
        tenant_id: other.id.clone(),
    };
    txn::run(&s.pool, &actor, &disable).await.into_result().unwrap();
    assert!(!tenant::find_for_admin(&s.pool, &other.id).await.unwrap().enabled);
    assert!(tenant::resolve(&s.pool, &other.id).await.unwrap().is_none());
    let enable = EnableTenant {
        tenant_id: other.id.clone(),
    };
    txn::run(&s.pool, &actor, &enable).await.into_result().unwrap();
    assert!(tenant::find_for_admin(&s.pool, &other.id).await.unwrap().enabled);

    let off = rows(&s, Event::AdminTenantDisable).await;
    assert_eq!(off.len(), 1);
    assert_eq!(off[0].3["enabled"], false);
    let on = rows(&s, Event::AdminTenantEnable).await;
    assert_eq!(on.len(), 1);
    assert_eq!(on[0].3["enabled"], true);
}

#[tokio::test]
async fn the_root_tenant_is_never_disabled() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let disable = DisableTenant {
        tenant_id: f.tenant.id.clone(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &actor, &disable).await),
        Refusal::Invalid(_)
    ));
    assert!(tenant::find_for_admin(&s.pool, &f.tenant.id).await.unwrap().enabled);
    assert!(rows(&s, Event::AdminTenantDisable).await.is_empty());
}

#[tokio::test]
async fn enabling_an_unknown_tenant_is_refused() {
    let s = TestServer::start().await;
    let enable = EnableTenant {
        tenant_id: rust_oidc::util::new_guid(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &Actor::Cli, &enable).await),
        Refusal::Invalid(_)
    ));
    assert!(rows(&s, Event::AdminTenantEnable).await.is_empty());
}

// ---- domains ----

#[tokio::test]
async fn a_domain_change_renames_every_account_with_its_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let other = user_fixture_in(&s, s.tenant("Fabrikam", "fabrikam.com").await, "bea@fabrikam.com").await;
    let change = ChangeTenantDomain {
        tenant_id: other.tenant.id.clone(),
        domain: "fabrikam.org".into(),
    };
    let done = txn::run(&s.pool, &actor, &change).await.into_result().unwrap();
    assert_eq!(done.renamed, 1);
    assert!(
        rust_oidc::users::find_by_upn(&s.pool, &other.tenant.id, "bea@fabrikam.org")
            .await
            .unwrap()
            .is_some()
    );
    let rows = rows(&s, Event::AdminTenantDomainChange).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3["from"], serde_json::json!(["fabrikam.com"]));
    assert_eq!(rows[0].3["to"], "fabrikam.org");
    assert_eq!(rows[0].3["renamed"], 1);
}

#[tokio::test]
async fn a_domain_another_tenant_holds_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let change = ChangeTenantDomain {
        tenant_id: other.id.clone(),
        domain: "contoso.com".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &admin(&s, &f.user_id).await, &change).await),
        Refusal::Invalid(_)
    ));
    assert_eq!(tenant::domains(&s.pool, &other.id).await.unwrap(), vec!["fabrikam.com"]);
    assert!(rows(&s, Event::AdminTenantDomainChange).await.is_empty());
}

#[tokio::test]
async fn a_surplus_domain_is_removed_but_not_the_last() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    second_domain(&s, &other.id, "fabrikam.net").await;
    let remove = RemoveTenantDomain {
        tenant_id: other.id.clone(),
        domain: "fabrikam.net".into(),
    };
    txn::run(&s.pool, &actor, &remove).await.into_result().unwrap();
    assert_eq!(tenant::domains(&s.pool, &other.id).await.unwrap(), vec!["fabrikam.com"]);
    let removed = rows(&s, Event::AdminTenantDomainRemove).await;
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].3["domain"], "fabrikam.net");

    let last = RemoveTenantDomain {
        tenant_id: other.id.clone(),
        domain: "fabrikam.com".into(),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &actor, &last).await),
        Refusal::Invalid(_)
    ));
    assert_eq!(tenant::domains(&s.pool, &other.id).await.unwrap(), vec!["fabrikam.com"]);
    assert_eq!(rows(&s, Event::AdminTenantDomainRemove).await.len(), 1);
}

// ---- settings ----

fn settings_with_access(secs: i64) -> TenantSettings {
    TenantSettings {
        access_token_lifetime_secs: secs,
        ..TenantSettings::default()
    }
}

#[tokio::test]
async fn a_tenant_administrator_saves_their_own_settings_with_a_row() {
    let s = TestServer::start().await;
    let ta = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &ta.user_id).await;
    let save = SaveTenantSettings {
        tenant_id: ta.tenant.id.clone(),
        settings: settings_with_access(1_800),
    };
    txn::run(&s.pool, &actor, &save).await.into_result().unwrap();
    let stored = tenant::find_for_admin(&s.pool, &ta.tenant.id).await.unwrap();
    assert_eq!(stored.settings.access_token_lifetime_secs, 1_800);
    let rows = rows(&s, Event::AdminTenantSettings).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, ta.user_id);
    assert_eq!(rows[0].1.as_deref(), Some(ta.tenant.id.as_str()));
    assert_eq!(rows[0].3["accessTokenLifetimeSecs"], 1_800);
}

#[tokio::test]
async fn settings_out_of_bounds_or_of_another_tenant_are_refused() {
    let s = TestServer::start().await;
    let ta = tenant_admin_fixture(&s).await;
    let actor = admin(&s, &ta.user_id).await;
    let save = SaveTenantSettings {
        tenant_id: ta.tenant.id.clone(),
        settings: settings_with_access(TenantSettings::MAX_ACCESS_TOKEN_SECS + 1),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &actor, &save).await),
        Refusal::Invalid(_)
    ));
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    let save = SaveTenantSettings {
        tenant_id: other.id.clone(),
        settings: settings_with_access(1_800),
    };
    assert_eq!(refused(txn::run(&s.pool, &actor, &save).await), Refusal::NotPermitted);
    let untouched = TenantSettings::default().access_token_lifetime_secs;
    for id in [&ta.tenant.id, &other.id] {
        let stored = tenant::find_for_admin(&s.pool, id).await.unwrap();
        assert_eq!(stored.settings.access_token_lifetime_secs, untouched);
    }
    assert!(rows(&s, Event::AdminTenantSettings).await.is_empty());
}

#[tokio::test]
async fn a_disabled_tenant_has_no_settings_to_save() {
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    tenant::set_enabled(&s.pool, &other.id, false).await.unwrap();
    let save = SaveTenantSettings {
        tenant_id: other.id.clone(),
        settings: settings_with_access(1_800),
    };
    assert!(matches!(
        refused(txn::run(&s.pool, &Actor::Cli, &save).await),
        Refusal::NotFound(_)
    ));
}

/// No audit, no change (TODO gap 6): a tenant change whose audit row cannot be
/// written is not made.
#[tokio::test]
async fn a_tenant_change_whose_audit_row_fails_changes_nothing() {
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.com").await;
    sqlx::query("CREATE TRIGGER no_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit is down'); END")
        .execute(&s.pool)
        .await
        .unwrap();
    let rename = RenameTenant {
        tenant_id: other.id.clone(),
        name: "Fabrikam Ltd".into(),
    };
    assert!(matches!(
        txn::run(&s.pool, &Actor::Cli, &rename).await,
        Outcome::Failed(_)
    ));
    let save = SaveTenantSettings {
        tenant_id: other.id.clone(),
        settings: settings_with_access(1_800),
    };
    assert!(matches!(
        txn::run(&s.pool, &Actor::Cli, &save).await,
        Outcome::Failed(_)
    ));
    let create = CreateTenant {
        name: "Northwind".into(),
        domain: "northwind.com".into(),
    };
    assert!(matches!(
        txn::run(&s.pool, &Actor::Cli, &create).await,
        Outcome::Failed(_)
    ));
    let stored = tenant::find_for_admin(&s.pool, &other.id).await.unwrap();
    assert_eq!(stored.name, "Fabrikam");
    assert_eq!(
        stored.settings.access_token_lifetime_secs,
        TenantSettings::default().access_token_lifetime_secs
    );
    assert!(tenant::find_for_admin(&s.pool, "northwind.com").await.is_err());
}
