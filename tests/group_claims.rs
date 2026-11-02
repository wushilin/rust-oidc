//! Which groups a token carries: the receiving application's
//! `groupMembershipClaims` (Entra's), `None` by default.
//!
//! - `None`: no `groups` claim at all.
//! - `All`: every group the user is in, nested ones included.
//! - `ApplicationGroup`: groups assigned to the application that the user is a
//!   direct member of.
//!
//! The access token follows the resource's setting, the ID token the client's.
//! `groups` carries object ids, as in Entra.

mod common;

use common::*;
use rust_oidc::apps::{self, GroupMembershipClaims, Principal};
use rust_oidc::groups;
use rust_oidc::txn::{self, Actor};
use serde_json::Value;

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

/// (access token, ID token) claims for alice, signing in to the web app for the
/// orders API, or for Graph when `api` is false.
async fn tokens(s: &TestServer, f: &UserFixture, api: bool) -> (Value, Value) {
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::set_password_grant_allowed(&s.pool, &web, true).await.unwrap();
    let scope = if api {
        format!("openid api://{}/Orders.Read", f.api.app_id)
    } else {
        "openid".to_string()
    };
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    (
        decode_unverified(body["access_token"].as_str().unwrap()),
        decode_unverified(body["id_token"].as_str().unwrap()),
    )
}

async fn set(s: &TestServer, app_id: &str, setting: GroupMembershipClaims) {
    let app = apps::find(&s.pool, app_id).await.unwrap().unwrap();
    apps::set_group_membership_claims(&s.pool, &app, setting).await.unwrap();
}

/// Alice is in Alpha and Beta; Gamma exists and she is not in it.
async fn three_groups(s: &TestServer, f: &UserFixture) -> (String, String, String) {
    let alpha = groups::create(&s.pool, &f.tenant, "Alpha", None).await.unwrap();
    let beta = groups::create(&s.pool, &f.tenant, "Beta", None).await.unwrap();
    let gamma = groups::create(&s.pool, &f.tenant, "Gamma", None).await.unwrap();
    for g in ["Alpha", "Beta"] {
        groups::add_member(&s.pool, &f.tenant, g, &f.upn).await.unwrap();
    }
    (alpha, beta, gamma)
}

async fn assign_group(s: &TestServer, f: &UserFixture, app_id: &str, group: &str) {
    let app = apps::find(&s.pool, app_id).await.unwrap().unwrap();
    apps::assign(&s.pool, &f.tenant, &app, &Principal::Group(group.into()), &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn by_default_no_token_carries_groups() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    three_groups(&s, &f).await;
    // Even assigned groups are not carried while the setting is None.
    assign_group(&s, &f, &f.web.app_id, "Alpha").await;
    assign_group(&s, &f, &f.api.app_id, "Alpha").await;
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    assert_eq!(web.group_membership_claims, GroupMembershipClaims::None);

    let (access, id) = tokens(&s, &f, true).await;
    for claims in [&access, &id] {
        assert!(claims.get("groups").is_none(), "{claims}");
        assert!(claims.get("group_ids").is_none(), "{claims}");
    }
}

#[tokio::test]
async fn all_carries_every_group_as_object_ids() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (alpha, beta, _) = three_groups(&s, &f).await;
    set(&s, &f.web.app_id, GroupMembershipClaims::All).await;
    set(&s, &f.api.app_id, GroupMembershipClaims::All).await;

    let (access, id) = tokens(&s, &f, true).await;
    for claims in [&access, &id] {
        assert_eq!(strings(&claims["groups"]), [alpha.clone(), beta.clone()], "{claims}");
        assert!(
            claims.get("group_ids").is_none(),
            "ids are the claim itself now: {claims}"
        );
    }
}

/// The access token is the resource's, the ID token the client's.
#[tokio::test]
async fn each_token_follows_the_application_that_receives_it() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (alpha, beta, _) = three_groups(&s, &f).await;

    set(&s, &f.api.app_id, GroupMembershipClaims::All).await;
    let (access, id) = tokens(&s, &f, true).await;
    assert_eq!(strings(&access["groups"]), [alpha.clone(), beta.clone()]);
    assert!(id.get("groups").is_none(), "the client did not ask: {id}");

    set(&s, &f.api.app_id, GroupMembershipClaims::None).await;
    set(&s, &f.web.app_id, GroupMembershipClaims::All).await;
    let (access, id) = tokens(&s, &f, true).await;
    assert!(access.get("groups").is_none(), "the API did not ask: {access}");
    assert_eq!(strings(&id["groups"]), [alpha, beta]);
}

#[tokio::test]
async fn graph_tokens_carry_no_groups() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    three_groups(&s, &f).await;
    set(&s, &f.web.app_id, GroupMembershipClaims::All).await;
    let (access, id) = tokens(&s, &f, false).await;
    assert!(access.get("groups").is_none(), "{access}");
    assert!(id.get("groups").is_some(), "{id}");
}

/// Only groups assigned to the application, and only those the user is in.
#[tokio::test]
async fn application_group_carries_only_assigned_groups_the_user_is_in() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let (alpha, _beta, _gamma) = three_groups(&s, &f).await;
    // Alpha: assigned, and she is in it. Gamma: assigned, she is not. Beta: she is
    // in it, not assigned.
    assign_group(&s, &f, &f.web.app_id, "Alpha").await;
    assign_group(&s, &f, &f.web.app_id, "Gamma").await;
    // Assigning her directly adds no group.
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::assign(&s.pool, &f.tenant, &web, &Principal::User(f.upn.clone()), &[])
        .await
        .unwrap();
    set(&s, &f.web.app_id, GroupMembershipClaims::ApplicationGroup).await;

    let (_, id) = tokens(&s, &f, true).await;
    assert_eq!(strings(&id["groups"]), [alpha]);
}

/// group1 contains group2 and alice is in group2: `All` carries both, and
/// `ApplicationGroup` with group1 assigned carries neither, since nesting does not
/// assign.
#[tokio::test]
async fn nesting_counts_for_all_and_not_for_assigned_groups() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let g1 = groups::create(&s.pool, &f.tenant, "group1", None).await.unwrap();
    let g2 = groups::create(&s.pool, &f.tenant, "group2", None).await.unwrap();
    let g3 = groups::create(&s.pool, &f.tenant, "group3", None).await.unwrap();
    for (outer, inner) in [(&g1, &g2), (&g2, &g3)] {
        let t = rust_oidc::txn::ops::groups::AddGroupToGroup {
            tenant_id: f.tenant.id.clone(),
            group_id: outer.clone(),
            member: rust_oidc::txn::ops::groups::GroupKey::Id(inner.clone()),
        };
        txn::run(&s.pool, &Actor::Cli, &t).await.into_result().unwrap();
    }
    groups::add_member(&s.pool, &f.tenant, "group2", &f.upn).await.unwrap();

    set(&s, &f.web.app_id, GroupMembershipClaims::All).await;
    let (_, id) = tokens(&s, &f, true).await;
    assert_eq!(strings(&id["groups"]), [g1, g2], "up to group1, not down to group3");

    assign_group(&s, &f, &f.web.app_id, "group1").await;
    set(&s, &f.web.app_id, GroupMembershipClaims::ApplicationGroup).await;
    let (_, id) = tokens(&s, &f, true).await;
    assert!(id.get("groups").is_none(), "{id}");
}

#[tokio::test]
async fn the_setting_is_a_transaction_with_its_audit_row() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let t = rust_oidc::txn::ops::apps::SetGroupMembershipClaims {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        setting: GroupMembershipClaims::ApplicationGroup,
    };
    txn::run(&s.pool, &Actor::Cli, &t).await.into_result().unwrap();
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    assert_eq!(web.group_membership_claims, GroupMembershipClaims::ApplicationGroup);
    let (details,): (String,) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ?",
    ))
    .bind(rust_oidc::db::Event::AdminAppGroupClaims.as_str())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(details.contains("ApplicationGroup"), "{details}");
}

/// A value this build does not know is read as None: fewer groups, never more.
#[tokio::test]
async fn an_unknown_stored_setting_carries_no_groups() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    three_groups(&s, &f).await;
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE applications SET group_membership_claims = ? WHERE app_id = ?",
    ))
    .bind("SomeFutureValue")
    .bind(&f.web.app_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, id) = tokens(&s, &f, true).await;
    assert!(id.get("groups").is_none(), "{id}");
}

/// The console's Token configuration tab sets it.
#[tokio::test]
async fn the_console_sets_the_groups_claim() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let page = b.get(&format!("{url}/token")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains(r#"value="None" checked"#), "{}", page.body);

    let saved = b
        .post(&url, &[("op", "group_claims"), ("group_membership_claims", "All")])
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let web = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    assert_eq!(web.group_membership_claims, GroupMembershipClaims::All);

    let bad = b
        .post(
            &url,
            &[("op", "group_claims"), ("group_membership_claims", "Everything")],
        )
        .await;
    assert_eq!(bad.status, 400, "{}", bad.body);
}
