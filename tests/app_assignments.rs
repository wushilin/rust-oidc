//! Assigning users and groups to an application.
//!
//! A user or group is assigned to the application; the roles they hold there are
//! a set ticked on that assignment, and may be empty. Being assigned is what
//! "assignment required" checks; the roles are what the `roles` claim carries.

mod common;

use common::*;
use rust_oidc::apps::{self, MemberType, Principal};
use rust_oidc::groups;
use serde_json::Value;

const NOT_ASSIGNED: &str = "AADSTS50105";

/// The fixture's web app with three roles for users and one for applications,
/// the password grant allowed (so a token is one request away) and assignment
/// required.
async fn app_with_roles(s: &TestServer, f: &UserFixture) -> apps::Application {
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id).await.unwrap();
    for role in ["role1", "role2", "role3"] {
        apps::add_role(&s.pool, &app, role, role, None, &[MemberType::User])
            .await
            .unwrap();
    }
    apps::add_role(&s.pool, &app, "Daemon.Run", "Daemon", None, &[MemberType::Application])
        .await
        .unwrap();
    apps::set_password_grant_allowed(&s.pool, &app, true).await.unwrap();
    let sp = apps::service_principal(&s.pool, &f.tenant.id, &app.app_id)
        .await
        .unwrap()
        .unwrap();
    apps::set_assignment_required(&s.pool, &sp.id, true).await.unwrap();
    apps::find_in_tenant(&s.pool, &f.tenant, &f.web.app_id).await.unwrap()
}

/// Sign the fixture's user in to the web app; the id token's claims, or the error.
async fn sign_in(s: &TestServer, f: &UserFixture) -> Result<Value, String> {
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &f.web.app_id),
                ("client_secret", &f.web.secret),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", "openid"),
            ],
        )
        .await;
    match body["id_token"].as_str() {
        Some(token) if status == 200 => Ok(decode_unverified(token)),
        _ => Err(body["error_description"].as_str().unwrap_or_default().to_string()),
    }
}

fn roles_of(claims: &Value) -> Vec<String> {
    claims["roles"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[tokio::test]
async fn a_user_assigned_with_no_role_can_sign_in_and_holds_none() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = app_with_roles(&s, &f).await;
    assert!(sign_in(&s, &f).await.unwrap_err().contains(NOT_ASSIGNED));

    apps::assign(&s.pool, &f.tenant, &app, &Principal::User(f.upn.clone()), &[])
        .await
        .unwrap();
    let claims = sign_in(&s, &f).await.expect("assigned, so signed in");
    assert!(claims.get("roles").is_none(), "no role was given: {claims}");

    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].principal_name, f.upn);
    assert!(listed[0].roles.is_empty());
}

#[tokio::test]
async fn a_group_assigned_with_roles_gives_them_to_its_members_and_the_set_is_replaced() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = app_with_roles(&s, &f).await;
    groups::create(&s.pool, &f.tenant, "group1", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "group1", &f.upn).await.unwrap();
    let group = Principal::Group("group1".into());

    let id = apps::assign(&s.pool, &f.tenant, &app, &group, &owned(&["role1", "role2", "role3"]))
        .await
        .unwrap();
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role1", "role2", "role3"]);

    // Assigning again is changing the roles: the set ticked replaces the set held,
    // and it is still the one assignment.
    let again = apps::assign(&s.pool, &f.tenant, &app, &group, &owned(&["role2"]))
        .await
        .unwrap();
    assert_eq!(again, id);
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role2"]);
    // Down to none: still assigned.
    apps::assign(&s.pool, &f.tenant, &app, &group, &[]).await.unwrap();
    assert!(roles_of(&sign_in(&s, &f).await.unwrap()).is_empty());

    // The user's own assignment adds to what the group gives.
    apps::assign(&s.pool, &f.tenant, &app, &group, &owned(&["role1"]))
        .await
        .unwrap();
    apps::assign(
        &s.pool,
        &f.tenant,
        &app,
        &Principal::User(f.upn.clone()),
        &owned(&["role3"]),
    )
    .await
    .unwrap();
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role1", "role3"]);
    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(
        (listed[0].principal_name.as_str(), &listed[0].roles),
        (f.upn.as_str(), &owned(&["role3"]))
    );
    assert_eq!(
        (listed[1].principal_name.as_str(), &listed[1].roles),
        ("group1", &owned(&["role1"]))
    );

    // Removing an assignment takes its roles; removing the last one locks out.
    assert!(
        apps::unassign(&s.pool, &f.tenant.id, &app, &listed[0].id)
            .await
            .unwrap()
    );
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role1"]);
    assert!(apps::unassign(&s.pool, &f.tenant.id, &app, &id).await.unwrap());
    assert!(sign_in(&s, &f).await.unwrap_err().contains(NOT_ASSIGNED));
    assert!(
        !apps::unassign(&s.pool, &f.tenant.id, &app, &id).await.unwrap(),
        "already gone"
    );
    assert!(
        apps::role_assignments(&s.pool, &f.tenant.id, &app)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_assignment_that_cannot_be_made_changes_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = app_with_roles(&s, &f).await;
    let user = Principal::User(f.upn.clone());
    apps::assign(&s.pool, &f.tenant, &app, &user, &owned(&["role1"]))
        .await
        .unwrap();

    for (principal, roles, why) in [
        (
            Principal::User(f.upn.clone()),
            owned(&["role2", "nope"]),
            "has no role 'nope'",
        ),
        (
            Principal::User(f.upn.clone()),
            owned(&["Daemon.Run"]),
            "cannot be given to users",
        ),
        (Principal::User("nobody@contoso.com".into()), vec![], "not found"),
        (Principal::Group("no-such-group".into()), vec![], "not found"),
        (Principal::App(f.api.app_id.clone()), vec![], "only a user or a group"),
    ] {
        let err = apps::assign(&s.pool, &f.tenant, &app, &principal, &roles)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(why), "{why}: {err}");
    }
    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].roles, ["role1"], "the roles held before are untouched");

    // An assignment id is good for its own application only.
    let api = apps::find_in_tenant(&s.pool, &f.tenant, &f.api.app_id).await.unwrap();
    assert!(
        !apps::unassign(&s.pool, &f.tenant.id, &api, &listed[0].id)
            .await
            .unwrap()
    );
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    assert!(!apps::unassign(&s.pool, &other.id, &app, &listed[0].id).await.unwrap());
    assert_eq!(apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap().len(), 1);
}

/// Granting one role the old way (the CLI, and existing callers) still leaves the
/// principal assigned: a role row never exists without its assignment.
#[tokio::test]
async fn holding_a_role_always_means_being_assigned() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = app_with_roles(&s, &f).await;
    apps::assign_role(&s.pool, &f.tenant, &app, "role2", &Principal::User(f.upn.clone()))
        .await
        .unwrap();
    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].roles, ["role2"]);
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role2"]);
}

/// What the migration does for a database from before assignments had their own
/// rows: everyone who held a role is assigned.
#[tokio::test]
async fn the_migration_assigns_everyone_who_held_a_role() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = app_with_roles(&s, &f).await;
    groups::create(&s.pool, &f.tenant, "group1", None).await.unwrap();
    for (principal, role) in [
        (Principal::User(f.upn.clone()), "role1"),
        (Principal::User(f.upn.clone()), "role2"),
        (Principal::Group("group1".into()), "role3"),
        (Principal::App(f.api.app_id.clone()), "Daemon.Run"),
    ] {
        apps::assign_role(&s.pool, &f.tenant, &app, role, &principal)
            .await
            .unwrap();
    }
    // As it was before: role rows, and no assignment rows at all.
    sqlx::query("DELETE FROM app_assignments")
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(sign_in(&s, &f).await.unwrap_err().contains(NOT_ASSIGNED));

    let sql = include_str!("../migrations/sqlite/0013_app_assignments.sql");
    let backfill = &sql[sql.find("INSERT INTO app_assignments").expect("the backfill statement")..];
    sqlx::raw_sql(backfill).execute(&s.pool).await.unwrap();

    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    let got: Vec<(&str, &[String])> = listed
        .iter()
        .map(|a| (a.principal_name.as_str(), a.roles.as_slice()))
        .collect();
    assert_eq!(
        got,
        [
            (f.upn.as_str(), owned(&["role1", "role2"]).as_slice()),
            ("group1", owned(&["role3"]).as_slice())
        ],
        "one assignment per person, and none for the client application"
    );
    assert_eq!(roles_of(&sign_in(&s, &f).await.unwrap()), ["role1", "role2"]);
}

/// Through the console: tick boxes on the assignment, not one role at a time.
#[tokio::test]
async fn the_console_assigns_with_roles_ticked_and_changes_them_in_place() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind_in_own_tenant(&s, &f, rust_oidc::rbac::RoleId::ApplicationAdministrator).await;
    let app = app_with_roles(&s, &f).await;
    groups::create(&s.pool, &f.tenant, "group1", None).await.unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));

    // The form offers the roles users may hold as tick boxes, and not the
    // application-only one.
    let page = b.get(&url).await;
    assert!(page.body.contains("Assign a user or group"), "{}", page.body);
    for role in ["role1", "role2", "role3"] {
        assert!(
            page.body
                .contains(&format!(r#"<input type="checkbox" name="role" value="{role}">"#)),
            "{role}: {}",
            page.body
        );
    }
    assert!(
        !page.body.contains(r#"type="checkbox" name="role" value="Daemon.Run""#),
        "{}",
        page.body
    );

    // A user with no role, and a group with three.
    let user = b
        .post(
            &url,
            &[("op", "assign"), ("principal_type", "User"), ("principal", &f.upn)],
        )
        .await;
    assert_eq!(user.status, 303, "{}", user.body);
    let group = b
        .post(
            &url,
            &[
                ("op", "assign"),
                ("principal_type", "Group"),
                ("principal", "group1"),
                ("role", "role1"),
                ("role", "role2"),
                ("role", "role3"),
            ],
        )
        .await;
    assert_eq!(group.status, 303, "{}", group.body);
    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].roles.is_empty());
    assert_eq!(listed[1].roles, ["role1", "role2", "role3"]);

    let page = b.get(&url).await;
    assert!(
        page.body.contains(r#"<span class="muted">no role</span>"#),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"<span class="pill">role3</span>"#),
        "{}",
        page.body
    );
    // The row's own form has what is held already ticked.
    assert!(
        page.body
            .contains(r#"<input type="checkbox" name="role" value="role2" checked>"#),
        "{}",
        page.body
    );

    // Saving with a different set ticked replaces it.
    let changed = b
        .post(
            &url,
            &[
                ("op", "assign"),
                ("principal_type", "Group"),
                ("principal", "group1"),
                ("role", "role2"),
            ],
        )
        .await;
    assert_eq!(changed.status, 303, "{}", changed.body);
    let listed = apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(listed.len(), 2, "changed, not added again");
    assert_eq!(listed[1].roles, ["role2"]);

    // Refusals are shown, and an application is not assigned this way.
    for (form, why) in [
        (
            vec![
                ("op", "assign"),
                ("principal_type", "User"),
                ("principal", "nobody@contoso.com"),
            ],
            "not found",
        ),
        (
            vec![
                ("op", "assign"),
                ("principal_type", "ServicePrincipal"),
                ("principal", f.api.app_id.as_str()),
            ],
            "choose a user or a group",
        ),
        (
            vec![
                ("op", "role_assign"),
                ("principal_type", "User"),
                ("principal", f.upn.as_str()),
                ("role", "role1"),
            ],
            "application only",
        ),
    ] {
        let page = b.post(&url, &form).await;
        assert_eq!(page.status, 400, "{why}: {}", page.body);
        assert!(page.body.contains(why), "{why}: {}", page.body);
    }

    let removed = b.post(&url, &[("op", "unassign"), ("assignment", &listed[1].id)]).await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert_eq!(apps::assignments(&s.pool, &f.tenant.id, &app).await.unwrap().len(), 1);

    // A viewer sees who is assigned and is offered none of it.
    let s2 = TestServer::start().await;
    let v = user_fixture(&s2).await;
    bind_in_own_tenant(&s2, &v, rust_oidc::rbac::RoleId::ApplicationViewer).await;
    let vb = signed_in_admin(&s2, &v).await;
    let vurl = s2.url(&format!("/admin/tenants/{}/apps/{}", v.tenant.id, v.web.app_id));
    let page = vb.get(&vurl).await;
    assert!(page.body.contains("Users and groups"), "{}", page.body);
    assert!(!page.body.contains("Assign a user or group"), "{}", page.body);
    let refused = vb
        .post(
            &vurl,
            &[("op", "assign"), ("principal_type", "User"), ("principal", &v.upn)],
        )
        .await;
    assert_eq!(refused.status, 403);
}
