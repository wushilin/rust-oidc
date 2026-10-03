//! Doing one thing to many users, groups or members at once: tick boxes on the
//! lists, one in the heading for all, and each row still under its own rules.

mod common;

use common::*;
use rust_oidc::db::Event;
use rust_oidc::rbac::RoleId;
use rust_oidc::{groups, users};

/// alice (the administrator) plus bob, carol and dave in the same tenant.
async fn staffed(s: &TestServer) -> (UserFixture, Vec<String>) {
    let f = admin_fixture(s).await;
    let mut ids = Vec::new();
    for upn in ["bob@contoso.com", "carol@contoso.com", "dave@contoso.com"] {
        ids.push(user_fixture_in(s, f.tenant.clone(), upn).await.user_id);
    }
    (f, ids)
}

async fn state(s: &TestServer, user_id: &str) -> &'static str {
    let (enabled, deleted): (i64, Option<i64>) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT enabled, deleted_at FROM users WHERE id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    match (enabled != 0, deleted.is_none()) {
        (_, false) => "deleted",
        (true, true) => "enabled",
        (false, true) => "disabled",
    }
}

async fn member_names(s: &TestServer, group: &str) -> Vec<String> {
    groups::members(&s.pool, group)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.upn)
        .collect()
}

#[tokio::test]
async fn ticked_users_are_disabled_enabled_and_deleted_together() {
    let s = TestServer::start().await;
    let (f, ids) = staffed(&s).await;
    let (bob, carol, dave) = (&ids[0], &ids[1], &ids[2]);
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users", f.tenant.id));

    // A box per row, one for all, and the buttons.
    let page = b.get(&url).await;
    assert!(
        page.body.contains(&format!(r#"name="item" value="{bob}""#)),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"class="all" name="all""#), "{}", page.body);
    for op in ["enable", "disable", "delete", "add_to_group"] {
        // "add to group" appears once there is a group to add to.
        let offered = page.body.contains(&format!(r#"name="op" value="{op}""#));
        assert_eq!(offered, op != "add_to_group", "{op}: {}", page.body);
    }

    // Two ticked rows.
    let done = b.post(&url, &[("op", "disable"), ("item", bob), ("item", carol)]).await;
    assert_eq!(done.status, 303, "{}", done.body);
    assert_eq!(
        [state(&s, bob).await, state(&s, carol).await, state(&s, dave).await],
        ["disabled", "disabled", "enabled"]
    );
    assert_eq!(
        audit_rows(&s, Event::AdminUserDisable.as_str()).await.len(),
        2,
        "one entry each"
    );

    // Nothing ticked, and a delete without its confirm box: nothing happens.
    for (form, why) in [
        (vec![("op", "enable")], "Tick the rows"),
        // An id the page did not list selects nothing.
        (
            vec![("op", "disable"), ("item", "11111111-2222-3333-4444-555555555555")],
            "Tick the rows",
        ),
    ] {
        let page = b.post(&url, &form).await;
        assert_eq!(page.status, 400, "{form:?}: {}", page.body);
        assert!(page.body.contains(why), "{form:?}: {}", page.body);
    }
    assert_eq!(state(&s, bob).await, "disabled");

    // The heading box: everyone listed. The administrator's own account is among
    // them and is refused under the same rule as on its own page; the rest are done.
    let all = b.post(&url, &[("op", "disable"), ("all", "on")]).await;
    assert_eq!(all.status, 400, "{}", all.body);
    assert!(all.body.contains("3 disabled"), "{}", all.body);
    assert!(
        all.body
            .contains("alice@contoso.com (This is the account you are signed in with"),
        "{}",
        all.body
    );
    assert_eq!(state(&s, dave).await, "disabled");
    assert_eq!(state(&s, &f.user_id).await, "enabled");

    let all = b.post(&url, &[("op", "enable"), ("all", "on")]).await;
    assert_eq!(all.status, 303, "{}", all.body);
    assert_eq!(state(&s, bob).await, "enabled");

    // "All" is all the page listed: with a search, only the matches.
    let some = b
        .post(
            &url,
            &[("op", "delete"), ("all", "on"), ("confirm", "on"), ("q", "carol")],
        )
        .await;
    assert_eq!(some.status, 303, "{}", some.body);
    assert!(some.location.unwrap().ends_with("?q=carol"), "back to the same search");
    assert_eq!(
        [state(&s, bob).await, state(&s, carol).await, state(&s, dave).await],
        ["enabled", "deleted", "enabled"]
    );
}

#[tokio::test]
async fn ticked_users_are_added_to_a_group_and_members_are_removed_together() {
    let s = TestServer::start().await;
    let (f, ids) = staffed(&s).await;
    let group = groups::create(&s.pool, &f.tenant, "Staff", None).await.unwrap();
    let b = signed_in_admin(&s, &f).await;
    let users_url = s.url(&format!("/admin/tenants/{}/users", f.tenant.id));
    let group_url = s.url(&format!("/admin/tenants/{}/groups/{}", f.tenant.id, group));

    // From the users list: everyone, into the picked group.
    let page = b.get(&users_url).await;
    assert!(
        page.body
            .contains(&format!(r#"<option value="{group}">Staff</option>"#)),
        "{}",
        page.body
    );
    let added = b
        .post(&users_url, &[("op", "add_to_group"), ("all", "on"), ("group", &group)])
        .await;
    assert_eq!(added.status, 303, "{}", added.body);
    assert_eq!(member_names(&s, &group).await.len(), 4);
    assert_eq!(audit_rows(&s, Event::AdminGroupMemberAdd.as_str()).await.len(), 4);

    // On the group's page: a box per member, and one button.
    let page = b.get(&group_url).await;
    assert!(
        page.body.contains(&format!(r#"name="item" value="{}""#, ids[0])),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(r#"name="op" value="member_remove""#),
        "{}",
        page.body
    );
    let removed = b
        .post(
            &group_url,
            &[("op", "member_remove"), ("item", &ids[0]), ("item", &ids[1])],
        )
        .await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert_eq!(
        member_names(&s, &group).await,
        ["alice@contoso.com", "dave@contoso.com"]
    );
    let nothing = b.post(&group_url, &[("op", "member_remove")]).await;
    assert_eq!(nothing.status, 400);
    assert!(nothing.body.contains("Tick the rows"), "{}", nothing.body);

    // Everyone at once, without clicking through them.
    let emptied = b.post(&group_url, &[("op", "member_remove"), ("all", "on")]).await;
    assert_eq!(emptied.status, 303, "{}", emptied.body);
    assert!(member_names(&s, &group).await.is_empty());

    // Several names typed at once, in any of the usual separators. The ones that
    // exist are added; the one that does not is reported.
    let typed = b
        .post(
            &group_url,
            &[
                ("op", "member_add"),
                (
                    "upns",
                    "bob@contoso.com, carol@contoso.com\nghost@contoso.com;dave@contoso.com",
                ),
            ],
        )
        .await;
    assert_eq!(typed.status, 400, "{}", typed.body);
    assert!(typed.body.contains("3 added"), "{}", typed.body);
    assert!(typed.body.contains("ghost@contoso.com ("), "{}", typed.body);
    assert_eq!(
        member_names(&s, &group).await,
        ["bob@contoso.com", "carol@contoso.com", "dave@contoso.com"]
    );
    let clean = b
        .post(&group_url, &[("op", "member_add"), ("upns", "alice@contoso.com")])
        .await;
    assert_eq!(clean.status, 303, "{}", clean.body);
}

#[tokio::test]
async fn ticked_groups_are_deleted_together_except_those_with_members() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let empty1 = groups::create(&s.pool, &f.tenant, "Empty one", None).await.unwrap();
    let empty2 = groups::create(&s.pool, &f.tenant, "Empty two", None).await.unwrap();
    let busy = groups::create(&s.pool, &f.tenant, "Busy", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "Busy", &f.upn).await.unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/groups", f.tenant.id));

    let page = b.get(&url).await;
    assert!(
        page.body.contains(&format!(r#"name="item" value="{busy}""#)),
        "{}",
        page.body
    );
    // Deleting asks first, in a dialog that counts what is ticked: there is no
    // tick box to confirm with.
    assert!(page.body.contains("Delete the ticked groups?"), "{}", page.body);
    assert!(page.body.contains(r#"class="ticked""#), "{}", page.body);
    assert!(!page.body.contains(r#"name="confirm""#), "{}", page.body);

    let done = b
        .post(&url, &[("op", "delete"), ("all", "on"), ("confirm", "on")])
        .await;
    assert_eq!(done.status, 400, "{}", done.body);
    assert!(done.body.contains("2 deleted"), "{}", done.body);
    assert!(done.body.contains("Busy ("), "{}", done.body);
    let left: Vec<String> = groups::list(&s.pool, &f.tenant.id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(left, [busy]);
    assert!(!left.contains(&empty1) && !left.contains(&empty2));
    assert_eq!(audit_rows(&s, Event::AdminGroupDelete.as_str()).await.len(), 2);

    // Creating a group from the same page still works, with and without the field.
    assert_eq!(b.post(&url, &[("op", "create"), ("name", "New")]).await.status, 303);
    assert_eq!(b.post(&url, &[("name", "Newer")]).await.status, 303);
}

/// A user's groups are tick boxes on their own page, saved in one go.
#[tokio::test]
async fn a_users_groups_are_set_together_on_their_page() {
    let s = TestServer::start().await;
    let (f, ids) = staffed(&s).await;
    let bob = &ids[0];
    let mut g = Vec::new();
    for name in ["Alpha", "Beta", "Gamma"] {
        g.push(groups::create(&s.pool, &f.tenant, name, None).await.unwrap());
    }
    groups::add_member(&s.pool, &f.tenant, "Alpha", "bob@contoso.com")
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, bob));

    let page = b.get(&url).await;
    assert!(
        page.body.contains(&format!(r#"name="group" value="{}" checked"#, g[0])),
        "the one they are in is ticked: {}",
        page.body
    );
    assert!(
        page.body.contains(&format!(r#"name="group" value="{}">"#, g[1])),
        "{}",
        page.body
    );

    // Out of Alpha, into Beta and Gamma.
    let saved = b
        .post(&url, &[("op", "groups"), ("group", &g[1]), ("group", &g[2])])
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    assert_eq!(groups::names_for_user(&s.pool, bob).await.unwrap(), ["Beta", "Gamma"]);
    assert_eq!(audit_rows(&s, Event::AdminGroupMemberAdd.as_str()).await.len(), 2);
    assert_eq!(audit_rows(&s, Event::AdminGroupMemberRemove.as_str()).await.len(), 1);
    // None ticked: out of all of them.
    assert_eq!(b.post(&url, &[("op", "groups")]).await.status, 303);
    assert!(groups::names_for_user(&s.pool, bob).await.unwrap().is_empty());

    // Membership is the group's to change: a User Administrator alone sees the
    // groups and cannot set them, and is offered no tick boxes on the list for it.
    let s2 = TestServer::start().await;
    let u = user_fixture(&s2).await;
    bind_in_own_tenant(&s2, &u, RoleId::UserAdministrator).await;
    groups::create(&s2.pool, &u.tenant, "Alpha", None).await.unwrap();
    let ub = signed_in_admin(&s2, &u).await;
    let own = s2.url(&format!("/admin/tenants/{}/users/{}", u.tenant.id, u.user_id));
    assert!(!ub.get(&own).await.body.contains(r#"value="groups""#));
    assert_eq!(ub.post(&own, &[("op", "groups")]).await.status, 403);
    let list = s2.url(&format!("/admin/tenants/{}/users", u.tenant.id));
    assert!(!ub.get(&list).await.body.contains(r#"value="add_to_group""#));
    assert_eq!(
        ub.post(&list, &[("op", "add_to_group"), ("all", "on")]).await.status,
        403
    );

    // And a viewer is offered nothing to tick at all.
    let s3 = TestServer::start().await;
    let v = reader_fixture(&s3).await;
    let vb = signed_in_admin(&s3, &v).await;
    for page in ["users", "groups"] {
        let body = vb
            .get(&s3.url(&format!("/admin/tenants/{}/{page}", v.tenant.id)))
            .await
            .body;
        assert!(!body.contains(r#"type="checkbox""#), "{page}: {body}");
    }
    assert_eq!(
        vb.post(
            &s3.url(&format!("/admin/tenants/{}/users", v.tenant.id)),
            &[("op", "disable"), ("all", "on")]
        )
        .await
        .status,
        403
    );
    let _ = users::LIST_LIMIT;
}

/// The lock-out rule holds through the bulk routes too: the last Global
/// Administrator, who holds the role through a group, cannot be swept out of it.
#[tokio::test]
async fn bulk_changes_cannot_remove_the_last_global_administrator() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let ops = groups::create(&s.pool, &f.tenant, "Operators", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "Operators", &f.upn)
        .await
        .unwrap();
    rust_oidc::admin::bindings::create(
        &s.pool,
        rust_oidc::directory::PrincipalType::Group,
        &ops,
        RoleId::GlobalAdministrator,
        &rust_oidc::rbac::Scope::All,
        "test",
    )
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let emptied = b
        .post(
            &s.url(&format!("/admin/tenants/{}/groups/{}", f.tenant.id, ops)),
            &[("op", "member_remove"), ("all", "on")],
        )
        .await;
    assert_eq!(emptied.status, 400, "{}", emptied.body);
    assert!(emptied.body.contains("Global Administrator"), "{}", emptied.body);
    let unticked = b
        .post(
            &s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
            &[("op", "groups")],
        )
        .await;
    assert_eq!(unticked.status, 400, "{}", unticked.body);
    assert_eq!(member_names(&s, &ops).await, std::slice::from_ref(&f.upn));
}
