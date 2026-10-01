//! The console's groups section, through HTTP.
//!
//! Group membership is not only the `groups` claim: a console role binding may
//! name a **group** as its principal, so adding somebody to a group can hand them
//! administrative rights. That makes the tenant boundary here worth the same
//! attention as the users section's — a group's object id from another tenant must
//! resolve to nothing, even when it is correct.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::groups;
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::users::{self, NewUser};

async fn member_upns(s: &TestServer, group_id: &str) -> Vec<String> {
    groups::members(&s.pool, group_id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.upn)
        .collect()
}

async fn group_id(s: &TestServer, tenant_id: &str, name: &str) -> String {
    groups::find(&s.pool, tenant_id, name)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("group '{name}' not found"))
}

#[tokio::test]
async fn a_group_is_created_and_its_membership_edited() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/groups", f.tenant.id));

    let created = b
        .post(&url, &[("name", "Engineering"), ("description", "Builds things")])
        .await;
    assert_eq!(created.status, 303, "{}", created.body);
    let id = group_id(&s, &f.tenant.id, "Engineering").await;
    let listed = groups::list(&s.pool, &f.tenant.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Engineering");
    assert_eq!(listed[0].description.as_deref(), Some("Builds things"));

    let detail = format!("{url}/{id}");
    let added = b.post(&detail, &[("op", "member_add"), ("upn", &f.upn)]).await;
    assert_eq!(added.status, 303, "{}", added.body);
    assert_eq!(member_upns(&s, &id).await, vec![f.upn.clone()]);
    // The claim follows from the membership, which is the point of the section.
    assert_eq!(
        groups::names_for_user(&s.pool, &f.user_id).await.unwrap(),
        vec!["Engineering".to_string()]
    );

    // Adding somebody who is already a member is not an error.
    let again = b.post(&detail, &[("op", "member_add"), ("upn", &f.upn)]).await;
    assert_eq!(again.status, 303, "{}", again.body);
    assert_eq!(member_upns(&s, &id).await.len(), 1);

    // A name no account in this tenant has is refused, and says so.
    let missing = b
        .post(&detail, &[("op", "member_add"), ("upn", "nobody@contoso.com")])
        .await;
    assert_eq!(missing.status, 400, "{}", missing.body);
    assert!(missing.body.contains("not found"), "{}", missing.body);

    let removed = b.post(&detail, &[("op", "member_remove"), ("user", &f.user_id)]).await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert!(member_upns(&s, &id).await.is_empty());
    assert!(groups::names_for_user(&s.pool, &f.user_id).await.unwrap().is_empty());

    // Removing somebody who is not a member says so rather than reporting success.
    let not_a_member = b.post(&detail, &[("op", "member_remove"), ("user", &f.user_id)]).await;
    assert_eq!(not_a_member.status, 400, "{}", not_a_member.body);

    for action in [
        "admin.group.create",
        "admin.group.member.add",
        "admin.group.member.remove",
    ] {
        let rows = audit_rows(&s, action).await;
        assert!(!rows.is_empty(), "{action} was not recorded");
        for row in &rows {
            assert_eq!(row.0, f.user_id, "{action} named the wrong actor");
            assert_eq!(row.2.as_deref(), Some(f.tenant.id.as_str()), "{action}");
        }
    }

    // The page shows the group and links to it from the list.
    let page = b.get(&url).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Engineering"), "{}", page.body);
    assert!(page.body.contains(&id), "{}", page.body);
}

#[tokio::test]
async fn a_duplicate_group_name_is_refused_whatever_its_case() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/groups", f.tenant.id));

    assert_eq!(b.post(&url, &[("name", "Engineering")]).await.status, 303);
    let clash = b.post(&url, &[("name", "ENGINEERING")]).await;
    assert_eq!(clash.status, 400, "{}", clash.body);
    assert_eq!(groups::list(&s.pool, &f.tenant.id).await.unwrap().len(), 1);

    let empty = b.post(&url, &[("name", "   ")]).await;
    assert_eq!(empty.status, 400, "{}", empty.body);
    assert_eq!(groups::list(&s.pool, &f.tenant.id).await.unwrap().len(), 1);
}

/// A role that may read groups but not write them.
#[tokio::test]
async fn a_reader_sees_groups_but_cannot_change_membership() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let group = groups::create(&s.pool, &f.tenant, "Engineering", Some("made outside the console"))
        .await
        .unwrap();
    groups::add_member(&s.pool, &f.tenant, "Engineering", &f.upn)
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/groups", f.tenant.id));

    let list = b.get(&url).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert!(list.body.contains("Engineering"));
    assert!(!list.body.contains("Create a group"), "{}", list.body);

    let detail = b.get(&format!("{url}/{group}")).await;
    assert_eq!(detail.status, 200, "{}", detail.body);
    assert!(detail.body.contains(&f.upn));
    assert!(!detail.body.contains("Add member"), "{}", detail.body);

    for form in [
        vec![("name", "Marketing")],
        vec![("op", "member_remove"), ("user", f.user_id.as_str())],
    ] {
        let target = if form[0].0 == "name" {
            url.clone()
        } else {
            format!("{url}/{group}")
        };
        let refused = b.post(&target, &form).await;
        assert_eq!(refused.status, 403, "{form:?} was allowed: {}", refused.body);
    }
    assert_eq!(member_upns(&s, &group).await, vec![f.upn.clone()]);
    assert_eq!(groups::list(&s.pool, &f.tenant.id).await.unwrap().len(), 1);
}

/// The second line of defence, tested on its own because the authorization gate
/// in front of it means the isolation test above would pass without it. Every
/// group lookup takes the tenant id, so a correct object id from another tenant
/// resolves to nothing.
#[tokio::test]
async fn a_group_lookup_is_scoped_to_its_tenant_whatever_the_id() {
    let s = TestServer::start().await;
    let mine = s.tenant("Contoso", "contoso.com").await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let theirs = groups::create(&s.pool, &other, "Fabrikam Admins", None).await.unwrap();
    let ours = groups::create(&s.pool, &mine, "Engineering", None).await.unwrap();

    assert!(
        groups::find_by_id(&s.pool, &mine.id, &theirs).await.unwrap().is_none(),
        "another tenant's group was found by id"
    );
    assert!(groups::find_by_id(&s.pool, &other.id, &theirs).await.unwrap().is_some());
    assert!(groups::find_by_id(&s.pool, &mine.id, &ours).await.unwrap().is_some());

    // And so is the write path that uses it.
    users::create(
        &s.pool,
        &mine,
        NewUser {
            upn: "dave@contoso.com",
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    assert!(
        groups::add_member_by_id(&s.pool, &mine.id, &theirs, "dave@contoso.com")
            .await
            .is_err(),
        "a member was added to another tenant's group"
    );
    assert!(member_upns(&s, &theirs).await.is_empty());
    assert!(
        !groups::remove_member(&s.pool, &mine.id, &theirs, "whoever")
            .await
            .unwrap(),
        "a removal reached another tenant's group"
    );
}

/// The isolation test for this section. The extra turn of the screw: the other
/// tenant's group is the principal of a console role binding, so reaching it would
/// be an escalation and not merely a read.
#[tokio::test]
async fn a_tenant_admin_cannot_reach_another_tenants_groups() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let privileged = groups::create(&s.pool, &other, "Fabrikam Admins", None).await.unwrap();
    // That group administers the other tenant.
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &privileged,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![other.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    // And somebody there to be displaced.
    let their_user = users::create(
        &s.pool,
        &other,
        NewUser {
            upn: "carol@fabrikam.test",
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    groups::add_member(&s.pool, &other, "Fabrikam Admins", "carol@fabrikam.test")
        .await
        .unwrap();
    let b = signed_in_admin(&s, &f).await;

    let list = format!("/admin/tenants/{}/groups", other.id);
    let detail = format!("{list}/{privileged}");
    let aliased = format!("/admin/tenants/fabrikam.test/groups/{privileged}");
    for path in [list.clone(), detail.clone(), aliased.clone()] {
        let page = b.get(&s.url(&path)).await;
        assert!(
            page.status == 403 || page.status == 404,
            "GET {path} leaked with {}: {}",
            page.status,
            page.body
        );
        assert!(
            !page.body.contains("Fabrikam Admins") && !page.body.contains("carol@fabrikam.test"),
            "GET {path} leaked the group: {}",
            page.body
        );
    }

    let posts: Vec<(String, Vec<(&str, &str)>)> = vec![
        (list.clone(), vec![("name", "Mole")]),
        // The escalation: join the group that administers the other tenant.
        (detail.clone(), vec![("op", "member_add"), ("upn", &f.upn)]),
        (aliased.clone(), vec![("op", "member_add"), ("upn", &f.upn)]),
        // Or empty it, which would remove its administrators.
        (detail.clone(), vec![("op", "member_remove"), ("user", &their_user)]),
    ];
    for (path, form) in posts {
        let page = b.post(&s.url(&path), &form).await;
        assert!(
            page.status == 403 || page.status == 404,
            "POST {path} {form:?} leaked with {}: {}",
            page.status,
            page.body
        );
    }

    // The other tenant's groups are exactly as they were, and the attacker gained
    // no binding through membership.
    assert_eq!(groups::list(&s.pool, &other.id).await.unwrap().len(), 1);
    assert_eq!(
        member_upns(&s, &privileged).await,
        vec!["carol@fabrikam.test".to_string()],
        "the privileged group's membership changed"
    );
    let effective = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(
        effective.iter().all(|binding| !binding.scope.covers(&other.id)),
        "the tenant admin gained reach into the other tenant: {effective:?}"
    );

    // Their own tenant's groups still work.
    let own = b.get(&s.url(&format!("/admin/tenants/{}/groups", f.tenant.id))).await;
    assert_eq!(own.status, 200, "{}", own.body);
}
