//! The last person who can act as Global Administrator cannot be removed, by any
//! route; nobody deletes or disables the account they are signed in with; and an
//! empty group can be deleted.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::admin::lockout::WouldLockOut;
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::{groups, users};

fn locks_out(err: &anyhow::Error) -> bool {
    err.downcast_ref::<WouldLockOut>().is_some()
}

async fn live(s: &TestServer, user_id: &str) -> (bool, bool) {
    let (enabled, deleted): (rust_oidc::db::Flag, Option<i64>) = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT enabled, deleted_at FROM users WHERE id = ?",
    ))
    .bind(user_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    (bool::from(enabled), deleted.is_none())
}

/// Every storage route that could take away the last one, with the role held
/// directly.
#[tokio::test]
async fn the_last_global_administrator_cannot_be_deleted_disabled_or_revoked() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let binding = bindings::list_all(&s.pool).await.unwrap().remove(0).id;

    let err = users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap_err();
    assert!(locks_out(&err), "{err}");
    let err = users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false)
        .await
        .unwrap_err();
    assert!(locks_out(&err), "{err}");
    let err = bindings::delete(&s.pool, &binding).await.unwrap_err();
    assert!(locks_out(&err), "{err}");
    // Nothing of any of them happened: the check is inside each transaction.
    assert_eq!(live(&s, &f.user_id).await, (true, true));
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 1);
    signed_in_admin(&s, &f).await; // still signs in

    // With a second one, each is allowed again.
    let second = user_fixture_in(&s, f.tenant.clone(), "bea@contoso.com").await;
    bind(&s, &second.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    assert!(
        users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false)
            .await
            .unwrap()
    );
    // ...and now the second is the last, however many disabled or deleted ones
    // still hold the role on paper.
    let err = users::soft_delete(&s.pool, &f.tenant.id, &second.user_id)
        .await
        .unwrap_err();
    assert!(locks_out(&err), "a disabled administrator does not count: {err}");
}

/// The same rule when the role comes through a group: the shape of the lock-out
/// the binding count alone could never see.
#[tokio::test]
async fn the_last_global_administrator_through_a_group_is_protected_too() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let group = groups::create(&s.pool, &f.tenant, "Operators", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "Operators", &f.upn)
        .await
        .unwrap();
    let binding = bindings::create(
        &s.pool,
        PrincipalType::Group,
        &group,
        RoleId::GlobalAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();

    let err = groups::remove_member(&s.pool, &f.tenant.id, &group, &f.user_id)
        .await
        .unwrap_err();
    assert!(locks_out(&err), "{err}");
    let err = users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap_err();
    assert!(locks_out(&err), "{err}");
    let err = bindings::delete(&s.pool, &binding).await.unwrap_err();
    assert!(locks_out(&err), "{err}");
    assert_eq!(groups::members(&s.pool, &group).await.unwrap().len(), 1);

    // A second member makes the first removable.
    let second = user_fixture_in(&s, f.tenant.clone(), "bea@contoso.com").await;
    groups::add_member(&s.pool, &f.tenant, "Operators", &second.upn)
        .await
        .unwrap();
    assert!(
        groups::remove_member(&s.pool, &f.tenant.id, &group, &f.user_id)
            .await
            .unwrap()
    );
}

/// Before there is any Global Administrator, nothing is refused on their account.
#[tokio::test]
async fn a_deployment_with_no_global_administrator_is_not_frozen() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    assert!(
        users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false)
            .await
            .unwrap()
    );
    assert!(users::soft_delete(&s.pool, &f.tenant.id, &f.user_id).await.unwrap());
}

/// Through the console: the page says why, and one's own account is never
/// offered for deletion in the first place.
#[tokio::test]
async fn nobody_deletes_or_disables_the_account_they_are_signed_in_with() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    // Not the last one, so what refuses here is the rule about oneself.
    let second = user_fixture_in(&s, f.tenant.clone(), "bea@contoso.com").await;
    bind(&s, &second.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    let b = signed_in_admin(&s, &f).await;
    let own = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id));

    let page = b.get(&own).await;
    assert_eq!(page.status, 200);
    for offered in [r#"value="delete""#, r#"value="disable""#] {
        assert!(!page.body.contains(offered), "{offered}: {}", page.body);
    }
    for op in ["delete", "disable"] {
        let refused = b.post(&own, &[("op", op)]).await;
        assert_eq!(refused.status, 400, "{op}: {}", refused.body);
        assert!(
            refused.body.contains("the account you are signed in with"),
            "{}",
            refused.body
        );
    }
    assert_eq!(live(&s, &f.user_id).await, (true, true));
    assert_eq!(b.get(&own).await.status, 200, "still signed in");

    // Somebody else's account: offered, and it works.
    let theirs = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, second.user_id));
    assert!(b.get(&theirs).await.body.contains(r#"value="delete""#));
    assert_eq!(b.post(&theirs, &[("op", "delete")]).await.status, 303);
    assert_eq!(live(&s, &second.user_id).await, (false, false));

    // And revoking the last Global Administrator from the roles page says why.
    let binding = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.principal_id == f.user_id)
        .unwrap()
        .id;
    let page = b
        .post(&s.url("/admin/bindings"), &[("op", "revoke"), ("binding", &binding)])
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("last Global Administrator"), "{}", page.body);
}

/// A deleted account comes back as it was: same id, password, groups and roles.
#[tokio::test]
async fn a_deleted_account_can_be_restored_as_it_was() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let second = user_fixture_in(&s, f.tenant.clone(), "bea@contoso.com").await;
    bind(&s, &second.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    assert!(
        users::soft_delete(&s.pool, &f.tenant.id, &second.user_id)
            .await
            .unwrap()
    );
    assert!(
        bindings::effective_for_user(&s.pool, &second.user_id)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        !users::restore(&s.pool, &f.tenant.id, "nobody@contoso.com")
            .await
            .unwrap()
    );
    assert!(
        !users::restore(&s.pool, &f.tenant.id, &f.upn).await.unwrap(),
        "not deleted"
    );
    assert!(users::restore(&s.pool, &f.tenant.id, "BEA@contoso.com").await.unwrap());
    assert_eq!(live(&s, &second.user_id).await, (true, true));
    let b = signed_in_admin(&s, &second).await; // the same password
    assert_eq!(b.get(&s.url("/admin/bindings")).await.status, 200, "and the same role");
}

#[tokio::test]
async fn an_empty_group_can_be_deleted_and_one_with_members_cannot() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let group = groups::create(&s.pool, &f.tenant, "Helpdesk", None).await.unwrap();
    groups::add_member(&s.pool, &f.tenant, "Helpdesk", &f.upn)
        .await
        .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &group,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/groups/{}", f.tenant.id, group));

    // With a member: not offered, and refused if asked for anyway.
    let page = b.get(&url).await;
    assert!(!page.body.contains(r#"value="group_delete""#), "{}", page.body);
    assert!(page.body.contains("once it has no members"), "{}", page.body);
    let refused = b.post(&url, &[("op", "group_delete")]).await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.body.contains("remove them first"), "{}", refused.body);
    assert!(
        groups::find_by_id(&s.pool, &f.tenant.id, &group)
            .await
            .unwrap()
            .is_some()
    );

    // Emptied: offered, deleted, and the role granted to it goes with it.
    assert_eq!(
        b.post(&url, &[("op", "member_remove"), ("user", &f.user_id)])
            .await
            .status,
        303
    );
    assert!(b.get(&url).await.body.contains(r#"value="group_delete""#));
    let deleted = b.post(&url, &[("op", "group_delete")]).await;
    assert_eq!(deleted.status, 303, "{}", deleted.body);
    assert!(deleted.location.unwrap().ends_with("/groups"), "back to the list");
    assert!(
        groups::find_by_id(&s.pool, &f.tenant.id, &group)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        bindings::list_all(&s.pool)
            .await
            .unwrap()
            .iter()
            .all(|x| x.principal_id != group)
    );
    assert_eq!(b.get(&url).await.status, 404);
    assert_eq!(
        audit_rows(&s, rust_oidc::db::Event::AdminGroupDelete.as_str())
            .await
            .len(),
        1
    );

    // A tenant's group is not deletable from another tenant's URL.
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let theirs = groups::create(&s.pool, &other, "Theirs", None).await.unwrap();
    assert!(!groups::delete(&s.pool, &f.tenant.id, &theirs).await.unwrap());
    assert!(groups::find_by_id(&s.pool, &other.id, &theirs).await.unwrap().is_some());
}
