//! Groups inside groups, run through the transaction engine without HTTP.
//!
//! Membership flows upward: a member of a group is a member of every group that
//! contains it, never of the groups inside it. `group_closure` is what reads use;
//! after every change it must equal what the nesting itself says.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::apps::{self, Principal};
use rust_oidc::db::Event;
use rust_oidc::groups::{self, MAX_GROUP_NESTING_DEPTH};
use rust_oidc::txn::ops::groups::{AddGroupToGroup, DeleteGroup, GroupKey, RemoveGroupFromGroup};
use rust_oidc::txn::{self, Actor, BatchOutcome, Outcome, Refusal, Txn};

struct World {
    s: TestServer,
    f: UserFixture,
    actor: Actor,
}

async fn world() -> World {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = Actor::Admin {
        user_id: f.user_id.clone(),
        bindings: bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap(),
    };
    World { s, f, actor }
}

impl World {
    async fn group(&self, name: &str) -> String {
        groups::create(&self.s.pool, &self.f.tenant, name, None).await.unwrap()
    }

    fn nest(&self, outer: &str, inner: &str) -> AddGroupToGroup {
        AddGroupToGroup {
            tenant_id: self.f.tenant.id.clone(),
            group_id: outer.to_string(),
            member: GroupKey::Id(inner.to_string()),
        }
    }

    async fn add(&self, outer: &str, inner: &str) -> Outcome<()> {
        txn::run(&self.s.pool, &self.actor, &self.nest(outer, inner))
            .await
            .map_done()
    }

    async fn remove(&self, outer: &str, inner: &str) -> Outcome<()> {
        let t = RemoveGroupFromGroup {
            tenant_id: self.f.tenant.id.clone(),
            group_id: outer.to_string(),
            member_group_id: inner.to_string(),
        };
        txn::run(&self.s.pool, &self.actor, &t).await
    }

    /// The user's effective groups, by name.
    async fn effective(&self) -> Vec<String> {
        groups::effective_for_user(&self.s.pool, &self.f.user_id)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect()
    }

    /// The stored closure equals one computed afresh from the nesting.
    async fn closure_is_consistent(&self) {
        let tid = &self.f.tenant.id;
        assert_eq!(
            groups::stored_closure(&self.s.pool, tid).await.unwrap(),
            groups::closure_from_nesting(&self.s.pool, tid).await.unwrap(),
            "the stored closure has drifted from the nesting"
        );
    }

    async fn audit_count(&self, event: Event) -> i64 {
        let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
            &self.s.pool,
            "SELECT COUNT(*) FROM audit_log WHERE action = ?",
        ))
        .bind(event.as_str())
        .fetch_one(&self.s.pool)
        .await
        .unwrap();
        n
    }
}

fn refusal(o: &Outcome<()>) -> String {
    match o {
        Outcome::Refused(r) => r.to_string(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// group1 contains group2, group2 contains group3; a member of group2 is in
/// group1 too, but not in group3.
#[tokio::test]
async fn membership_flows_up_to_containing_groups_and_not_down() {
    let w = world().await;
    let (g1, g2, g3) = (
        w.group("group1").await,
        w.group("group2").await,
        w.group("group3").await,
    );
    assert!(w.add(&g1, &g2).await.is_done());
    assert!(w.add(&g2, &g3).await.is_done());
    groups::add_member(&w.s.pool, &w.f.tenant, "group2", &w.f.upn)
        .await
        .unwrap();

    assert_eq!(w.effective().await, ["group1", "group2"]);
    // Direct membership is untouched by nesting.
    let direct: Vec<String> = groups::for_user(&w.s.pool, &w.f.user_id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.name)
        .collect();
    assert_eq!(direct, ["group2"]);

    // The user page's account of why: direct, or through which group.
    let why = groups::memberships_for_user(&w.s.pool, &w.f.user_id).await.unwrap();
    let g1_row = why.iter().find(|m| m.group.id == g1).unwrap();
    assert_eq!(g1_row.via.as_ref().map(|v| v.id.as_str()), Some(g2.as_str()));
    assert!(why.iter().find(|m| m.group.id == g2).unwrap().via.is_none());

    assert_eq!(w.audit_count(Event::AdminGroupNestAdd).await, 2);
    w.closure_is_consistent().await;
}

#[tokio::test]
async fn without_nesting_effective_groups_are_the_direct_ones() {
    let w = world().await;
    w.group("a").await;
    w.group("b").await;
    groups::add_member(&w.s.pool, &w.f.tenant, "b", &w.f.upn).await.unwrap();
    let direct = groups::for_user(&w.s.pool, &w.f.user_id).await.unwrap();
    let effective = groups::effective_for_user(&w.s.pool, &w.f.user_id).await.unwrap();
    assert_eq!(direct, effective);
}

#[tokio::test]
async fn a_group_cannot_be_put_inside_itself() {
    let w = world().await;
    let g = w.group("solo").await;
    let o = w.add(&g, &g).await;
    assert!(refusal(&o).contains("itself"), "{o:?}");
    assert_eq!(w.audit_count(Event::AdminGroupNestAdd).await, 0);
}

/// The guard on the write: a group already inside another cannot contain it.
#[tokio::test]
async fn a_loop_is_refused_and_nothing_changes() {
    let w = world().await;
    let (a, b, c) = (w.group("A").await, w.group("B").await, w.group("C").await);
    assert!(w.add(&a, &b).await.is_done());
    assert!(w.add(&b, &c).await.is_done());
    let before = groups::stored_closure(&w.s.pool, &w.f.tenant.id).await.unwrap();

    for (outer, inner) in [(&b, &a), (&c, &a)] {
        let o = w.add(outer, inner).await;
        // Said by the check before the write, not by the rebuild's backstop.
        assert!(refusal(&o).contains("would make a loop"), "{o:?}");
    }
    assert_eq!(groups::stored_closure(&w.s.pool, &w.f.tenant.id).await.unwrap(), before);
    assert_eq!(w.audit_count(Event::AdminGroupNestAdd).await, 2);
}

/// Two nestings that are each fine alone but make a loop together, in one batch:
/// the second sees the first, and the batch commits nothing.
#[tokio::test]
async fn a_batch_that_would_close_a_loop_commits_nothing() {
    let w = world().await;
    let (a, b, c, d) = (
        w.group("A").await,
        w.group("B").await,
        w.group("C").await,
        w.group("D").await,
    );
    assert!(w.add(&b, &c).await.is_done());
    assert!(w.add(&d, &a).await.is_done());
    let before = groups::stored_closure(&w.s.pool, &w.f.tenant.id).await.unwrap();
    let batch = [Txn::from(w.nest(&a, &b)), Txn::from(w.nest(&c, &d))];
    match txn::run_batch(&w.s.pool, &w.actor, &batch).await {
        BatchOutcome::Aborted { index, outcome } => {
            assert_eq!(index, 1);
            assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
        }
        BatchOutcome::Done(_) => panic!("a loop was committed"),
    }
    assert_eq!(groups::stored_closure(&w.s.pool, &w.f.tenant.id).await.unwrap(), before);
}

#[tokio::test]
async fn chains_are_limited_in_depth() {
    let w = world().await;
    let mut chain = Vec::new();
    for i in 0..=MAX_GROUP_NESTING_DEPTH + 1 {
        chain.push(w.group(&format!("level{i:02}")).await);
    }
    // MAX links is allowed...
    for pair in chain[..=MAX_GROUP_NESTING_DEPTH as usize].windows(2) {
        assert!(w.add(&pair[0], &pair[1]).await.is_done());
    }
    // ...one more is not, from below...
    let last = chain.len() - 1;
    let o = w.add(&chain[last - 1], &chain[last]).await;
    assert!(refusal(&o).contains("the limit is"), "{o:?}");
    // ...nor by joining two chains in the middle.
    let top = w.group("top").await;
    let o = w.add(&top, &chain[0]).await;
    assert!(refusal(&o).contains("the limit is"), "{o:?}");
    w.closure_is_consistent().await;
}

/// A group reachable two ways stays inside the top when one way is removed.
#[tokio::test]
async fn removing_one_path_of_a_diamond_keeps_the_other() {
    let w = world().await;
    let (a, b, c, d) = (
        w.group("A").await,
        w.group("B").await,
        w.group("C").await,
        w.group("D").await,
    );
    for (outer, inner) in [(&a, &b), (&a, &c), (&b, &d), (&c, &d)] {
        assert!(w.add(outer, inner).await.is_done());
        w.closure_is_consistent().await;
    }
    groups::add_member(&w.s.pool, &w.f.tenant, "D", &w.f.upn).await.unwrap();
    assert_eq!(w.effective().await, ["A", "B", "C", "D"]);

    assert!(w.remove(&b, &d).await.is_done());
    w.closure_is_consistent().await;
    assert_eq!(w.effective().await, ["A", "C", "D"], "still in A, through C");

    assert!(w.remove(&c, &d).await.is_done());
    w.closure_is_consistent().await;
    assert_eq!(w.effective().await, ["D"]);
    assert_eq!(w.audit_count(Event::AdminGroupNestRemove).await, 2);

    let o = w.remove(&c, &d).await;
    assert!(matches!(o, Outcome::Refused(Refusal::NotFound(_))), "{o:?}");
}

#[tokio::test]
async fn a_group_with_groups_inside_cannot_be_deleted_but_one_inside_another_can() {
    let w = world().await;
    let (outer, inner) = (w.group("outer").await, w.group("inner").await);
    assert!(w.add(&outer, &inner).await.is_done());

    let delete = |group_id: &str| DeleteGroup {
        tenant_id: w.f.tenant.id.clone(),
        group_id: group_id.to_string(),
    };
    let o = txn::run(&w.s.pool, &w.actor, &delete(&outer)).await.map_done();
    assert!(refusal(&o).contains("member"), "{o:?}");

    assert!(txn::run(&w.s.pool, &w.actor, &delete(&inner)).await.is_done());
    assert!(groups::member_groups(&w.s.pool, &outer).await.unwrap().is_empty());
    w.closure_is_consistent().await;
    assert!(txn::run(&w.s.pool, &w.actor, &delete(&outer)).await.is_done());
    assert!(
        groups::stored_closure(&w.s.pool, &w.f.tenant.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_group_of_another_tenant_cannot_be_nested() {
    let w = world().await;
    let mine = w.group("mine").await;
    let other = w.s.tenant("Fabrikam", "fabrikam.com").await;
    let theirs = groups::create(&w.s.pool, &other, "theirs", None).await.unwrap();
    let o = w.add(&mine, &theirs).await;
    assert!(matches!(o, Outcome::Refused(Refusal::NotFound(_))), "{o:?}");
    assert!(groups::member_groups(&w.s.pool, &mine).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_command_line_names_the_inner_group() {
    let w = world().await;
    let outer = w.group("outer").await;
    w.group("inner").await;
    let t = AddGroupToGroup {
        tenant_id: w.f.tenant.id.clone(),
        group_id: outer.clone(),
        member: GroupKey::Name("INNER".into()),
    };
    let added = txn::run(&w.s.pool, &Actor::Cli, &t).await.into_result().unwrap();
    assert_eq!(added.name, "inner");
    // Already there is a conflict, not a silent success.
    let again = txn::run(&w.s.pool, &Actor::Cli, &t).await.map_done();
    assert!(matches!(again, Outcome::Refused(Refusal::Conflict(_))), "{again:?}");
}

/// Nesting counts for the claim only. Assignment to an application, and the
/// roles it carries, count direct members, as in Entra.
#[tokio::test]
async fn nesting_does_not_assign_or_grant_roles() {
    let w = world().await;
    let (outer, inner) = (w.group("outer").await, w.group("inner").await);
    assert!(w.add(&outer, &inner).await.is_done());
    groups::add_member(&w.s.pool, &w.f.tenant, "inner", &w.f.upn)
        .await
        .unwrap();

    let api = apps::find(&w.s.pool, &w.f.api.app_id).await.unwrap().unwrap();
    let sp = apps::service_principal(&w.s.pool, &w.f.tenant.id, &api.app_id)
        .await
        .unwrap()
        .unwrap();
    let held_before = apps::app_roles_for_user(&w.s.pool, &sp.id, &w.f.user_id).await.unwrap();
    apps::add_role(
        &w.s.pool,
        &api,
        "Outer.Thing",
        "Outer thing",
        None,
        &[apps::MemberType::User],
    )
    .await
    .unwrap();
    apps::assign(
        &w.s.pool,
        &w.f.tenant,
        &api,
        &Principal::Group("outer".into()),
        &["Outer.Thing".to_string()],
    )
    .await
    .unwrap();

    assert!(
        groups::effective_for_user(&w.s.pool, &w.f.user_id)
            .await
            .unwrap()
            .iter()
            .any(|g| g.id == outer)
    );
    // Assigned to the API before (the fixture's own role) is beside the point: the
    // outer group's role is not theirs.
    let held = apps::app_roles_for_user(&w.s.pool, &sp.id, &w.f.user_id).await.unwrap();
    assert_eq!(held, held_before);
}

#[test]
fn a_loop_in_stored_nesting_is_never_walked_forever() {
    use std::collections::HashMap;
    let parents: HashMap<String, Vec<String>> = [("a", "b"), ("b", "a")]
        .into_iter()
        .map(|(c, p)| (c.to_string(), vec![p.to_string()]))
        .collect();
    assert!(groups::ancestors_of(&parents, "a").is_err());
}

/// The console: a group's page lists member groups with their type, linking to
/// their own page, and the inner group's page says what it is a member of.
#[tokio::test]
async fn the_console_nests_and_lists_groups() {
    let w = world().await;
    let (outer, inner) = (w.group("Engineering").await, w.group("Backend").await);
    groups::add_member(&w.s.pool, &w.f.tenant, "Backend", &w.f.upn)
        .await
        .unwrap();
    let b = signed_in_admin(&w.s, &w.f).await;
    let base = w.s.url(&format!("/admin/tenants/{}/groups", w.f.tenant.id));

    let page = b.get(&format!("{base}/{outer}")).await;
    assert!(
        page.body
            .contains(&format!(r#"<option value="{inner}">Backend</option>"#)),
        "{}",
        page.body
    );
    let added = b
        .post(
            &format!("{base}/{outer}"),
            &[("op", "member_group_add"), ("member_group", &inner)],
        )
        .await;
    assert_eq!(added.status, 303, "{}", added.body);

    let page = b.get(&format!("{base}/{outer}")).await;
    assert!(
        page.body.contains(&format!("/{inner}\">Backend</a>")),
        "a link to its page: {}",
        page.body
    );
    assert!(page.body.contains("<svg"), "a type icon");
    assert!(
        page.body.contains("1 user"),
        "the member group's own count: {}",
        page.body
    );
    // Filtering to users leaves the group out.
    let users_only = b.get(&format!("{base}/{outer}?show=users")).await;
    assert!(
        !users_only.body.contains(&format!("/{inner}\">Backend</a>")),
        "{}",
        users_only.body
    );

    let inner_page = b.get(&format!("{base}/{inner}")).await;
    assert!(inner_page.body.contains("Member of"), "{}", inner_page.body);
    assert!(inner_page.body.contains(&format!("/{outer}\">")), "{}", inner_page.body);
    // Engineering is not offered inside Backend: that would be a loop.
    assert!(
        !inner_page.body.contains(&format!(r#"<option value="{outer}">"#)),
        "{}",
        inner_page.body
    );

    // The user's page shows the inherited group and why.
    let user_page = b
        .get(&w.s.url(&format!("/admin/tenants/{}/users/{}", w.f.tenant.id, w.f.user_id)))
        .await;
    assert!(user_page.body.contains("Through nested groups"), "{}", user_page.body);
    assert!(user_page.body.contains(">Backend</a>"), "{}", user_page.body);

    let removed = b
        .post(
            &format!("{base}/{outer}"),
            &[("op", "member_group_remove"), ("member_group", &inner)],
        )
        .await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert!(groups::member_groups(&w.s.pool, &outer).await.unwrap().is_empty());
}
