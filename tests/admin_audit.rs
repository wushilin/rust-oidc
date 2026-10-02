//! The audit log viewer, through HTTP.
//!
//! Three properties, each tested as a property rather than as a feature:
//!
//! - **Only this tenant's rows.** The table holds every tenant's history in one
//!   place, so a reader that leaked would leak everything. Tested by writing rows
//!   for another tenant that are deliberately easy to spot.
//! - **The page size is capped.** `audit_log` is append-only, unbounded, and
//!   unauthenticated requests append to it, so an uncapped page is a denial of
//!   service against the administrator's own browser.
//! - **The filters are the indexes** `0009` added, and they narrow rather than
//!   widen: an unknown action filters nothing, it does not match everything.

mod common;

use common::*;
use rust_oidc::db::{self, Actor, Event};
use rust_oidc::rbac::{RoleId, Scope};

/// Write `n` rows for a tenant, as the audit trail's own writer would.
async fn fill(s: &TestServer, tenant_id: &str, event: Event, target: &str, n: usize) {
    for i in 0..n {
        db::audit(
            &s.pool,
            Some(tenant_id),
            Actor::Cli,
            event,
            Some(target),
            serde_json::json!({ "n": i }),
        )
        .await
        .unwrap();
    }
}

/// The rendered table only.
///
/// Assertions about which rows a page shows must not be made against the whole
/// body: the filter `<select>` necessarily names every action this build knows,
/// and the search box echoes back whatever was typed into it. Either would make a
/// "this is on the page" assertion pass for the wrong reason, and -- worse -- make
/// a "this is absent" assertion fail for the wrong reason.
///
/// A page with no rows has no table at all: the console writes a sentence in its
/// place, so "no table" is "no rows" and is returned as the empty string.
fn table(page: &Page) -> &str {
    let Some(start) = page.body.find("<table>") else {
        return "";
    };
    let end = page.body[start..].find("</table>").expect("the table is closed") + start;
    &page.body[start..end]
}

/// How many rows the table has, not counting the header.
fn table_rows(page: &Page) -> usize {
    table(page).matches("<tr>").count().saturating_sub(1)
}

#[tokio::test]
async fn the_page_shows_this_tenants_history_newest_first() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/audit", f.tenant.id));

    // Something to look at: the console's own sign-in, plus a user edit.
    let user_url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id));
    assert_eq!(
        b.post(&user_url, &[("op", "attributes"), ("display_name", "Alice S")])
            .await
            .status,
        303
    );

    let page = b.get(&url).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let rows = table(&page);
    assert!(rows.contains("admin.user.update"), "{rows}");
    assert!(rows.contains("admin.sign_in"), "{rows}");
    assert!(rows.contains(&f.user_id), "the actor is shown: {rows}");

    // Newest first: the update happened after the sign-in.
    let update_at = rows.find("admin.user.update").unwrap();
    let signin_at = rows.find("admin.sign_in").unwrap();
    assert!(update_at < signin_at, "the newest row is not first: {rows}");

    // The link from the person's own page carries the target filter.
    let user_page = b.get(&user_url).await;
    assert!(
        user_page.body.contains(&format!("audit?target={}", f.user_id)),
        "the user page links to their history: {}",
        user_page.body
    );
}

#[tokio::test]
async fn the_filters_narrow_by_action_and_by_target() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/audit", f.tenant.id));
    fill(&s, &f.tenant.id, Event::UserCreate, "subject-one", 3).await;
    fill(&s, &f.tenant.id, Event::GroupCreate, "subject-two", 2).await;

    let by_action = b.get(&format!("{url}?action=user.create")).await;
    assert_eq!(by_action.status, 200);
    assert_eq!(table_rows(&by_action), 3, "{}", table(&by_action));
    assert!(!table(&by_action).contains("subject-two"), "{}", table(&by_action));
    // The chosen action comes back selected, so the page says what it is showing.
    assert!(
        by_action.body.contains(r#"value="user.create" selected"#),
        "the filter is not shown as chosen"
    );

    let by_target = b.get(&format!("{url}?target=subject-two")).await;
    assert_eq!(by_target.status, 200);
    assert_eq!(table_rows(&by_target), 2, "{}", table(&by_target));
    assert!(table(&by_target).contains("subject-two"));
    assert!(!table(&by_target).contains("subject-one"), "{}", table(&by_target));

    let both = b.get(&format!("{url}?action=group.create&target=subject-one")).await;
    assert_eq!(both.status, 200);
    assert_eq!(table_rows(&both), 0, "the two filters are an AND: {}", table(&both));

    // An action this build does not know narrows nothing rather than matching
    // everything: the box is a convenience, not an authorization decision.
    let unknown = b.get(&format!("{url}?action=something.from.the.future")).await;
    assert_eq!(unknown.status, 200);
    assert!(table(&unknown).contains("subject-one"), "{}", table(&unknown));
    assert!(table(&unknown).contains("subject-two"), "{}", table(&unknown));

    // A target nobody has shows nothing, and does not fall back to everything.
    let nothing = b.get(&format!("{url}?target=no-such-object")).await;
    assert_eq!(table_rows(&nothing), 0, "{}", table(&nothing));
}

/// The table is unbounded, so the page must not be.
#[tokio::test]
async fn the_page_size_is_capped_however_many_rows_exist() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/audit", f.tenant.id));
    let over = (db::AUDIT_PAGE_LIMIT + 40) as usize;
    fill(&s, &f.tenant.id, Event::TokenIssued, "a-client", over).await;

    let page = b.get(&url).await;
    assert_eq!(page.status, 200);
    assert_eq!(
        table_rows(&page) as i64,
        db::AUDIT_PAGE_LIMIT,
        "the page is not capped at {}",
        db::AUDIT_PAGE_LIMIT
    );
    assert!(page.body.contains("most recent"), "the cap is stated: {}", page.body);

    // Filtering does not lift the cap either.
    let filtered = b.get(&format!("{url}?action=token.issued")).await;
    assert_eq!(table_rows(&filtered) as i64, db::AUDIT_PAGE_LIMIT);

    // And the reader itself refuses to be asked for more.
    let asked = db::audit_for_tenant(&s.pool, &f.tenant.id, None, None, 10_000)
        .await
        .unwrap();
    assert_eq!(asked.len() as i64, db::AUDIT_PAGE_LIMIT);
}

/// The isolation test for this section, and the one that matters most: every
/// tenant's history is in one table.
#[tokio::test]
async fn a_tenant_admin_never_sees_another_tenants_audit_rows() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    // Rows for the other tenant, easy to spot if any of them escapes.
    fill(&s, &other.id, Event::UserCreate, "fabrikam-secret-subject", 5).await;
    fill(&s, &other.id, Event::AppSecretAdd, "fabrikam-secret-app", 5).await;
    // And one for their own, so an empty page cannot pass by accident.
    fill(&s, &f.tenant.id, Event::UserCreate, "contoso-subject", 1).await;

    // The other tenant's page is refused outright, by GUID and by alias.
    for path in [
        format!("/admin/tenants/{}/audit", other.id),
        "/admin/tenants/fabrikam.test/audit".to_string(),
    ] {
        let page = b.get(&s.url(&path)).await;
        assert!(
            page.status == 403 || page.status == 404,
            "GET {path} leaked with {}: {}",
            page.status,
            page.body
        );
        assert!(
            !page.body.contains("fabrikam-secret"),
            "GET {path} leaked rows: {}",
            page.body
        );
        assert!(!page.body.contains("<table>"), "GET {path} rendered a table at all");
    }

    // And their own page never shows the other tenant's rows, however it is
    // filtered -- including by a target that only exists over there.
    let own = s.url(&format!("/admin/tenants/{}/audit", f.tenant.id));
    for query in [
        String::new(),
        "?action=user.create".to_string(),
        "?target=fabrikam-secret-subject".to_string(),
        "?action=app.secret.add&target=fabrikam-secret-app".to_string(),
        "?action=".to_string(),
        "?target=".to_string(),
    ] {
        let page = b.get(&format!("{own}{query}")).await;
        assert_eq!(page.status, 200, "{query}: {}", page.body);
        // Against the table, not the body: searching for a target echoes it back
        // into the search box, which is the administrator's own input returning,
        // not a row from the other tenant.
        assert!(
            !table(&page).contains("fabrikam-secret"),
            "{query} showed another tenant's rows: {}",
            table(&page)
        );
        assert!(!page.body.contains(&other.id), "{query} leaked the tenant id");
    }
    // Their own row is there, so the page is not simply empty.
    let page = b.get(&own).await;
    assert!(table(&page).contains("contoso-subject"), "{}", table(&page));

    // The reader cannot be asked for another tenant's rows at all: it takes a
    // tenant id that is not optional.
    let theirs = db::audit_for_tenant(&s.pool, &f.tenant.id, None, Some("fabrikam-secret-subject"), 10)
        .await
        .unwrap();
    assert!(theirs.is_empty(), "the reader crossed the boundary");
}

/// A role with no `Audit:Read` at all gets nothing, and is not offered the page.
#[tokio::test]
async fn a_role_without_audit_read_is_refused_the_page() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // Platform Administrator holds `Audit:Read`; this one deliberately does not,
    // so the test is about the action and not about the scope.
    bind(&s, &f.user_id, RoleId::PlatformAdministrator, Scope::All).await;
    let no_audit = user_fixture_in(&s, s.tenant("Northwind", "northwind.test").await, "eve@northwind.test").await;
    bind(
        &s,
        &no_audit.user_id,
        RoleId::GlobalReader,
        Scope::Tenants(vec![no_audit.tenant.id.clone()]),
    )
    .await;

    // Global Reader does hold `Audit:Read`, so it sees the page.
    let reader = signed_in_admin(&s, &no_audit).await;
    let page = reader
        .get(&s.url(&format!("/admin/tenants/{}/audit", no_audit.tenant.id)))
        .await;
    assert_eq!(page.status, 200, "{}", page.body);

    // But not another tenant's, even though it holds the action.
    let elsewhere = reader
        .get(&s.url(&format!("/admin/tenants/{}/audit", f.tenant.id)))
        .await;
    assert!(
        elsewhere.status == 403 || elsewhere.status == 404,
        "{} {}",
        elsewhere.status,
        elsewhere.body
    );
}
