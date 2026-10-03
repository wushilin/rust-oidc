//! There is no "assume tenant": opening a tenant from the list is how an
//! administrator works in it, and that changes nothing about who they are.
mod common;
use common::*;

#[tokio::test]
async fn there_is_no_assume_and_no_leave() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let list = b.get(&s.url("/admin/tenants")).await;
    assert!(!list.body.contains("/admin/assume/"), "{}", list.body);
    assert!(!list.body.contains(">Assume<"), "{}", list.body);
    for path in [format!("/admin/assume/{}", target.id), "/admin/leave".to_string()] {
        let page = b.post(&s.url(&path), &[]).await;
        assert!(matches!(page.status, 404 | 405), "{path}: {}", page.status);
    }

    // Opening a tenant is the way in; the header names it and offers the way back.
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", target.id))).await;
    assert_eq!(page.status, 200);
    assert!(
        page.body
            .contains(r#"<span class="tenant">Tenant <strong>Fabrikam</strong></span>"#),
        "{}",
        page.body
    );
    assert!(page.body.contains("All tenants"), "{}", page.body);
    assert!(!page.body.contains("/admin/leave"), "{}", page.body);
    // And the global pages have no tenant in view.
    let page = b.get(&s.url("/admin/tenants")).await;
    assert!(page.body.contains("No tenant selected"), "{}", page.body);
}
