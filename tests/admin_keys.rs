//! The signing keys page, through HTTP.
//!
//! The keys are shared by every tenant, so this is the sharpest platform/tenant
//! line in the console: a tenant administrator — even a Global Administrator of
//! their own tenant — must not be able to rotate the key every other tenant's
//! tokens are signed with, and must not even see the page.
//!
//! Rotation is also the one console action whose correctness is observable from
//! outside: after it, the key that signs is the one that was published as `next`,
//! and the key that was signing is still published so tokens already issued
//! verify. That is asserted against the live JWKS rather than against the table.

mod common;

use common::*;
use rust_oidc::keys::{self, KeyStatus};

async fn kids_by_status(s: &TestServer, status: KeyStatus) -> Vec<String> {
    keys::list(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.status == status)
        .map(|k| k.kid)
        .collect()
}

#[tokio::test]
async fn the_page_lists_every_published_key_with_its_place_in_the_lifecycle() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.get(&s.url("/admin/keys")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for key in keys::list(&s.pool).await.unwrap() {
        assert!(page.body.contains(&key.kid), "{} is not listed", key.kid);
    }
    // `keys::ensure` runs at startup, so there is an active key and a next one.
    assert!(page.body.contains("active"), "{}", page.body);
    assert!(page.body.contains("next"), "{}", page.body);
    // The page says what the buttons do before offering them.
    assert!(page.body.contains("affects every tenant"), "{}", page.body);
    assert!(page.body.contains("Rotate the signing key"), "{}", page.body);
}

#[tokio::test]
async fn rotating_promotes_the_published_next_key_and_keeps_the_old_one_verifiable() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;

    let was_active = kids_by_status(&s, KeyStatus::Active).await;
    let was_next = kids_by_status(&s, KeyStatus::Next).await;
    assert_eq!(was_active.len(), 1);
    assert_eq!(was_next.len(), 1);

    let rotated = b.post(&s.url("/admin/keys"), &[("op", "rotate")]).await;
    assert_eq!(rotated.status, 303, "{}", rotated.body);

    let now_active = kids_by_status(&s, KeyStatus::Active).await;
    assert_eq!(
        now_active, was_next,
        "the pre-published next key is the one now signing"
    );
    assert!(
        kids_by_status(&s, KeyStatus::Retired).await.contains(&was_active[0]),
        "the key that was signing is retired, not deleted"
    );
    assert_eq!(
        kids_by_status(&s, KeyStatus::Next).await.len(),
        1,
        "a fresh next key was published"
    );

    // The retired key is still published, which is what keeps tokens it signed
    // verifiable. Asked of the server itself, not of the table.
    let (status, jwks) = s.get_json(&format!("/{}/discovery/v2.0/keys", f.tenant.id)).await;
    assert_eq!(status, 200);
    let published: Vec<String> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_string())
        .collect();
    assert!(published.contains(&was_active[0]), "the retired key is still in JWKS");
    assert!(published.contains(&now_active[0]), "the new active key is in JWKS");

    let rows = audit_rows(&s, "admin.key.rotate").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.user_id, "the rotation is attributable to the person");
}

#[tokio::test]
async fn pruning_deletes_only_keys_retired_longer_ago_than_asked() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/keys");

    let was_active = kids_by_status(&s, KeyStatus::Active).await;
    assert_eq!(b.post(&url, &[("op", "rotate")]).await.status, 303);
    let retired = kids_by_status(&s, KeyStatus::Retired).await;
    assert_eq!(retired, was_active);

    // A key retired moments ago is far younger than the age asked for, so nothing
    // goes: that is the property that stops a prune deleting a live token's key.
    let pruned = b.post(&url, &[("op", "prune"), ("days", "2")]).await;
    assert_eq!(pruned.status, 303, "{}", pruned.body);
    assert_eq!(
        kids_by_status(&s, KeyStatus::Retired).await,
        retired,
        "a key retired seconds ago was deleted"
    );

    // Zero or negative would mean "delete what was retired in the future", which
    // is refused rather than treated as "delete everything".
    for days in ["0", "-1", "not a number", ""] {
        let page = b.post(&url, &[("op", "prune"), ("days", days)]).await;
        assert_eq!(page.status, 400, "days={days:?} was accepted: {}", page.body);
        assert_eq!(kids_by_status(&s, KeyStatus::Retired).await, retired);
    }

    // Backdate the retirement, and the same request now collects it.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "UPDATE signing_keys SET retired_at = ? WHERE status = ?",
    ))
    .bind(0_i64)
    .bind(KeyStatus::Retired.as_str())
    .execute(&s.pool)
    .await
    .unwrap();
    let pruned = b.post(&url, &[("op", "prune"), ("days", "2")]).await;
    assert_eq!(pruned.status, 303, "{}", pruned.body);
    assert!(
        kids_by_status(&s, KeyStatus::Retired).await.is_empty(),
        "the long-retired key was collected"
    );
    let rows = audit_rows(&s, "admin.key.prune").await;
    assert_eq!(
        rows.len(),
        2,
        "both prunes are recorded, including the one that collected nothing"
    );
    assert!(rows.iter().all(|r| r.0 == f.user_id));
}

/// The isolation test for this section: the keys belong to the platform, so a
/// tenant administrator gets nothing here, not even the list.
#[tokio::test]
async fn a_tenant_admin_can_neither_see_nor_rotate_the_signing_keys() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url("/admin/keys");

    let before = keys::list(&s.pool).await.unwrap();
    let active_before: Vec<String> = before
        .iter()
        .filter(|k| k.status == KeyStatus::Active)
        .map(|k| k.kid.clone())
        .collect();

    let page = b.get(&url).await;
    assert_eq!(page.status, 403, "{}", page.body);
    for key in &before {
        assert!(!page.body.contains(&key.kid), "a key id leaked: {}", page.body);
    }
    for form in [vec![("op", "rotate")], vec![("op", "prune"), ("days", "1")]] {
        let refused = b.post(&url, &form).await;
        assert_eq!(refused.status, 403, "{form:?} was allowed: {}", refused.body);
    }
    // Nothing rotated and nothing was deleted.
    assert_eq!(
        kids_by_status(&s, KeyStatus::Active).await,
        active_before,
        "the signing key changed"
    );
    assert_eq!(keys::list(&s.pool).await.unwrap().len(), before.len());
    assert!(audit_rows(&s, "admin.key.rotate").await.is_empty());
    assert!(audit_rows(&s, "admin.key.prune").await.is_empty());

    // And the console never offers it to them.
    let tenants = b.get(&s.url("/admin/tenants")).await;
    assert_eq!(tenants.status, 200);
    assert!(!tenants.body.contains("Signing keys"), "{}", tenants.body);
}
