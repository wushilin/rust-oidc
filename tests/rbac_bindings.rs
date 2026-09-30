//! Role-binding storage, and its expansion into the grants a request is checked
//! against.
//!
//! The module under test arrived early, with the `wids` work that needed it
//! (ruling R6 in the console ledger), so these are the tests that task never got.
//! They pin the properties the design depends on rather than the happy path only:
//! an orphaned scope row grants nothing, a tenant alias does not match a scope,
//! and a role this build does not know is skipped instead of failing the request.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{Action, Resource, RoleId, Scope, Verb, allowed};

const WRITE_USER: Action = Action::new(Resource::User, Verb::Write);
const WRITE_GROUP: Action = Action::new(Resource::Group, Verb::Write);

#[tokio::test]
async fn a_user_binding_is_effective_for_that_user() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(allowed(&eff, WRITE_USER, &f.tenant.id));
    // ...and only for the role it names.
    assert!(!allowed(&eff, WRITE_GROUP, &f.tenant.id));
}

#[tokio::test]
async fn a_group_binding_reaches_its_members() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let group_id = rust_oidc::groups::create(&s.pool, &f.tenant, "admins", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&s.pool, &f.tenant, "admins", &f.upn)
        .await
        .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &group_id,
        RoleId::GroupsAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(allowed(&eff, WRITE_GROUP, &f.tenant.id));
}

#[tokio::test]
async fn all_scope_round_trips_without_tenant_rows() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].scope, Scope::All);
    assert!(allowed(
        &eff,
        Action::new(Resource::Tenant, Verb::Create),
        "a-tenant-that-does-not-exist"
    ));
}

/// Review Focus 2: an orphaned `role_binding_tenants` row must grant nothing, not
/// everything. `scope_of` joins `tenants`, so a deleted tenant yields an empty
/// tenant list -- and an empty `Scope::Tenants` covers nothing.
#[tokio::test]
async fn a_binding_for_a_deleted_tenant_grants_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let doomed = s.tenant("Doomed", "doomed.test").await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![doomed.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    // Sanity: it grants while the tenant exists, so the assertion below is about
    // the deletion and not about the binding never having worked.
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(allowed(&eff, WRITE_USER, &doomed.id));

    sqlx::query(rust_oidc::db::q(&s.pool, "DELETE FROM tenants WHERE id = ?"))
        .bind(&doomed.id)
        .execute(&s.pool)
        .await
        .unwrap();

    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(
        !allowed(&eff, WRITE_USER, &doomed.id),
        "an orphaned scope row must not grant anything"
    );
    assert!(
        !allowed(&eff, WRITE_USER, &f.tenant.id),
        "and it certainly must not widen to another tenant"
    );
}

/// Review Focus 1: `{tenant}` in a URL may be a GUID or a verified domain, but a
/// scope holds ids. A check that compared the raw URL segment could be bypassed
/// by using the alias form, so the alias must not match.
#[tokio::test]
async fn scope_is_compared_against_the_canonical_tenant_id() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(
        !allowed(&eff, WRITE_USER, "contoso.com"),
        "the alias form must not match a scope; callers resolve first"
    );
    let resolved = rust_oidc::tenant::resolve(&s.pool, "contoso.com")
        .await
        .unwrap()
        .unwrap();
    assert!(allowed(&eff, WRITE_USER, &resolved.id));
}

/// A row written by a newer build must not fail an older build's request.
#[tokio::test]
async fn an_unknown_role_in_the_database_is_ignored_not_fatal() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind("b1")
    .bind(PrincipalType::User.as_str())
    .bind(&f.user_id)
    .bind("RoleFromTheFuture")
    .bind(rust_oidc::rbac::ScopeKind::All.as_str())
    .bind(0_i64)
    .bind("test")
    .execute(&s.pool)
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id)
        .await
        .expect("an unparseable role must not be an error");
    assert!(eff.is_empty(), "an unparseable role is skipped, not honoured");
}

/// The same tolerance for an unknown scope kind.
#[tokio::test]
async fn an_unknown_scope_kind_in_the_database_is_ignored_not_fatal() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind("b2")
    .bind(PrincipalType::User.as_str())
    .bind(&f.user_id)
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind("scopeFromTheFuture")
    .bind(0_i64)
    .bind("test")
    .execute(&s.pool)
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id)
        .await
        .expect("an unparseable scope kind must not be an error");
    assert!(eff.is_empty(), "an unparseable scope kind grants nothing");
}

#[tokio::test]
async fn deleting_a_binding_takes_effect_on_the_next_read() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let id = bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    assert_eq!(
        bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap().len(),
        1
    );

    assert!(bindings::delete(&s.pool, &id).await.unwrap());
    assert!(
        bindings::effective_for_user(&s.pool, &f.user_id)
            .await
            .unwrap()
            .is_empty(),
        "grants are recomputed per read, never cached"
    );
    assert!(
        !bindings::delete(&s.pool, &id).await.unwrap(),
        "deleting twice reports that nothing was removed"
    );
}

#[tokio::test]
async fn listings_see_all_scope_bindings_from_every_tenant() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();

    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 2);
    // A tenant's listing shows its own bindings plus every `all`-scope one, since
    // those reach it too.
    let mine = bindings::list_for_tenant(&s.pool, &f.tenant.id).await.unwrap();
    assert_eq!(mine.len(), 2, "own binding plus the all-scope one");
    let theirs = bindings::list_for_tenant(&s.pool, &other.id).await.unwrap();
    assert_eq!(theirs.len(), 1, "only the all-scope one reaches Fabrikam");
    assert_eq!(theirs[0].role, RoleId::PlatformAdministrator);
}
