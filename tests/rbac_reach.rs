//! Reach beyond one's own tenant belongs to the root tenant.
//!
//! The rule is not on any page. It is in the one function every role grant is
//! written through and the one function permissions are read from, so these
//! tests go at those two directly, and then at the console to see it shows.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, ReachRefused};
use rust_oidc::directory::PrincipalType;
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::{groups, tenant};

async fn grant(s: &TestServer, kind: PrincipalType, id: &str, scope: Scope) -> anyhow::Result<String> {
    bindings::create(&s.pool, kind, id, RoleId::GlobalAdministrator, &scope, "test").await
}

#[tokio::test]
async fn a_principal_outside_the_root_tenant_cannot_be_granted_reach_beyond_its_own() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await; // Contoso, not the root tenant
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let group = groups::create(&s.pool, &f.tenant, "Admins", None).await.unwrap();
    let before = bindings::list_all(&s.pool).await.unwrap().len();

    for (kind, id) in [
        (PrincipalType::User, f.user_id.as_str()),
        (PrincipalType::Group, group.as_str()),
    ] {
        for scope in [
            Scope::All,
            Scope::Tenants(vec![other.id.clone()]),
            // Its own tenant plus one more is still beyond its own.
            Scope::Tenants(vec![f.tenant.id.clone(), other.id.clone()]),
        ] {
            let err = grant(&s, kind, id, scope.clone()).await.expect_err("must be refused");
            assert!(
                err.downcast_ref::<ReachRefused>().is_some(),
                "{kind:?} {scope:?} refused for the wrong reason: {err}"
            );
        }
        // Its own tenant is fine.
        grant(&s, kind, id, Scope::Tenants(vec![f.tenant.id.clone()]))
            .await
            .unwrap();
    }
    // Nothing of the refused grants was left behind: the check is inside the
    // transaction that writes the row.
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), before + 2);
}

#[tokio::test]
async fn a_principal_of_the_root_tenant_can_be_granted_any_reach() {
    let s = TestServer::start().await;
    let f = root_user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    grant(&s, PrincipalType::User, &f.user_id, Scope::All).await.unwrap();
    grant(
        &s,
        PrincipalType::User,
        &f.user_id,
        Scope::Tenants(vec![other.id.clone()]),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_grant_to_nobody_is_refused() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let err = grant(
        &s,
        PrincipalType::User,
        "11111111-2222-3333-4444-555555555555",
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await
    .expect_err("there is no such user");
    assert!(err.to_string().contains("no such user or group"), "{err}");
}

/// A row that reached the table some other way -- an older build, a restore, an
/// edit by hand -- still grants nothing beyond the principal's own tenant.
#[tokio::test]
async fn a_row_written_around_the_rule_grants_nothing_beyond_its_tenant() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await; // not the root tenant
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    // Straight into the table, as `create` would never do.
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind("by-hand")
    .bind(PrincipalType::User.as_str())
    .bind(&f.user_id)
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind("all")
    .bind(0_i64)
    .bind("by-hand")
    .execute(&s.pool)
    .await
    .unwrap();

    let effective = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(effective.len(), 1);
    assert_eq!(
        effective[0].scope,
        Scope::Tenants(vec![f.tenant.id.clone()]),
        "an every-tenant row held outside the root tenant is cut back to its own tenant"
    );
    assert!(rust_oidc::rbac::allowed(
        &effective,
        rust_oidc::admin::USER_READ,
        &f.tenant.id
    ));
    assert!(!rust_oidc::rbac::allowed(
        &effective,
        rust_oidc::admin::USER_READ,
        &other.id
    ));
    assert!(!rust_oidc::rbac::allowed_at_all_scope(
        &effective,
        rust_oidc::admin::TENANT_READ
    ));

    // And in the console: that account is an administrator of its own tenant only.
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(
        b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id)))
            .await
            .status,
        200
    );
    assert_eq!(
        b.get(&s.url(&format!("/admin/tenants/{}/users", other.id)))
            .await
            .status,
        403
    );
    assert_eq!(b.get(&s.url("/admin/bindings")).await.status, 403);
}

/// The console says so, and names the principal's tenant, without holding the
/// rule itself: the message is the one the write function returns.
#[tokio::test]
async fn the_console_reports_the_refusal_and_shows_whose_principal_it_is() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await; // an administrator in the root tenant
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    let outsider = rust_oidc::users::create(
        &s.pool,
        &fabrikam,
        rust_oidc::users::NewUser {
            upn: "zed@fabrikam.test",
            password: "Another-Passw0rd!",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    let b = signed_in_admin(&s, &f).await;

    // From the platform page...
    let page = b
        .post(
            &s.url("/admin/bindings"),
            &[
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", "GlobalReader"),
                ("scope", "all"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(
        page.body.contains("Only accounts and groups in the root tenant"),
        "{}",
        page.body
    );
    // ...and from the tenant's own Roles page, asking for every tenant.
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/roles", fabrikam.id)),
            &[
                ("op", "grant"),
                ("principal", "zed@fabrikam.test"),
                ("principal_type", "User"),
                ("role", "GlobalReader"),
                ("scope", "all"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(
        page.body.contains("Only accounts and groups in the root tenant"),
        "{}",
        page.body
    );
    assert!(
        bindings::list_all(&s.pool)
            .await
            .unwrap()
            .iter()
            .all(|x| x.principal_id != outsider)
    );

    // In its own tenant it can be granted, and the platform page then says whose
    // account it is.
    let page = b
        .post(
            &s.url(&format!("/admin/tenants/{}/roles", fabrikam.id)),
            &[
                ("op", "grant"),
                ("principal", "zed@fabrikam.test"),
                ("principal_type", "User"),
                ("role", "GlobalReader"),
                ("scope", "tenants"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let page = b.get(&s.url("/admin/bindings")).await;
    assert!(page.body.contains("<th>Their tenant</th>"), "{}", page.body);
    assert!(
        page.body.contains("<td>zed@fabrikam.test</td><td>Fabrikam</td>"),
        "the row names the principal's tenant: {}",
        page.body
    );
    // The fixture tenant is the root one and is marked as such.
    let _ = tenant::root(&s.pool).await.unwrap().expect("a root tenant");
    assert!(page.body.contains(r#"<span class="pill">root</span>"#), "{}", page.body);
}
