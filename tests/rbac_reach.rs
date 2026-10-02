//! Where a role applies is decided by the role and by whose it is, never chosen.
//!
//! Global Administrator is everything and is held from the root tenant. Every
//! other role applies to the tenant its holder belongs to. The rule is not on any
//! page: it is in the one function every grant is written through and the one
//! permissions are read from, so these tests go at those two directly, and then
//! at the console to see it shows.

mod common;

use common::*;
use rust_oidc::admin::bindings::{self, ScopeRefused};
use rust_oidc::directory::PrincipalType;
use rust_oidc::rbac::{RoleId, Scope};
use rust_oidc::{groups, users};

async fn grant(s: &TestServer, kind: PrincipalType, id: &str, role: RoleId, scope: Scope) -> anyhow::Result<String> {
    bindings::create(&s.pool, kind, id, role, &scope, "test").await
}

fn refusal(err: &anyhow::Error) -> Option<&ScopeRefused> {
    err.downcast_ref::<ScopeRefused>()
}

async fn user_in(s: &TestServer, tenant: &rust_oidc::tenant::Tenant, upn: &str) -> String {
    users::create(
        &s.pool,
        tenant,
        users::NewUser {
            upn,
            password: "Another-Passw0rd!",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_tenant_role_is_granted_in_the_holders_own_tenant_and_nowhere_else() {
    let s = TestServer::start().await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    // The rule is the same in the root tenant as outside it.
    for f in [
        root_user_fixture(&s).await,
        user_fixture_in(&s, other.clone(), "zed@fabrikam.test").await,
    ] {
        let elsewhere = s
            .tenant("Northwind", &format!("{}.northwind.test", &f.user_id[..8]))
            .await;
        let group = groups::create(&s.pool, &f.tenant, "Admins", None).await.unwrap();
        let before = bindings::list_all(&s.pool).await.unwrap().len();
        for (kind, id) in [
            (PrincipalType::User, f.user_id.as_str()),
            (PrincipalType::Group, group.as_str()),
        ] {
            for scope in [
                Scope::All,
                Scope::Tenants(vec![elsewhere.id.clone()]),
                // Its own tenant plus one more is still more than its own.
                Scope::Tenants(vec![f.tenant.id.clone(), elsewhere.id.clone()]),
                Scope::Tenants(vec![]),
            ] {
                let err = grant(&s, kind, id, RoleId::TenantAdministrator, scope.clone())
                    .await
                    .expect_err("must be refused");
                assert_eq!(
                    refusal(&err),
                    Some(&ScopeRefused::OwnTenantOnly(RoleId::TenantAdministrator.display_name())),
                    "{kind:?} {scope:?}: {err}"
                );
            }
            grant(
                &s,
                kind,
                id,
                RoleId::TenantAdministrator,
                Scope::Tenants(vec![f.tenant.id.clone()]),
            )
            .await
            .unwrap();
        }
        // Nothing of the refused grants was left behind: the check is inside the
        // transaction that writes the row.
        assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), before + 2);
    }
}

#[tokio::test]
async fn global_administrator_is_everything_and_is_held_from_the_root_tenant() {
    let s = TestServer::start().await;
    let root = root_user_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let outsider = user_in(&s, &other, "zed@fabrikam.test").await;

    grant(
        &s,
        PrincipalType::User,
        &root.user_id,
        RoleId::GlobalAdministrator,
        Scope::All,
    )
    .await
    .unwrap();
    // It takes no list of tenants, not even the holder's own.
    let err = grant(
        &s,
        PrincipalType::User,
        &root.user_id,
        RoleId::GlobalAdministrator,
        Scope::Tenants(vec![root.tenant.id.clone()]),
    )
    .await
    .expect_err("must be refused");
    assert_eq!(refusal(&err), Some(&ScopeRefused::GlobalNeedsEverything), "{err}");
    // And nobody outside the root tenant holds it, at any scope.
    for scope in [Scope::All, Scope::Tenants(vec![other.id.clone()])] {
        let err = grant(&s, PrincipalType::User, &outsider, RoleId::GlobalAdministrator, scope)
            .await
            .expect_err("must be refused");
        assert_eq!(refusal(&err), Some(&ScopeRefused::GlobalOutsideRoot), "{err}");
    }
}

#[tokio::test]
async fn a_grant_to_nobody_is_refused() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let err = grant(
        &s,
        PrincipalType::User,
        "11111111-2222-3333-4444-555555555555",
        RoleId::TenantViewer,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await
    .expect_err("there is no such user");
    assert!(err.to_string().contains("no such user or group"), "{err}");
}

/// Straight into the tables, as `create` would never do.
async fn by_hand(s: &TestServer, id: &str, user_id: &str, role: RoleId, scope: &Scope) {
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(id)
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(role.as_str())
    .bind(scope.kind().as_str())
    .bind(0_i64)
    .bind("by-hand")
    .execute(&s.pool)
    .await
    .unwrap();
    if let Scope::Tenants(ids) = scope {
        for t in ids {
            sqlx::query(rust_oidc::db::q(
                &s.pool,
                "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)",
            ))
            .bind(id)
            .bind(t)
            .execute(&s.pool)
            .await
            .unwrap();
        }
    }
}

/// A row that reached the table some other way -- an older build, a restore, an
/// edit by hand -- grants what the rule allows and nothing more.
#[tokio::test]
async fn a_row_written_around_the_rule_grants_nothing_more_than_the_rule_allows() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await; // not the root tenant
    let other = s.tenant("Fabrikam", "fabrikam.test").await;

    // Global Administrator held outside the root tenant: nothing at all.
    by_hand(&s, "h1", &f.user_id, RoleId::GlobalAdministrator, &Scope::All).await;
    // A tenant role in somebody else's tenant: nothing.
    by_hand(
        &s,
        "h3",
        &f.user_id,
        RoleId::GroupsAdministrator,
        &Scope::Tenants(vec![other.id.clone()]),
    )
    .await;
    assert!(
        bindings::effective_for_user(&s.pool, &f.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    let b = signed_in_admin(&s, &f).await;
    for t in [&f.tenant.id, &other.id] {
        assert_eq!(b.get(&s.url(&format!("/admin/tenants/{t}/users"))).await.status, 403);
    }
    assert_eq!(b.get(&s.url("/admin/bindings")).await.status, 403);

    // A tenant role in its own tenant and another: its own tenant only.
    by_hand(
        &s,
        "h4",
        &f.user_id,
        RoleId::TenantViewer,
        &Scope::Tenants(vec![f.tenant.id.clone(), other.id.clone()]),
    )
    .await;
    // And one stored at every tenant: likewise.
    by_hand(&s, "h2", &f.user_id, RoleId::GroupViewer, &Scope::All).await;
    let effective = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(effective.len(), 2);
    for held in &effective {
        assert!(matches!(held.role, RoleId::TenantViewer | RoleId::GroupViewer));
        assert_eq!(held.scope, Scope::Tenants(vec![f.tenant.id.clone()]));
    }
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
}

async fn held(s: &TestServer, id: &str) -> Vec<(RoleId, Scope)> {
    bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|x| x.principal_id == id)
        .map(|x| (x.role, x.scope))
        .collect()
}

/// The console never asks where a role applies: it follows from the account.
#[tokio::test]
async fn the_console_derives_where_a_role_applies_from_the_account() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await; // a Global Administrator, in the root tenant
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    let outsider = user_in(&s, &fabrikam, "zed@fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    // The global page grants Global Administrator and nothing else: a tenant role
    // asked for there is refused, and sent to the tenant.
    let page = b
        .post(
            &s.url("/admin/bindings"),
            &[
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", "TenantViewer"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("that tenant's Roles tab"), "{}", page.body);
    assert!(held(&s, &outsider).await.is_empty());

    // Global Administrator for an account outside the root tenant is refused,
    // in the words the storage layer uses.
    let page = b
        .post(
            &s.url("/admin/bindings"),
            &[
                ("op", "grant"),
                ("account", "zed@fabrikam.test"),
                ("role", "GlobalAdministrator"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(
        page.body.contains("Only accounts and groups in the root tenant"),
        "{}",
        page.body
    );

    // The tenant's own Roles page grants in that tenant, and does not offer or
    // accept Global Administrator.
    let roles = s.url(&format!("/admin/tenants/{}/roles", fabrikam.id));
    let page = b.get(&roles).await;
    assert!(!page.body.contains(r#"value="GlobalAdministrator""#), "{}", page.body);
    assert!(
        !page.body.contains(r#"name="scope""#),
        "no scope is asked for: {}",
        page.body
    );
    let page = b
        .post(
            &roles,
            &[
                ("op", "grant"),
                ("principal", "zed@fabrikam.test"),
                ("principal_type", "User"),
                ("role", "GlobalAdministrator"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    let page = b
        .post(
            &roles,
            &[
                ("op", "grant"),
                ("principal", "zed@fabrikam.test"),
                ("principal_type", "User"),
                ("role", "UserAdministrator"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(
        held(&s, &outsider).await,
        [(RoleId::UserAdministrator, Scope::Tenants(vec![fabrikam.id.clone()]))],
        "in the account's own tenant, without it being asked for"
    );

    // Each view shows its own grants and not the other's. The tenant's page has
    // the tenant role and not the Global Administrator...
    let page = b.get(&roles).await;
    assert!(page.body.contains("zed@fabrikam.test"), "{}", page.body);
    assert!(!page.body.contains(&format!("<td>{}</td>", f.upn)), "{}", page.body);
    assert!(!page.body.contains("Global Administrator</td>"), "{}", page.body);
    // ...and the global page has the Global Administrator, whose tenant it names,
    // and nothing that is bound to a tenant.
    let page = b.get(&s.url("/admin/bindings")).await;
    assert!(page.body.contains("<th>Their tenant</th>"), "{}", page.body);
    assert!(page.body.contains(&format!("<td>{}</td>", f.upn)), "{}", page.body);
    assert!(page.body.contains(r#"<span class="pill">root</span>"#), "{}", page.body);
    assert!(!page.body.contains("zed@fabrikam.test"), "{}", page.body);
    assert!(!page.body.contains("User Administrator"), "{}", page.body);
    assert!(
        !page.body.contains("<select"),
        "there is one role here and no tenant to pick: {}",
        page.body
    );

    // Nor does either revoke the other's: each binding is revoked where it is listed.
    let all = bindings::list_all(&s.pool).await.unwrap();
    let global = &all.iter().find(|x| x.scope == Scope::All).unwrap().id;
    let scoped = &all.iter().find(|x| x.scope != Scope::All).unwrap().id;
    let wrong = b.post(&roles, &[("op", "revoke"), ("binding", global)]).await;
    assert_eq!(wrong.status, 403, "{}", wrong.body);
    let wrong = b
        .post(&s.url("/admin/bindings"), &[("op", "revoke"), ("binding", scoped)])
        .await;
    assert_eq!(wrong.status, 403, "{}", wrong.body);
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), 2);
    assert_eq!(
        b.post(&roles, &[("op", "revoke"), ("binding", scoped)]).await.status,
        303
    );
}
