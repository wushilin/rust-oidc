//! `0012_console_roles`: bindings written under the old role set are carried
//! across in place. Old rows are put into a migrated database by hand and the
//! migration's own SQL is run over them.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::rbac::{RoleId, Scope};

const MIGRATION: &str = include_str!("../migrations/sqlite/0012_console_roles.sql");

async fn old_row(s: &TestServer, id: &str, kind: &str, principal: &str, role: &str, tenants: Option<&[&str]>) {
    sqlx::query(rust_oidc::db::q(
        &s.pool,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, 0, 'old')",
    ))
    .bind(id)
    .bind(kind)
    .bind(principal)
    .bind(role)
    .bind(if tenants.is_some() { "tenants" } else { "all" })
    .execute(&s.pool)
    .await
    .unwrap();
    for t in tenants.unwrap_or_default() {
        sqlx::query(rust_oidc::db::q(
            &s.pool,
            "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)",
        ))
        .bind(id)
        .bind(*t)
        .execute(&s.pool)
        .await
        .unwrap();
    }
}

async fn held(s: &TestServer, principal: &str) -> Vec<(RoleId, Scope)> {
    let mut v: Vec<(RoleId, Scope)> = bindings::list_all(&s.pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.principal_id == principal)
        .map(|b| (b.role, b.scope))
        .collect();
    v.sort_by_key(|(r, _)| r.as_str());
    v
}

#[tokio::test]
async fn old_bindings_are_carried_across_to_the_new_roles() {
    let s = TestServer::start().await;
    let root = root_user_fixture(&s).await;
    let fab = s.tenant("Fabrikam", "fabrikam.test").await;
    let (r, f) = (root.tenant.id.as_str(), fab.id.as_str());
    let user = |upn: &'static str, tenant: rust_oidc::tenant::Tenant| {
        let s = &s;
        async move { user_fixture_in(s, tenant, upn).await.user_id }
    };
    // The shape of the two live deployments' administrators.
    let both = user("both@contoso.com", root.tenant.clone()).await;
    old_row(&s, "m1", "User", &both, "GlobalAdministrator", None).await;
    old_row(&s, "m2", "User", &both, "PlatformAdministrator", None).await;
    let split = user("split@contoso.com", root.tenant.clone()).await;
    old_row(&s, "m3", "User", &split, "GlobalAdministrator", Some(&[r])).await;
    old_row(&s, "m4", "User", &split, "PlatformAdministrator", None).await;
    // A root account administering another tenant: that reach is gone.
    let reach = user("reach@contoso.com", root.tenant.clone()).await;
    old_row(&s, "m5", "User", &reach, "ApplicationAdministrator", Some(&[f])).await;
    old_row(&s, "m6", "User", &reach, "GlobalReader", None).await;
    // A tenant's own people.
    let boss = user("boss@fabrikam.test", fab.clone()).await;
    old_row(&s, "m7", "User", &boss, "GlobalAdministrator", Some(&[f])).await;
    let roles = user("roles@fabrikam.test", fab.clone()).await;
    old_row(&s, "m8", "User", &roles, "PrivilegedRoleAdministrator", Some(&[f])).await;
    let cloud = user("cloud@fabrikam.test", fab.clone()).await;
    old_row(&s, "m9", "User", &cloud, "CloudApplicationAdministrator", Some(&[f])).await;
    old_row(&s, "m10", "User", &cloud, "UserAdministrator", Some(&[f, r])).await;
    // A group, and a platform role that never granted anything.
    let group = rust_oidc::groups::create(&s.pool, &fab, "Helpdesk", None)
        .await
        .unwrap();
    old_row(&s, "m11", "Group", &group, "GroupsAdministrator", Some(&[f])).await;
    old_row(&s, "m12", "Group", &group, "PlatformAdministrator", Some(&[f])).await;

    sqlx::raw_sql(MIGRATION).execute(&s.pool).await.unwrap();

    let own = |t: &str| Scope::Tenants(vec![t.to_string()]);
    assert_eq!(
        held(&s, &both).await,
        [(RoleId::GlobalAdministrator, Scope::All)],
        "one, not two"
    );
    assert_eq!(
        held(&s, &split).await,
        [
            (RoleId::GlobalAdministrator, Scope::All),
            (RoleId::TenantAdministrator, own(r))
        ]
    );
    assert_eq!(
        held(&s, &reach).await,
        [(RoleId::TenantViewer, own(r))],
        "every-tenant reader becomes a viewer of their own tenant; the role in another tenant is gone"
    );
    assert_eq!(held(&s, &boss).await, [(RoleId::TenantAdministrator, own(f))]);
    assert_eq!(held(&s, &roles).await, [(RoleId::TenantAdministrator, own(f))]);
    assert_eq!(
        held(&s, &cloud).await,
        [
            (RoleId::ApplicationAdministrator, own(f)),
            (RoleId::UserAdministrator, own(f))
        ]
    );
    assert_eq!(held(&s, &group).await, [(RoleId::GroupsAdministrator, own(f))]);

    // Everything left is a binding the new rule would itself have written, so
    // what is stored is what is in effect.
    for (who, n) in [(&both, 1), (&split, 2), (&reach, 1), (&boss, 1), (&cloud, 2)] {
        assert_eq!(bindings::effective_for_user(&s.pool, who).await.unwrap().len(), n);
    }
    // And running it again changes nothing.
    let before = bindings::list_all(&s.pool).await.unwrap().len();
    sqlx::raw_sql(MIGRATION).execute(&s.pool).await.unwrap();
    assert_eq!(bindings::list_all(&s.pool).await.unwrap().len(), before);
}

#[test]
fn the_three_engines_run_the_same_statements() {
    for other in [
        include_str!("../migrations/postgres/0012_console_roles.sql"),
        include_str!("../migrations/mysql/0012_console_roles.sql"),
    ] {
        assert_eq!(other, MIGRATION);
    }
}
