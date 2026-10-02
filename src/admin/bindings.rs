//! Storage for role bindings, and expansion into effective grants.

use crate::db::DbPool;
use sqlx::Row;

use crate::rbac::{EffectiveBinding, RoleId, Scope, ScopeKind};
use crate::util::{new_guid, now};

/// Who a binding is granted to.
///
/// The same enum `app_role_assignments` uses, so the two `principal_type` columns
/// have one spelling between them. A console role binding is narrower than an app
/// role assignment: a service principal cannot use the console, and
/// [`create`] refuses one rather than a second near-identical enum existing.
pub use crate::directory::PrincipalType;

pub struct StoredBinding {
    pub id: String,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub role: RoleId,
    pub scope: Scope,
}

/// Refusal of a grant that would give a principal outside the root tenant reach
/// beyond its own tenant. See [`Scope::may_be_held_by`].
#[derive(Debug, thiserror::Error)]
#[error(
    "Only accounts and groups in the root tenant can be given roles that reach beyond their own tenant. \
     This one can be given roles in its own tenant, from that tenant's Roles tab."
)]
pub struct ReachRefused;

#[derive(sqlx::FromRow)]
struct Home {
    tenant_id: String,
    #[sqlx(try_from = "crate::db::Flag")]
    is_root: bool,
}

/// The tenant a principal belongs to, and whether that is the root tenant.
/// `None` when there is no such user or group.
async fn home_of<'e, E>(
    executor: E,
    engine: crate::db::Engine,
    principal_type: PrincipalType,
    principal_id: &str,
) -> anyhow::Result<Option<(String, bool)>>
where
    E: sqlx::Executor<'e, Database = crate::db::Db>,
{
    let sql = match principal_type {
        PrincipalType::User => {
            "SELECT t.id AS tenant_id, t.is_root FROM users u JOIN tenants t ON t.id = u.tenant_id
             WHERE u.id = ? AND u.deleted_at IS NULL"
        }
        PrincipalType::Group => {
            "SELECT t.id AS tenant_id, t.is_root FROM user_groups g JOIN tenants t ON t.id = g.tenant_id
             WHERE g.id = ?"
        }
        PrincipalType::ServicePrincipal => return Ok(None),
    };
    let home: Option<Home> = sqlx::query_as(crate::db::sql_stmt(engine, sql))
        .bind(principal_id)
        .fetch_optional(executor)
        .await?;
    Ok(home.map(|h| (h.tenant_id, h.is_root)))
}

/// The one way a role binding is written.
///
/// The rule that only the root tenant's principals reach beyond their own tenant
/// is checked here, inside the transaction that writes the row, so no page, CLI
/// command or future caller can grant around it.
pub async fn create(
    pool: &DbPool,
    principal_type: PrincipalType,
    principal_id: &str,
    role: RoleId,
    scope: &Scope,
    created_by: &str,
) -> anyhow::Result<String> {
    // A service principal cannot sign in to the console, so a binding naming one
    // could only ever be dead weight -- and `effective_for_user` would ignore it
    // anyway. Refuse it here rather than leave that as an implicit property of a
    // query two functions away.
    if principal_type == PrincipalType::ServicePrincipal {
        anyhow::bail!("a service principal cannot hold a console role");
    }
    let id = new_guid();
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let Some((home, home_is_root)) = home_of(&mut *tx, engine, principal_type, principal_id).await? else {
        anyhow::bail!("no such user or group");
    };
    if !scope.may_be_held_by(&home, home_is_root) {
        return Err(ReachRefused.into());
    }
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(principal_type.as_str())
    .bind(principal_id)
    .bind(role.as_str())
    .bind(scope.kind().as_str())
    .bind(now())
    .bind(created_by)
    .execute(&mut *tx)
    .await?;
    if let Scope::Tenants(ids) = scope {
        for tenant_id in ids {
            sqlx::query(crate::db::sql_stmt(
                engine,
                "INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)",
            ))
            .bind(&id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(id)
}

pub async fn delete(pool: &DbPool, binding_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::q(pool, "DELETE FROM role_bindings WHERE id = ?"))
        .bind(binding_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Scope rows join `tenants`, so a binding naming a deleted tenant yields no
/// tenant ids and therefore grants nothing.
async fn scope_of(pool: &DbPool, binding_id: &str, kind: ScopeKind) -> anyhow::Result<Scope> {
    match kind {
        ScopeKind::All => Ok(Scope::All),
        ScopeKind::Tenants => {
            let rows = sqlx::query(crate::db::q(
                pool,
                "SELECT rbt.tenant_id FROM role_binding_tenants rbt
                 JOIN tenants t ON t.id = rbt.tenant_id
                 WHERE rbt.binding_id = ?",
            ))
            .bind(binding_id)
            .fetch_all(pool)
            .await?;
            Ok(Scope::Tenants(rows.iter().map(|r| r.get("tenant_id")).collect()))
        }
    }
}

/// Every binding held by the user directly or through a group they belong to.
/// Recomputed on each call: never cache this in a session.
pub async fn effective_for_user(pool: &DbPool, user_id: &str) -> anyhow::Result<Vec<EffectiveBinding>> {
    let rows = sqlx::query(crate::db::q(
        pool,
        "SELECT id, role_id, scope_kind FROM role_bindings
         WHERE (principal_type = ? AND principal_id = ?)
            OR (principal_type = ? AND principal_id IN
                (SELECT group_id FROM group_members WHERE user_id = ?))",
    ))
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // The read-side half of the rule `create` enforces: whatever a row says, a
    // user outside the root tenant holds nothing beyond their own tenant.
    let Some((home, home_is_root)) = home_of(pool, crate::db::engine_of(pool), PrincipalType::User, user_id).await?
    else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let Some(role) = RoleId::parse(row.get::<String, _>("role_id").as_str()) else {
            continue; // a role we do not know is ignored, not fatal
        };
        let Some(kind) = ScopeKind::parse(row.get::<String, _>("scope_kind").as_str()) else {
            continue;
        };
        out.push(EffectiveBinding {
            role,
            scope: scope_of(pool, &id, kind).await?.held_by(&home, home_is_root),
        });
    }
    Ok(out)
}

pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<StoredBinding>> {
    // Through `db::q` like every other statement, although this one carries no
    // placeholder today: `tests/sql_routing.rs` only flags calls containing `?`,
    // so an unrouted statement here would stay invisible until someone added a
    // `WHERE` and broke Postgres.
    let rows = sqlx::query(crate::db::q(
        pool,
        "SELECT id, principal_type, principal_id, role_id, scope_kind FROM role_bindings ORDER BY created_at",
    ))
    .fetch_all(pool)
    .await?;
    hydrate(pool, rows).await
}

pub async fn list_for_tenant(pool: &DbPool, tenant_id: &str) -> anyhow::Result<Vec<StoredBinding>> {
    let rows = sqlx::query(crate::db::q(
        pool,
        "SELECT b.id, b.principal_type, b.principal_id, b.role_id, b.scope_kind
         FROM role_bindings b
         LEFT JOIN role_binding_tenants rbt ON rbt.binding_id = b.id
         WHERE b.scope_kind = ? OR rbt.tenant_id = ?
         GROUP BY b.id ORDER BY b.created_at",
    ))
    .bind(ScopeKind::All.as_str())
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    hydrate(pool, rows).await
}

async fn hydrate(pool: &DbPool, rows: Vec<sqlx::any::AnyRow>) -> anyhow::Result<Vec<StoredBinding>> {
    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let (Some(principal_type), Some(role), Some(kind)) = (
            PrincipalType::parse(row.get::<String, _>("principal_type").as_str()),
            RoleId::parse(row.get::<String, _>("role_id").as_str()),
            ScopeKind::parse(row.get::<String, _>("scope_kind").as_str()),
        ) else {
            continue;
        };
        let scope = scope_of(pool, &id, kind).await?;
        out.push(StoredBinding {
            id,
            principal_type,
            principal_id: row.get("principal_id"),
            role,
            scope,
        });
    }
    Ok(out)
}
