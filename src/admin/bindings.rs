//! Storage for role bindings, and expansion into effective grants.

use crate::db::DbPool;
use sqlx::Row;

use crate::rbac::{EffectiveBinding, RoleId, Scope, ScopeKind};
use crate::util::{new_guid, now};

/// Who a binding is granted to. Service principals cannot use the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Group,
}

impl PrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "User" => Some(Self::User),
            "Group" => Some(Self::Group),
            _ => None,
        }
    }
}

pub struct StoredBinding {
    pub id: String,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub role: RoleId,
    pub scope: Scope,
}

pub async fn create(
    pool: &DbPool,
    principal_type: PrincipalType,
    principal_id: &str,
    role: RoleId,
    scope: &Scope,
    created_by: &str,
) -> anyhow::Result<String> {
    let id = new_guid();
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
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
            scope: scope_of(pool, &id, kind).await?,
        });
    }
    Ok(out)
}

pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<StoredBinding>> {
    let rows = sqlx::query(
        "SELECT id, principal_type, principal_id, role_id, scope_kind FROM role_bindings ORDER BY created_at",
    )
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
