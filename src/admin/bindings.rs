//! Storage for role bindings, and expansion into effective grants.

use crate::db::Handle;
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

/// Refusal of a grant at a scope the role cannot be held at by that principal.
/// See [`RoleId::scope_held_by`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeRefused {
    #[error(
        "Only accounts and groups in the root tenant can be Global Administrator. \
         This one can be given roles in its own tenant."
    )]
    GlobalOutsideRoot,
    #[error("Global Administrator covers everything. It cannot be limited to some tenants.")]
    GlobalNeedsEverything,
    #[error("{0} applies to the tenant the account or group belongs to, and to no other.")]
    OwnTenantOnly(&'static str),
}

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
/// Where a role applies is not the caller's choice: [`RoleId::scope_held_by`] says
/// what it is for this principal, and anything else is refused here, inside the
/// transaction that writes the row, so no page, CLI command or future caller can
/// grant around it.
pub async fn create<'c>(
    db: impl Handle<'c>,
    principal_type: PrincipalType,
    principal_id: &str,
    role: RoleId,
    scope: &Scope,
    created_by: &str,
) -> anyhow::Result<String> {
    let mut conn = db.acquire().await?;
    create_in(&mut conn, principal_type, principal_id, role, scope, created_by).await
}

pub(crate) async fn create_in(
    conn: &mut crate::db::Conn,
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
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let Some((home, home_is_root)) = home_of(&mut *tx, engine, principal_type, principal_id).await? else {
        anyhow::bail!("no such user or group");
    };
    match role.scope_held_by(&home, home_is_root) {
        Some(held) if held == *scope => {}
        None => return Err(ScopeRefused::GlobalOutsideRoot.into()),
        Some(Scope::All) => return Err(ScopeRefused::GlobalNeedsEverything.into()),
        Some(Scope::Tenants(_)) => return Err(ScopeRefused::OwnTenantOnly(role.display_name()).into()),
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

pub async fn delete<'c>(db: impl Handle<'c>, binding_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    delete_in(&mut conn, binding_id).await
}

pub(crate) async fn delete_in(conn: &mut crate::db::Conn, binding_id: &str) -> anyhow::Result<bool> {
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let admins = crate::admin::lockout::global_administrators(&mut tx, engine).await?;
    let done = sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM role_bindings WHERE id = ?"))
        .bind(binding_id)
        .execute(&mut *tx)
        .await?;
    crate::admin::lockout::ensure_one_remains(&mut tx, engine, admins).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// Scope rows join `tenants`, so a binding naming a deleted tenant yields no
/// tenant ids and therefore grants nothing.
async fn scope_of_in(conn: &mut crate::db::Conn, binding_id: &str, kind: ScopeKind) -> anyhow::Result<Scope> {
    match kind {
        ScopeKind::All => Ok(Scope::All),
        ScopeKind::Tenants => {
            let rows = sqlx::query(crate::db::qc(
                conn,
                "SELECT rbt.tenant_id FROM role_binding_tenants rbt
                 JOIN tenants t ON t.id = rbt.tenant_id
                 WHERE rbt.binding_id = ?",
            ))
            .bind(binding_id)
            .fetch_all(&mut *conn)
            .await?;
            Ok(Scope::Tenants(rows.iter().map(|r| r.get("tenant_id")).collect()))
        }
    }
}

/// Every binding held by the user directly or through a group they belong to.
/// Recomputed on each call: never cache this in a session.
pub async fn effective_for_user<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Vec<EffectiveBinding>> {
    let mut conn = db.acquire().await?;
    effective_for_user_in(&mut conn, user_id).await
}

pub(crate) async fn effective_for_user_in(
    conn: &mut crate::db::Conn,
    user_id: &str,
) -> anyhow::Result<Vec<EffectiveBinding>> {
    let rows = sqlx::query(crate::db::qc(
        conn,
        "SELECT id, role_id, scope_kind FROM role_bindings
         WHERE (principal_type = ? AND principal_id = ?)
            OR (principal_type = ? AND principal_id IN
                (SELECT group_id FROM group_members WHERE user_id = ?))",
    ))
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;

    // The read-side half of the rule `create` enforces, applied with the user's
    // own tenant (a group is always in its members' tenant).
    let engine = crate::db::engine_of_conn(conn);
    let Some((home, home_is_root)) = home_of(&mut *conn, engine, PrincipalType::User, user_id).await? else {
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
        // A stored scope grants what the role can be held at and nothing more:
        // a row that says otherwise is cut back to that, or grants nothing.
        let stored = scope_of_in(&mut *conn, &id, kind).await?;
        let Some(held) = role.scope_held_by(&home, home_is_root) else {
            continue;
        };
        let in_effect = match (&held, &stored) {
            (Scope::All, Scope::All) => true,
            (Scope::Tenants(own), stored) => own.iter().all(|t| stored.covers(t)),
            (Scope::All, Scope::Tenants(_)) => false,
        };
        if in_effect {
            out.push(EffectiveBinding { role, scope: held });
        }
    }
    Ok(out)
}

pub async fn list_all<'c>(db: impl Handle<'c>) -> anyhow::Result<Vec<StoredBinding>> {
    let mut conn = db.acquire().await?;
    list_all_in(&mut conn).await
}

pub(crate) async fn list_all_in(conn: &mut crate::db::Conn) -> anyhow::Result<Vec<StoredBinding>> {
    // Through `db::q` like every other statement, although this one carries no
    // placeholder today: `tests/sql_routing.rs` only flags calls containing `?`,
    // so an unrouted statement here would stay invisible until someone added a
    // `WHERE` and broke Postgres.
    let rows = sqlx::query(crate::db::qc(
        conn,
        "SELECT id, principal_type, principal_id, role_id, scope_kind FROM role_bindings ORDER BY created_at",
    ))
    .fetch_all(&mut *conn)
    .await?;
    hydrate_in(&mut *conn, rows).await
}

pub async fn list_for_tenant<'c>(db: impl Handle<'c>, tenant_id: &str) -> anyhow::Result<Vec<StoredBinding>> {
    let mut conn = db.acquire().await?;
    list_for_tenant_in(&mut conn, tenant_id).await
}

pub(crate) async fn list_for_tenant_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
) -> anyhow::Result<Vec<StoredBinding>> {
    let rows = sqlx::query(crate::db::qc(
        conn,
        "SELECT b.id, b.principal_type, b.principal_id, b.role_id, b.scope_kind
         FROM role_bindings b
         LEFT JOIN role_binding_tenants rbt ON rbt.binding_id = b.id
         WHERE b.scope_kind = ? OR rbt.tenant_id = ?
         GROUP BY b.id ORDER BY b.created_at",
    ))
    .bind(ScopeKind::All.as_str())
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;
    hydrate_in(&mut *conn, rows).await
}

async fn hydrate_in(conn: &mut crate::db::Conn, rows: Vec<sqlx::any::AnyRow>) -> anyhow::Result<Vec<StoredBinding>> {
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
        let scope = scope_of_in(&mut *conn, &id, kind).await?;
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
