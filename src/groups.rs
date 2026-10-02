use crate::admin::lockout;
use crate::db::DbPool;
use anyhow::{Context, bail};

use crate::tenant::Tenant;
use crate::util::{new_guid, now};

pub async fn create(pool: &DbPool, tenant: &Tenant, name: &str, description: Option<&str>) -> anyhow::Result<String> {
    if name.trim().is_empty() {
        bail!("group name must not be empty");
    }
    let id = new_guid();
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO user_groups (id, tenant_id, name, name_folded, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(&tenant.id)
    .bind(name.trim())
    .bind(crate::util::fold(name))
    .bind(description)
    .bind(now())
    .execute(pool)
    .await
    .with_context(|| format!("group '{name}' already exists"))?;
    Ok(id)
}

/// Add a member to a group named by name, as the CLI does. The console names a
/// group by its object id instead; see [`add_member_by_id`]. Both resolve the
/// user and record the membership through the same two helpers.
pub async fn add_member(pool: &DbPool, tenant: &Tenant, group: &str, upn: &str) -> anyhow::Result<()> {
    let group_id = find(pool, &tenant.id, group)
        .await?
        .with_context(|| format!("group '{group}' not found"))?;
    let user_id = user_id_in(pool, &tenant.id, upn).await?;
    insert_member(pool, &group_id, &user_id).await
}

/// Names of the user's groups (the `groups` claim).
pub async fn names_for_user(pool: &DbPool, user_id: &str) -> anyhow::Result<Vec<String>> {
    Ok(for_user(pool, user_id).await?.into_iter().map(|g| g.name).collect())
}

/// A group as a token names it: the name, and the id that stays the same when the
/// group is renamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    pub id: String,
    pub name: String,
}

/// The groups a user belongs to, in one fixed order (by name, then id), so the
/// `groups` and `group_ids` claims built from it line up position for position.
pub async fn for_user(pool: &DbPool, user_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT g.id, g.name FROM user_groups g JOIN group_members m ON m.group_id = g.id
         WHERE m.user_id = ? ORDER BY g.name, g.id",
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id, name)| GroupRef { id, name }).collect())
}

/// A group's id by name within a tenant, case-insensitively.
pub async fn find(pool: &DbPool, tenant_id: &str, name: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM user_groups WHERE tenant_id = ? AND name_folded = ?",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(name))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// A group as the console lists it.
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

pub async fn list(pool: &DbPool, tenant_id: &str) -> anyhow::Result<Vec<Group>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, name, description FROM user_groups WHERE tenant_id = ? ORDER BY name",
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, description)| Group { id, name, description })
        .collect())
}

/// One group of this tenant, by object id. `None` for a group of another tenant,
/// so an id alone can never reach across the boundary.
pub async fn find_by_id(pool: &DbPool, tenant_id: &str, group_id: &str) -> anyhow::Result<Option<Group>> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id, name, description FROM user_groups WHERE tenant_id = ? AND id = ?",
    ))
    .bind(tenant_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, name, description)| Group { id, name, description }))
}

/// A member of a group: the object id and the user name.
pub struct Member {
    pub user_id: String,
    pub upn: String,
}

/// The group's members. A soft-deleted account is not one.
pub async fn members(pool: &DbPool, group_id: &str) -> anyhow::Result<Vec<Member>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT u.id, u.upn FROM group_members m JOIN users u ON u.id = m.user_id
         WHERE m.group_id = ? AND u.deleted_at IS NULL ORDER BY u.upn",
    ))
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(user_id, upn)| Member { user_id, upn }).collect())
}

/// Add a member to a group named by its object id, for the console: the id is
/// what a page link carries, where the CLI has only a name.
///
/// The group is looked up inside `tenant_id`, so a group id from another tenant
/// is simply not found.
pub async fn add_member_by_id(pool: &DbPool, tenant_id: &str, group_id: &str, upn: &str) -> anyhow::Result<()> {
    let group = find_by_id(pool, tenant_id, group_id)
        .await?
        .with_context(|| format!("group '{group_id}' not found"))?;
    let user_id = user_id_in(pool, tenant_id, upn).await?;
    insert_member(pool, &group.id, &user_id).await
}

/// Remove a member. `false` when they were not one, so the caller can say so.
pub async fn remove_member(pool: &DbPool, tenant_id: &str, group_id: &str, user_id: &str) -> anyhow::Result<bool> {
    // The tenant check first, as its own statement: MySQL refuses to delete from
    // a table named in its own subquery, and two statements need no subquery.
    if find_by_id(pool, tenant_id, group_id).await?.is_none() {
        return Ok(false);
    }
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let admins = lockout::global_administrators(&mut tx, engine).await?;
    let done = sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
    ))
    .bind(group_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    lockout::ensure_one_remains(&mut tx, engine, admins).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}

/// Delete a group that has no members, along with the console roles and app
/// roles granted to it. `false` when there is no such group in this tenant.
///
/// A group with members is refused: deleting it would silently take from each of
/// them whatever the group gave, and the console has no "are you sure". Emptying
/// it first makes each of those a deliberate step.
pub async fn delete(pool: &DbPool, tenant_id: &str, group_id: &str) -> anyhow::Result<bool> {
    if find_by_id(pool, tenant_id, group_id).await?.is_none() {
        return Ok(false);
    }
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let (members,): (i64,) = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT COUNT(*) FROM group_members WHERE group_id = ?",
    ))
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await?;
    if members > 0 {
        anyhow::bail!("this group still has {members} member(s); remove them first");
    }
    let group = crate::directory::PrincipalType::Group.as_str();
    for sql in [
        "DELETE FROM role_binding_tenants WHERE binding_id IN
            (SELECT id FROM role_bindings WHERE principal_type = ? AND principal_id = ?)",
        "DELETE FROM role_bindings WHERE principal_type = ? AND principal_id = ?",
        "DELETE FROM app_role_assignments WHERE principal_type = ? AND principal_id = ?",
    ] {
        sqlx::query(crate::db::sql_stmt(engine, sql))
            .bind(group)
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM user_groups WHERE id = ?"))
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// The id of a live account in this tenant, by user name.
async fn user_id_in(pool: &DbPool, tenant_id: &str, upn: &str) -> anyhow::Result<String> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .fetch_optional(pool)
    .await?;
    let (id,) = row.with_context(|| format!("user '{upn}' not found"))?;
    Ok(id)
}

/// Record a membership. Already a member is success: the primary key
/// `(group_id, user_id)` makes it a no-op.
async fn insert_member(pool: &DbPool, group_id: &str, user_id: &str) -> anyhow::Result<()> {
    crate::db::inserted(
        sqlx::query(crate::db::q(
            pool,
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
        ))
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await,
    )?;
    Ok(())
}
