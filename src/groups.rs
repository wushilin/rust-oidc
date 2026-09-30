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

pub async fn add_member(pool: &DbPool, tenant: &Tenant, group: &str, upn: &str) -> anyhow::Result<()> {
    let group_id: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM user_groups WHERE tenant_id = ? AND name_folded = ?",
    ))
    .bind(&tenant.id)
    .bind(crate::util::fold(group))
    .fetch_optional(pool)
    .await?;
    let (group_id,) = group_id.with_context(|| format!("group '{group}' not found"))?;
    let user_id: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ?",
    ))
    .bind(&tenant.id)
    .bind(crate::util::fold(upn))
    .fetch_optional(pool)
    .await?;
    let (user_id,) = user_id.with_context(|| format!("user '{upn}' not found"))?;
    // Already a member is success: the primary key (group_id, user_id) makes it a no-op.
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

/// Names of the user's groups (the `groups` claim).
pub async fn names_for_user(pool: &DbPool, user_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        crate::db::q(pool, "SELECT g.name FROM user_groups g JOIN group_members m ON m.group_id = g.id WHERE m.user_id = ? ORDER BY g.name"),
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(n,)| n).collect())
}
