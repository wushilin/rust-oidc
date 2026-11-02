use crate::admin::lockout;
use crate::db::Handle;
use anyhow::{Context, bail};

use crate::tenant::Tenant;
use crate::util::{new_guid, now};

pub async fn create<'c>(
    db: impl Handle<'c>,
    tenant: &Tenant,
    name: &str,
    description: Option<&str>,
) -> anyhow::Result<String> {
    let mut conn = db.acquire().await?;
    create_in(&mut conn, tenant, name, description).await
}

pub(crate) async fn create_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    name: &str,
    description: Option<&str>,
) -> anyhow::Result<String> {
    if name.trim().is_empty() {
        bail!("group name must not be empty");
    }
    // Looked for first: inside a transaction a broken unique constraint is a
    // database failure (and on Postgres aborts the whole transaction), not a
    // refusal the administrator can act on.
    if find_in(&mut *conn, &tenant.id, name.trim()).await?.is_some() {
        bail!("group '{}' already exists", name.trim());
    }
    let id = new_guid();
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO user_groups (id, tenant_id, name, name_folded, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(&id)
    .bind(&tenant.id)
    .bind(name.trim())
    .bind(crate::util::fold(name))
    .bind(description)
    .bind(now())
    .execute(&mut *conn)
    .await
    .with_context(|| format!("group '{name}' already exists"))?;
    // Its own ancestor, at depth 0: the effective-groups join needs no special
    // case for a user's direct groups.
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO group_closure (ancestor_id, descendant_id, tenant_id, depth) VALUES (?, ?, ?, 0)",
    ))
    .bind(&id)
    .bind(&id)
    .bind(&tenant.id)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

/// Add a member to a group named by name, as the CLI does. The console names a
/// group by its object id instead; see [`add_member_by_id`]. Both resolve the
/// user and record the membership through the same two helpers.
pub async fn add_member<'c>(db: impl Handle<'c>, tenant: &Tenant, group: &str, upn: &str) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    add_member_in(&mut conn, tenant, group, upn).await
}

pub(crate) async fn add_member_in(
    conn: &mut crate::db::Conn,
    tenant: &Tenant,
    group: &str,
    upn: &str,
) -> anyhow::Result<()> {
    let group_id = find_in(&mut *conn, &tenant.id, group)
        .await?
        .with_context(|| format!("group '{group}' not found"))?;
    let user_id = user_id_in(&mut *conn, &tenant.id, upn).await?;
    insert_member_in(&mut *conn, &group_id, &user_id).await
}

/// Names of the user's groups (the `groups` claim).
pub async fn names_for_user<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Vec<String>> {
    let mut conn = db.acquire().await?;
    names_for_user_in(&mut conn, user_id).await
}

pub(crate) async fn names_for_user_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<Vec<String>> {
    Ok(for_user_in(&mut *conn, user_id)
        .await?
        .into_iter()
        .map(|g| g.name)
        .collect())
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
pub async fn for_user<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let mut conn = db.acquire().await?;
    for_user_in(&mut conn, user_id).await
}

pub(crate) async fn for_user_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT g.id, g.name FROM user_groups g JOIN group_members m ON m.group_id = g.id
         WHERE m.user_id = ? ORDER BY g.name, g.id",
    ))
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|(id, name)| GroupRef { id, name }).collect())
}

/// A group's id by name within a tenant, case-insensitively.
pub async fn find<'c>(db: impl Handle<'c>, tenant_id: &str, name: &str) -> anyhow::Result<Option<String>> {
    let mut conn = db.acquire().await?;
    find_in(&mut conn, tenant_id, name).await
}

pub(crate) async fn find_in(conn: &mut crate::db::Conn, tenant_id: &str, name: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id FROM user_groups WHERE tenant_id = ? AND name_folded = ?",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(name))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// A group as the console lists it.
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

pub async fn list<'c>(db: impl Handle<'c>, tenant_id: &str) -> anyhow::Result<Vec<Group>> {
    let mut conn = db.acquire().await?;
    list_in(&mut conn, tenant_id).await
}

pub(crate) async fn list_in(conn: &mut crate::db::Conn, tenant_id: &str) -> anyhow::Result<Vec<Group>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id, name, description FROM user_groups WHERE tenant_id = ? ORDER BY name",
    ))
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, description)| Group { id, name, description })
        .collect())
}

/// One group of this tenant, by object id. `None` for a group of another tenant,
/// so an id alone can never reach across the boundary.
pub async fn find_by_id<'c>(db: impl Handle<'c>, tenant_id: &str, group_id: &str) -> anyhow::Result<Option<Group>> {
    let mut conn = db.acquire().await?;
    find_by_id_in(&mut conn, tenant_id, group_id).await
}

pub(crate) async fn find_by_id_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    group_id: &str,
) -> anyhow::Result<Option<Group>> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id, name, description FROM user_groups WHERE tenant_id = ? AND id = ?",
    ))
    .bind(tenant_id)
    .bind(group_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id, name, description)| Group { id, name, description }))
}

/// A member of a group: the object id and the user name.
pub struct Member {
    pub user_id: String,
    pub upn: String,
}

/// The group's members. A soft-deleted account is not one.
pub async fn members<'c>(db: impl Handle<'c>, group_id: &str) -> anyhow::Result<Vec<Member>> {
    let mut conn = db.acquire().await?;
    members_in(&mut conn, group_id).await
}

pub(crate) async fn members_in(conn: &mut crate::db::Conn, group_id: &str) -> anyhow::Result<Vec<Member>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT u.id, u.upn FROM group_members m JOIN users u ON u.id = m.user_id
         WHERE m.group_id = ? AND u.deleted_at IS NULL ORDER BY u.upn",
    ))
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|(user_id, upn)| Member { user_id, upn }).collect())
}

/// Add a member to a group named by its object id, for the console: the id is
/// what a page link carries, where the CLI has only a name.
///
/// The group is looked up inside `tenant_id`, so a group id from another tenant
/// is simply not found.
pub async fn add_member_by_id<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    group_id: &str,
    upn: &str,
) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    add_member_by_id_in(&mut conn, tenant_id, group_id, upn).await
}

pub(crate) async fn add_member_by_id_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    group_id: &str,
    upn: &str,
) -> anyhow::Result<()> {
    let group = find_by_id_in(&mut *conn, tenant_id, group_id)
        .await?
        .with_context(|| format!("group '{group_id}' not found"))?;
    let user_id = user_id_in(&mut *conn, tenant_id, upn).await?;
    insert_member_in(&mut *conn, &group.id, &user_id).await
}

/// Add a member named by object id, as a list of ticked rows does. The group and
/// the account are each looked up inside `tenant_id`.
pub async fn add_member_id<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    group_id: &str,
    user_id: &str,
) -> anyhow::Result<()> {
    let mut conn = db.acquire().await?;
    add_member_id_in(&mut conn, tenant_id, group_id, user_id).await
}

pub(crate) async fn add_member_id_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    group_id: &str,
    user_id: &str,
) -> anyhow::Result<()> {
    let group = find_by_id_in(&mut *conn, tenant_id, group_id)
        .await?
        .with_context(|| format!("group '{group_id}' not found"))?;
    let live: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id FROM users WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    if live.is_none() {
        bail!("no such account in this tenant");
    }
    insert_member_in(&mut *conn, &group.id, user_id).await
}

/// What [`set_for_user`] changed: the groups joined and the groups left.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MembershipChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Make a user a member of exactly `group_ids` among this tenant's groups, in
/// one transaction. Ids that are not groups of the tenant are ignored.
pub async fn set_for_user<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    user_id: &str,
    group_ids: &[String],
) -> anyhow::Result<MembershipChange> {
    let mut conn = db.acquire().await?;
    set_for_user_in(&mut conn, tenant_id, user_id, group_ids).await
}

pub(crate) async fn set_for_user_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    user_id: &str,
    group_ids: &[String],
) -> anyhow::Result<MembershipChange> {
    let all = list_in(&mut *conn, tenant_id).await?;
    let held: Vec<String> = for_user_in(&mut *conn, user_id)
        .await?
        .into_iter()
        .map(|g| g.id)
        .collect();
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let live: Option<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT id FROM users WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if live.is_none() {
        bail!("no such account in this tenant");
    }
    let admins = lockout::global_administrators(&mut tx, engine).await?;
    let mut change = MembershipChange::default();
    for group in &all {
        let (wanted, has) = (group_ids.contains(&group.id), held.contains(&group.id));
        if wanted && !has {
            sqlx::query(crate::db::sql_stmt(
                engine,
                "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            ))
            .bind(&group.id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            change.added.push(group.id.clone());
        } else if has && !wanted {
            sqlx::query(crate::db::sql_stmt(
                engine,
                "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            ))
            .bind(&group.id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            change.removed.push(group.id.clone());
        }
    }
    lockout::ensure_one_remains(&mut tx, engine, admins).await?;
    tx.commit().await?;
    Ok(change)
}

/// Remove a member. `false` when they were not one, so the caller can say so.
pub async fn remove_member<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    group_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    remove_member_in(&mut conn, tenant_id, group_id, user_id).await
}

pub(crate) async fn remove_member_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    group_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    // The tenant check first, as its own statement: MySQL refuses to delete from
    // a table named in its own subquery, and two statements need no subquery.
    if find_by_id_in(&mut *conn, tenant_id, group_id).await?.is_none() {
        return Ok(false);
    }
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
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

/// Delete a group that has no members (no accounts and no groups inside it),
/// along with the console roles and app roles granted to it. `false` when there
/// is no such group in this tenant.
///
/// A group with members is refused: deleting it would silently take from each of
/// them whatever the group gave, and the console has no "are you sure". Emptying
/// it first makes each of those a deliberate step.
pub async fn delete<'c>(db: impl Handle<'c>, tenant_id: &str, group_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    delete_in(&mut conn, tenant_id, group_id).await
}

pub(crate) async fn delete_in(conn: &mut crate::db::Conn, tenant_id: &str, group_id: &str) -> anyhow::Result<bool> {
    if find_by_id_in(&mut *conn, tenant_id, group_id).await?.is_none() {
        return Ok(false);
    }
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let (members,): (i64,) = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT COUNT(*) FROM group_members WHERE group_id = ?",
    ))
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await?;
    let (member_groups,): (i64,) = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT COUNT(*) FROM group_nesting WHERE parent_id = ?",
    ))
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await?;
    if members + member_groups > 0 {
        anyhow::bail!(
            "this group still has {} member(s); remove them first",
            members + member_groups
        );
    }
    // No group is inside it, so nothing below it loses an ancestor: removing the
    // rows that name it leaves every other group's ancestors correct. Done here
    // rather than left to the foreign keys, so it does not depend on them.
    for sql in [
        "DELETE FROM group_nesting WHERE child_id = ?",
        "DELETE FROM group_closure WHERE descendant_id = ?",
        "DELETE FROM group_closure WHERE ancestor_id = ?",
    ] {
        sqlx::query(crate::db::sql_stmt(engine, sql))
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
    }
    let group = crate::directory::PrincipalType::Group.as_str();
    for sql in [
        "DELETE FROM role_binding_tenants WHERE binding_id IN
            (SELECT id FROM role_bindings WHERE principal_type = ? AND principal_id = ?)",
        "DELETE FROM role_bindings WHERE principal_type = ? AND principal_id = ?",
        "DELETE FROM app_role_assignments WHERE principal_type = ? AND principal_id = ?",
        "DELETE FROM app_assignments WHERE principal_type = ? AND principal_id = ?",
    ] {
        sqlx::query(crate::db::sql_stmt(engine, sql))
            .bind(group)
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
    }
    // What it was, for the audit log and Find by id: its id is in old tokens and
    // audit entries, and would otherwise name nothing at all.
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO deleted_groups (id, tenant_id, name, description, deleted_at)
         SELECT id, tenant_id, name, description, ? FROM user_groups WHERE id = ?",
    ))
    .bind(now())
    .bind(group_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM user_groups WHERE id = ?"))
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// The id of a live account in this tenant, by user name.
async fn user_id_in(conn: &mut crate::db::Conn, tenant_id: &str, upn: &str) -> anyhow::Result<String> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id FROM users WHERE tenant_id = ? AND upn_folded = ? AND deleted_at IS NULL",
    ))
    .bind(tenant_id)
    .bind(crate::util::fold(upn))
    .fetch_optional(&mut *conn)
    .await?;
    let (id,) = row.with_context(|| format!("user '{upn}' not found"))?;
    Ok(id)
}

/// Record a membership. Already a member is success, and is looked for first:
/// inside a transaction a broken primary key would fail it (on Postgres, abort
/// it), so the key is the backstop against a race, not the check.
async fn insert_member_in(conn: &mut crate::db::Conn, group_id: &str, user_id: &str) -> anyhow::Result<()> {
    let held: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT group_id FROM group_members WHERE group_id = ? AND user_id = ?",
    ))
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    if held.is_some() {
        return Ok(());
    }
    crate::db::inserted(
        sqlx::query(crate::db::qc(
            conn,
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
        ))
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await,
    )?;
    Ok(())
}

// ---- groups inside groups ----
//
// `group_nesting` holds what an administrator did: "parent directly contains
// child". `group_closure` holds every group above every group, with the longest
// chain between them, and is what reads use, so finding a user's groups is one
// join and never a walk. The closure is never edited row by row: every change to
// the nesting rebuilds the rows of the groups it can affect, from the nesting, in
// the same transaction.
//
// Membership flows upward: a member of a group is also a member of every group
// that contains it, not of the groups inside it.
//
// Only the `groups` claim follows nesting. Assignment to applications, the roles
// it carries, and console role bindings count direct members only, as in Entra.

/// The most links allowed between the outermost and the innermost group of any
/// chain. A change that would make a longer chain is refused; nothing is ever
/// refused when reading.
pub const MAX_GROUP_NESTING_DEPTH: i64 = 8;

/// Every group a user is in: their direct groups and every group containing one
/// of them, in one fixed order (by name, then id).
///
/// The direct groups are read from `group_members` as well as through the
/// closure, so a missing closure row could only ever lose an inherited group,
/// never one the user was put in.
pub async fn effective_for_user<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let mut conn = db.acquire().await?;
    effective_for_user_in(&mut conn, user_id).await
}

pub(crate) async fn effective_for_user_in(conn: &mut crate::db::Conn, user_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT g.id, g.name FROM user_groups g
         WHERE g.id IN (SELECT group_id FROM group_members WHERE user_id = ?)
            OR g.id IN (SELECT c.ancestor_id FROM group_closure c
                        JOIN group_members m ON m.group_id = c.descendant_id
                        WHERE m.user_id = ?)
         ORDER BY g.name, g.id",
    ))
    .bind(user_id)
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|(id, name)| GroupRef { id, name }).collect())
}

/// How a user is in a group, for their page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub group: GroupRef,
    /// `None` when they were put in it; otherwise a group inside it that they
    /// are (directly or not) in, which is why they are in this one.
    pub via: Option<GroupRef>,
}

/// Every group a user is in, each saying whether directly or through which group.
pub async fn memberships_for_user<'c>(db: impl Handle<'c>, user_id: &str) -> anyhow::Result<Vec<Membership>> {
    let mut conn = db.acquire().await?;
    let direct = for_user_in(&mut conn, user_id).await?;
    let effective = effective_for_user_in(&mut conn, user_id).await?;
    let mut out = Vec::with_capacity(effective.len());
    for group in effective {
        if direct.iter().any(|d| d.id == group.id) {
            out.push(Membership { group, via: None });
            continue;
        }
        // A group directly inside this one that the user is also in. There is
        // one, since this group is above one of theirs; the first by name is shown.
        let children = member_groups_in(&mut conn, &group.id).await?;
        let mut via = None;
        for child in children {
            if is_effective_member_in(&mut conn, user_id, &child.id).await? {
                via = Some(GroupRef {
                    id: child.id,
                    name: child.name,
                });
                break;
            }
        }
        out.push(Membership { group, via });
    }
    Ok(out)
}

async fn is_effective_member_in(conn: &mut crate::db::Conn, user_id: &str, group_id: &str) -> anyhow::Result<bool> {
    let (n,): (i64,) = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT COUNT(*) FROM group_members m JOIN group_closure c ON c.descendant_id = m.group_id
         WHERE m.user_id = ? AND c.ancestor_id = ?",
    ))
    .bind(user_id)
    .bind(group_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// What the `groups` claim of a token for `sp_id` (the receiving application's
/// service principal, when it has one in the tenant) carries under `setting`.
pub async fn for_claim<'c>(
    db: impl Handle<'c>,
    setting: crate::apps::GroupMembershipClaims,
    sp_id: Option<&str>,
    user_id: &str,
) -> anyhow::Result<Vec<GroupRef>> {
    let mut conn = db.acquire().await?;
    for_claim_in(&mut conn, setting, sp_id, user_id).await
}

pub(crate) async fn for_claim_in(
    conn: &mut crate::db::Conn,
    setting: crate::apps::GroupMembershipClaims,
    sp_id: Option<&str>,
    user_id: &str,
) -> anyhow::Result<Vec<GroupRef>> {
    use crate::apps::GroupMembershipClaims as Claims;
    match (setting, sp_id) {
        (Claims::None, _) | (Claims::ApplicationGroup, None) => Ok(Vec::new()),
        (Claims::All, _) => effective_for_user_in(&mut *conn, user_id).await,
        (Claims::ApplicationGroup, Some(sp_id)) => {
            let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
                conn,
                "SELECT g.id, g.name FROM user_groups g
                 JOIN group_members m ON m.group_id = g.id
                 JOIN app_assignments a ON a.principal_id = g.id
                 WHERE m.user_id = ? AND a.resource_id = ? AND a.principal_type = ?
                 ORDER BY g.name, g.id",
            ))
            .bind(user_id)
            .bind(sp_id)
            .bind(crate::directory::PrincipalType::Group.as_str())
            .fetch_all(&mut *conn)
            .await?;
            Ok(rows.into_iter().map(|(id, name)| GroupRef { id, name }).collect())
        }
    }
}

/// A group directly inside another, as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberGroup {
    pub id: String,
    pub name: String,
    /// Its own direct members: live accounts, and groups.
    pub users: i64,
    pub groups: i64,
}

/// The groups directly inside `group_id`, by name.
pub async fn member_groups<'c>(db: impl Handle<'c>, group_id: &str) -> anyhow::Result<Vec<MemberGroup>> {
    let mut conn = db.acquire().await?;
    member_groups_in(&mut conn, group_id).await
}

pub(crate) async fn member_groups_in(conn: &mut crate::db::Conn, group_id: &str) -> anyhow::Result<Vec<MemberGroup>> {
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT g.id, g.name,
                (SELECT COUNT(*) FROM group_members m JOIN users u ON u.id = m.user_id
                 WHERE m.group_id = g.id AND u.deleted_at IS NULL),
                (SELECT COUNT(*) FROM group_nesting k WHERE k.parent_id = g.id)
         FROM group_nesting n JOIN user_groups g ON g.id = n.child_id
         WHERE n.parent_id = ? ORDER BY g.name, g.id",
    ))
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, users, groups)| MemberGroup {
            id,
            name,
            users,
            groups,
        })
        .collect())
}

/// The groups `group_id` is directly inside, by name.
pub async fn parent_groups<'c>(db: impl Handle<'c>, group_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let mut conn = db.acquire().await?;
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT g.id, g.name FROM group_nesting n JOIN user_groups g ON g.id = n.parent_id
         WHERE n.child_id = ? ORDER BY g.name, g.id",
    ))
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|(id, name)| GroupRef { id, name }).collect())
}

/// The groups of the tenant that could be put inside `group_id`: not itself, and
/// not one it is already inside (which would make a loop), by name. Whether the
/// chain would grow too long is left to the add, which says so.
pub async fn nestable_into<'c>(db: impl Handle<'c>, tenant_id: &str, group_id: &str) -> anyhow::Result<Vec<GroupRef>> {
    let mut conn = db.acquire().await?;
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT g.id, g.name FROM user_groups g
         WHERE g.tenant_id = ?
           AND g.id NOT IN (SELECT ancestor_id FROM group_closure WHERE descendant_id = ?)
           AND g.id NOT IN (SELECT child_id FROM group_nesting WHERE parent_id = ?)
         ORDER BY g.name, g.id",
    ))
    .bind(tenant_id)
    .bind(group_id)
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(id, _)| id != group_id)
        .map(|(id, name)| GroupRef { id, name })
        .collect())
}

/// The longest chain of links above `group_id` (0 when nothing contains it).
async fn depth_above_in(conn: &mut crate::db::Conn, group_id: &str) -> anyhow::Result<i64> {
    let (n,): (Option<i64>,) = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT MAX(depth) FROM group_closure WHERE descendant_id = ?",
    ))
    .bind(group_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n.unwrap_or(0))
}

/// The longest chain of links below `group_id` (0 when nothing is inside it).
async fn depth_below_in(conn: &mut crate::db::Conn, group_id: &str) -> anyhow::Result<i64> {
    let (n,): (Option<i64>,) = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT MAX(depth) FROM group_closure WHERE ancestor_id = ?",
    ))
    .bind(group_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n.unwrap_or(0))
}

/// Put `child_id` inside `parent_id`, both groups of `tenant_id`. `false` when it
/// already was. Refused when it would put a group inside itself, make a loop, or
/// make a chain longer than [`MAX_GROUP_NESTING_DEPTH`].
///
/// The caller holds the tenant's lock: two nestings that are each fine alone can
/// make a loop together, so they must not run side by side.
pub(crate) async fn add_member_group_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    parent_id: &str,
    child_id: &str,
) -> anyhow::Result<bool> {
    let parent = find_by_id_in(&mut *conn, tenant_id, parent_id)
        .await?
        .with_context(|| "there is no such group in this tenant".to_string())?;
    let child = find_by_id_in(&mut *conn, tenant_id, child_id)
        .await?
        .with_context(|| "there is no such group in this tenant".to_string())?;
    if parent.id == child.id {
        bail!("a group cannot be a member of itself");
    }
    let held: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT parent_id FROM group_nesting WHERE parent_id = ? AND child_id = ?",
    ))
    .bind(&parent.id)
    .bind(&child.id)
    .fetch_optional(&mut *conn)
    .await?;
    if held.is_some() {
        return Ok(false);
    }
    // A loop: the parent is already somewhere inside the child.
    let (inside,): (i64,) = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT COUNT(*) FROM group_closure WHERE ancestor_id = ? AND descendant_id = ?",
    ))
    .bind(&child.id)
    .bind(&parent.id)
    .fetch_one(&mut *conn)
    .await?;
    if inside > 0 {
        bail!(
            "{} is already inside {}; putting {} inside it would make a loop",
            parent.name,
            child.name,
            child.name
        );
    }
    let chain = depth_above_in(&mut *conn, &parent.id).await? + 1 + depth_below_in(&mut *conn, &child.id).await?;
    if chain > MAX_GROUP_NESTING_DEPTH {
        bail!(
            "putting {} inside {} would make a chain of {chain} nested groups; the limit is \
             {MAX_GROUP_NESTING_DEPTH}",
            child.name,
            parent.name
        );
    }
    crate::db::inserted(
        sqlx::query(crate::db::qc(
            conn,
            "INSERT INTO group_nesting (parent_id, child_id, tenant_id, created_at) VALUES (?, ?, ?, ?)",
        ))
        .bind(&parent.id)
        .bind(&child.id)
        .bind(tenant_id)
        .bind(now())
        .execute(&mut *conn)
        .await,
    )?;
    rebuild_closure_in(&mut *conn, tenant_id, &child.id).await?;
    Ok(true)
}

/// Take `child_id` out of `parent_id`. `false` when it was not inside it.
pub(crate) async fn remove_member_group_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    parent_id: &str,
    child_id: &str,
) -> anyhow::Result<bool> {
    if find_by_id_in(&mut *conn, tenant_id, parent_id).await?.is_none()
        || find_by_id_in(&mut *conn, tenant_id, child_id).await?.is_none()
    {
        return Ok(false);
    }
    let done = sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM group_nesting WHERE parent_id = ? AND child_id = ?",
    ))
    .bind(parent_id)
    .bind(child_id)
    .execute(&mut *conn)
    .await?;
    if done.rows_affected() == 0 {
        return Ok(false);
    }
    rebuild_closure_in(&mut *conn, tenant_id, child_id).await?;
    Ok(true)
}

/// Every group of the tenant's nesting, as "child -> its parents".
async fn parents_by_child_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
) -> anyhow::Result<std::collections::HashMap<String, Vec<String>>> {
    let edges: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT parent_id, child_id FROM group_nesting WHERE tenant_id = ?",
    ))
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut parents: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (parent, child) in edges {
        parents.entry(child).or_default().push(parent);
    }
    Ok(parents)
}

/// Every group above `group_id` with the longest chain to it, from the nesting
/// itself, including `group_id` at 0. Fails on a loop or a chain past the limit,
/// so a closure is never written from a nesting that breaks either rule.
pub fn ancestors_of(
    parents: &std::collections::HashMap<String, Vec<String>>,
    group_id: &str,
) -> anyhow::Result<std::collections::BTreeMap<String, i64>> {
    // Depth-first upward, keeping the path to spot a loop. The depth bound keeps
    // the walk finite even before the loop check would see one.
    fn walk(
        parents: &std::collections::HashMap<String, Vec<String>>,
        at: &str,
        depth: i64,
        path: &mut Vec<String>,
        out: &mut std::collections::BTreeMap<String, i64>,
    ) -> anyhow::Result<()> {
        if path.iter().any(|p| p == at) {
            bail!("the groups inside one another make a loop");
        }
        if depth > MAX_GROUP_NESTING_DEPTH {
            bail!("groups are nested more than {MAX_GROUP_NESTING_DEPTH} deep");
        }
        let best = out.entry(at.to_string()).or_insert(depth);
        *best = (*best).max(depth);
        path.push(at.to_string());
        for parent in parents.get(at).map(Vec::as_slice).unwrap_or_default() {
            walk(parents, parent, depth + 1, path, out)?;
        }
        path.pop();
        Ok(())
    }
    let mut out = std::collections::BTreeMap::new();
    walk(parents, group_id, 0, &mut Vec::new(), &mut out)?;
    Ok(out)
}

/// Rewrite the closure rows of `group_id` and every group inside it, the only
/// groups whose ancestors a change to the nesting just above `group_id` can
/// change. Computed afresh from the nesting, never patched.
async fn rebuild_closure_in(conn: &mut crate::db::Conn, tenant_id: &str, group_id: &str) -> anyhow::Result<()> {
    // Who is inside `group_id` does not change when only its own parents do, so
    // the closure's current answer is the right one.
    let below: Vec<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT descendant_id FROM group_closure WHERE ancestor_id = ?",
    ))
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut affected: Vec<String> = below.into_iter().map(|(id,)| id).collect();
    if !affected.iter().any(|id| id == group_id) {
        affected.push(group_id.to_string());
    }
    let parents = parents_by_child_in(&mut *conn, tenant_id).await?;
    for descendant in &affected {
        let ancestors = ancestors_of(&parents, descendant)?;
        sqlx::query(crate::db::qc(conn, "DELETE FROM group_closure WHERE descendant_id = ?"))
            .bind(descendant)
            .execute(&mut *conn)
            .await?;
        for (ancestor, depth) in ancestors {
            sqlx::query(crate::db::qc(
                conn,
                "INSERT INTO group_closure (ancestor_id, descendant_id, tenant_id, depth) VALUES (?, ?, ?, ?)",
            ))
            .bind(&ancestor)
            .bind(descendant)
            .bind(tenant_id)
            .bind(depth)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// The closure as the nesting says it should be, for every group of the tenant:
/// `(ancestor, descendant, depth)`, sorted. What a test compares the stored
/// closure against.
pub async fn closure_from_nesting<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
) -> anyhow::Result<Vec<(String, String, i64)>> {
    let mut conn = db.acquire().await?;
    let parents = parents_by_child_in(&mut conn, tenant_id).await?;
    let mut out = Vec::new();
    for g in list_in(&mut conn, tenant_id).await? {
        for (ancestor, depth) in ancestors_of(&parents, &g.id)? {
            out.push((ancestor, g.id.clone(), depth));
        }
    }
    out.sort();
    Ok(out)
}

/// The stored closure for every group of the tenant, sorted like
/// [`closure_from_nesting`].
pub async fn stored_closure<'c>(db: impl Handle<'c>, tenant_id: &str) -> anyhow::Result<Vec<(String, String, i64)>> {
    let mut conn = db.acquire().await?;
    let mut rows: Vec<(String, String, i64)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT ancestor_id, descendant_id, depth FROM group_closure WHERE tenant_id = ?",
    ))
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.sort();
    Ok(rows)
}
