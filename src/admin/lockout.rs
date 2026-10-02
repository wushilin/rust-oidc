//! Nobody may be left unable to administer the deployment.
//!
//! A Global Administrator is the only one who can create a tenant, enter one, or
//! make another Global Administrator, and the console is the only admin surface.
//! So the last *person* who can sign in as one must not be removed -- by whatever
//! route: revoking the role, deleting or disabling the account, taking them out
//! of the group that holds the role, or deleting that group.
//!
//! The rule is about people, not rows, so it is not checked per page or per kind
//! of change. Every storage function that could remove one counts them inside its
//! transaction before and after its change, and fails the transaction if it took
//! the last one away.

use crate::db::Engine;
use crate::directory::PrincipalType;
use crate::rbac::{RoleId, ScopeKind};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("That would leave nobody who can sign in as a Global Administrator. Make somebody else one first.")]
pub struct WouldLockOut;

/// How many accounts can sign in and act as Global Administrator right now: live,
/// enabled accounts of the root tenant that hold the role themselves or through
/// a group they belong to.
pub async fn global_administrators(conn: &mut sqlx::AnyConnection, engine: Engine) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT COUNT(*) FROM users u JOIN tenants t ON t.id = u.tenant_id
         WHERE u.deleted_at IS NULL AND u.enabled = ? AND t.is_root = ? AND t.deleted_at IS NULL
           AND (u.id IN (SELECT b.principal_id FROM role_bindings b
                         WHERE b.principal_type = ? AND b.role_id = ? AND b.scope_kind = ?)
             OR u.id IN (SELECT gm.user_id FROM group_members gm
                         JOIN role_bindings b ON b.principal_id = gm.group_id
                         WHERE b.principal_type = ? AND b.role_id = ? AND b.scope_kind = ?))",
    ))
    .bind(true)
    .bind(true)
    .bind(PrincipalType::User.as_str())
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind(ScopeKind::All.as_str())
    .bind(PrincipalType::Group.as_str())
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind(ScopeKind::All.as_str())
    .fetch_one(&mut *conn)
    .await?;
    Ok(count)
}

/// Fail unless somebody is still a Global Administrator, given that `before`
/// were when the transaction began. A deployment that had none to begin with
/// (not bootstrapped yet) is not made worse by anything, so nothing is refused.
pub async fn ensure_one_remains(conn: &mut sqlx::AnyConnection, engine: Engine, before: i64) -> anyhow::Result<()> {
    if before > 0 && global_administrators(conn, engine).await? == 0 {
        return Err(WouldLockOut.into());
    }
    Ok(())
}
