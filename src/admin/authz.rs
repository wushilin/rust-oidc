//! Authorization rules that are about more than one tenant at a time.
//!
//! Everything else in the console authorizes one action against one tenant, which
//! [`crate::rbac::allowed`] answers. Two rules do not fit that shape, and both are
//! about role bindings themselves:
//!
//! - **No widening.** A binding write is checked against the *target* binding's
//!   scope, so no principal can grant reach it does not already hold.
//! - **No lock-out.** The last binding that can administer the platform cannot be
//!   removed, or nobody can create a tenant or assume one ever again.

use anyhow::Context;

use crate::db::DbPool;
use crate::rbac::{Action, EffectiveBinding, Resource, RoleId, Scope, ScopeKind, Verb, allowed, allowed_at_all_scope};

const WRITE_BINDING: Action = Action::new(Resource::RoleBinding, Verb::Write);

/// Whether `bindings` may create or delete a binding whose scope is `target`.
///
/// Checked against the target's scope, not the actor's, which is what stops a
/// tenant-scoped admin from minting themselves a wider one. Every tenant in the
/// target must be covered: a partial overlap is still a widening.
pub fn may_write_binding(bindings: &[EffectiveBinding], target: &Scope) -> bool {
    match target {
        // Only a principal that already holds the action everywhere may grant it
        // everywhere. `allowed` would be satisfied by any single tenant.
        Scope::All => allowed_at_all_scope(bindings, WRITE_BINDING),
        // An empty scope grants nothing and is far more likely a bug than intent.
        Scope::Tenants(ids) if ids.is_empty() => false,
        Scope::Tenants(ids) => ids.iter().all(|t| allowed(bindings, WRITE_BINDING, t)),
    }
}

/// Why a binding delete was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum RefusedReason {
    /// No such binding, or the caller may not write at that scope.
    NotPermitted,
    /// Removing it would leave nobody able to administer the platform.
    WouldLockOut,
}

/// Refuse a delete that would leave the platform with no administrator.
///
/// Only `GlobalAdministrator` can create a tenant or assume one,
/// so the last such binding is load-bearing: without it the console can still be
/// signed into but no tenant can ever be added or entered again, and there is no
/// CLI to repair it (the console is deliberately web-only).
///
/// **What this does not check.** It counts bindings, not reachable humans. A
/// binding to a group with no members, or to a disabled or soft-deleted user,
/// counts as one. So this prevents the obvious lock-out, not every lock-out;
/// tightening it means joining `users` and `group_members` and deciding what
/// "reachable" means, which is a product question. Recorded in
/// `docs/decisions-log.md`.
pub async fn check_delete(pool: &DbPool, binding_id: &str) -> Result<(), RefusedReason> {
    let row: Option<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT role_id, scope_kind FROM role_bindings WHERE id = ?",
    ))
    .bind(binding_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| RefusedReason::NotPermitted)?;
    let Some((role, scope_kind)) = row else {
        return Err(RefusedReason::NotPermitted);
    };
    // Anything that is not a Global Administrator binding cannot be
    // the last thing holding the platform up.
    if role != RoleId::GlobalAdministrator.as_str() || scope_kind != ScopeKind::All.as_str() {
        return Ok(());
    }
    let (count,): (i64,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT COUNT(*) FROM role_bindings WHERE role_id = ? AND scope_kind = ?",
    ))
    .bind(RoleId::GlobalAdministrator.as_str())
    .bind(ScopeKind::All.as_str())
    .fetch_one(pool)
    .await
    .map_err(|_| RefusedReason::NotPermitted)?;
    if count <= 1 {
        Err(RefusedReason::WouldLockOut)
    } else {
        Ok(())
    }
}

/// Delete a binding, having checked both rules. The one entry point a handler
/// should use, so neither rule can be forgotten at a call site.
pub async fn delete(pool: &DbPool, actor: &[EffectiveBinding], binding_id: &str) -> Result<(), RefusedReason> {
    let target = target_scope(pool, binding_id)
        .await
        .map_err(|_| RefusedReason::NotPermitted)?;
    if !may_write_binding(actor, &target) {
        return Err(RefusedReason::NotPermitted);
    }
    check_delete(pool, binding_id).await?;
    match crate::admin::bindings::delete(pool, binding_id).await {
        Ok(true) => Ok(()),
        // Gone between the check and the delete: the end state is the one asked
        // for, so this is not an error the caller needs to distinguish.
        Ok(false) => Ok(()),
        // The rule about people rather than rows: the last account that can act
        // as Global Administrator, held directly or through a group.
        Err(err) if err.downcast_ref::<crate::admin::lockout::WouldLockOut>().is_some() => {
            Err(RefusedReason::WouldLockOut)
        }
        Err(_) => Err(RefusedReason::NotPermitted),
    }
}

/// The scope of an existing binding, for authorizing a write against it.
async fn target_scope(pool: &DbPool, binding_id: &str) -> anyhow::Result<Scope> {
    let all = crate::admin::bindings::list_all(pool).await?;
    all.into_iter()
        .find(|b| b.id == binding_id)
        .map(|b| b.scope)
        .context("no such binding")
}
