//! The transactions themselves, by what they change.
//!
//! Each is a struct whose fields are its parameters. Its `run` does the checks
//! and the writes on the context's connection, through the storage layer's
//! `_in` functions, and aborts only through the context.

pub mod apps;
pub mod bootstrap;
pub mod flow;
pub mod groups;
pub mod keys;
pub mod roles;
pub mod self_service;
pub mod tenants;
pub mod users;

use super::{Cx, Refusal, Step};
use crate::admin::authz::{self, BindingWriter};
use crate::tenant::Tenant;
use crate::users::User;

/// How a transaction names an account: the console has its id, the command line
/// its user name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Account {
    Id(String),
    Upn(String),
}

/// What a refusal says when the account named is not a live one of the tenant.
pub(crate) const NO_SUCH_ACCOUNT: &str = "There is no such account in this tenant.";

/// The tenant, live and enabled, or abort.
pub(crate) async fn tenant(cx: &mut Cx<'_>, tenant_id: &str) -> Step<Tenant> {
    let found = crate::tenant::resolve_in(cx.conn(), tenant_id).await;
    match cx.check(found)? {
        Some(t) if t.id == tenant_id => Ok(t),
        _ => Err(cx.fail(Refusal::NotFound("There is no such tenant.".into()))),
    }
}

/// Abort unless the actor may change this account, which holds console roles
/// the actor would have to be able to grant ([`authz::may_change_account_in`]).
pub(crate) async fn may_change_account(cx: &mut Cx<'_>, user_id: &str) -> Step<()> {
    let actor = cx.actor().clone();
    let permitted = authz::may_change_account_in(cx.conn(), BindingWriter::of(&actor), user_id).await;
    let permitted = cx.check(permitted)?;
    cx.ensure(permitted, || Refusal::NotPermitted)
}

/// Abort unless the actor may change who is in this group, which holds console
/// roles the actor would have to be able to grant ([`authz::may_change_members_in`]).
pub(crate) async fn may_change_members(cx: &mut Cx<'_>, group_id: &str) -> Step<()> {
    let actor = cx.actor().clone();
    let permitted = authz::may_change_members_in(cx.conn(), BindingWriter::of(&actor), group_id).await;
    let permitted = cx.check(permitted)?;
    cx.ensure(permitted, || Refusal::NotPermitted)
}

/// A live account of the tenant, or abort.
pub(crate) async fn user(cx: &mut Cx<'_>, tenant_id: &str, account: &Account) -> Step<User> {
    let found = match account {
        Account::Id(id) => crate::users::find_in(cx.conn(), tenant_id, id).await,
        Account::Upn(upn) => crate::users::find_by_upn_in(cx.conn(), tenant_id, upn).await,
    };
    match (cx.check(found)?, account) {
        (Some(u), _) => Ok(u),
        // Named by the person asking, so the refusal names it back.
        (None, Account::Upn(upn)) => Err(cx.fail(Refusal::NotFound(format!(
            "User '{}' not found in this tenant.",
            crate::routes::audit::clip(upn)
        )))),
        (None, Account::Id(_)) => Err(cx.fail(Refusal::NotFound(NO_SUCH_ACCOUNT.into()))),
    }
}
