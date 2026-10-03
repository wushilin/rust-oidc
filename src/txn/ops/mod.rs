//! The transactions themselves, by what they change.
//!
//! Each is a struct whose fields are its parameters. Its `run` does the checks
//! and the writes on the context's connection, through the storage layer's
//! `_in` functions, and aborts only through the context.

pub mod apps;
pub mod groups;
pub mod self_service;
pub mod tenants;
pub mod users;

use super::{Cx, Refusal, Step};
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

/// A live account of the tenant, or abort.
pub(crate) async fn user(cx: &mut Cx<'_>, tenant_id: &str, account: &Account) -> Step<User> {
    let found = match account {
        Account::Id(id) => crate::users::find_in(cx.conn(), tenant_id, id).await,
        Account::Upn(upn) => crate::users::find_by_upn_in(cx.conn(), tenant_id, upn).await,
    };
    match cx.check(found)? {
        Some(u) => Ok(u),
        None => Err(cx.fail(Refusal::NotFound(NO_SUCH_ACCOUNT.into()))),
    }
}
