//! The admin console: RBAC storage, session, authorization gate and pages.
//!
//! Everything the console can do is one of the [`Action`]s below, checked by
//! [`context::AdminContext::require`] against the signed-in administrator's
//! effective bindings. They are named here, once, so a handler cannot assemble a
//! different action than the nav entry that offered it.

pub mod authz;
pub mod bindings;
pub mod context;
pub mod roles;
pub mod routes;
pub mod session;
pub mod users;
pub mod view;

use crate::rbac::{Action, Resource, Verb};

pub const TENANT_READ: Action = Action::new(Resource::Tenant, Verb::Read);
pub const TENANT_ASSUME: Action = Action::new(Resource::Tenant, Verb::Assume);
pub const USER_READ: Action = Action::new(Resource::User, Verb::Read);
pub const USER_WRITE: Action = Action::new(Resource::User, Verb::Write);
pub const USER_RESET: Action = Action::new(Resource::User, Verb::Reset);
pub const GROUP_READ: Action = Action::new(Resource::Group, Verb::Read);
pub const BINDING_READ: Action = Action::new(Resource::RoleBinding, Verb::Read);
pub const BINDING_WRITE: Action = Action::new(Resource::RoleBinding, Verb::Write);
