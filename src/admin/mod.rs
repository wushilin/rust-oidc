//! The admin console: RBAC storage, session, authorization gate and pages.
//!
//! Everything the console can do is one of the [`Action`]s below, checked by
//! [`context::AdminContext::require`] against the signed-in administrator's
//! effective bindings. They are named here, once, so a handler cannot assemble a
//! different action than the nav entry that offered it.

pub mod apps;
pub mod audit;
pub mod authz;
pub mod bindings;
pub mod context;
pub mod find;
pub mod flow;
pub mod groups;
pub mod keys;
pub mod lockout;
pub mod platform_roles;
pub mod roles;
pub mod routes;
pub mod session;
pub mod settings;
pub mod tenants;
pub mod users;
pub mod view;

use crate::rbac::{Action, Resource, Verb};

pub const TENANT_READ: Action = Action::new(Resource::Tenant, Verb::Read);
pub const TENANT_CREATE: Action = Action::new(Resource::Tenant, Verb::Create);
/// Renaming, enabling and disabling a tenant, its verified domains, and its
/// settings. The design spec's wording: "change tenant settings and domains".
pub const TENANT_WRITE: Action = Action::new(Resource::Tenant, Verb::Write);
pub const TENANT_ASSUME: Action = Action::new(Resource::Tenant, Verb::Assume);
pub const USER_READ: Action = Action::new(Resource::User, Verb::Read);
pub const USER_WRITE: Action = Action::new(Resource::User, Verb::Write);
pub const USER_RESET: Action = Action::new(Resource::User, Verb::Reset);
pub const GROUP_READ: Action = Action::new(Resource::Group, Verb::Read);
pub const GROUP_WRITE: Action = Action::new(Resource::Group, Verb::Write);
pub const APP_READ: Action = Action::new(Resource::App, Verb::Read);
/// An app registration and everything about it *except* its credentials: URIs,
/// scopes, roles and the grant flags.
pub const APP_WRITE: Action = Action::new(Resource::App, Verb::Write);
/// Credentials: client secrets and certificate key credentials.
pub const APP_ROTATE: Action = Action::new(Resource::App, Verb::Rotate);
pub const ASSIGNMENT_READ: Action = Action::new(Resource::Assignment, Verb::Read);
pub const ASSIGNMENT_WRITE: Action = Action::new(Resource::Assignment, Verb::Write);
pub const BINDING_READ: Action = Action::new(Resource::RoleBinding, Verb::Read);
pub const BINDING_WRITE: Action = Action::new(Resource::RoleBinding, Verb::Write);
pub const KEY_READ: Action = Action::new(Resource::Key, Verb::Read);
/// Rotating the signing keys, and pruning the retired ones: there is no
/// `Key:Prune` verb, and inventing one would mean widening a role to hold it.
/// Both are the same platform-scope key lifecycle. Recorded in
/// `docs/decisions-log.md`.
pub const KEY_ROTATE: Action = Action::new(Resource::Key, Verb::Rotate);
pub const AUDIT_READ: Action = Action::new(Resource::Audit, Verb::Read);
