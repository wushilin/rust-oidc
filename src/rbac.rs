//! Role-based access control for the admin console.
//!
//! A role carries **actions**; a binding carries the **scope**. The grant is the
//! product of the two. `allowed` is the only place scope is interpreted — no
//! handler compares tenant ids or branches on role names.

use crate::directory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Tenant,
    User,
    Group,
    App,
    Assignment,
    RoleBinding,
    Key,
    Audit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Read,
    Write,
    Create,
    Reset,
    Rotate,
    Assume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    pub resource: Resource,
    pub verb: Verb,
}

impl Action {
    pub const fn new(resource: Resource, verb: Verb) -> Self {
        Self { resource, verb }
    }
}

/// Built-in roles. Those that exist in Entra keep Microsoft's template GUID so
/// the `wids` claim stays faithful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleId {
    GlobalAdministrator,
    GlobalReader,
    UserAdministrator,
    GroupsAdministrator,
    ApplicationAdministrator,
    CloudApplicationAdministrator,
    PrivilegedRoleAdministrator,
    PlatformAdministrator,
}

use Resource::*;
use Verb::*;

const READ_ALL: &[Action] = &[
    Action::new(Tenant, Read),
    Action::new(User, Read),
    Action::new(Group, Read),
    Action::new(App, Read),
    Action::new(Assignment, Read),
    Action::new(RoleBinding, Read),
    Action::new(Key, Read),
    Action::new(Audit, Read),
];

impl RoleId {
    pub const ALL: &'static [RoleId] = &[
        Self::GlobalAdministrator,
        Self::GlobalReader,
        Self::UserAdministrator,
        Self::GroupsAdministrator,
        Self::ApplicationAdministrator,
        Self::CloudApplicationAdministrator,
        Self::PrivilegedRoleAdministrator,
        Self::PlatformAdministrator,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalAdministrator => "GlobalAdministrator",
            Self::GlobalReader => "GlobalReader",
            Self::UserAdministrator => "UserAdministrator",
            Self::GroupsAdministrator => "GroupsAdministrator",
            Self::ApplicationAdministrator => "ApplicationAdministrator",
            Self::CloudApplicationAdministrator => "CloudApplicationAdministrator",
            Self::PrivilegedRoleAdministrator => "PrivilegedRoleAdministrator",
            Self::PlatformAdministrator => "PlatformAdministrator",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == raw)
    }

    /// Human-readable name, matching Entra's where one exists.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::GlobalAdministrator => "Global Administrator",
            Self::GlobalReader => "Global Reader",
            Self::UserAdministrator => "User Administrator",
            Self::GroupsAdministrator => "Groups Administrator",
            Self::ApplicationAdministrator => "Application Administrator",
            Self::CloudApplicationAdministrator => "Cloud Application Administrator",
            Self::PrivilegedRoleAdministrator => "Privileged Role Administrator",
            Self::PlatformAdministrator => "Platform Administrator",
        }
    }

    /// Microsoft's well-known GUID, for roles Entra also has. `None` means the
    /// role is ours alone and must never appear in `wids`.
    pub fn template_id(self) -> Option<&'static str> {
        match self {
            Self::GlobalAdministrator => Some(directory::GLOBAL_ADMINISTRATOR),
            Self::GlobalReader => Some("f2ef992c-3afb-46b9-b7cf-a126ee74c451"),
            Self::UserAdministrator => Some("fe930be7-5e62-47db-91af-98c3a49a38b1"),
            Self::GroupsAdministrator => Some("fdd7a751-b60b-444a-984c-02652fe8fa1c"),
            Self::ApplicationAdministrator => Some("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"),
            Self::CloudApplicationAdministrator => Some("158c047a-c907-4556-b7ef-446551a6b5f7"),
            Self::PrivilegedRoleAdministrator => Some("e8611ab8-c189-46e8-94e1-60213ab1f814"),
            Self::PlatformAdministrator => None,
        }
    }

    pub fn actions(self) -> Vec<Action> {
        let mut out: Vec<Action> = Vec::new();
        match self {
            Self::GlobalAdministrator => {
                out.extend_from_slice(READ_ALL);
                out.extend_from_slice(&[
                    Action::new(Tenant, Write),
                    Action::new(User, Write),
                    Action::new(User, Reset),
                    Action::new(Group, Write),
                    Action::new(App, Write),
                    Action::new(App, Rotate),
                    Action::new(Assignment, Write),
                    Action::new(RoleBinding, Write),
                ]);
            }
            Self::GlobalReader => out.extend_from_slice(READ_ALL),
            Self::UserAdministrator => out.extend_from_slice(&[
                Action::new(User, Read),
                Action::new(User, Write),
                Action::new(User, Reset),
                Action::new(Group, Read),
                Action::new(Audit, Read),
            ]),
            Self::GroupsAdministrator => out.extend_from_slice(&[
                Action::new(Group, Read),
                Action::new(Group, Write),
                Action::new(User, Read),
                Action::new(Audit, Read),
            ]),
            Self::ApplicationAdministrator => out.extend_from_slice(&[
                Action::new(App, Read),
                Action::new(App, Write),
                Action::new(App, Rotate),
                Action::new(Assignment, Read),
                Action::new(Assignment, Write),
                Action::new(Audit, Read),
            ]),
            Self::CloudApplicationAdministrator => out.extend_from_slice(&[
                Action::new(App, Read),
                Action::new(App, Write),
                Action::new(Assignment, Read),
                Action::new(Assignment, Write),
                Action::new(Audit, Read),
            ]),
            Self::PrivilegedRoleAdministrator => out.extend_from_slice(&[
                Action::new(RoleBinding, Read),
                Action::new(RoleBinding, Write),
                Action::new(Assignment, Read),
                Action::new(Assignment, Write),
                Action::new(Audit, Read),
            ]),
            Self::PlatformAdministrator => out.extend_from_slice(&[
                Action::new(Tenant, Read),
                Action::new(Tenant, Create),
                Action::new(Tenant, Write),
                Action::new(Tenant, Assume),
                Action::new(Key, Read),
                Action::new(Key, Rotate),
                Action::new(Audit, Read),
            ]),
        }
        out
    }
}

/// Where a binding applies. `All` is the `[*]` case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    All,
    Tenants(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    All,
    Tenants,
}

impl ScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Tenants => "tenants",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "all" => Some(Self::All),
            "tenants" => Some(Self::Tenants),
            _ => None,
        }
    }
}

impl Scope {
    pub fn kind(&self) -> ScopeKind {
        match self {
            Self::All => ScopeKind::All,
            Self::Tenants(_) => ScopeKind::Tenants,
        }
    }

    /// `tenant_id` must already be canonical (a tenant GUID), never a URL alias.
    pub fn covers(&self, tenant_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Tenants(ids) => ids.iter().any(|t| t == tenant_id),
        }
    }
}

/// A role granted at a scope, after group expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveBinding {
    pub role: RoleId,
    pub scope: Scope,
}

/// The whole of the authorization rule.
pub fn allowed(bindings: &[EffectiveBinding], action: Action, tenant_id: &str) -> bool {
    bindings
        .iter()
        .any(|b| b.scope.covers(tenant_id) && b.role.actions().contains(&action))
}

/// True when the principal holds `action` at `All` scope. Used by the
/// no-widening rule when a new `All`-scope binding is requested.
pub fn allowed_at_all_scope(bindings: &[EffectiveBinding], action: Action) -> bool {
    bindings
        .iter()
        .any(|b| b.scope == Scope::All && b.role.actions().contains(&action))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(role: RoleId, scope: Scope) -> EffectiveBinding {
        EffectiveBinding { role, scope }
    }

    #[test]
    fn all_scope_covers_every_tenant() {
        let b = [binding(RoleId::GlobalAdministrator, Scope::All)];
        assert!(allowed(&b, Action::new(Resource::User, Verb::Write), "t1"));
        assert!(allowed(&b, Action::new(Resource::User, Verb::Write), "t9"));
    }

    #[test]
    fn tenant_scope_covers_only_listed_tenants() {
        let b = [binding(
            RoleId::GlobalAdministrator,
            Scope::Tenants(vec!["t1".into(), "t2".into()]),
        )];
        assert!(allowed(&b, Action::new(Resource::User, Verb::Write), "t1"));
        assert!(!allowed(&b, Action::new(Resource::User, Verb::Write), "t3"));
    }

    #[test]
    fn role_limits_actions_independently_of_scope() {
        // Global Administrator is broad but cannot create tenants.
        let b = [binding(RoleId::GlobalAdministrator, Scope::All)];
        assert!(!allowed(&b, Action::new(Resource::Tenant, Verb::Create), "t1"));
        // Global Reader can read but never write, even at all scope.
        let r = [binding(RoleId::GlobalReader, Scope::All)];
        assert!(allowed(&r, Action::new(Resource::User, Verb::Read), "t1"));
        assert!(!allowed(&r, Action::new(Resource::User, Verb::Write), "t1"));
    }

    #[test]
    fn platform_administrator_holds_the_platform_actions() {
        let b = [binding(RoleId::PlatformAdministrator, Scope::All)];
        for verb in [Verb::Create, Verb::Assume] {
            assert!(allowed(&b, Action::new(Resource::Tenant, verb), "t1"), "{verb:?}");
        }
        assert!(allowed(&b, Action::new(Resource::Key, Verb::Rotate), "t1"));
    }

    #[test]
    fn several_bindings_union_their_grants() {
        let b = [
            binding(RoleId::UserAdministrator, Scope::Tenants(vec!["t1".into()])),
            binding(RoleId::GroupsAdministrator, Scope::Tenants(vec!["t2".into()])),
        ];
        assert!(allowed(&b, Action::new(Resource::User, Verb::Write), "t1"));
        assert!(!allowed(&b, Action::new(Resource::User, Verb::Write), "t2"));
        assert!(allowed(&b, Action::new(Resource::Group, Verb::Write), "t2"));
    }

    #[test]
    fn platform_administrator_has_no_template_id() {
        assert!(RoleId::PlatformAdministrator.template_id().is_none());
        assert_eq!(
            RoleId::GlobalAdministrator.template_id(),
            Some(crate::directory::GLOBAL_ADMINISTRATOR)
        );
    }

    #[test]
    fn role_ids_round_trip() {
        for role in RoleId::ALL {
            assert_eq!(RoleId::parse(role.as_str()), Some(*role));
        }
    }
}
