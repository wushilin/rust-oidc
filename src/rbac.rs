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

/// Built-in roles.
///
/// One role is about the deployment and everything in it; the rest are about
/// what is inside a tenant, each either the whole tenant or one kind of object,
/// and each either an administrator (view and change) or a viewer (view only).
/// The role decides the shape of its scope: see [`RoleId::scope_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleId {
    /// Everything, outside tenants and inside every one of them.
    GlobalAdministrator,
    /// Everything inside the tenants it is granted in, and nothing outside them.
    TenantAdministrator,
    TenantViewer,
    UserAdministrator,
    UserViewer,
    GroupsAdministrator,
    GroupViewer,
    ApplicationAdministrator,
    ApplicationViewer,
}

use Resource::*;
use Verb::*;

/// Everything there is to view inside a tenant.
const VIEW_TENANT: &[Action] = &[
    Action::new(Tenant, Read),
    Action::new(User, Read),
    Action::new(Group, Read),
    Action::new(App, Read),
    Action::new(Assignment, Read),
    Action::new(RoleBinding, Read),
    Action::new(Audit, Read),
];

/// Everything there is to change inside a tenant.
const CHANGE_TENANT: &[Action] = &[
    Action::new(Tenant, Write),
    Action::new(User, Write),
    Action::new(User, Reset),
    Action::new(Group, Write),
    Action::new(App, Write),
    Action::new(App, Rotate),
    Action::new(Assignment, Write),
    Action::new(RoleBinding, Write),
];

/// What is about the deployment rather than any tenant.
const OUTSIDE_TENANTS: &[Action] = &[
    Action::new(Tenant, Create),
    Action::new(Tenant, Assume),
    Action::new(Key, Read),
    Action::new(Key, Rotate),
];

impl RoleId {
    pub const ALL: &'static [RoleId] = &[
        Self::GlobalAdministrator,
        Self::TenantAdministrator,
        Self::TenantViewer,
        Self::UserAdministrator,
        Self::UserViewer,
        Self::GroupsAdministrator,
        Self::GroupViewer,
        Self::ApplicationAdministrator,
        Self::ApplicationViewer,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalAdministrator => "GlobalAdministrator",
            Self::TenantAdministrator => "TenantAdministrator",
            Self::TenantViewer => "TenantViewer",
            Self::UserAdministrator => "UserAdministrator",
            Self::UserViewer => "UserViewer",
            Self::GroupsAdministrator => "GroupsAdministrator",
            Self::GroupViewer => "GroupViewer",
            Self::ApplicationAdministrator => "ApplicationAdministrator",
            Self::ApplicationViewer => "ApplicationViewer",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == raw)
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::GlobalAdministrator => "Global Administrator",
            Self::TenantAdministrator => "Tenant Administrator",
            Self::TenantViewer => "Tenant Viewer",
            Self::UserAdministrator => "User Administrator",
            Self::UserViewer => "User Viewer",
            Self::GroupsAdministrator => "Group Administrator",
            Self::GroupViewer => "Group Viewer",
            Self::ApplicationAdministrator => "Application Administrator",
            Self::ApplicationViewer => "Application Viewer",
        }
    }

    /// One line on what the role is for, shown where it is granted.
    pub fn summary(self) -> &'static str {
        match self {
            Self::GlobalAdministrator => "Everything: tenants, signing keys, and everything inside every tenant.",
            Self::TenantAdministrator => "Everything inside the tenant, including its settings, roles and audit log.",
            Self::TenantViewer => "Sees everything inside the tenant. Changes nothing.",
            Self::UserAdministrator => "Sees and changes users, including passwords.",
            Self::UserViewer => "Sees users. Changes nothing.",
            Self::GroupsAdministrator => "Sees and changes groups and who is in them.",
            Self::GroupViewer => "Sees groups. Changes nothing.",
            Self::ApplicationAdministrator => {
                "Sees and changes applications, their secrets and who is assigned to them, and runs the flow tester."
            }
            Self::ApplicationViewer => "Sees applications and who is assigned to them. Changes nothing.",
        }
    }

    /// The shape of scope this role is granted at, which is not a choice made per
    /// grant. `GlobalAdministrator` is everything and takes no list of tenants;
    /// every other role is about named tenants and is never "all of them".
    /// Enforced where bindings are written and read (`admin::bindings`).
    pub fn scope_kind(self) -> ScopeKind {
        match self {
            Self::GlobalAdministrator => ScopeKind::All,
            Self::TenantAdministrator
            | Self::TenantViewer
            | Self::UserAdministrator
            | Self::UserViewer
            | Self::GroupsAdministrator
            | Self::GroupViewer
            | Self::ApplicationAdministrator
            | Self::ApplicationViewer => ScopeKind::Tenants,
        }
    }

    /// The Entra directory role this one stands for in the `wids` claim of a
    /// tenant's tokens. A tenant's administrator is that directory's Global
    /// Administrator in Entra's terms, and its viewer the Global Reader. `None`
    /// for roles Entra has no counterpart of, which never appear in `wids`.
    pub fn template_id(self) -> Option<&'static str> {
        match self {
            Self::GlobalAdministrator | Self::TenantAdministrator => Some(directory::GLOBAL_ADMINISTRATOR),
            Self::TenantViewer => Some(directory::GLOBAL_READER),
            Self::UserAdministrator => Some(directory::USER_ADMINISTRATOR),
            Self::GroupsAdministrator => Some(directory::GROUPS_ADMINISTRATOR),
            Self::ApplicationAdministrator => Some(directory::APPLICATION_ADMINISTRATOR),
            Self::UserViewer | Self::GroupViewer | Self::ApplicationViewer => None,
        }
    }

    /// The role a tenant-scoped grant of an Entra directory role maps to.
    pub fn for_template_in_tenant(template_id: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|r| r.scope_kind() == ScopeKind::Tenants && r.template_id() == Some(template_id))
    }

    /// The one scope this role can be held at by a principal whose own tenant is
    /// `home`: the whole of the rule about where a role applies.
    ///
    /// `GlobalAdministrator` is everything, and belongs to the root tenant, where
    /// the people who run the deployment have their accounts. Every other role
    /// applies to the principal's own tenant and nowhere else, so there is never a
    /// tenant to choose when granting one. `None` means the principal cannot hold
    /// the role at all.
    pub fn scope_held_by(self, home: &str, home_is_root: bool) -> Option<Scope> {
        match self.scope_kind() {
            ScopeKind::All => home_is_root.then_some(Scope::All),
            ScopeKind::Tenants => Some(Scope::Tenants(vec![home.to_string()])),
        }
    }

    pub fn actions(self) -> Vec<Action> {
        let mut out: Vec<Action> = Vec::new();
        match self {
            Self::GlobalAdministrator => {
                out.extend_from_slice(VIEW_TENANT);
                out.extend_from_slice(CHANGE_TENANT);
                out.extend_from_slice(OUTSIDE_TENANTS);
            }
            Self::TenantAdministrator => {
                out.extend_from_slice(VIEW_TENANT);
                out.extend_from_slice(CHANGE_TENANT);
            }
            Self::TenantViewer => out.extend_from_slice(VIEW_TENANT),
            Self::UserAdministrator => out.extend_from_slice(&[
                Action::new(User, Read),
                Action::new(User, Write),
                Action::new(User, Reset),
            ]),
            Self::UserViewer => out.push(Action::new(User, Read)),
            Self::GroupsAdministrator => out.extend_from_slice(&[Action::new(Group, Read), Action::new(Group, Write)]),
            Self::GroupViewer => out.push(Action::new(Group, Read)),
            Self::ApplicationAdministrator => out.extend_from_slice(&[
                Action::new(App, Read),
                Action::new(App, Write),
                Action::new(App, Rotate),
                Action::new(Assignment, Read),
                Action::new(Assignment, Write),
            ]),
            Self::ApplicationViewer => out.extend_from_slice(&[Action::new(App, Read), Action::new(Assignment, Read)]),
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
        // A tenant's administrator runs the tenant, not the deployment.
        let b = [binding(RoleId::TenantAdministrator, Scope::Tenants(vec!["t1".into()]))];
        assert!(allowed(&b, Action::new(Resource::User, Verb::Write), "t1"));
        assert!(!allowed(&b, Action::new(Resource::Tenant, Verb::Create), "t1"));
        assert!(!allowed(&b, Action::new(Resource::Key, Verb::Read), "t1"));
        // A viewer reads and never writes.
        let r = [binding(RoleId::TenantViewer, Scope::Tenants(vec!["t1".into()]))];
        assert!(allowed(&r, Action::new(Resource::User, Verb::Read), "t1"));
        assert!(!allowed(&r, Action::new(Resource::User, Verb::Write), "t1"));
    }

    #[test]
    fn global_administrator_holds_every_action_any_role_holds() {
        let global = RoleId::GlobalAdministrator.actions();
        for role in RoleId::ALL {
            for action in role.actions() {
                assert!(global.contains(&action), "{role:?} {action:?}");
            }
        }
    }

    #[test]
    fn only_global_administrator_is_granted_at_every_tenant() {
        for role in RoleId::ALL {
            assert_eq!(
                role.scope_kind() == ScopeKind::All,
                *role == RoleId::GlobalAdministrator,
                "{role:?}"
            );
        }
    }

    #[test]
    fn a_viewer_holds_no_action_that_changes_anything() {
        for role in [
            RoleId::TenantViewer,
            RoleId::UserViewer,
            RoleId::GroupViewer,
            RoleId::ApplicationViewer,
        ] {
            assert!(role.actions().iter().all(|a| a.verb == Verb::Read), "{role:?}");
        }
    }

    #[test]
    fn the_narrow_roles_do_not_overlap() {
        let narrow = [
            (RoleId::UserAdministrator, RoleId::UserViewer),
            (RoleId::GroupsAdministrator, RoleId::GroupViewer),
            (RoleId::ApplicationAdministrator, RoleId::ApplicationViewer),
        ];
        for (i, (admin, viewer)) in narrow.iter().enumerate() {
            // Each viewer is its administrator's read half.
            for action in viewer.actions() {
                assert!(admin.actions().contains(&action), "{viewer:?} {action:?}");
            }
            // And no two kinds share an action.
            for (other, _) in narrow.iter().skip(i + 1) {
                for action in admin.actions() {
                    assert!(!other.actions().contains(&action), "{admin:?} {other:?} {action:?}");
                }
            }
        }
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
    fn roles_without_an_entra_counterpart_have_no_template_id() {
        assert!(RoleId::UserViewer.template_id().is_none());
        assert_eq!(
            RoleId::TenantAdministrator.template_id(),
            Some(crate::directory::GLOBAL_ADMINISTRATOR)
        );
        assert_eq!(
            RoleId::for_template_in_tenant(crate::directory::GLOBAL_ADMINISTRATOR),
            Some(RoleId::TenantAdministrator)
        );
    }

    #[test]
    fn a_role_is_held_at_exactly_one_scope() {
        assert_eq!(
            RoleId::GlobalAdministrator.scope_held_by("root", true),
            Some(Scope::All)
        );
        assert_eq!(RoleId::GlobalAdministrator.scope_held_by("t1", false), None);
        for role in RoleId::ALL.iter().filter(|r| **r != RoleId::GlobalAdministrator) {
            for is_root in [true, false] {
                assert_eq!(
                    role.scope_held_by("t1", is_root),
                    Some(Scope::Tenants(vec!["t1".into()])),
                    "{role:?}"
                );
            }
        }
    }

    #[test]
    fn role_ids_round_trip() {
        for role in RoleId::ALL {
            assert_eq!(RoleId::parse(role.as_str()), Some(*role));
        }
    }

    #[test]
    fn what_is_outside_tenants_is_held_by_global_administrator_alone() {
        for role in RoleId::ALL {
            for action in OUTSIDE_TENANTS {
                assert_eq!(
                    role.actions().contains(action),
                    *role == RoleId::GlobalAdministrator,
                    "{role:?} {action:?}"
                );
            }
        }
    }

    #[test]
    fn scope_kinds_round_trip() {
        for kind in [ScopeKind::All, ScopeKind::Tenants] {
            assert_eq!(ScopeKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ScopeKind::parse("bogus"), None);
        assert_eq!(Scope::All.kind(), ScopeKind::All);
        assert_eq!(Scope::Tenants(vec![]).kind(), ScopeKind::Tenants);
    }

    #[test]
    fn allowed_at_all_scope_requires_an_all_binding() {
        let action = Action::new(Resource::User, Verb::Write);
        let all = [binding(RoleId::UserAdministrator, Scope::All)];
        let some = [binding(RoleId::UserAdministrator, Scope::Tenants(vec!["t1".into()]))];
        assert!(allowed_at_all_scope(&all, action));
        assert!(!allowed_at_all_scope(&some, action));
        // Right scope, wrong role.
        let wrong = [binding(RoleId::UserViewer, Scope::All)];
        assert!(!allowed_at_all_scope(&wrong, action));
    }
}
