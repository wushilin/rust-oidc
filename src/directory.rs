//! Built-in directory roles. Template ids are Microsoft's well-known GUIDs, so
//! apps that check the `wids` claim behave the same as against Entra ID.

use crate::db::DbPool;

/// What kind of directory object a principal is: the `principal_type` column of
/// `app_role_assignments` and of `role_bindings`.
///
/// One enum for both tables even though their value sets differ: a console role
/// binding may name only a user or a group (a service principal cannot use the
/// console), and `admin::bindings::create` refuses `ServicePrincipal` rather than
/// a second near-identical enum existing. The names are Entra's own, as Graph
/// spells them in `appRoleAssignment.principalType`.
///
/// Not to be confused with [`crate::apps::Principal`], which is how the command
/// line *names* a principal (by appId, UPN or group name) before it is resolved
/// to an id and a `PrincipalType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Group,
    ServicePrincipal,
}

impl PrincipalType {
    pub const ALL: &'static [PrincipalType] = &[Self::User, Self::Group, Self::ServicePrincipal];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::ServicePrincipal => "ServicePrincipal",
        }
    }

    /// A value read back from a stored row. `None` for anything this build does
    /// not know: a row written by a newer build must not be misread as one of
    /// ours, and the caller decides what an unknown principal type means (every
    /// caller here treats it as granting nothing).
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }
}

pub struct DirectoryRole {
    pub template_id: &'static str,
    pub name: &'static str,
}

pub const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";
pub const GLOBAL_READER: &str = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
pub const USER_ADMINISTRATOR: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
pub const GROUPS_ADMINISTRATOR: &str = "fdd7a751-b60b-444a-984c-02652fe8fa1c";
pub const APPLICATION_ADMINISTRATOR: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";

pub const ROLES: &[DirectoryRole] = &[
    DirectoryRole {
        template_id: GLOBAL_ADMINISTRATOR,
        name: "Global Administrator",
    },
    DirectoryRole {
        template_id: GLOBAL_READER,
        name: "Global Reader",
    },
    DirectoryRole {
        template_id: USER_ADMINISTRATOR,
        name: "User Administrator",
    },
    DirectoryRole {
        template_id: GROUPS_ADMINISTRATOR,
        name: "Groups Administrator",
    },
    DirectoryRole {
        template_id: APPLICATION_ADMINISTRATOR,
        name: "Application Administrator",
    },
    DirectoryRole {
        template_id: "158c047a-c907-4556-b7ef-446551a6b5f7",
        name: "Cloud Application Administrator",
    },
    DirectoryRole {
        template_id: "e8611ab8-c189-46e8-94e1-60213ab1f814",
        name: "Privileged Role Administrator",
    },
];

pub fn find(name_or_id: &str) -> Option<&'static DirectoryRole> {
    ROLES
        .iter()
        .find(|r| r.template_id.eq_ignore_ascii_case(name_or_id) || r.name.eq_ignore_ascii_case(name_or_id))
}

/// `wids`: the directory roles this user holds in `tenant_id`, derived from role
/// bindings. Roles without a Microsoft template id (ours alone) are not `wids`.
pub async fn wids_for_user(pool: &DbPool, tenant_id: &str, user_id: &str) -> anyhow::Result<Vec<String>> {
    let bindings = crate::admin::bindings::effective_for_user(pool, user_id).await?;
    let mut out: Vec<String> = bindings
        .iter()
        .filter(|b| b.scope.covers(tenant_id))
        .filter_map(|b| b.role.template_id())
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}
