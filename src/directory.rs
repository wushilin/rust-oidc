//! Built-in directory roles. Template ids are Microsoft's well-known GUIDs, so
//! apps that check the `wids` claim behave the same as against Entra ID.

use crate::db::DbPool;

pub struct DirectoryRole {
    pub template_id: &'static str,
    pub name: &'static str,
}

pub const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";

pub const ROLES: &[DirectoryRole] = &[
    DirectoryRole {
        template_id: GLOBAL_ADMINISTRATOR,
        name: "Global Administrator",
    },
    DirectoryRole {
        template_id: "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
        name: "Global Reader",
    },
    DirectoryRole {
        template_id: "fe930be7-5e62-47db-91af-98c3a49a38b1",
        name: "User Administrator",
    },
    DirectoryRole {
        template_id: "fdd7a751-b60b-444a-984c-02652fe8fa1c",
        name: "Groups Administrator",
    },
    DirectoryRole {
        template_id: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
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
