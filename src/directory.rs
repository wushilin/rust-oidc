//! Built-in directory roles. Template ids are Microsoft's well-known GUIDs, so
//! apps that check the `wids` claim behave the same as against Entra ID.

use anyhow::bail;
use sqlx::SqlitePool;

use crate::util::now;

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

pub async fn assign(
    pool: &SqlitePool,
    tenant_id: &str,
    role: &str,
    principal_id: &str,
    principal_type: &str,
) -> anyhow::Result<()> {
    let Some(role) = find(role) else {
        bail!("unknown directory role '{role}'");
    };
    sqlx::query(
        "INSERT OR IGNORE INTO directory_role_assignments
            (tenant_id, role_template_id, principal_id, principal_type, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(role.template_id)
    .bind(principal_id)
    .bind(principal_type)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Directory role template ids held by the user, directly or through groups
/// (the `wids` claim).
pub async fn wids_for_user(pool: &SqlitePool, tenant_id: &str, user_id: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT role_template_id FROM directory_role_assignments
         WHERE tenant_id = ?1
           AND ((principal_type = 'User' AND principal_id = ?2)
             OR (principal_type = 'Group' AND principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?2)))
         ORDER BY role_template_id",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(r,)| r).collect())
}
