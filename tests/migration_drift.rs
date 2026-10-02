//! The three migration sets are parallel translations. `0006`'s role arms are
//! the part where drift is a privilege bug, so pin them against the code.

use std::collections::BTreeSet;

const FILES: [(&str, &str); 3] = [
    ("sqlite", include_str!("../migrations/sqlite/0006_admin_rbac.sql")),
    ("postgres", include_str!("../migrations/postgres/0006_admin_rbac.sql")),
    ("mysql", include_str!("../migrations/mysql/0006_admin_rbac.sql")),
];

type Arms = BTreeSet<(String, String)>;

/// Every `WHEN '<guid>' THEN '<role>'` pair, one set per CASE expression.
fn case_blocks(sql: &str) -> Vec<Arms> {
    sql.split("CASE")
        .skip(1)
        .map(|block| {
            let block = block.split("END").next().unwrap();
            block
                .split("WHEN '")
                .skip(1)
                .map(|arm| {
                    let (guid, rest) = arm.split_once("' THEN '").expect("arm shape");
                    let (role, _) = rest.split_once('\'').expect("arm role");
                    (guid.to_string(), role.to_string())
                })
                .collect()
        })
        .collect()
}

/// The roles `0006` was written against. The role set has since changed
/// (`0012_console_roles` carries those rows on), so this is pinned to history and
/// not to `RoleId`: an applied migration must never change.
const ROLES_AT_0006: [(&str, &str); 7] = [
    ("62e90394-69f5-4237-9190-012177145e10", "GlobalAdministrator"),
    ("f2ef992c-3afb-46b9-b7cf-a126ee74c451", "GlobalReader"),
    ("fe930be7-5e62-47db-91af-98c3a49a38b1", "UserAdministrator"),
    ("fdd7a751-b60b-444a-984c-02652fe8fa1c", "GroupsAdministrator"),
    ("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "ApplicationAdministrator"),
    ("158c047a-c907-4556-b7ef-446551a6b5f7", "CloudApplicationAdministrator"),
    ("e8611ab8-c189-46e8-94e1-60213ab1f814", "PrivilegedRoleAdministrator"),
];

fn expected() -> Arms {
    ROLES_AT_0006
        .iter()
        .map(|(guid, role)| (guid.to_string(), role.to_string()))
        .collect()
}

/// Every 8-4-4-4-12 hex token in the file (comments included, so a stray GUID
/// in a comment is also held to the known set).
fn guid_literals(sql: &str) -> BTreeSet<String> {
    sql.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .filter(|s| {
            let parts: Vec<&str> = s.split('-').collect();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(&parts)
                    .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn every_dialect_carries_the_same_role_arms_in_both_inserts() {
    let want = expected();
    assert_eq!(want.len(), 7, "seven Entra-backed roles");
    for (engine, sql) in FILES {
        let blocks = case_blocks(sql);
        assert_eq!(
            blocks.len(),
            2,
            "{engine}: expected two CASE expressions (binding insert and tenant join)"
        );
        assert_eq!(
            blocks[0], blocks[1],
            "{engine}: the two INSERTs disagree on the arm list"
        );
        assert_eq!(
            blocks[0], want,
            "{engine}: arms differ from the roles 0006 was written against"
        );
    }
}

#[test]
fn every_guid_in_0006_is_a_known_role_template() {
    let known: BTreeSet<String> = expected().into_iter().map(|(g, _)| g).collect();
    for (engine, sql) in FILES {
        let found = guid_literals(sql);
        assert!(!found.is_empty(), "{engine}: no GUID literals parsed");
        let unknown: Vec<_> = found.difference(&known).collect();
        assert!(unknown.is_empty(), "{engine}: unknown GUIDs {unknown:?}");
    }
}

/// Collapse every run of whitespace to one space and drop `--` comments.
fn squash(sql: &str) -> String {
    sql.lines()
        .map(|l| l.split("--").next().unwrap())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Losing `role_id` from the GROUP BY would fold every role of a principal into
/// one binding; losing it from the join would attach a tenant to the wrong role.
#[test]
fn every_dialect_groups_by_role_and_joins_tenants_on_role() {
    for (engine, sql) in FILES {
        let flat = squash(sql);
        assert!(
            flat.contains("GROUP BY principal_type, principal_id, role_id;"),
            "{engine}: the binding backfill must GROUP BY role_id"
        );
        assert!(
            flat.contains("AND b.role_id = CASE d.role_template_id"),
            "{engine}: the tenant join must match b.role_id against the CASE"
        );
    }
}
