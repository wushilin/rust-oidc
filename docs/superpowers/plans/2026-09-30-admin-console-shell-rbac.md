# Admin Console: Shell, RBAC and Users Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the web admin console's foundation — a structured RBAC model (roles carry actions, bindings carry scope), OIDC sign-in, assume-tenant, audit, and the users section end to end.

**Architecture:** Server-rendered askama templates under `src/routes/admin/`, calling the existing domain modules (`tenant`, `users`, `groups`, `apps`, `directory`). All authorization goes through one function, `AdminContext::require`, so no handler branches on roles or tenant ids. New domain functions are added in the domain layer so the later CLI work reuses them.

**Tech Stack:** Rust, axum 0.8, sqlx/SQLite, askama (new), htmx (vendored, no build step), jsonwebtoken. Tests: `cargo test` integration tests using the existing `tests/common` `TestServer`/`Browser` harness.

**Spec:** `docs/superpowers/specs/2026-09-30-admin-console-rbac-design.md`

## Global Constraints

- **No magic values.** Every closed value set is a Rust enum with `as_str`/`parse`; DB and wire strings come from the enum. Applies to `Resource`, `Verb`, `RoleId`, `ScopeKind`, `PrincipalType`.
- **No JS build step.** askama templates plus htmx served as a static asset.
- **Entra fidelity.** Roles that exist in Entra keep Microsoft's well-known template GUIDs already in `src/directory.rs`. `Platform Administrator` has no GUID and never appears in `wids`.
- **Audit every mutation.** Through the existing `db::audit(pool, tenant, actor, action, target, details)`. Actor is always the real signed-in admin, never the assumed tenant's identity.
- **Tenant ids are canonical before any scope comparison.** `{tenant}` in a URL may be a GUID or a verified domain; resolve via `tenant::resolve` and compare the resolved `id`.
- **Soft delete.** `users.deleted_at`, mirroring `applications.deleted_at`; every user query filters it.
- Clippy must be clean (`cargo clippy --all-targets`), and `cargo test` green, before each commit.

## Review Focus

Input classes the spec implies but that no task's happy-path tests would exercise. Each has its test assigned to the task that owns the code.

1. **Tenant addressed by domain alias instead of GUID** — a scope check that compares the raw URL segment can be bypassed by using the alias form. Resolve to canonical id first. *(Task 3)*
2. **Binding whose tenant was deleted** — an orphaned `role_binding_tenants` row must grant nothing, not everything. *(Task 3)*
3. **Group membership or binding revoked mid-session** — effective bindings must be recomputed per request, never cached in the session cookie. *(Task 7)*
4. **Assuming a disabled or non-existent tenant** — must 404 identically in both cases, so the console is not a tenant-existence oracle. *(Task 9)*
5. **Last `all`-scope binding removed** — must not be possible to lock every admin out; removing your own last platform binding is refused. *(Task 5)*

---

### Task 1: RBAC core — actions, roles, scope, evaluation

Pure logic, no database. This is the module every later task authorizes through.

**Files:**
- Create: `src/rbac.rs`
- Modify: `src/lib.rs` (add `pub mod rbac;`)
- Test: inline `#[cfg(test)] mod tests` in `src/rbac.rs`

**Interfaces:**
- Consumes: `crate::directory::GLOBAL_ADMINISTRATOR` and the other template GUIDs.
- Produces: `Resource`, `Verb`, `Action`, `Action::new`, `RoleId`, `RoleId::actions`, `RoleId::template_id`, `RoleId::parse`, `RoleId::as_str`, `Scope`, `Scope::covers`, `EffectiveBinding`, `allowed`.

- [ ] **Step 1: Write the failing tests**

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib rbac`
Expected: FAIL to compile — `src/rbac.rs` does not exist.

- [ ] **Step 3: Write the implementation**

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib rbac && cargo clippy --all-targets`
Expected: all rbac tests PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/rbac.rs src/lib.rs
git commit -m "feat(rbac): roles carry actions, bindings carry scope"
```

---

### Task 2: Schema — bindings, admin sessions, user soft delete

**Files:**
- Create: `migrations/0006_admin_rbac.sql`
- Test: `tests/rbac_migration.rs`

**Interfaces:**
- Produces: tables `role_bindings`, `role_binding_tenants`, `admin_sessions`; column `users.deleted_at`. `directory_role_assignments` is migrated then dropped.

- [ ] **Step 1: Write the failing test**

```rust
//! The migration must carry existing directory role assignments across.
mod common;
use common::*;

#[tokio::test]
async fn directory_role_assignments_become_tenant_scoped_bindings() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    // A row inserted the way bootstrap used to, then read back as a binding.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM role_bindings WHERE scope_kind = 'tenants'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "fresh database starts with no bindings");

    // The old table must be gone, so there is only one source of truth.
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE name = 'directory_role_assignments'")
            .fetch_optional(&s.pool)
            .await
            .unwrap();
    assert!(exists.is_none(), "directory_role_assignments should be dropped");

    // users.deleted_at exists and defaults to NULL.
    let _: (Option<i64>,) = sqlx::query_as("SELECT deleted_at FROM users LIMIT 0")
        .fetch_optional(&s.pool)
        .await
        .unwrap()
        .unwrap_or((None,));
    let _ = t;
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test rbac_migration`
Expected: FAIL — `no such table: role_bindings`.

- [ ] **Step 3: Write the migration**

```sql
-- Admin console RBAC: a role carries actions, a binding carries the scope.

CREATE TABLE role_bindings (
    id             TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,              -- PrincipalType: User | Group
    principal_id   TEXT NOT NULL,
    role_id        TEXT NOT NULL,              -- RoleId::as_str
    scope_kind     TEXT NOT NULL,              -- ScopeKind: all | tenants
    created_at     INTEGER NOT NULL,
    created_by     TEXT
);
CREATE INDEX role_bindings_principal ON role_bindings(principal_type, principal_id);

CREATE TABLE role_binding_tenants (
    binding_id TEXT NOT NULL REFERENCES role_bindings(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    PRIMARY KEY (binding_id, tenant_id)
);

-- Carry existing directory role assignments across as tenant-scoped bindings.
-- Only User and Group principals: a service principal cannot use the console.
INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
SELECT lower(hex(randomblob(16))), principal_type, principal_id,
       CASE role_template_id
           WHEN '62e90394-69f5-4237-9190-012177145e10' THEN 'GlobalAdministrator'
           WHEN 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' THEN 'GlobalReader'
           WHEN 'fe930be7-5e62-47db-91af-98c3a49a38b1' THEN 'UserAdministrator'
           WHEN 'fdd7a751-b60b-444a-984c-02652fe8fa1c' THEN 'GroupsAdministrator'
           WHEN '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' THEN 'ApplicationAdministrator'
           WHEN '158c047a-c907-4556-b7ef-446551a6b5f7' THEN 'CloudApplicationAdministrator'
           WHEN 'e8611ab8-c189-46e8-94e1-60213ab1f814' THEN 'PrivilegedRoleAdministrator'
       END,
       'tenants', created_at, 'migration'
FROM directory_role_assignments
WHERE principal_type IN ('User', 'Group')
  AND role_template_id IN (
      '62e90394-69f5-4237-9190-012177145e10','f2ef992c-3afb-46b9-b7cf-a126ee74c451',
      'fe930be7-5e62-47db-91af-98c3a49a38b1','fdd7a751-b60b-444a-984c-02652fe8fa1c',
      '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7',
      'e8611ab8-c189-46e8-94e1-60213ab1f814');

INSERT INTO role_binding_tenants (binding_id, tenant_id)
SELECT b.id, d.tenant_id
FROM role_bindings b
JOIN directory_role_assignments d
  ON d.principal_id = b.principal_id AND d.principal_type = b.principal_type
WHERE b.created_by = 'migration';

DROP TABLE directory_role_assignments;

-- The console's own session: not tenant-scoped, and records any assumed tenant.
CREATE TABLE admin_sessions (
    cookie_hash   TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    home_tenant   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    acting_tenant TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX admin_sessions_expires ON admin_sessions(expires_at);

-- Soft delete for users, mirroring applications.deleted_at.
ALTER TABLE users ADD COLUMN deleted_at INTEGER;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test rbac_migration`
Expected: PASS.

Note: `directory::wids_for_user` and `directory::assign` still reference the dropped table, so the build breaks here. That is fixed in Task 4; to keep the tree compiling, temporarily have `directory::assign` and `wids_for_user` return `Ok(Default::default())` with a `// replaced in Task 4` comment, and do not commit until `cargo test` is green.

- [ ] **Step 5: Commit**

```bash
git add migrations/0006_admin_rbac.sql tests/rbac_migration.rs src/directory.rs
git commit -m "feat(rbac): bindings, admin sessions and user soft delete schema"
```

---

### Task 3: Binding storage and effective bindings

**Files:**
- Create: `src/admin/mod.rs`, `src/admin/bindings.rs`
- Modify: `src/lib.rs` (`pub mod admin;`)
- Test: `tests/rbac_bindings.rs`

**Interfaces:**
- Consumes: `rbac::{RoleId, Scope, ScopeKind, EffectiveBinding}`, `tenant::resolve`.
- Produces:
  - `PrincipalType` enum (`User`, `Group`) with `as_str`/`parse`
  - `bindings::create(pool, principal_type, principal_id, role, &Scope, created_by) -> anyhow::Result<String>`
  - `bindings::delete(pool, binding_id) -> anyhow::Result<bool>`
  - `bindings::list_for_tenant(pool, tenant_id) -> anyhow::Result<Vec<StoredBinding>>`
  - `bindings::list_all(pool) -> anyhow::Result<Vec<StoredBinding>>`
  - `bindings::effective_for_user(pool, user_id) -> anyhow::Result<Vec<EffectiveBinding>>`
  - `struct StoredBinding { id, principal_type, principal_id, role, scope }`

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{Action, EffectiveBinding, Resource, RoleId, Scope, Verb, allowed};

#[tokio::test]
async fn a_user_binding_is_effective_for_that_user() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::UserAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(allowed(&eff, Action::new(Resource::User, Verb::Write), &f.tenant.id));
}

#[tokio::test]
async fn a_group_binding_reaches_its_members() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let group_id = rust_oidc::groups::create(&s.pool, &f.tenant, "admins", None).await.unwrap();
    rust_oidc::groups::add_member(&s.pool, &group_id, &f.user_id).await.unwrap();
    bindings::create(
        &s.pool,
        PrincipalType::Group,
        &group_id,
        RoleId::GroupsAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(allowed(&eff, Action::new(Resource::Group, Verb::Write), &f.tenant.id));
}

#[tokio::test]
async fn all_scope_round_trips_without_tenant_rows() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::PlatformAdministrator,
        &Scope::All,
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].scope, Scope::All);
    assert!(allowed(&eff, Action::new(Resource::Tenant, Verb::Create), "any-tenant"));
}

/// Review Focus 2: a binding whose tenant was deleted must grant nothing.
#[tokio::test]
async fn a_binding_for_a_deleted_tenant_grants_nothing() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let doomed = s.tenant("Doomed", "doomed.test").await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![doomed.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM tenants WHERE id = ?")
        .bind(&doomed.id)
        .execute(&s.pool)
        .await
        .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(
        !allowed(&eff, Action::new(Resource::User, Verb::Write), &doomed.id),
        "an orphaned scope row must not grant anything"
    );
}

/// Review Focus 1: a tenant may be addressed by domain, but scope compares ids.
#[tokio::test]
async fn scope_is_compared_against_the_canonical_tenant_id() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(
        &s.pool,
        PrincipalType::User,
        &f.user_id,
        RoleId::GlobalAdministrator,
        &Scope::Tenants(vec![f.tenant.id.clone()]),
        "test",
    )
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    // The alias must be resolved before comparison; the raw alias must not match.
    assert!(!allowed(&eff, Action::new(Resource::User, Verb::Write), "contoso.com"));
    let resolved = rust_oidc::tenant::resolve(&s.pool, "contoso.com").await.unwrap().unwrap();
    assert!(allowed(&eff, Action::new(Resource::User, Verb::Write), &resolved.id));
}

#[tokio::test]
async fn an_unknown_role_string_in_the_database_is_ignored_not_fatal() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    sqlx::query(
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at)
         VALUES ('b1', 'User', ?, 'RoleFromTheFuture', 'all', 0)",
    )
    .bind(&f.user_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let eff = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(eff.is_empty(), "an unparseable role is skipped, not an error");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test rbac_bindings`
Expected: FAIL to compile — `rust_oidc::admin` does not exist.

- [ ] **Step 3: Write the implementation**

`src/admin/mod.rs`:

```rust
//! The admin console: RBAC storage, session, and pages.

pub mod bindings;
```

`src/admin/bindings.rs`:

```rust
//! Storage for role bindings, and expansion into effective grants.

use sqlx::{Row, SqlitePool};

use crate::rbac::{EffectiveBinding, RoleId, Scope, ScopeKind};
use crate::util::{new_guid, now};

/// Who a binding is granted to. Service principals cannot use the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Group,
}

impl PrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "User" => Some(Self::User),
            "Group" => Some(Self::Group),
            _ => None,
        }
    }
}

pub struct StoredBinding {
    pub id: String,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub role: RoleId,
    pub scope: Scope,
}

pub async fn create(
    pool: &SqlitePool,
    principal_type: PrincipalType,
    principal_id: &str,
    role: RoleId,
    scope: &Scope,
    created_by: &str,
) -> anyhow::Result<String> {
    let id = new_guid();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO role_bindings (id, principal_type, principal_id, role_id, scope_kind, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(principal_type.as_str())
    .bind(principal_id)
    .bind(role.as_str())
    .bind(scope.kind().as_str())
    .bind(now())
    .bind(created_by)
    .execute(&mut *tx)
    .await?;
    if let Scope::Tenants(ids) = scope {
        for tenant_id in ids {
            sqlx::query("INSERT INTO role_binding_tenants (binding_id, tenant_id) VALUES (?, ?)")
                .bind(&id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(id)
}

pub async fn delete(pool: &SqlitePool, binding_id: &str) -> anyhow::Result<bool> {
    let done = sqlx::query("DELETE FROM role_bindings WHERE id = ?")
        .bind(binding_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Scope rows join `tenants`, so a binding naming a deleted tenant yields no
/// tenant ids and therefore grants nothing.
async fn scope_of(pool: &SqlitePool, binding_id: &str, kind: ScopeKind) -> anyhow::Result<Scope> {
    match kind {
        ScopeKind::All => Ok(Scope::All),
        ScopeKind::Tenants => {
            let rows = sqlx::query(
                "SELECT rbt.tenant_id FROM role_binding_tenants rbt
                 JOIN tenants t ON t.id = rbt.tenant_id
                 WHERE rbt.binding_id = ?",
            )
            .bind(binding_id)
            .fetch_all(pool)
            .await?;
            Ok(Scope::Tenants(rows.iter().map(|r| r.get("tenant_id")).collect()))
        }
    }
}

/// Every binding held by the user directly or through a group they belong to.
/// Recomputed on each call: never cache this in a session.
pub async fn effective_for_user(pool: &SqlitePool, user_id: &str) -> anyhow::Result<Vec<EffectiveBinding>> {
    let rows = sqlx::query(
        "SELECT id, role_id, scope_kind FROM role_bindings
         WHERE (principal_type = 'User'  AND principal_id = ?1)
            OR (principal_type = 'Group' AND principal_id IN
                (SELECT group_id FROM group_members WHERE user_id = ?1))",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let Some(role) = RoleId::parse(row.get::<String, _>("role_id").as_str()) else {
            continue; // a role we do not know is ignored, not fatal
        };
        let Some(kind) = ScopeKind::parse(row.get::<String, _>("scope_kind").as_str()) else {
            continue;
        };
        out.push(EffectiveBinding {
            role,
            scope: scope_of(pool, &id, kind).await?,
        });
    }
    Ok(out)
}

pub async fn list_all(pool: &SqlitePool) -> anyhow::Result<Vec<StoredBinding>> {
    let rows = sqlx::query(
        "SELECT id, principal_type, principal_id, role_id, scope_kind FROM role_bindings ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;
    hydrate(pool, rows).await
}

pub async fn list_for_tenant(pool: &SqlitePool, tenant_id: &str) -> anyhow::Result<Vec<StoredBinding>> {
    let rows = sqlx::query(
        "SELECT b.id, b.principal_type, b.principal_id, b.role_id, b.scope_kind
         FROM role_bindings b
         LEFT JOIN role_binding_tenants rbt ON rbt.binding_id = b.id
         WHERE b.scope_kind = 'all' OR rbt.tenant_id = ?
         GROUP BY b.id ORDER BY b.created_at",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    hydrate(pool, rows).await
}

async fn hydrate(pool: &SqlitePool, rows: Vec<sqlx::sqlite::SqliteRow>) -> anyhow::Result<Vec<StoredBinding>> {
    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let (Some(principal_type), Some(role), Some(kind)) = (
            PrincipalType::parse(row.get::<String, _>("principal_type").as_str()),
            RoleId::parse(row.get::<String, _>("role_id").as_str()),
            ScopeKind::parse(row.get::<String, _>("scope_kind").as_str()),
        ) else {
            continue;
        };
        let scope = scope_of(pool, &id, kind).await?;
        out.push(StoredBinding {
            id,
            principal_type,
            principal_id: row.get("principal_id"),
            role,
            scope,
        });
    }
    Ok(out)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test rbac_bindings && cargo clippy --all-targets`
Expected: all six PASS, clippy clean.

If `groups::create`/`groups::add_member` have different signatures, read `src/groups.rs` and adjust the test call sites — do not change `groups.rs`.

- [ ] **Step 5: Commit**

```bash
git add src/admin/ src/lib.rs tests/rbac_bindings.rs
git commit -m "feat(rbac): binding storage and effective-grant expansion"
```

---

### Task 4: `wids` derived from bindings

**Files:**
- Modify: `src/directory.rs` (replace `wids_for_user` and `assign`)
- Modify: `src/main.rs` (bootstrap creates bindings instead of directory assignments)
- Test: `tests/rbac_wids.rs`

**Interfaces:**
- Consumes: `admin::bindings::effective_for_user`, `rbac::RoleId::template_id`.
- Produces: `directory::wids_for_user(pool, tenant_id, user_id) -> anyhow::Result<Vec<String>>` (same signature as before, new source).

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{RoleId, Scope};

#[tokio::test]
async fn a_tenant_scoped_binding_appears_in_wids_for_that_tenant_only() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    bindings::create(&s.pool, PrincipalType::User, &f.user_id,
        RoleId::GlobalAdministrator, &Scope::Tenants(vec![f.tenant.id.clone()]), "test")
        .await.unwrap();

    let here = rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id).await.unwrap();
    assert_eq!(here, vec![RoleId::GlobalAdministrator.template_id().unwrap().to_string()]);
    let there = rust_oidc::directory::wids_for_user(&s.pool, &other.id, &f.user_id).await.unwrap();
    assert!(there.is_empty(), "the binding does not cover that tenant");
}

#[tokio::test]
async fn an_all_scope_binding_appears_in_every_tenants_wids() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let other = s.tenant("Other", "other.test").await;
    bindings::create(&s.pool, PrincipalType::User, &f.user_id,
        RoleId::GlobalAdministrator, &Scope::All, "test").await.unwrap();
    for tid in [&f.tenant.id, &other.id] {
        let wids = rust_oidc::directory::wids_for_user(&s.pool, tid, &f.user_id).await.unwrap();
        assert!(wids.contains(&RoleId::GlobalAdministrator.template_id().unwrap().to_string()), "{tid}");
    }
}

#[tokio::test]
async fn platform_administrator_never_appears_in_wids() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bindings::create(&s.pool, PrincipalType::User, &f.user_id,
        RoleId::PlatformAdministrator, &Scope::All, "test").await.unwrap();
    let wids = rust_oidc::directory::wids_for_user(&s.pool, &f.tenant.id, &f.user_id).await.unwrap();
    assert!(wids.is_empty(), "it has no Entra template id, so it is not a wid");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test rbac_wids`
Expected: FAIL — `wids_for_user` returns empty (the Task 2 stub).

- [ ] **Step 3: Write the implementation**

In `src/directory.rs`, replace the body of `wids_for_user` and delete `assign`:

```rust
/// `wids`: the directory roles this user holds in `tenant_id`, derived from role
/// bindings. Roles without a Microsoft template id (ours alone) are not `wids`.
pub async fn wids_for_user(pool: &SqlitePool, tenant_id: &str, user_id: &str) -> anyhow::Result<Vec<String>> {
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
```

In `src/main.rs`, the bootstrap path replaces `directory::assign(...)` with two bindings — the first admin is both a tenant admin of the root tenant and the platform administrator:

```rust
use rust_oidc::admin::bindings::{self as role_bindings, PrincipalType};
use rust_oidc::rbac::{RoleId, Scope};

role_bindings::create(&pool, PrincipalType::User, &user_id,
    RoleId::GlobalAdministrator, &Scope::All, "bootstrap").await?;
role_bindings::create(&pool, PrincipalType::User, &user_id,
    RoleId::PlatformAdministrator, &Scope::All, "bootstrap").await?;
```

Keep `directory::ROLES` and `find` — the console uses them for display names.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test && cargo clippy --all-targets`
Expected: the three new tests PASS and the whole suite stays green — `tests/user_flow.rs::groups_wids_and_assignment_required` covers the old behaviour and must still pass.

- [ ] **Step 5: Verify the migration against real data**

The `INSERT … SELECT` in Task 2 cannot be exercised by an integration test,
because every test starts from an empty database where there is nothing to
migrate. Verify it against a copy of the deployed database instead, which does
have a `directory_role_assignments` row (the bootstrap admin):

```bash
cp /opt/processmaster/services/rust-oidc/data/rust-oidc.db /tmp/migrate-check.db
# Record what the admin holds today, before migrating.
sqlite3 /tmp/migrate-check.db \
  "SELECT tenant_id, role_template_id, principal_id FROM directory_role_assignments;"
# Run the new migration by pointing the binary at the copy.
RUST_OIDC_DATABASE="sqlite:///tmp/migrate-check.db" ./target/debug/rust-oidc app list --tenant wushilin.net >/dev/null
# The same principal must now hold the same role, scoped to the same tenant.
sqlite3 /tmp/migrate-check.db \
  "SELECT b.principal_id, b.role_id, t.tenant_id FROM role_bindings b
   JOIN role_binding_tenants t ON t.binding_id = b.id;"
rm /tmp/migrate-check.db
```

Expected: one `GlobalAdministrator` binding for the bootstrap admin's object id,
scoped to the tenant it was assigned in, and no `directory_role_assignments`
table remaining. If the mapping is wrong, fix the migration before committing —
this is the only check that the `CASE role_template_id` arms are correct.

- [ ] **Step 6: Commit**

```bash
git add src/directory.rs src/main.rs tests/rbac_wids.rs
git commit -m "feat(rbac): derive wids from role bindings"
```

---

### Task 5: The no-widening rule

**Files:**
- Create: `src/admin/authz.rs`
- Modify: `src/admin/mod.rs`
- Test: `tests/rbac_no_widening.rs`

**Interfaces:**
- Consumes: `rbac::{allowed, allowed_at_all_scope, Action, Resource, Verb, Scope, EffectiveBinding}`.
- Produces: `authz::may_write_binding(&[EffectiveBinding], &Scope) -> bool`, `authz::check_delete(&SqlitePool, binding_id) -> Result<(), RefusedReason>`, `enum RefusedReason { NotPermitted, WouldLockOut }`.

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use rust_oidc::admin::authz::{self, RefusedReason};
use rust_oidc::rbac::{EffectiveBinding, RoleId, Scope};

fn b(role: RoleId, scope: Scope) -> EffectiveBinding {
    EffectiveBinding { role, scope }
}

#[test]
fn an_admin_may_grant_within_tenants_they_hold() {
    let me = [b(RoleId::GlobalAdministrator, Scope::Tenants(vec!["t1".into(), "t2".into()]))];
    assert!(authz::may_write_binding(&me, &Scope::Tenants(vec!["t1".into()])));
    assert!(authz::may_write_binding(&me, &Scope::Tenants(vec!["t1".into(), "t2".into()])));
}

#[test]
fn an_admin_may_not_grant_outside_their_scope() {
    let me = [b(RoleId::GlobalAdministrator, Scope::Tenants(vec!["t1".into()]))];
    assert!(!authz::may_write_binding(&me, &Scope::Tenants(vec!["t2".into()])));
    // Partial overlap is still a widening.
    assert!(!authz::may_write_binding(&me, &Scope::Tenants(vec!["t1".into(), "t2".into()])));
}

#[test]
fn only_an_all_scope_principal_may_mint_an_all_scope_binding() {
    let scoped = [b(RoleId::GlobalAdministrator, Scope::Tenants(vec!["t1".into()]))];
    assert!(!authz::may_write_binding(&scoped, &Scope::All));
    let global = [b(RoleId::GlobalAdministrator, Scope::All)];
    assert!(authz::may_write_binding(&global, &Scope::All));
}

#[test]
fn a_role_without_rolebinding_write_may_not_grant_at_all() {
    let helpdesk = [b(RoleId::UserAdministrator, Scope::All)];
    assert!(!authz::may_write_binding(&helpdesk, &Scope::Tenants(vec!["t1".into()])));
}

#[test]
fn an_empty_tenant_scope_is_refused() {
    let global = [b(RoleId::GlobalAdministrator, Scope::All)];
    assert!(!authz::may_write_binding(&global, &Scope::Tenants(vec![])));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test rbac_no_widening`
Expected: FAIL to compile — `authz` does not exist.

- [ ] **Step 3: Write the implementation**

```rust
//! Authorization rules that are about more than one tenant at a time.

use crate::rbac::{Action, EffectiveBinding, Resource, Scope, Verb, allowed, allowed_at_all_scope};

const WRITE_BINDING: Action = Action::new(Resource::RoleBinding, Verb::Write);

/// A binding write is authorized against the **target** binding's scope, so no
/// principal can grant reach it does not already have.
pub fn may_write_binding(bindings: &[EffectiveBinding], target: &Scope) -> bool {
    match target {
        Scope::All => allowed_at_all_scope(bindings, WRITE_BINDING),
        // An empty scope would grant nothing and is more likely a bug than intent.
        Scope::Tenants(ids) if ids.is_empty() => false,
        Scope::Tenants(ids) => ids.iter().all(|t| allowed(bindings, WRITE_BINDING, t)),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RefusedReason {
    NotPermitted,
    /// Removing this would leave nobody able to administer the platform.
    WouldLockOut,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test rbac_no_widening && cargo clippy --all-targets`
Expected: five PASS, clippy clean.

- [ ] **Step 5: Write the failing lock-out test (Review Focus 5)**

```rust
// tests/rbac_no_widening.rs — appended
mod common_db {
    pub use crate::common::*;
}

#[tokio::test]
async fn removing_the_last_platform_binding_is_refused() {
    use common::*;
    use rust_oidc::admin::bindings::{self, PrincipalType};
    use rust_oidc::admin::authz;
    use rust_oidc::rbac::{RoleId, Scope};

    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let id = bindings::create(&s.pool, PrincipalType::User, &f.user_id,
        RoleId::PlatformAdministrator, &Scope::All, "test").await.unwrap();

    // It is the only one, so removing it must be refused.
    let refused = authz::check_delete(&s.pool, &id).await.unwrap_err();
    assert_eq!(refused, authz::RefusedReason::WouldLockOut);

    // With a second platform admin, removal is allowed.
    let other = rust_oidc::users::create(&s.pool, &f.tenant, rust_oidc::users::NewUser {
        upn: "bob@contoso.com", password: "Correct-Horse-9",
        display_name: None, given_name: None, family_name: None, email: None,
    }).await.unwrap();
    bindings::create(&s.pool, PrincipalType::User, &other,
        RoleId::PlatformAdministrator, &Scope::All, "test").await.unwrap();
    assert!(authz::check_delete(&s.pool, &id).await.is_ok());
}
```

- [ ] **Step 6: Implement `check_delete`, run, and commit**

```rust
/// Refuse a delete that would leave the platform with no administrator.
pub async fn check_delete(pool: &sqlx::SqlitePool, binding_id: &str) -> Result<(), RefusedReason> {
    let role: Option<(String,)> = sqlx::query_as("SELECT role_id FROM role_bindings WHERE id = ?")
        .bind(binding_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| RefusedReason::NotPermitted)?;
    let Some((role,)) = role else { return Err(RefusedReason::NotPermitted) };
    if role != crate::rbac::RoleId::PlatformAdministrator.as_str() {
        return Ok(());
    }
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM role_bindings WHERE role_id = ? AND scope_kind = 'all'",
    )
    .bind(crate::rbac::RoleId::PlatformAdministrator.as_str())
    .fetch_one(pool)
    .await
    .map_err(|_| RefusedReason::NotPermitted)?;
    if count <= 1 { Err(RefusedReason::WouldLockOut) } else { Ok(()) }
}
```

Run: `cargo test --test rbac_no_widening && cargo clippy --all-targets`

```bash
git add src/admin/authz.rs src/admin/mod.rs tests/rbac_no_widening.rs
git commit -m "feat(rbac): bindings cannot widen scope or lock out the platform"
```

---

### Task 6: Console app registration at startup

**Files:**
- Create: `src/admin/client.rs`
- Modify: `src/admin/mod.rs`, `src/server.rs` (call at startup)
- Test: `tests/admin_client.rs`

**Interfaces:**
- Consumes: `apps::{create, find, add_redirect_uri, add_secret}`, `tenant::root`, `config::PublicUrl`.
- Produces: `client::CONSOLE_APP_ID: &str`, `client::ensure(pool, &PublicUrl) -> anyhow::Result<ConsoleClient>`, `struct ConsoleClient { app_id: String, secret: String, redirect_uri: String }`.

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;

#[tokio::test]
async fn the_console_registration_is_created_once_and_reused() {
    let s = TestServer::start().await;
    let url = rust_oidc::config::PublicUrl::parse(&s.base).unwrap();
    let first = rust_oidc::admin::client::ensure(&s.pool, &url).await.unwrap();
    assert_eq!(first.app_id, rust_oidc::admin::client::CONSOLE_APP_ID);
    assert!(first.redirect_uri.ends_with("/admin/callback"));

    let second = rust_oidc::admin::client::ensure(&s.pool, &url).await.unwrap();
    assert_eq!(first.app_id, second.app_id, "the same registration is reused");

    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM applications WHERE app_id = ?")
        .bind(rust_oidc::admin::client::CONSOLE_APP_ID)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "no duplicate registration on restart");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test admin_client`
Expected: FAIL to compile — `admin::client` does not exist.

- [ ] **Step 3: Write the implementation**

```rust
//! The console is an OIDC client of this server. Its registration is created at
//! startup so nothing about installing the console needs the CLI.

use sqlx::SqlitePool;

use crate::apps;
use crate::config::PublicUrl;
use crate::tenant;

/// Reserved, stable app id so the registration survives restarts and is
/// recognisable in audit rows.
pub const CONSOLE_APP_ID: &str = "00000000-0000-0000-c000-00000000adm1";
const DISPLAY_NAME: &str = "Admin Console";

pub struct ConsoleClient {
    pub app_id: String,
    pub secret: String,
    pub redirect_uri: String,
}

pub async fn ensure(pool: &SqlitePool, url: &PublicUrl) -> anyhow::Result<ConsoleClient> {
    let root = tenant::root(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("not bootstrapped: no root tenant"))?;
    let redirect_uri = format!("{}/admin/callback", url.base());

    if let Some(existing) = apps::find(pool, CONSOLE_APP_ID).await? {
        let secret = console_secret(pool).await?;
        return Ok(ConsoleClient { app_id: existing.app_id, secret, redirect_uri });
    }

    let created = apps::create_with_app_id(pool, &root, DISPLAY_NAME, CONSOLE_APP_ID).await?;
    apps::add_redirect_uri(pool, &created.application, apps::PLATFORM_WEB, &redirect_uri).await?;
    let secret = console_secret(pool).await?;
    apps::add_secret_value(pool, &created.application, &secret, Some("console"), 3650).await?;
    Ok(ConsoleClient { app_id: CONSOLE_APP_ID.to_string(), secret, redirect_uri })
}
```

`apps::create` generates a random `app_id`, so add a sibling that takes one:

Move the existing body of `create` into a new function that takes the app id,
and have `create` delegate to it, so there is exactly one implementation:

```rust
// src/apps.rs
/// Register an app in its home tenant: application object, default identifier
/// URI `api://{appId}` and the home-tenant service principal.
pub async fn create(pool: &SqlitePool, tenant: &Tenant, display_name: &str) -> anyhow::Result<CreatedApp> {
    create_with_app_id(pool, tenant, display_name, &new_guid()).await
}

/// As `create`, with a caller-chosen appId. For reserved built-in apps such as
/// the admin console, whose id must be stable across restarts.
pub async fn create_with_app_id(
    pool: &SqlitePool,
    tenant: &Tenant,
    display_name: &str,
    app_id: &str,
) -> anyhow::Result<CreatedApp> {
    let application = Application {
        id: new_guid(),
        app_id: app_id.to_string(),
        tenant_id: tenant.id.clone(),
        display_name: display_name.to_string(),
        allow_password_grant: false,
    };
    // ... the remainder is the current body of `create`, unchanged: insert into
    // applications, app_identifier_uris and service_principals in one
    // transaction, then return CreatedApp.
}
```

The console's secret must survive restarts rather than being regenerated each
boot. `server_secrets` stores bytes keyed by name, and `src/secrets.rs` already
has the `INSERT OR IGNORE` + `SELECT` idiom for exactly this; reuse it:

```rust
// src/admin/client.rs
const SECRET_NAME: &str = "admin_console_client_secret";

/// The console's client secret, created on first use and stable thereafter.
async fn console_secret(pool: &SqlitePool) -> anyhow::Result<String> {
    sqlx::query("INSERT OR IGNORE INTO server_secrets (name, value, created_at) VALUES (?, ?, ?)")
        .bind(SECRET_NAME)
        .bind(crate::util::random_bytes(32))
        .bind(crate::util::now())
        .execute(pool)
        .await?;
    let (value,): (Vec<u8>,) = sqlx::query_as("SELECT value FROM server_secrets WHERE name = ?")
        .bind(SECRET_NAME)
        .fetch_one(pool)
        .await?;
    Ok(crate::util::b64url(&value))
}
```

The app registration stores the hash of that same value as its client secret, so
`ensure` calls `console_secret` first, then registers it with
`apps::add_secret_value(pool, &app, &secret, Some("console"), 3650)` — add that
sibling to `apps.rs` beside `add_secret`, taking the secret instead of
generating one, and have `add_secret` delegate to it with
`generate_client_secret()`.

Call it from startup, in `src/server.rs` after `keys::ensure`:

```rust
if tenant::root(&pool).await?.is_some() {
    admin::client::ensure(&pool, &public_url).await?;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test admin_client && cargo test && cargo clippy --all-targets`
Expected: PASS and the whole suite green.

- [ ] **Step 5: Commit**

```bash
git add src/admin/client.rs src/admin/mod.rs src/apps.rs src/server.rs src/secrets.rs tests/admin_client.rs
git commit -m "feat(admin): self-register the console's OIDC client at startup"
```

---

### Task 7: Admin session, `AdminContext` and the request guard

**Files:**
- Create: `src/admin/session.rs`, `src/admin/context.rs`
- Modify: `src/admin/mod.rs`
- Test: `tests/admin_context.rs`

**Interfaces:**
- Consumes: `bindings::effective_for_user`, `rbac::{allowed, Action}`, `tenant::resolve`.
- Produces:
  - `session::ADMIN_COOKIE: &str`, `session::create(pool, user_id, home_tenant) -> anyhow::Result<String>`, `session::find(pool, headers) -> anyhow::Result<Option<AdminSession>>`, `session::set_acting_tenant`, `session::end`
  - `struct AdminSession { cookie_hash, user_id, home_tenant, acting_tenant }`
  - `struct AdminContext { pub user: User, pub bindings: Vec<EffectiveBinding>, pub acting_tenant: Option<Tenant> }`
  - `AdminContext::require(Action, On) -> Result<(), Response>`, `AdminContext::can(Action, On) -> bool`, `enum On<'a> { Tenant(&'a str), Platform }`
  - `impl FromRequestParts<AppState> for AdminContext`

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;
use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::rbac::{RoleId, Scope};

/// Review Focus 3: grants must be recomputed per request, never cached.
#[tokio::test]
async fn revoking_a_binding_takes_effect_on_the_next_request() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let id = bindings::create(&s.pool, PrincipalType::User, &f.user_id,
        RoleId::UserAdministrator, &Scope::Tenants(vec![f.tenant.id.clone()]), "test")
        .await.unwrap();

    let before = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert_eq!(before.len(), 1);

    bindings::delete(&s.pool, &id).await.unwrap();
    let after = bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    assert!(after.is_empty(), "the next request must see the revocation");
}

#[tokio::test]
async fn losing_group_membership_takes_effect_on_the_next_request() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let group_id = rust_oidc::groups::create(&s.pool, &f.tenant, "admins", None).await.unwrap();
    rust_oidc::groups::add_member(&s.pool, &group_id, &f.user_id).await.unwrap();
    bindings::create(&s.pool, PrincipalType::Group, &group_id,
        RoleId::GroupsAdministrator, &Scope::All, "test").await.unwrap();
    assert_eq!(bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap().len(), 1);

    sqlx::query("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
        .bind(&group_id).bind(&f.user_id).execute(&s.pool).await.unwrap();
    assert!(bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn an_admin_session_round_trips_and_can_be_ended() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let cookie = rust_oidc::admin::session::create(&s.pool, &f.user_id, &f.tenant.id).await.unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("{}={cookie}", rust_oidc::admin::session::ADMIN_COOKIE).parse().unwrap(),
    );
    let found = rust_oidc::admin::session::find(&s.pool, &headers).await.unwrap().unwrap();
    assert_eq!(found.user_id, f.user_id);
    assert!(found.acting_tenant.is_none());

    rust_oidc::admin::session::end(&s.pool, &headers).await.unwrap();
    assert!(rust_oidc::admin::session::find(&s.pool, &headers).await.unwrap().is_none());
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test admin_context`
Expected: FAIL to compile — `admin::session` does not exist.

- [ ] **Step 3: Write the implementation**

`src/admin/session.rs` mirrors `src/session.rs` (read it first and follow its
cookie helpers), against the `admin_sessions` table: `create` inserts a hashed
cookie with `expires_at = now + ADMIN_SESSION_LIFETIME` (8 hours, a named
const); `find` selects by `sha256_hex(cookie)` where `expires_at > now`;
`set_acting_tenant` updates `acting_tenant`; `end` deletes the row.

`src/admin/context.rs`:

```rust
//! One request's admin identity and the single authorization entry point.

pub enum On<'a> {
    /// A specific tenant, addressed by GUID or domain alias.
    Tenant(&'a str),
    /// Platform-wide: only an `All`-scope grant satisfies it.
    Platform,
}

pub struct AdminContext {
    pub user: User,
    pub home_tenant: Tenant,
    pub acting_tenant: Option<Tenant>,
    bindings: Vec<EffectiveBinding>,
    resolved: HashMap<String, String>, // alias-or-id -> canonical id, per request
}

impl AdminContext {
    /// The only place an action is checked. Handlers call this and nothing else.
    pub fn require(&self, action: Action, on: On<'_>) -> Result<(), Response> {
        if self.can(action, on) { Ok(()) } else { Err(forbidden(action)) }
    }

    pub fn can(&self, action: Action, on: On<'_>) -> bool {
        match on {
            On::Platform => rbac::allowed_at_all_scope(&self.bindings, action),
            On::Tenant(key) => match self.resolved.get(key) {
                // Scope is compared against the canonical id, never the alias.
                Some(id) => rbac::allowed(&self.bindings, action, id),
                None => false,
            },
        }
    }
}
```

`FromRequestParts` resolves the session, loads the user (rejecting a disabled or
soft-deleted one), recomputes `effective_for_user` **every request**, and
resolves the `{tenant}` path parameter through `tenant::resolve` into
`resolved` so `can` never sees an alias. A request with no session redirects to
`/admin`; a session whose user has no bindings at all renders the "no access"
page.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test admin_context && cargo clippy --all-targets`

- [ ] **Step 5: Commit**

```bash
git add src/admin/session.rs src/admin/context.rs src/admin/mod.rs tests/admin_context.rs
git commit -m "feat(admin): per-request admin context with one authorization gate"
```

---

### Task 8: Console sign-in, layout and the global tenant list

**Files:**
- Create: `src/admin/routes.rs`, `templates/admin/layout.html`, `templates/admin/tenants.html`, `templates/admin/no_access.html`, `static/htmx.min.js`
- Modify: `Cargo.toml` (askama), `src/routes/mod.rs` (mount `/admin`), `src/admin/mod.rs`
- Test: `tests/admin_signin.rs`

**Interfaces:**
- Consumes: `client::ensure`, `session`, `AdminContext`, `tenant::list`.
- Produces: routes `GET /admin`, `GET /admin/callback`, `POST /admin/signout`; `admin::routes::router() -> Router<AppState>`.

- [ ] **Step 1: Add askama and htmx**

```bash
cargo add askama
curl -sL https://cdnjs.cloudflare.com/ajax/libs/htmx/2.0.4/htmx.min.js -o static/htmx.min.js
```

Serve `static/` with `tower_http::services::ServeDir` under `{prefix}/static`.
No build step; the file is vendored and committed.

- [ ] **Step 2: Write the failing test**

```rust
mod common;
use common::*;

#[tokio::test]
async fn the_console_redirects_an_anonymous_visitor_to_sign_in() {
    let s = TestServer::start().await;
    let b = Browser::new();
    let page = b.get(&s.url("/admin")).await;
    assert_eq!(page.status, 302, "{}", page.body);
    let location = page.location.unwrap();
    assert!(location.contains("/oauth2/v2.0/authorize"), "{location}");
    assert!(location.contains("client_id=00000000-0000-0000-c000-00000000adm1"), "{location}");
    assert!(location.contains("code_challenge"), "PKCE is used: {location}");
}

#[tokio::test]
async fn signing_in_shows_the_tenant_list_to_a_platform_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;   // see Step 3
    let b = Browser::new();
    let page = b.get(&s.url("/admin")).await;
    let page = b.follow_oidc_sign_in(&s, page, &f.upn, &f.password).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Contoso"), "the tenant list: {}", page.body);
}

#[tokio::test]
async fn a_user_with_no_bindings_sees_no_access_not_a_raw_error() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;    // a plain user, no bindings
    let b = Browser::new();
    let page = b.get(&s.url("/admin")).await;
    let page = b.follow_oidc_sign_in(&s, page, &f.upn, &f.password).await;
    assert_eq!(page.status, 403);
    assert!(page.body.to_lowercase().contains("access"), "{}", page.body);
}
```

Add to `tests/common/mod.rs`: `admin_fixture` (a `user_fixture` plus
`GlobalAdministrator` and `PlatformAdministrator` bindings at `All` scope), and
`Browser::follow_oidc_sign_in`, which follows the redirect to `/authorize`,
submits the login form with the existing `login` helper, then follows the
redirect back to `/admin/callback`.

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test --test admin_signin`
Expected: FAIL — `/admin` returns 404.

- [ ] **Step 4: Implement sign-in and the layout**

`GET /admin` with no admin session: build an authorize URL for
`CONSOLE_APP_ID` with `response_type=code`, `scope=openid profile`,
`code_challenge` (S256; store the verifier and state in a short-lived signed
cookie), and redirect. `GET /admin/callback` exchanges the code at the token
endpoint over loopback, validates the ID token with `st.keys.verify`, creates the
admin session for the `oid`, and redirects to `/admin`.

`templates/admin/layout.html` holds the chrome: product name, the signed-in
admin's UPN, a sign-out form, the assumed-tenant banner slot, and a nav rendered
from `can(...)` — a nav entry is emitted only where the corresponding action is
permitted, so the UI cannot offer what the guard would refuse.

`templates/admin/tenants.html` lists tenants from `tenant::list`, each linking
to `/admin/tenants/{id}/users`, gated on `Action::new(Resource::Tenant, Verb::Read)`.

Visual design: this is the console's first screen, so do the design pass here
(the `frontend-design` skill) rather than copying `src/html.rs`'s stylesheet.
Keep it a single stylesheet in the layout template.

- [ ] **Step 5: Run the tests, then commit**

Run: `cargo test --test admin_signin && cargo test && cargo clippy --all-targets`

```bash
git add Cargo.toml Cargo.lock static/ templates/ src/admin/routes.rs src/routes/mod.rs tests/
git commit -m "feat(admin): console sign-in, layout and tenant list"
```

---

### Task 9: Assume tenant

**Files:**
- Modify: `src/admin/routes.rs`, `templates/admin/layout.html`
- Test: `tests/admin_assume.rs`

**Interfaces:**
- Consumes: `AdminContext::require`, `session::set_acting_tenant`, `db::audit`.
- Produces: `POST /admin/assume/{tenant}`, `POST /admin/leave`.

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;

#[tokio::test]
async fn a_platform_admin_can_assume_a_tenant_and_leave_it() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.post_form(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;
    assert_eq!(page.status, 302);
    let page = b.get(&s.url("/admin")).await;
    assert!(page.body.contains("Fabrikam"), "banner names the assumed tenant: {}", page.body);

    let page = b.post_form(&s.url("/admin/leave"), &[]).await;
    assert_eq!(page.status, 302);
    let page = b.get(&s.url("/admin")).await;
    assert!(!page.body.contains("Acting in"), "banner is gone: {}", page.body);
}

#[tokio::test]
async fn a_tenant_admin_cannot_assume() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;   // GlobalAdministrator scoped to one tenant
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.post_form(&s.url(&format!("/admin/assume/{}", other.id)), &[]).await;
    assert_eq!(page.status, 403, "{}", page.body);
}

/// Review Focus 4: a disabled and a non-existent tenant must look identical.
#[tokio::test]
async fn assuming_a_disabled_or_unknown_tenant_is_the_same_404() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let disabled = s.tenant("Gone", "gone.test").await;
    sqlx::query("UPDATE tenants SET enabled = 0 WHERE id = ?")
        .bind(&disabled.id).execute(&s.pool).await.unwrap();
    let b = signed_in_admin(&s, &f).await;

    let a = b.post_form(&s.url(&format!("/admin/assume/{}", disabled.id)), &[]).await;
    let c = b.post_form(&s.url("/admin/assume/11111111-1111-1111-1111-111111111111"), &[]).await;
    assert_eq!(a.status, 404);
    assert_eq!(c.status, 404);
    assert_eq!(a.body, c.body, "the console must not reveal which tenants exist");
}

#[tokio::test]
async fn actions_taken_while_assuming_are_audited_against_the_real_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let target = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    b.post_form(&s.url(&format!("/admin/assume/{}", target.id)), &[]).await;

    let (actor, action): (String, String) = sqlx::query_as(
        "SELECT actor, action FROM audit_log ORDER BY created_at DESC LIMIT 1",
    ).fetch_one(&s.pool).await.unwrap();
    assert_eq!(actor, f.upn, "the person, not a tenant-local identity");
    assert_eq!(action, "admin.tenant.assume");
}
```

Add `signed_in_admin`, `tenant_admin_fixture` to `tests/common/mod.rs`.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test admin_assume`
Expected: FAIL — the routes do not exist.

- [ ] **Step 3: Implement**

```rust
async fn assume(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(Action::new(Resource::Tenant, Verb::Assume), On::Platform) {
        return resp;
    }
    // Enabled tenants only, and an unknown tenant is indistinguishable.
    let Ok(Some(t)) = tenant::resolve(&st.pool, &key).await else {
        return not_found();
    };
    // ... set_acting_tenant, audit "admin.tenant.assume", redirect to /admin
}
```

`require` comes before the lookup so an unauthorized caller learns nothing about
which tenants exist. The banner renders from `ctx.acting_tenant`. Authorization
is unchanged while assuming — the `All`-scope binding already covers the tenant —
so no handler consults `acting_tenant` when deciding access.

- [ ] **Step 4: Run and commit**

Run: `cargo test --test admin_assume && cargo clippy --all-targets`

```bash
git add src/admin/routes.rs templates/admin/layout.html tests/admin_assume.rs tests/common/mod.rs
git commit -m "feat(admin): assume and leave a tenant, audited as the real admin"
```

---

### Task 10: Users list and search

**Files:**
- Create: `templates/admin/users.html`, `src/admin/users.rs`
- Modify: `src/users.rs` (add `list`), `src/admin/routes.rs`
- Test: `tests/admin_users.rs`

**Interfaces:**
- Consumes: `AdminContext`, `users::list`.
- Produces: `users::list(pool, tenant_id, query: Option<&str>, limit, offset) -> anyhow::Result<Vec<User>>`; route `GET /admin/tenants/{tenant}/users`.

- [ ] **Step 1: Write the failing test**

```rust
mod common;
use common::*;

#[tokio::test]
async fn the_user_list_searches_and_excludes_deleted_users() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    for upn in ["bob@contoso.com", "carol@contoso.com"] {
        rust_oidc::users::create(&s.pool, &f.tenant, rust_oidc::users::NewUser {
            upn, password: "Correct-Horse-9", display_name: Some(upn),
            given_name: None, family_name: None, email: None,
        }).await.unwrap();
    }
    let all = rust_oidc::users::list(&s.pool, &f.tenant.id, None, 50, 0).await.unwrap();
    assert!(all.len() >= 3);

    let found = rust_oidc::users::list(&s.pool, &f.tenant.id, Some("carol"), 50, 0).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].upn, "carol@contoso.com");

    sqlx::query("UPDATE users SET deleted_at = 1 WHERE upn = 'carol@contoso.com'")
        .execute(&s.pool).await.unwrap();
    let after = rust_oidc::users::list(&s.pool, &f.tenant.id, Some("carol"), 50, 0).await.unwrap();
    assert!(after.is_empty(), "soft-deleted users are excluded");
}

#[tokio::test]
async fn the_users_page_renders_for_a_permitted_admin() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains(&f.upn), "{}", page.body);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test admin_users`
Expected: FAIL to compile — `users::list` does not exist.

- [ ] **Step 3: Implement**

```rust
// src/users.rs
/// List users in a tenant, optionally filtered by UPN or display name.
/// Soft-deleted users are never returned.
pub async fn list(
    pool: &SqlitePool,
    tenant_id: &str,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<User>> {
    let like = query.map(|q| format!("%{q}%"));
    Ok(sqlx::query_as(
        "SELECT id, tenant_id, upn, email, email_verified, display_name, given_name, family_name, enabled
         FROM users
         WHERE tenant_id = ?1 AND deleted_at IS NULL
           AND (?2 IS NULL OR upn LIKE ?2 OR display_name LIKE ?2)
         ORDER BY upn LIMIT ?3 OFFSET ?4",
    )
    .bind(tenant_id).bind(like).bind(limit).bind(offset)
    .fetch_all(pool)
    .await?)
}
```

Audit the existing user queries (`users::find`, `users::authenticate`) and add
`AND deleted_at IS NULL` to each, so a soft-deleted user cannot sign in. The
handler calls `ctx.require(Action::new(Resource::User, Verb::Read), On::Tenant(&key))?`
and renders `users.html` with a search box posting back to the same route.

- [ ] **Step 4: Run and commit**

Run: `cargo test && cargo clippy --all-targets`

```bash
git add src/users.rs src/admin/users.rs templates/admin/users.html src/admin/routes.rs tests/admin_users.rs
git commit -m "feat(admin): user list with search, excluding soft-deleted users"
```

---

### Task 11: Create a user

**Files:**
- Create: `templates/admin/user_new.html`
- Modify: `src/admin/users.rs`, `src/admin/routes.rs`
- Test: `tests/admin_users.rs` (append)

**Interfaces:**
- Consumes: `users::create`, `users::validate_upn`, `db::audit`.
- Produces: `GET|POST /admin/tenants/{tenant}/users/new`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn creating_a_user_validates_the_domain_and_audits() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id));

    // A UPN outside the tenant's verified domains is refused with a message.
    let page = b.post_form(&url, &[
        ("upn", "dave@notours.test"), ("password", "Correct-Horse-9"), ("display_name", "Dave"),
    ]).await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.to_lowercase().contains("domain"), "{}", page.body);

    let page = b.post_form(&url, &[
        ("upn", "dave@contoso.com"), ("password", "Correct-Horse-9"), ("display_name", "Dave"),
    ]).await;
    assert_eq!(page.status, 302, "{}", page.body);
    let found = rust_oidc::users::list(&s.pool, &f.tenant.id, Some("dave"), 10, 0).await.unwrap();
    assert_eq!(found.len(), 1);

    let (actor, action): (String, String) = sqlx::query_as(
        "SELECT actor, action FROM audit_log WHERE action = 'admin.user.create' ORDER BY created_at DESC LIMIT 1",
    ).fetch_one(&s.pool).await.unwrap();
    assert_eq!(actor, f.upn);
    assert_eq!(action, "admin.user.create");
}

#[tokio::test]
async fn a_reader_cannot_create_a_user() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;   // GlobalReader at All scope
    let b = signed_in_admin(&s, &f).await;
    let page = b.post_form(&s.url(&format!("/admin/tenants/{}/users/new", f.tenant.id)), &[
        ("upn", "eve@contoso.com"), ("password", "Correct-Horse-9"), ("display_name", "Eve"),
    ]).await;
    assert_eq!(page.status, 403, "{}", page.body);
}
```

Add `reader_fixture` to `tests/common/mod.rs`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test admin_users creating_a_user`
Expected: FAIL — the route does not exist (404, not 400/302).

- [ ] **Step 3: Implement the create route**

`GET` renders `user_new.html`. `POST` does, in order: `require` the action, parse
the form, call `users::create`, audit, redirect.

```rust
async fn create_user(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(resp) = ctx.require(Action::new(Resource::User, Verb::Write), On::Tenant(&key)) {
        return resp;
    }
    let form = parse_form(&body);
    let Some(tenant) = ctx.tenant(&key) else { return not_found() };
    let upn = form.get("upn").map(String::as_str).unwrap_or_default();
    // users::create already rejects a UPN whose suffix is not a verified domain.
    match users::create(&st.pool, tenant, users::NewUser {
        upn,
        password: form.get("password").map(String::as_str).unwrap_or_default(),
        display_name: form.get("display_name").map(String::as_str),
        given_name: form.get("given_name").map(String::as_str),
        family_name: form.get("family_name").map(String::as_str),
        email: form.get("email").map(String::as_str),
    }).await {
        Ok(user_id) => {
            audit(&st, &ctx, tenant, "admin.user.create", Some(&user_id), json!({ "upn": upn })).await;
            redirect(&format!("{}/admin/tenants/{}/users/{user_id}", st.public_url.base(), tenant.id))
        }
        // The message names the problem (e.g. the domain is not verified).
        Err(e) => new_user_page(&ctx, tenant, &form, Some(&e.to_string()), StatusCode::BAD_REQUEST),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test admin_users && cargo clippy --all-targets`
Expected: both new tests PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/admin/users.rs templates/admin/user_new.html tests/admin_users.rs tests/common/mod.rs
git commit -m "feat(admin): create a user from the console"
```

---

### Task 12: Edit attributes, enable and disable

**Files:**
- Create: `templates/admin/user_detail.html`
- Modify: `src/users.rs`, `src/admin/users.rs`
- Test: `tests/admin_users.rs` (append)

**Interfaces:**
- Produces: `users::update_attributes(pool, tenant_id, user_id, &UserAttributes) -> anyhow::Result<bool>`, `users::set_enabled(pool, tenant_id, user_id, bool) -> anyhow::Result<bool>`, `struct UserAttributes { display_name, given_name, family_name, email, email_verified }`; routes `GET /admin/tenants/{tenant}/users/{id}` and `POST .../users/{id}`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn editing_attributes_persists_and_shows_in_tokens() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id));

    let page = b.post_form(&url, &[
        ("op", "attributes"), ("display_name", "Alice Cooper"),
        ("given_name", "Alice"), ("family_name", "Cooper"),
        ("email", "alice.cooper@example.org"), ("email_verified", "on"),
    ]).await;
    assert_eq!(page.status, 302, "{}", page.body);

    let user = rust_oidc::users::find(&s.pool, &f.tenant.id, &f.user_id).await.unwrap().unwrap();
    assert_eq!(user.display_name.as_deref(), Some("Alice Cooper"));
    assert_eq!(user.family_name.as_deref(), Some("Cooper"));
    assert!(user.email_verified);
}

#[tokio::test]
async fn disabling_a_user_blocks_sign_in() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let target = rust_oidc::users::create(&s.pool, &f.tenant, rust_oidc::users::NewUser {
        upn: "frank@contoso.com", password: "Correct-Horse-9",
        display_name: None, given_name: None, family_name: None, email: None,
    }).await.unwrap();

    b.post_form(&s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, target)),
        &[("op", "disable")]).await;

    let outcome = rust_oidc::users::authenticate(&s.pool, &f.tenant, "frank@contoso.com", "Correct-Horse-9")
        .await.unwrap();
    assert!(matches!(outcome, rust_oidc::users::AuthResult::Disabled), "{outcome:?}");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test admin_users editing_attributes`
Expected: FAIL — `users::update_attributes` does not exist.

- [ ] **Step 3: Add the domain functions**

```rust
// src/users.rs
pub struct UserAttributes<'a> {
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub email_verified: bool,
}

pub async fn update_attributes(
    pool: &SqlitePool, tenant_id: &str, user_id: &str, attrs: &UserAttributes<'_>,
) -> anyhow::Result<bool> {
    let done = sqlx::query(
        "UPDATE users SET display_name = ?, given_name = ?, family_name = ?, email = ?,
                          email_verified = ?, updated_at = ?
         WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    )
    .bind(attrs.display_name).bind(attrs.given_name).bind(attrs.family_name)
    .bind(attrs.email).bind(attrs.email_verified).bind(now())
    .bind(user_id).bind(tenant_id)
    .execute(pool).await?;
    Ok(done.rows_affected() > 0)
}
```

`set_enabled` is the same shape against `enabled`. Both take `tenant_id` in the
`WHERE`, so a handler cannot be tricked into editing another tenant's user even
if the id is guessed.

- [ ] **Step 4: Implement the detail page and its actions**

The handler dispatches on an `op` field via a `UserOp` enum
(`Attributes | Enable | Disable | Reset | Delete`) — no bare strings — requiring
`User:Write` for attribute/enable/disable, `User:Reset` for a reset, and audits
`admin.user.update` / `admin.user.enable` / `admin.user.disable`.

`user_detail.html` also shows the user's **group memberships read-only** (from
`groups::names_for_user`); editing them arrives with the groups sub-project.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test admin_users && cargo clippy --all-targets`
Expected: PASS, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add src/users.rs src/admin/users.rs templates/admin/user_detail.html tests/admin_users.rs
git commit -m "feat(admin): edit user attributes, enable and disable"
```

---

### Task 13: Reset a password and soft delete

**Files:**
- Modify: `src/users.rs` (soft delete), `src/admin/users.rs`
- Test: `tests/admin_users.rs` (append)

**Interfaces:**
- Produces: `users::soft_delete(pool, tenant_id, user_id) -> anyhow::Result<bool>`; `op=reset` and `op=delete` on the detail route.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn resetting_a_password_revokes_sessions_and_refresh_tokens() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    b.post_form(&s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
        &[("op", "reset"), ("password", "Brand-New-Pass-1")]).await;

    let outcome = rust_oidc::users::authenticate(&s.pool, &f.tenant, &f.upn, "Brand-New-Pass-1")
        .await.unwrap();
    assert!(matches!(outcome, rust_oidc::users::AuthResult::Ok(_)));
    let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = ?")
        .bind(&f.user_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(sessions, 0, "set_password revokes sessions");
}

#[tokio::test]
async fn a_soft_deleted_user_disappears_and_cannot_sign_in() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let target = rust_oidc::users::create(&s.pool, &f.tenant, rust_oidc::users::NewUser {
        upn: "gina@contoso.com", password: "Correct-Horse-9",
        display_name: None, given_name: None, family_name: None, email: None,
    }).await.unwrap();

    b.post_form(&s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, target)),
        &[("op", "delete")]).await;

    assert!(rust_oidc::users::find(&s.pool, &f.tenant.id, &target).await.unwrap().is_none());
    let outcome = rust_oidc::users::authenticate(&s.pool, &f.tenant, "gina@contoso.com", "Correct-Horse-9")
        .await.unwrap();
    assert!(!matches!(outcome, rust_oidc::users::AuthResult::Ok(_)), "deleted users cannot sign in");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test admin_users soft_deleted`
Expected: FAIL — `users::soft_delete` does not exist.

- [ ] **Step 3: Implement soft delete**

```rust
// src/users.rs
/// Mark the user deleted and end their access immediately. Kept rather than
/// removed so audit rows and token `oid`s still resolve to something.
pub async fn soft_delete(pool: &SqlitePool, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let done = sqlx::query(
        "UPDATE users SET deleted_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    )
    .bind(now()).bind(now()).bind(user_id).bind(tenant_id)
    .execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(now()).bind(user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(done.rows_affected() > 0)
}
```

The `op=reset` branch reuses `users::set_password`, which already revokes
sessions and refresh tokens. Audit `admin.user.reset` and `admin.user.delete`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test admin_users && cargo clippy --all-targets`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/users.rs src/admin/users.rs tests/admin_users.rs
git commit -m "feat(admin): reset a password and soft delete a user"
```

---

### Task 14: Isolation and escalation tests

The point of the whole design. No new production code unless a test finds a hole
— in which case fix it and say so in the commit message.

**Files:**
- Create: `tests/admin_isolation.rs`

- [ ] **Step 1: Write the tests**

```rust
//! A tenant admin must be confined to the tenants they are bound to.
mod common;
use common::*;

/// Every tenant-scoped route, for an admin bound only to `t1`, against `t2`.
#[tokio::test]
async fn a_tenant_admin_is_refused_on_another_tenant() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;          // GlobalAdministrator on f.tenant only
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let victim = rust_oidc::users::create(&s.pool, &other, rust_oidc::users::NewUser {
        upn: "target@fabrikam.test", password: "Correct-Horse-9",
        display_name: None, given_name: None, family_name: None, email: None,
    }).await.unwrap();
    let b = signed_in_admin(&s, &f).await;

    for (method, path) in [
        ("GET",  format!("/admin/tenants/{}/users", other.id)),
        ("GET",  format!("/admin/tenants/{}/users/{victim}", other.id)),
        ("POST", format!("/admin/tenants/{}/users/new", other.id)),
        ("POST", format!("/admin/tenants/{}/users/{victim}", other.id)),
    ] {
        let page = match method {
            "GET" => b.get(&s.url(&path)).await,
            _ => b.post_form(&s.url(&path), &[("op", "disable")]).await,
        };
        assert!(
            page.status == 403 || page.status == 404,
            "{method} {path} leaked with {}: {}", page.status, page.body
        );
    }
    // And the victim is untouched.
    let still = rust_oidc::users::find(&s.pool, &other.id, &victim).await.unwrap().unwrap();
    assert!(still.enabled);
}

/// The domain alias form must not bypass the scope check.
#[tokio::test]
async fn the_domain_alias_form_does_not_bypass_scope() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url("/admin/tenants/fabrikam.test/users")).await;
    assert!(page.status == 403 || page.status == 404, "{} {}", page.status, page.body);
    let _ = other;
}

#[tokio::test]
async fn a_tenant_admin_cannot_grant_themselves_another_tenant() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let eff = rust_oidc::admin::bindings::effective_for_user(&s.pool, &f.user_id).await.unwrap();
    use rust_oidc::admin::authz::may_write_binding;
    use rust_oidc::rbac::Scope;

    assert!(may_write_binding(&eff, &Scope::Tenants(vec![f.tenant.id.clone()])));
    assert!(!may_write_binding(&eff, &Scope::Tenants(vec![other.id.clone()])));
    assert!(!may_write_binding(&eff, &Scope::Tenants(vec![f.tenant.id.clone(), other.id.clone()])));
    assert!(!may_write_binding(&eff, &Scope::All));
}

#[tokio::test]
async fn a_reader_can_look_but_not_touch() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let list = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert_eq!(list.status, 200, "{}", list.body);
    let write = b.post_form(&s.url(&format!("/admin/tenants/{}/users/{}", f.tenant.id, f.user_id)),
        &[("op", "disable")]).await;
    assert_eq!(write.status, 403, "{}", write.body);
}

#[tokio::test]
async fn the_nav_offers_only_permitted_actions() {
    let s = TestServer::start().await;
    let f = reader_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/users", f.tenant.id))).await;
    assert!(!page.body.contains("users/new"), "a reader is not offered create: {}", page.body);
}
```

- [ ] **Step 2: Run them**

Run: `cargo test --test admin_isolation`
Expected: all PASS. Any failure is a real hole — fix the production code, do not
weaken the test.

- [ ] **Step 3: Full verification**

Run: `cargo test && cargo clippy --all-targets && compat/run.sh`
Expected: whole Rust suite green, clippy silent, compat suite unchanged (the
`wids` change is covered by `tests/user_flow.rs` and the MSAL suites).

- [ ] **Step 4: Commit**

```bash
git add tests/admin_isolation.rs
git commit -m "test(admin): tenant isolation, alias bypass and escalation"
```
