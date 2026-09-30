# Admin console: shell, RBAC and the users section

Date: 2026-09-30
Status: awaiting review
Scope: sub-project 1 of 5 (see "Later sub-projects")

## Intent

Administration is CLI-only today, and the CLI is create-heavy: user attributes
cannot be updated at all, `TenantSettings` has no management path, and directory
roles can only be granted at `bootstrap`. This project builds the **web** admin
surface. The CLI gaps are deliberately deferred to a later project.

Two surfaces:

- **Global page** — platform work: tenants, domains, tenant settings, signing
  keys, who the platform admins are.
- **Tenant admin page** — work inside one tenant: users, groups, attributes,
  applications, assignments (MFA later).

**Operating model (agreed).** Delegated: a tenant admin manages only the
tenants they are bound to and must not see others. A super admin is bound at
platform scope, can manage tenants, and can **assume** any tenant and act as
its admin.

**Success criteria.** A tenant admin can do day-to-day user administration in a
browser without the CLI; a tenant admin cannot read or write another tenant's
data, proven by tests; a super admin can switch into any tenant and every
action they take there is attributable to them personally in the audit log.

Non-goals for this sub-project: MFA management (phase 3 does not exist yet), a
public admin API, CLI parity, per-tenant branding, self-service tenant signup.

## RBAC model

A role carries **actions**. A binding carries the **scope**. The grant is the
product of the two.

```
Role    : name          -> set of Actions      (what may be done)
Binding : principal, role, scope               (where it may be done)
Grant   : role.actions  x  binding.scope
```

### Actions

Structured as resource + verb, not flat strings, so the UI and any future custom
roles can reason about them. Modelled as Rust enums (project rule: no magic
values).

```rust
enum Resource { Tenant, User, Group, App, Assignment, RoleBinding, Key, Audit }
enum Verb     { Read, Write, Reset, Rotate, Create, Assume }
struct Action { resource: Resource, verb: Verb }
```

The action set used by this sub-project and the ones after it:

| Action | Meaning |
|---|---|
| `Tenant:Read` | see a tenant and its settings |
| `Tenant:Create` | create a tenant |
| `Tenant:Write` | change tenant settings and domains |
| `Tenant:Assume` | switch into a tenant and act as its admin |
| `User:Read` / `User:Write` | list/see users; create, edit attributes, enable/disable, delete |
| `User:Reset` | reset a password (revokes sessions and refresh tokens) |
| `Group:Read` / `Group:Write` | groups and membership |
| `App:Read` / `App:Write` | app registrations and their URIs, scopes, roles, flags |
| `App:Rotate` | add/remove secrets and certificate credentials |
| `Assignment:Read` / `Assignment:Write` | app-role and directory-role assignments |
| `RoleBinding:Read` / `RoleBinding:Write` | manage the bindings themselves (privileged) |
| `Key:Read` / `Key:Rotate` | signing keys |
| `Audit:Read` | read the audit log |

### Roles

Built-in and fixed in this sub-project (no custom roles yet). Roles that Entra
has keep Microsoft's well-known template GUIDs, already in `src/directory.rs`,
so the `wids` claim stays faithful.

| Role | Template GUID | Actions |
|---|---|---|
| Global Administrator | `62e90394-…5e10` | every action except `Tenant:Create`, `Key:Rotate`, `Tenant:Assume` (includes `RoleBinding:*`, subject to the no-widening rule below) |
| Global Reader | `f2ef992c-…c451` | every `Read` |
| User Administrator | `fe930be7-…38b1` | `User:*`, `Group:Read`, `Audit:Read` |
| Groups Administrator | `fdd7a751-…fa1c` | `Group:*`, `User:Read`, `Audit:Read` |
| Application Administrator | `9b895d92-…a5c3` | `App:*`, `Assignment:*`, `Audit:Read` |
| Cloud Application Administrator | `158c047a-…b5f7` | as Application Administrator, without `App:Rotate` |
| Privileged Role Administrator | `e8611ab8-…f814` | `RoleBinding:*`, `Assignment:*`, `Audit:Read` |
| **Platform Administrator** | none (not an Entra role) | `Tenant:Create`, `Tenant:Write`, `Tenant:Assume`, `Key:*`, `Audit:Read` |

Platform Administrator has no Entra counterpart, so it has no template GUID and
never appears in `wids`.

### Bindings

```sql
CREATE TABLE role_bindings (
    id             TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,          -- PrincipalType: User | Group
    principal_id   TEXT NOT NULL,
    role_id        TEXT NOT NULL,          -- RoleId
    scope_kind     TEXT NOT NULL,          -- ScopeKind: all | tenants
    created_at     INTEGER NOT NULL,
    created_by     TEXT
);
CREATE TABLE role_binding_tenants (
    binding_id TEXT NOT NULL REFERENCES role_bindings(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    PRIMARY KEY (binding_id, tenant_id)
);
```

`scope_kind = 'all'` is the `[*]` case and has no `role_binding_tenants` rows.
`scope_kind = 'tenants'` has one row per tenant, giving `['t1','t2']`. A
principal may be a **User or a Group**, so bindings expand through group
membership. Groups are tenant-scoped (`groups.tenant_id`), so a Group principal
is a group belonging to some tenant; membership confers no scope of its own —
the scope is whatever the binding says.

Examples:

| Principal | Role | Scope |
|---|---|---|
| global root | Global Administrator + Platform Administrator | `all` |
| tenant admin | Global Administrator | `tenants[t1, t2]` |
| helpdesk | User Administrator | `tenants[t1]` |
| auditor | Global Reader | `all` |

### Binding writes cannot widen scope

Global Administrator can manage bindings, as in Entra. Without a further rule
that is a privilege-escalation path: an admin scoped to `t1` could bind
themselves to `t2`. So a binding write is authorized against the **target
binding's** scope, not merely the page's tenant:

```
may_write_binding(principal, target_scope) <=>
      target_scope = Tenants(ids)  and  for every t in ids:
          allowed(principal, RoleBinding:Write, t)
  or  target_scope = All           and  allowed_at_all_scope(principal, RoleBinding:Write)
```

`allowed_at_all_scope` requires a binding whose own scope is `All`. So an admin
scoped to `[t1, t2]` can grant roles within `t1` and `t2` and nowhere else, and
only a principal already at `all` scope can mint another `all`-scope binding.
No role can widen its own reach; the rule is enforced in the same module as
`require`, not in handlers.

### The single check point

```
allowed(principal, action, tenant) <=>
    exists binding in bindings(principal) :
        action in role(binding).actions
      and covers(binding.scope, tenant)

covers(All, _)          = true
covers(Tenants(ids), t) = t in ids
```

This is the only place scope is interpreted. An axum extractor builds an
`AdminContext` from the session and the `{tenant}` path segment, loading
effective bindings once per request:

```rust
pub struct AdminContext {
    principal: Principal,          // the real signed-in admin, never the assumed one
    bindings: Vec<EffectiveBinding>,
    acting_tenant: Option<String>, // set while a tenant is assumed
}

impl AdminContext {
    pub fn require(&self, action: Action, on: On) -> Result<(), Forbidden>;
    pub fn can(&self, action: Action, on: On) -> bool;   // for rendering only
}
```

Every handler authorizes in one line:

```rust
ctx.require(Action::new(Resource::User, Verb::Write), On::Tenant(&tenant_id))?;
```

Handlers never branch on role names, never compare tenant ids and never
special-case the super admin: `all` scope covers every tenant, so "assume
tenant" needs no separate code path. Navigation and buttons render from
`can(...)`, the same function the guard uses, so the UI cannot offer an action
the check would refuse.

### `wids`

`wids` is derived from bindings: roles that have a template GUID whose scope
covers the token's tenant. One source of truth, so what the console enforces and
what tokens claim cannot drift.

**Accepted behaviour change:** a root admin bound at `all` scope will carry
Global Administrator in every tenant's tokens, where today `bootstrap` grants it
in the root tenant only. This is intended for a principal who can assume any
tenant. `directory_role_assignments` is migrated into `role_bindings` (each
existing row becomes a `tenants[<its tenant>]` binding) and the old table is
dropped, so only one system remains.

## Console authentication

The console is an OIDC client of rust-oidc itself.

- Its app registration is created **at startup** if absent (`Admin Console`,
  with a reserved app id held as a constant so it is stable across restarts and
  recognisable in audit rows, redirect URI
  `{public_url}/admin/callback`, no secret — it is a confidential client using
  PKCE with a startup-generated secret held in `server_secrets`). Nothing here
  requires the CLI.
- Sign-in is authorization code + PKCE against the server's own
  `/authorize`, so the console dogfoods the flows it administers.
- The console session is the existing browser session cookie plus a separate
  `admin` session record holding the signed-in principal and any assumed tenant.
- Access requires at least one binding granting any action; otherwise the
  console renders "you do not have access" rather than a raw 403.

**Known risk, accepted for now:** if OIDC or the signing keys break, there is no
way into the console to fix them. A CLI-issued break-glass session is the
intended remedy and is deferred with the rest of the CLI work.

## URLs

```
/{prefix}/admin                      global page: tenant list, keys, bindings
/{prefix}/admin/tenants/{tenant}/…   tenant admin pages
/{prefix}/admin/assume/{tenant}      POST: begin acting in a tenant
/{prefix}/admin/leave                POST: stop acting in a tenant
/{prefix}/admin/callback             OIDC redirect
```

Tenant admin pages live under `/admin/tenants/{tenant}/…` rather than the
existing `/{tenant}/…` space, so no tenant key can ever collide with the
`admin` path segment, and a tenant named or aliased `admin` is harmless. No
reserved-name guard is needed, which is why none is specified.

## Assume tenant

- Requires `Tenant:Assume` (Platform Administrator).
- `POST /admin/assume/{tenant}` records `acting_tenant` on the admin session;
  `POST /admin/leave` clears it.
- Authorization is unchanged while assuming: the super admin's `all`-scope
  bindings already cover the tenant. Assuming only changes navigation context,
  never the permission set.
- Every page shows a persistent banner naming the assumed tenant and offering
  "leave".
- Audit records the **real** principal plus the assumed tenant, so an action is
  always attributable to the person, never to an anonymous "admin".

## Users section

The one section built end to end in this sub-project, proving the whole path.

- **List** — search by UPN or display name, paged, showing enabled state.
- **Detail / edit** — display name, given name, family name, email,
  `email_verified`, enabled. These need new domain functions
  (`users::update_attributes`, `users::set_enabled`), which the later CLI work
  reuses rather than reimplements.
- **Create** — UPN validated against the tenant's verified domains, initial
  password.
- **Reset password** — reuses `users::set_password`, which already revokes
  sessions and refresh tokens.
- **Delete** — soft delete via a new `users.deleted_at` column, mirroring
  `applications.deleted_at`; every user query must then filter it out.
- **Group membership** — read-only here; editing arrives with the groups
  sub-project.

## Audit

Nothing in `src/routes/` writes audit today; every mutating admin action writes
one entry through the existing `db::audit`, recording actor (the real admin's
object id and UPN), tenant, action, target and a details object. The audit
reader is part of a later sub-project; this one only writes.

## Error handling

- Unauthenticated → redirect to the console sign-in.
- Authenticated but no binding → a plain "no access" page, HTTP 403.
- Authenticated, has bindings, lacks this action → 403 page naming the action
  required. The UI should rarely reach this because rendering uses `can(...)`.
- Unknown or disabled tenant in the URL → 404, identical whether or not the
  tenant exists, so the console is not a tenant-existence oracle for someone
  with narrow scope.
- Domain errors surface as page-level messages, reusing `html::error`.

## Testing

- **RBAC unit tests** over the evaluation rule: the table above as cases, plus
  group-derived bindings and a binding whose tenant was deleted.
- **Isolation integration tests** — the important ones, since real people hold
  tenant-admin rights: a tenant admin bound to `t1` gets 403/404 on every
  `t2` route (list, read, write, reset, delete), and cannot assume a tenant.
- **Escalation tests** — the sharpest edge in this design: an admin scoped to
  `t1` may create a binding scoped to `t1`, but is refused one scoped to `t2`,
  one scoped to `[t1, t2]`, and one scoped to `all`.
- **Assume-tenant tests**: super admin acts in `t2`; the audit row names the
  super admin, not a tenant-local identity.
- **`wids` migration test**: an existing `directory_role_assignments` row keeps
  producing the same `wids` for that tenant after migration.
- **Users section integration tests** through the HTTP surface, using the
  existing `TestServer`/`Browser` harness.

## Later sub-projects

2. Groups and assignments (including `RoleBinding` management UI).
3. Applications: URIs, scopes, roles, secrets, certificates, flags.
4. Global page: tenant create/disable, domains, tenant settings, signing keys.
5. MFA section, once phase 3 exists; then CLI parity and break-glass.

## Visual design

The existing sign-in pages are deliberately plain. The console is held to a
higher bar per the project's standing note, so implementation begins with a
design pass (the `frontend-design` skill) rather than extending
`src/html.rs`'s stylesheet. askama templates, htmx for interactions, no JS
build step.
