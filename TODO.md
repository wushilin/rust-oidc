# TODO

## Transactions: every change through one executor

Agreed with the user on 2026-10-03. **Not started.**

### The rule

Every change is one *command*, run by one *executor*. A command either did not
run (nothing changed, nothing recorded) or completed (every write and its audit
row committed together). There is no state in between.

### Decisions

1. **Bulk operations run one command per row.** Ticking twenty users and
   pressing Disable runs twenty commands; each succeeds or is refused on its
   own, and the page lists the refusals, as today.
2. **No audit, no change.** The audit row is written inside the command's
   transaction. If it cannot be written, the whole command rolls back. A broken
   audit table therefore stops all administrative changes; that is accepted.
3. **Converted in one go**, not incrementally: every command below moves to the
   executor in one piece of work, and the old direct paths are removed.

### Shape

```rust
trait Command {
    type Output;
    /// What authorizes it, and where (a tenant, or the whole deployment).
    fn action(&self) -> (Action, On);
    /// Preconditions, read inside the transaction, after its locks are taken.
    async fn check(&self, tx: &mut Tx) -> Result<(), Refusal>;
    /// The writes.
    async fn apply(&self, tx: &mut Tx) -> Result<Self::Output, Refusal>;
    /// The audit row: event, target, details (never a secret, never an
    /// unresolved identifier -- see the audit hygiene rules).
    fn audit(&self, out: &Self::Output) -> AuditEntry;
}
```

The executor, the only way a command runs:

1. Authorize the actor (console session or CLI) and, for the console, check CSRF.
2. Begin a transaction that takes its write locks up front:
   `BEGIN IMMEDIATE` on SQLite; `SERIALIZABLE` (or explicit row locks) on
   Postgres and MySQL, with a bounded retry on serialization failure.
3. `check`, then `apply`.
4. Run the global invariants once, inside the transaction:
   - at least one live, enabled root-tenant account can act as Global Administrator;
   - every role binding has the scope its role and holder allow;
   - no application that accepts only its own tenant has outside assignments.
5. Write the audit row.
6. Commit. Any error at any step rolls back.

### Locking

- Locks are taken when the transaction begins and released at commit or
  rollback. A transaction dropped on any error path rolls back, so no lock can
  outlive its command.
- Nothing slow runs inside a transaction: password hashing (Argon2), key
  generation and any HTTP call happen before it begins, and their results are
  passed in.
- The existing key-rotation lock (migration 0008) becomes the executor's
  locking for the key commands.

### Gaps this closes (known today)

1. Application *Sign-in and grants* saves up to four settings in separate writes;
   a failure part-way leaves some saved.
2. Creating a user in the console with *require change* is two writes.
3. *Reset MFA* removes the authenticator in one transaction and ends sessions in
   another.
4. Turning *Accept accounts of other tenants* off checks for outside assignments
   and updates in separate statements; a concurrent assignment can slip between.
5. The last-Global-Administrator rule can be beaten on Postgres at the default
   isolation level by two concurrent removals (write skew).
6. Audit rows are written after the change commits, and a failed audit write is
   only logged (`routes/audit.rs`), leaving an unaudited change.

### Scope: every command to convert

**Admin console**

| Page | Commands |
|---|---|
| Tenants | Create, Rename, Enable, Disable, DomainChange, DomainRemove |
| Tenant settings | Save settings |
| Users (one) | Create, Attributes, Enable, Disable, Reset, Delete, Groups, MfaPolicy, MfaReset, CrossTenant |
| Users (list) | Enable, Disable, Delete, AddToGroup — one command per row |
| Find | Restore user |
| Groups | Create, Delete (per row), member Add, member Remove (per row), DeleteGroup |
| Applications | Create, Flags, SecretAdd, SecretRemove, CertificateAdd, CertificateRemove, RedirectUriAdd, RedirectUriRemove, IdentifierUriAdd, IdentifierUriRemove, ScopeAdd, RoleAdd, Assign, Unassign, RoleAssign, RoleUnassign |
| Tenant roles | Grant, Revoke |
| Global roles | Grant, Revoke |
| Signing keys | Rotate, Prune |
| Flow tester | AddCallback, CreateTestClient (Start, ForgetSignIn and Check change no directory data and stay as they are) |

**My Account** (the user acting on themselves): Password, MfaSetup (the
enrolment step), MfaReplace, RecoveryCodes, SignOutEverywhere.

**Command line**: bootstrap; tenant create, change-domain; user create,
set-password, restore; group create, add-member; app create, add-identifier-uri,
add-redirect-uri, add-scope, implicit, password-grant, assignment-required, role and assignment
commands; key rotate, prune. The CLI actor is recorded as `cli`, as today.

**Out of scope**: sign-in bookkeeping (failed-attempt counters, lockout,
sessions, MFA tickets, codes and tokens). These are not administrative changes
and keep their own handling.

### Done when

- Every command above runs only through the executor; no handler or CLI path
  writes the directory directly.
- Tests: each gap above has a test that fails on today's code; a command whose
  audit write fails changes nothing; concurrent last-Global-Administrator
  removals leave one (SQLite here; Postgres and MySQL when those runs resume).
- `docs/decisions-log.md` records the design.
