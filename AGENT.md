# House rules

Rules for anyone (human or agent) changing this repository. They are decisions
the owner has made; follow them, and ask before departing from one.

## Every change is a transaction, run by the one engine

This is a structural guarantee, not a convention. *Status: being introduced
(see `TODO.md`); until it is finished, new code must follow it and old code is
being moved to it.*

1. **One change, one transaction type.** Every administrative change (admin
   console, CLI, and a user's own changes in My Account) is a struct
   implementing `Transaction`, listed once in the `Txn` enum. No handler, page or
   CLI command writes the directory any other way.
2. **Parameters are typed fields.** Required parameters are plain fields,
   optional ones `Option<T>`; there are no stringly-typed parameter bags. Each
   transaction declares its own `Output` type.
3. **All or nothing.** A transaction either did not run (nothing changed,
   nothing recorded) or completed (every write and its audit row committed
   together). There is no state in between, and no partial save.
4. **Aborting needs a reason.** A transaction aborts only through its context,
   `cx.fail(reason)`; it cannot abort without saying why. Database errors are
   failures too, classified by the engine (a lock not granted becomes `Busy`).
5. **One standard result.** The engine returns an `Outcome`: done (committed),
   refused (rolled back, the actor can fix it), or failed (rolled back, our
   fault). Pages and the CLI turn an `Outcome` into a response one way only.
6. **No audit, no change.** The audit row is written inside the transaction. If
   it cannot be written, the whole change rolls back.
7. **Batches commit once.** Several transactions run as a batch share one
   context; nothing commits until the last succeeds, and any abort rolls back
   the batch. The console's bulk buttons run one transaction per row instead.
8. **Global rules are checked by the engine**, at the end, against the final
   state (for example: someone can still act as Global Administrator). Storage
   functions also enforce their own rules where they write.
9. **A transaction declares its own locks** (`Transaction::locks`); the engine
   takes every lock of the run or batch before anything runs, sorted in one
   fixed order (named locks, tenant, user, group, application; then by id), so
   no two transactions wait on each other in a cycle. Every wait has a timeout
   (5 s); a lock not granted in time aborts the transaction as `Busy`. Locks
   are released at commit or rollback, on every path.
10. **Nothing slow inside a transaction**: password hashing, key generation and
    HTTP calls happen before it begins, and their results are passed in.
11. **Storage functions take a handle, not a pool**: `impl Handle<'c>`, so the
    same function runs on its own (given the pool) or inside a transaction
    (given the transaction's connection, where its own `begin` is a savepoint).
12. **Tested without HTTP.** Each transaction is tested by running it through the
    engine against a test database and asserting on the `Outcome`.

## Other standing rules

- **Follow Microsoft Entra ID** as closely as possible at the protocol level:
  endpoints, claims, error codes (AADSTS numbers), behaviour.
- **No magic values.** Enums over bare strings and numbers; a value with meaning
  is named once.
- **Rules live in the storage layer**, not in page handlers: an invariant is
  enforced where the data is written (and re-checked where it is read), so no
  page or command can get around it.
- **The admin console is script-free**: CSP `default-src 'none'`, no JavaScript,
  no web fonts. Interactivity is HTML and CSS (forms, `<details>`, the popover
  attributes, `:has()`).
- **Audit hygiene**: never write a secret, and never write an identifier that was
  not resolved to a known object, into the audit log.
- **Migrations are additive and in place**, written for all three engines
  (SQLite, Postgres, MySQL); an applied migration never changes.
- **Tests**: run the SQLite suite (`cargo test`) before every commit;
  Postgres/MySQL runs are paused until the owner asks for them. A security test
  must fail when the guard it covers is removed (check it).
- **Decisions** made without asking go in `docs/decisions-log.md`.
