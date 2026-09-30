# Databases

rust-oidc runs on **SQLite** (default), **PostgreSQL** and **MySQL**, all through sqlx's
`Any` driver. The engine is chosen from the scheme of `RUST_OIDC_DATABASE`.

SQLite remains the default. The deployed service uses SQLite and is unaffected.

## Connection URLs

| Engine | Forms |
|---|---|
| SQLite | `sqlite:data/rust-oidc.db`, `sqlite://data/rust-oidc.db`, `sqlite:///abs/path.db` (both `sqlite:path` and `sqlite://path` work) |
| PostgreSQL | `postgres://user:pass@host:5432/db`, `postgresql://...` |
| MySQL | `mysql://user:pass@host:3306/db` |
| MariaDB | `mariadb://...` is accepted and mapped to MySQL, but is **untested** |

Migrations run at startup from `migrations/<engine>/`.

## Running the tests

- `cargo test` covers **SQLite only**. It prints two skip lines for the engines that are not
  configured. A green `cargo test` is therefore **not** evidence of portability.
- `bash scripts/test-engines.sh` starts throwaway PostgreSQL and MySQL containers under
  podman and runs the whole suite against all three engines.

## Keeping migrations in step

`migrations/{sqlite,postgres,mysql}/` each hold the same migration names, and every change
must be made in all three. This is the ongoing maintenance cost of the design.
`tests/migration_drift.rs` guards the `0006` CASE arms specifically, because divergence
there is a privilege-escalation bug, not a cosmetic one.

## sqlx `Any` limitations

- **No placeholder rewriting.** `?` works on SQLite and MySQL and fails on PostgreSQL, so
  every query goes through `db::sql_stmt`. `tests/sql_routing.rs` guards this; its own blind
  spots are documented in that file.
- **MySQL `TINYINT` cannot be mapped at all**, so MySQL booleans are `SMALLINT`. Any other
  unmapped MySQL type behaves the same way, for example `DECIMAL` or a `SUM()` result. Treat
  this as a constraint on future schema work (cast in SQL or avoid such types).
- Type coverage is limited to `AnyValueKind`: Bool, SmallInt, Integer, BigInt, Real, Double,
  Text, Blob.

## Case-insensitive identity

This is done in Rust, not by collation: `util::fold` plus `*_folded` columns with unique
indexes, reconciled at startup by `db::reconcile_folded`. A folding collision **refuses to
start**, deliberately, with a full diagnostic. The operator must rename or remove one of the
conflicting rows and restart. No CLI command can do that; use the engine's own client
(`sqlite3`, `psql`, `mysql`). Only `serve` fails closed: other subcommands log the collision
and continue.

## MySQL specifics

- Requires **MySQL 8.0.16+**. `DEFAULT ('{}')` needs 8.0.13, but before 8.0.16 MySQL parsed
  and silently ignored `CHECK` clauses, and this schema relies on its table-level checks
  (`0001_init.sql`, `0003`).
- The schema assumes a **strict** `sql_mode` (the 8.0 default). A non-strict server truncates
  over-long values instead of erroring.
- Key columns are `VARCHAR`-capped: a `jti` over 255 characters or a UPN over 320 fails on
  MySQL (error 1406), where SQLite and Postgres accept it.
- `utf8mb4_unicode_ci` is PAD SPACE: trailing spaces are insignificant on the non-`_bin`
  columns, which are display names only.
- The MySQL migrations were amended in place before the first release. Do **not** edit
  migrations after release by analogy; add a new one, since sqlx checksums applied files.
- Exact-match columns carry `COLLATE utf8mb4_bin`. The default collation is case- and
  accent-insensitive, which would otherwise loosen OAuth redirect-URI matching.
- `GROUPS` is a reserved word, so the table is `user_groups`.
- **A `TEXT` column cannot be indexed without a prefix length.** `0009` therefore narrows
  `audit_log.actor`/`action`/`target` to `VARCHAR` (with `utf8mb4_bin`, since all three are
  equality matches) before creating the indexes. Any future index on a `TEXT` column needs
  the same treatment, or a prefix length -- and a prefix index cannot serve a unique
  constraint the way the full column does.

## Which closed sets the schema enforces, and which it does not

Every closed set is a Rust enum (the "no magic values" rule), but only some are also
constrained by the database. Where the schema does **not** constrain one, the Rust-side
parse is load-bearing and must fail closed rather than default.

| Column | `CHECK` in the schema? |
|---|---|
| `app_redirect_uris.platform` | **Yes**, all three engines: `CHECK (platform IN ('web','spa','publicClient'))` |
| `auth_codes.platform` | **No** — only a `-- web \| spa \| publicClient` comment |
| `refresh_tokens.platform` | **No** — same |
| `app_scopes.type`, `app_roles.allowed_member_types`, `app_role_assignments.principal_type`, `role_bindings.principal_type`, `audit_log.action`, `audit_log.actor` | **No** |

The two grant tables are the ones that mattered: `authenticate_for_platform` used to
compare the stored platform as a string and fall through to *public client* rules for
anything it did not recognise, so an unreadable value meant "no client authentication"
(decision 42). `src/routes/user_grants.rs::stored_platform` now refuses instead.

Adding a `CHECK` to those two columns would be defence in depth. It is not done because
SQLite cannot add a constraint to an existing table without rebuilding it, and these
migrations have only ever run against empty databases (see *Known limitations*).
`tests/storage_vocabulary.rs` asserts both halves of the table above, so a migration
that adds or drops one of these constraints is noticed.

## Not supported

**SQL Server** and **Oracle** are outside sqlx: SQL Server support was dropped before sqlx
0.7 and Oracle was never supported. Adding either means a separate driver (`tiberius`, or
the synchronous `oracle` crate) or ODBC behind a repository trait. It is not a feature flag.

## Known limitations

- MariaDB is untested; other engine versions than those in `scripts/test-engines.sh` are
  untested.
- High-contention concurrency is untested. MySQL gap-lock deadlocks are not retried by the
  upserts.
- **Upgrading a populated database is untested.** The migrations have only ever run against
  empty databases.
- `keys::rotate` is unsafe under two concurrent rotations (pre-existing).
