# Multi-Engine Database Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** rust-oidc runs on SQLite, PostgreSQL and MySQL, with the whole test suite passing against all three.

**Architecture:** One `sqlx::Any` pool behind a `db::DbPool` alias, so no module names an engine. Dialect differences are handled in three places and nowhere else: a placeholder rewriter, per-engine migration directories, and engine-neutral rewrites of the upserts and case-insensitive comparisons. Nothing above `src/db.rs` knows which engine is in use.

**Tech Stack:** Rust, sqlx 0.9 with the `any`, `sqlite`, `postgres` and `mysql` features, podman for the Postgres and MySQL test containers.

**Spec:** none — this plan was authorised directly, after a spike established the two constraints below. Treat this header as the spec.

## Findings from the spike (these drive the design; do not re-litigate them)

- `AnyValueKind` carries `Bool`, `SmallInt`, `Integer`, `BigInt`, `Real`, `Double`, `Text` and `Blob(Arc<Vec<u8>>)`. Every type this codebase stores is covered, so `Any` is viable.
- **`Any` does NOT rewrite placeholders.** `sqlx-postgres-0.9.0/src/any.rs::fetch_optional` passes the SQL string through untouched. `?` works on SQLite and MySQL and fails on Postgres, so the rewriter in Task 2 is mandatory, not a nicety.
- There are no literal `?` characters inside any SQL string in `src/`, so the rewriter only has to be careful, not clever.
- 12 numbered placeholders (`?1`, `?2`) exist in `src/admin/bindings.rs` (4), `src/apps.rs` (6) and `src/tenant.rs` (2).
- 3 `COLLATE NOCASE` columns in `migrations/0001_init.sql`: `users.upn`, `tenant_domains.domain`, `groups.name`.

## Global Constraints

- **No module outside `src/db.rs` names an engine.** No `SqlitePool`, `PgPool`, `Sqlite`, `Postgres` or `MySql` type anywhere else, and no `#[cfg(feature = ...)]` engine branches in domain code.
- **No magic values.** Closed sets are Rust enums with `as_str`/`parse`. This includes the new `Engine` enum.
- **Every query goes through the placeholder rewriter.** A raw `sqlx::query("… ?")` that bypasses it is a defect, because it silently works on two engines and fails on the third.
- **Case-insensitive identity is normalised in Rust, not delegated to collation.** UPNs, tenant domains and group names must compare and unique-constrain identically on all three engines. This is security-relevant: if `alice@x` and `Alice@X` are one account on one engine and two on another, that is an account-takeover shaped bug.
- Clippy silent (`cargo clippy --all-targets`), and the suite green on **all three engines** before a task is done from Task 6 onward. Before Task 6, SQLite green is the bar.
- SQLite stays the default so the titanl deployment keeps working untouched.

## Review Focus

Input classes that no happy-path test would exercise. Each has its test assigned to the task that owns the code.

1. **A UPN differing only by case, across engines** — sign-in must find the same account on all three, and creating `Alice@x` when `alice@x` exists must be refused everywhere. *(Task 4)*
2. **Placeholder rewriting with a `?` inside a quoted SQL literal** — today none exist, but the rewriter must not corrupt one if somebody adds it. *(Task 2)*
3. **Two concurrent upserts of the same row** — the engine-neutral SELECT-then-write pattern replaces atomic `ON CONFLICT`, so it must not lose a write or raise a unique violation to the caller. *(Task 5)*
4. **Blob round-trip on each engine** — signing-key DER, `server_secrets.value` and the client-certificate modulus/exponent must come back byte-identical from `BYTEA` and `BLOB`, not hex-encoded or truncated. *(Task 6)*
5. **Boolean and timestamp shape per engine** — `enabled`, `email_verified` and the `INTEGER` epoch columns must read back as the same Rust values from Postgres `BOOLEAN`/`BIGINT` as from SQLite `INTEGER`. *(Task 3)*

---

### Task 1: The `db` abstraction and the pool sweep

**Files:**
- Modify: `Cargo.toml`, `src/db.rs`, then every module that names `SqlitePool` (`src/keys.rs`, `groups.rs`, `scopes.rs`, `session.rs`, `directory.rs`, `tenant.rs`, `secrets.rs`, `apps.rs`, `users.rs`, `admin/bindings.rs`, `main.rs`, `lib.rs`, and `src/routes/*`)
- Test: `tests/db_engine.rs`

**Interfaces:**
- Produces: `db::Db` (= `sqlx::Any`), `db::DbPool` (= `sqlx::Pool<sqlx::Any>`), `db::Engine { Sqlite, Postgres, MySql }` with `as_str`/`parse`/`from_url`, `db::connect(url) -> anyhow::Result<DbPool>`, `db::engine_of(&DbPool) -> Engine`.

- [ ] **Step 1: Write the failing test**

```rust
mod common;
use rust_oidc::db::Engine;

#[test]
fn the_engine_is_recognised_from_the_url() {
    assert_eq!(Engine::from_url("sqlite://x.db"), Some(Engine::Sqlite));
    assert_eq!(Engine::from_url("postgres://u@h/db"), Some(Engine::Postgres));
    assert_eq!(Engine::from_url("postgresql://u@h/db"), Some(Engine::Postgres));
    assert_eq!(Engine::from_url("mysql://u@h/db"), Some(Engine::MySql));
    assert_eq!(Engine::from_url("mariadb://u@h/db"), Some(Engine::MySql));
    assert_eq!(Engine::from_url("oracle://nope"), None);
}

#[test]
fn engine_names_round_trip() {
    for e in Engine::ALL {
        assert_eq!(Engine::parse(e.as_str()), Some(*e));
    }
}

#[tokio::test]
async fn a_sqlite_url_still_connects_and_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("t.db").display());
    let pool = rust_oidc::db::connect(&url).await.unwrap();
    assert_eq!(rust_oidc::db::engine_of(&pool), Engine::Sqlite);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test db_engine`
Expected: FAIL to compile — `db::Engine` does not exist.

- [ ] **Step 3: Implement**

`Cargo.toml`: change the sqlx line to
`sqlx = { version = "0.9.0", default-features = false, features = ["runtime-tokio", "any", "sqlite", "postgres", "mysql", "migrate", "macros"] }`

`src/db.rs`:

```rust
/// The one place an engine is named. Everything above this module uses `DbPool`.
pub type Db = sqlx::Any;
pub type DbPool = sqlx::Pool<Db>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Sqlite,
    Postgres,
    MySql,
}

impl Engine {
    pub const ALL: &'static [Engine] = &[Self::Sqlite, Self::Postgres, Self::MySql];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_str() == raw)
    }

    /// Which engine a connection URL selects. Accepts the aliases sqlx accepts.
    pub fn from_url(url: &str) -> Option<Self> {
        let scheme = url.split("://").next()?.to_ascii_lowercase();
        match scheme.as_str() {
            "sqlite" => Some(Self::Sqlite),
            "postgres" | "postgresql" => Some(Self::Postgres),
            "mysql" | "mariadb" => Some(Self::MySql),
            _ => None,
        }
    }
}
```

`db::connect` calls `sqlx::any::install_default_drivers()` once (guard it with a `std::sync::Once` — calling it twice panics), rejects an unrecognised URL with a clear error naming the three supported schemes, creates the pool, then runs the migrations for that engine (Task 3 supplies the per-engine directories; until then keep the existing single `migrations/` call so this task can be green on its own). `engine_of` records the engine in a `OnceLock` set by `connect`, or re-derives it from `pool.connect_options()` — whichever is simpler; state which you chose.

Then the sweep: replace every `SqlitePool` with `db::DbPool` and every `sqlx::Sqlite` type parameter with `db::Db`. `grep -rn "Sqlite" src/` must return hits only in `src/db.rs` when you are done. Do not change any SQL in this task.

- [ ] **Step 4: Verify**

Run: `cargo test` (all 84 must pass on SQLite), `cargo clippy --all-targets` (silent), and `grep -rn "SqlitePool\|sqlx::Sqlite" src/ | grep -v "^src/db.rs"` (must be empty).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/ tests/db_engine.rs
git commit -m "refactor(db): one Any pool behind db::DbPool, engine from the URL"
```

---

### Task 2: Placeholder rewriting

Mandatory: `Any` does not do this for us, so without it every query fails on Postgres.

**Files:**
- Modify: `src/db.rs`; the three files with numbered placeholders (`src/admin/bindings.rs`, `src/apps.rs`, `src/tenant.rs`); then every query call site
- Test: inline `#[cfg(test)]` in `src/db.rs`

**Interfaces:**
- Produces: `db::sql(engine: Engine, sql: &str) -> std::borrow::Cow<'_, str>` — returns the input unchanged for SQLite and MySQL, and `?` → `$1, $2, …` for Postgres.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_and_mysql_keep_question_marks() {
        let q = "SELECT a FROM t WHERE b = ? AND c = ?";
        assert_eq!(sql(Engine::Sqlite, q), q);
        assert_eq!(sql(Engine::MySql, q), q);
    }

    #[test]
    fn postgres_gets_numbered_parameters() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT a FROM t WHERE b = ? AND c = ?"),
            "SELECT a FROM t WHERE b = $1 AND c = $2"
        );
    }

    #[test]
    fn postgres_numbering_counts_every_placeholder_in_order() {
        assert_eq!(
            sql(Engine::Postgres, "INSERT INTO t (a,b,c) VALUES (?, ?, ?)"),
            "INSERT INTO t (a,b,c) VALUES ($1, $2, $3)"
        );
    }

    /// Review Focus 2: a `?` inside a quoted literal is data, not a placeholder.
    #[test]
    fn a_question_mark_inside_a_string_literal_is_left_alone() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT a FROM t WHERE b = ? AND c = 'why?'"),
            "SELECT a FROM t WHERE b = $1 AND c = 'why?'"
        );
        assert_eq!(
            sql(Engine::Postgres, "SELECT 'a?b' AS x WHERE y = ?"),
            "SELECT 'a?b' AS x WHERE y = $1"
        );
    }

    #[test]
    fn a_doubled_quote_inside_a_literal_does_not_end_it() {
        assert_eq!(
            sql(Engine::Postgres, "SELECT 'it''s ?' WHERE y = ?"),
            "SELECT 'it''s ?' WHERE y = $1"
        );
    }

    #[test]
    fn sql_without_placeholders_is_unchanged_and_not_reallocated() {
        let q = "SELECT 1";
        assert!(matches!(sql(Engine::Postgres, q), std::borrow::Cow::Borrowed(_)));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --lib db`
Expected: FAIL to compile — `db::sql` does not exist.

- [ ] **Step 3: Implement**

```rust
/// Rewrite placeholders for the target engine. SQLite and MySQL use `?`;
/// Postgres needs `$1`, `$2`, … in order. A `?` inside a single-quoted literal
/// is data and must be left alone; `''` is an escaped quote, not a terminator.
pub fn sql(engine: Engine, sql: &str) -> std::borrow::Cow<'_, str> {
    if engine != Engine::Postgres || !sql.contains('?') {
        return std::borrow::Cow::Borrowed(sql);
    }
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0usize;
    let mut in_literal = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                out.push(c);
                if in_literal && chars.peek() == Some(&'\'') {
                    out.push(chars.next().expect("peeked"));
                } else {
                    in_literal = !in_literal;
                }
            }
            '?' if !in_literal => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}
```

- [ ] **Step 4: Normalise the numbered placeholders**

`?1`-style placeholders reuse one bind for several positions, which the rewriter cannot express. In `src/admin/bindings.rs`, `src/apps.rs` and `src/tenant.rs`, convert each numbered query to positional `?` and bind the value once per occurrence. Find them with `grep -rnE '\?[0-9]' src/`. There are 12. Keep the semantics identical — re-read each query and count the occurrences before you change the binds.

- [ ] **Step 5: Route every call site through the rewriter**

Every `sqlx::query(...)`, `sqlx::query_as(...)` and `sqlx::raw_sql(...)` whose SQL contains `?` must become `sqlx::query(&db::sql(engine, "…"))`. The engine comes from `db::engine_of(pool)`. Where a function only has a `&DbPool`, derive it there.

Verify none were missed: `grep -rn 'sqlx::query' src/ | grep '?' | grep -v 'db::sql'` must be empty.

- [ ] **Step 6: Verify and commit**

Run: `cargo test` (84 on SQLite), `cargo clippy --all-targets`.

```bash
git add src/
git commit -m "feat(db): rewrite placeholders per engine; Any does not do it for us"
```

---

### Task 3: Per-engine migrations

**Files:**
- Create: `migrations/sqlite/` (the six existing files, moved), `migrations/postgres/`, `migrations/mysql/`
- Modify: `src/db.rs` (select the directory), `tests/common/mod.rs`
- Test: `tests/db_engine.rs` (append)

- [ ] **Step 1: Move the existing migrations**

`git mv migrations/*.sql migrations/sqlite/`. These are the reference: the other two are translations of them, and must produce the same logical schema.

- [ ] **Step 2: Author the Postgres and MySQL sets**

Translate all six files. The differences that actually bite, all of which appear in this schema:

| SQLite | Postgres | MySQL |
|---|---|---|
| `TEXT` | `TEXT` | `VARCHAR(255)` for keys/indexed columns, `TEXT` otherwise |
| `INTEGER` used as a boolean | `BOOLEAN` | `TINYINT(1)` |
| `INTEGER` epoch seconds | `BIGINT` | `BIGINT` |
| `BLOB` | `BYTEA` | `BLOB` / `LONGBLOB` |
| `COLLATE NOCASE` | (removed — Task 4 handles case) | (removed — Task 4) |
| `AUTOINCREMENT` | `GENERATED BY DEFAULT AS IDENTITY` | `AUTO_INCREMENT` |
| `lower(hex(randomblob(16)))` | `gen_random_uuid()::text` | `uuid()` |
| `INSERT OR IGNORE` | `INSERT … ON CONFLICT DO NOTHING` | `INSERT IGNORE` |

MySQL caps index key length, so any `TEXT` column in a `PRIMARY KEY` or `UNIQUE` must become a bounded `VARCHAR`. Every id in this schema is a GUID string, so `VARCHAR(64)` is ample; UPNs and domains need `VARCHAR(320)` (the email maximum).

`migrations/*/0006_admin_rbac.sql` is the one with real logic. Its `CASE role_template_id` arms and the role-keyed join must be reproduced exactly — that join prevents a cross-tenant privilege escalation, and the two `INSERT`s must keep the identical arm list. Re-read the SQLite version before translating, and keep the `GROUP BY (principal_type, principal_id, role_id)` that makes it one binding per principal-and-role.

- [ ] **Step 3: Select the directory at runtime**

`sqlx::migrate!` is a compile-time macro over one path, so use three macros behind a match on `Engine` — each arm is a separate `Migrator`. Run the matching one in `db::connect`.

- [ ] **Step 4: Test the schema matches across engines**

```rust
/// Review Focus 5: booleans and epoch columns must read back identically.
#[tokio::test]
async fn booleans_and_timestamps_round_trip_on_every_available_engine() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        let id = rust_oidc::users::create(&pool, &t, rust_oidc::users::NewUser {
            upn: "alice@contoso.test", password: "Correct-Horse-9",
            display_name: None, given_name: None, family_name: None,
            email: Some("a@example.org"),
        }).await.unwrap();
        let u = rust_oidc::users::find(&pool, &t.id, &id).await.unwrap().unwrap();
        assert!(u.enabled, "enabled must read back true");
        assert!(!u.email_verified, "email_verified must read back false");
    }
}
```

`common::all_engine_pools()` arrives in Task 6; until then have it return just the SQLite pool so this task is green on its own.

- [ ] **Step 5: Verify and commit**

Run: `cargo test`, `cargo clippy --all-targets`.

```bash
git add migrations/ src/db.rs tests/
git commit -m "feat(db): per-engine migration directories"
```

---

### Task 4: Case-insensitive identity without collation

**Files:**
- Create: `migrations/*/0007_case_normalisation.sql`
- Modify: `src/users.rs`, `src/tenant.rs`, `src/groups.rs`
- Test: `tests/db_case.rs`

Security-relevant: this decides whether `alice@x` and `Alice@X` are one account.

- [ ] **Step 1: Write the failing tests**

```rust
mod common;
use common::*;

/// Review Focus 1: identity must fold case identically on every engine.
#[tokio::test]
async fn a_upn_differing_only_by_case_is_the_same_account() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        rust_oidc::users::create(&pool, &t, rust_oidc::users::NewUser {
            upn: "alice@contoso.test", password: "Correct-Horse-9",
            display_name: None, given_name: None, family_name: None, email: None,
        }).await.unwrap();

        // Sign-in must find her whatever the case.
        for attempt in ["alice@contoso.test", "Alice@Contoso.Test", "ALICE@CONTOSO.TEST"] {
            let outcome = rust_oidc::users::authenticate(&pool, &t, attempt, "Correct-Horse-9")
                .await.unwrap();
            assert!(matches!(outcome, rust_oidc::users::AuthResult::Ok(_)), "{attempt}");
        }

        // And a second account differing only by case must be refused.
        let dup = rust_oidc::users::create(&pool, &t, rust_oidc::users::NewUser {
            upn: "Alice@Contoso.Test", password: "Correct-Horse-9",
            display_name: None, given_name: None, family_name: None, email: None,
        }).await;
        assert!(dup.is_err(), "a case-variant duplicate must be refused");
    }
}

#[tokio::test]
async fn tenant_domains_and_group_names_fold_case_too() {
    for pool in common::all_engine_pools().await {
        let t = rust_oidc::tenant::create(&pool, "Contoso", "contoso.test", false).await.unwrap();
        assert!(rust_oidc::tenant::resolve(&pool, "CONTOSO.TEST").await.unwrap().is_some());
        rust_oidc::groups::create(&pool, &t, "Admins", None).await.unwrap();
        assert!(rust_oidc::groups::create(&pool, &t, "admins", None).await.is_err());
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --test db_case`
Expected: FAIL — the case-variant duplicate is currently accepted on engines without `NOCASE`, and `tenant::resolve` is case-sensitive.

- [ ] **Step 3: Implement**

Add a normalised column beside each case-insensitive one, filled by the application, with a plain unique index — portable on all three engines, unlike expression indexes:

```sql
-- migrations/*/0007_case_normalisation.sql
ALTER TABLE users ADD COLUMN upn_folded TEXT;
UPDATE users SET upn_folded = lower(upn);
CREATE UNIQUE INDEX users_tenant_upn_folded ON users(tenant_id, upn_folded);

ALTER TABLE tenant_domains ADD COLUMN domain_folded TEXT;
UPDATE tenant_domains SET domain_folded = lower(domain);
CREATE UNIQUE INDEX tenant_domains_folded ON tenant_domains(domain_folded);

ALTER TABLE groups ADD COLUMN name_folded TEXT;
UPDATE groups SET name_folded = lower(name);
CREATE UNIQUE INDEX groups_tenant_name_folded ON groups(tenant_id, name_folded);
```

**MySQL cannot index a `TEXT` column without a prefix length**, so in
`migrations/mysql/0007_case_normalisation.sql` the folded columns must be
`VARCHAR(320)` (the email maximum) for UPNs and domains and `VARCHAR(255)` for
group names, not `TEXT`. The block above is the SQLite/Postgres shape.

In Rust, add one helper — `pub fn fold(value: &str) -> String { value.trim().to_lowercase() }` in `src/util.rs` — and use it for every write and every lookup of those three columns. The display column keeps the original casing; only lookups and uniqueness use the folded one. Drop `COLLATE NOCASE` from the SQLite migration set so all three behave the same, and confirm no query still relies on it.

Use `to_lowercase` (full Unicode), not `to_ascii_lowercase`, and say in a comment why: a UPN may contain non-ASCII, and folding must not depend on the engine's locale.

- [ ] **Step 4: Verify and commit**

Run: `cargo test`, `cargo clippy --all-targets`. The existing `tests/tenant_isolation.rs` and `tests/user_flow.rs` cover the old behaviour and must still pass.

```bash
git add migrations/ src/ tests/db_case.rs
git commit -m "feat(db): fold case in Rust instead of relying on COLLATE NOCASE"
```

---

### Task 5: Engine-neutral upserts

**Files:**
- Modify: `src/secrets.rs`, `src/session.rs`, and any other `INSERT OR IGNORE` / `ON CONFLICT` site
- Test: `tests/db_upsert.rs`

- [ ] **Step 1: Find every site**

`grep -rn "INSERT OR IGNORE\|ON CONFLICT" src/` — there are 6 at the time of writing. Do not trust that list: run the grep and fix what you find. `src/admin/client.rs` does **not** exist yet (it belongs to the paused admin-console plan), so ignore any reference to it.

- [ ] **Step 2: Write the failing test**

```rust
mod common;

/// Review Focus 3: the neutral pattern replaces atomic ON CONFLICT, so it must
/// neither lose a write nor surface a unique violation under concurrency.
#[tokio::test]
async fn concurrent_upserts_of_one_row_all_succeed_and_agree() {
    for pool in common::all_engine_pools().await {
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let p = pool.clone();
            tasks.push(tokio::spawn(async move {
                rust_oidc::secrets::Secrets::new(p).pairwise_sub("user-1", "app-1").await
            }));
        }
        let mut seen = std::collections::HashSet::new();
        for t in tasks {
            seen.insert(t.await.unwrap().expect("no upsert should fail"));
        }
        assert_eq!(seen.len(), 1, "every caller must derive the same pairwise sub");
    }
}
```

- [ ] **Step 3: Implement**

Replace each site with a transactional pattern that works everywhere: attempt the `INSERT`, and on a unique-violation error fall back to the `SELECT` (for the ignore cases) or to an `UPDATE`-then-`INSERT`-if-zero-rows (for the do-update cases). Detect the violation with `sqlx::Error::Database(e) if e.is_unique_violation()`, which is engine-neutral — do **not** match on message text.

A retry loop is required, not optional: between a failed insert and the follow-up select, another writer may still be mid-transaction. Bound it (three attempts) and return a clear error if it never converges.

- [ ] **Step 4: Verify and commit**

Run: `cargo test`, `cargo clippy --all-targets`.

```bash
git add src/ tests/db_upsert.rs
git commit -m "feat(db): engine-neutral upserts with unique-violation fallback"
```

---

### Task 6: Run the suite against all three engines

> **Controller amendment (Ruling M10): run Task 7 BEFORE this task.** Task 6's bar
> is a green suite on all three engines, which is unreachable while the
> boolean-vs-integer comparisons and the reserved-word `groups` table still fail
> on Postgres and MySQL. Order is T4, T5, T7, T6, T8.

This is the task that turns the abstraction from indirection into something proven.

**Files:**
- Modify: `tests/common/mod.rs`
- Create: `scripts/test-engines.sh`
- Test: `tests/db_blob.rs`

- [ ] **Step 1: Containers**

`scripts/test-engines.sh` starts Postgres and MySQL in podman, waits for each to accept connections, exports `RUST_OIDC_TEST_POSTGRES` and `RUST_OIDC_TEST_MYSQL`, runs `cargo test`, and removes the containers on exit (`trap`). Follow `compat/kafka/test_oauthbearer.sh` for the podman conventions already used in this repo, including the readiness loop rather than a fixed sleep.

```bash
podman run -d --name rust-oidc-test-pg -e POSTGRES_PASSWORD=test -p 15432:5432 docker.io/library/postgres:16
podman run -d --name rust-oidc-test-my -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=rustoidc -p 13306:3306 docker.io/library/mysql:8
```

- [ ] **Step 2: Parameterise the harness**

`common::all_engine_pools()` returns one freshly migrated pool per engine that is actually reachable: always SQLite, plus Postgres and MySQL when their env var is set. Each must get its **own empty database or schema** per test — a shared database makes tests order-dependent. Create a uniquely named schema/database per call and drop it on teardown.

Print one line per skipped engine (`skipping postgres: RUST_OIDC_TEST_POSTGRES not set`) so a green run never silently means "SQLite only".

- [ ] **Step 3: Write the blob test**

```rust
/// Review Focus 4: BYTEA and BLOB must round-trip byte-identically.
#[tokio::test]
async fn blobs_round_trip_byte_identically() {
    for pool in common::all_engine_pools().await {
        rust_oidc::keys::ensure(&pool).await.unwrap();
        let store = rust_oidc::keys::KeyStore::new(pool.clone());
        let published = store.published().await.unwrap();
        assert!(!published.is_empty(), "a signing key must exist");
        for k in published.iter() {
            assert!(!k.cert_der.is_empty(), "certificate DER must not come back empty");
            assert_eq!(k.kid, rust_oidc::util::b64url(&sha1_of(&k.cert_der)),
                "kid is the SHA-1 of the DER, so a corrupted blob changes it");
        }
    }
}
```

Write `sha1_of` in the test with the `sha1` crate, mirroring `src/keys.rs`.

- [ ] **Step 4: Verify**

Run `bash scripts/test-engines.sh`. Every test must pass on all three, with no "skipping" lines. Then run `cargo test` alone and confirm it still passes with SQLite only and prints the two skip lines.

- [ ] **Step 5: Commit**

```bash
git add tests/ scripts/test-engines.sh
git commit -m "test(db): run the suite against sqlite, postgres and mysql"
```

---

### Task 7: Sweep the remaining engine-specific corners

**Files:**
- Modify: `tests/rbac_migration.rs`, any test using `sqlite_master`, `src/db.rs`
- Test: existing suites

- [ ] **Step 1: Find them**

`grep -rn "sqlite_master\|PRAGMA\|randomblob\|AUTOINCREMENT\|COLLATE NOCASE" src/ tests/ migrations/`

- [ ] **Step 2: Fix each**

- `tests/rbac_migration.rs` queries `sqlite_master` and applies `migrations/*.sql` by `include_str!`. Both are now engine-specific. Point it at `migrations/sqlite/` explicitly and rename the test to say it is SQLite-specific, since it is testing migration mechanics rather than behaviour — a per-engine copy of that test is not worth the maintenance. State this in a comment so the next reader does not think it is an oversight.
- Replace any remaining `COLLATE NOCASE` with the Task 4 folded columns.
- Confirm `grep -rn "Sqlite" src/ | grep -v src/db.rs` is still empty.

- [ ] **Step 3: Verify and commit**

Run: `bash scripts/test-engines.sh`, `cargo clippy --all-targets`.

```bash
git add src/ tests/ migrations/
git commit -m "refactor(db): remove the last engine-specific corners"
```

---

### Task 8: Documentation and deployment

**Files:**
- Modify: `README.md` (or create `docs/databases.md`), `compat/run.sh`
- Test: none beyond the suite

- [ ] **Step 1: Document**

Write the supported URL forms for all three engines, how to run `scripts/test-engines.sh`, the fact that SQLite remains the default, and — honestly — the two limits: SQL Server and Oracle are **not** reachable through sqlx (SQL Server was dropped before sqlx 0.7, Oracle never supported), so adding them later means a separate driver (`tiberius`, the sync `oracle` crate) or ODBC behind a repository trait, not a feature flag. Note that the per-engine migration directories must be kept in step, since that is the ongoing maintenance cost of this design.

- [ ] **Step 2: Confirm the deployment is untouched**

The titanl service uses `sqlite://…`; `db::connect` must treat it exactly as before. Build the release binary and run it against a copy of the deployed database, confirming it starts and serves discovery:

```bash
cp /opt/processmaster/services/rust-oidc/data/rust-oidc.db /tmp/deploy-check.db
RUST_OIDC_DATABASE="sqlite:///tmp/deploy-check.db" ./target/release/rust-oidc serve --bind '[::]:18600' --tls-mode none --public-url http://127.0.0.1:18600/rust-oidc &
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18600/rust-oidc/healthz
```

Expected: 200, and no migration error in the log. Kill the server and remove the copy.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/ compat/
git commit -m "docs(db): supported engines, how to test them, and what is out of reach"
```
