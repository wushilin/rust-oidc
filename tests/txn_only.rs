//! Guard: nothing outside the storage layer and the transaction engine
//! (`src/txn`) changes the directory, so every change is a transaction.
//!
//! Three rules, over every `.rs` file under `src/` that is not a storage module,
//! not `src/db.rs` and not under `src/txn/` (their `#[cfg(test)]` modules aside,
//! which set data up directly):
//!
//! 1. **No call to a storage function that writes**: `module::function(`. The
//!    write functions are found from the storage modules' source: a function
//!    whose body has an `INSERT INTO`, `UPDATE … SET` or `DELETE FROM`, or that
//!    calls one of those. [`ALLOWED`] lists the deliberate exceptions: sign-in
//!    bookkeeping and start-up, which are not administrative changes (see
//!    `TODO.md`, "Out of scope").
//! 2. **No importing one by name** (`use crate::users::create`), which would let
//!    rule 1 be dodged with a bare call.
//! 3. **No SQL that writes a directory table.** A table is directory data unless
//!    [`STATE_TABLES`] lists it as protocol or session state (codes, tokens,
//!    sessions, tickets, the audit log), so a new table is guarded until someone
//!    decides otherwise. This also catches a new storage module: its SQL fails
//!    here until it is added to [`STORAGE`], which brings its functions under
//!    rule 1.
//!
//! What it still does not catch, so a clean run is not over-trusted: SQL built
//! at run time (`format!`), a glob import (`use crate::users::*`), and a write
//! function imported inside a nested group (`use crate::{users::create}`).
//! None exists today.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The storage modules, by the path they are called through.
const STORAGE: &[(&str, &str)] = &[
    ("users", "src/users.rs"),
    ("groups", "src/groups.rs"),
    ("apps", "src/apps.rs"),
    ("tenant", "src/tenant.rs"),
    ("mfa", "src/mfa.rs"),
    ("access", "src/access.rs"),
    ("bindings", "src/admin/bindings.rs"),
    ("authz", "src/admin/authz.rs"),
    ("keys", "src/keys.rs"),
    ("flowtest", "src/flowtest.rs"),
    ("scopes", "src/scopes.rs"),
    ("directory", "src/directory.rs"),
];

/// Files that may write anything, besides the storage modules: the engine, and
/// `db.rs` (the audit log, and folding names consistently at start-up).
const ENGINE_DIR: &str = "src/txn/";
const DB: &str = "src/db.rs";

/// Writes anyone may make, and why.
const ALLOWED: &[(&str, &str)] = &[
    // Sign-in: failed-attempt counters and lockout.
    ("users", "authenticate"),
    ("users", "authenticate_traced"),
    ("access", "authenticate"),
    // The second sign-in step: its ticket, attempts, and the code's time step.
    ("mfa", "begin"),
    ("mfa", "check"),
    ("mfa", "failed_attempt"),
    ("mfa", "finish"),
    // The flow tester's own run state (not directory data).
    ("flowtest", "start"),
    ("flowtest", "take"),
    // Start-up: a signing key exists before the server serves.
    ("keys", "ensure"),
];

/// Tables that hold protocol or session state rather than the directory: written
/// where the protocol happens, not by transactions. Every other table is the
/// directory's.
const STATE_TABLES: &[&str] = &[
    "admin_sessions",
    "sessions",
    "auth_codes",
    "refresh_tokens",
    "device_codes",
    "client_assertion_jti",
    "mfa_pending",
    "flow_tests",
    "audit_log",
    "server_secrets",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every source file the rules apply to: all of `src/` but the storage
/// modules, `db.rs` and the engine.
fn guarded_files(root: &Path) -> Vec<PathBuf> {
    let exempt: BTreeSet<PathBuf> = STORAGE
        .iter()
        .map(|(_, p)| root.join(p))
        .chain([root.join(DB)])
        .collect();
    let mut all = Vec::new();
    rs_files(&root.join("src"), &mut all);
    all.into_iter()
        .filter(|p| !exempt.contains(p) && !p.starts_with(root.join(ENGINE_DIR)))
        .collect()
}

/// The source without its `#[cfg(test)]` module: tests set data up directly.
fn without_tests(src: &str) -> &str {
    src.find("#[cfg(test)]").map_or(src, |i| &src[..i])
}

fn glued_left(src: &str, at: usize) -> bool {
    src[..at]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Each function of a file, by name, with its body (up to the next function).
fn functions(src: &str) -> Vec<(String, String)> {
    let src = without_tests(src);
    let mut starts: Vec<(usize, String)> = Vec::new();
    for (i, _) in src.match_indices("fn ") {
        let line_start = src[..i].rfind('\n').map_or(0, |n| n + 1);
        let head = src[line_start..i].trim();
        if !["", "pub", "pub(crate)", "async", "pub async", "pub(crate) async"].contains(&head) {
            continue;
        }
        let name: String = src[i + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            starts.push((line_start, name));
        }
    }
    let mut out = Vec::new();
    for (k, (at, name)) in starts.iter().enumerate() {
        let end = starts.get(k + 1).map_or(src.len(), |(n, _)| *n);
        out.push((name.clone(), src[*at..end].to_string()));
    }
    out
}

fn calls(body: &str, name: &str) -> bool {
    body.match_indices(&format!("{name}("))
        .any(|(i, _)| !glued_left(body, i))
}

/// `(module, function)` for every storage function that writes.
fn write_functions(root: &Path) -> BTreeSet<(&'static str, String)> {
    let mut all: Vec<(&'static str, String, String)> = Vec::new();
    for (module, path) in STORAGE {
        for (name, body) in functions(&fs::read_to_string(root.join(path)).unwrap()) {
            all.push((module, name, body));
        }
    }
    let sql = |b: &str| b.contains("INSERT INTO") || b.contains("DELETE FROM") || b.contains(" SET ");
    let mut writes: BTreeSet<(&'static str, String)> = all
        .iter()
        .filter(|(_, _, b)| sql(b))
        .map(|(m, n, _)| (*m, n.clone()))
        .collect();
    // And whatever calls one: in its own module by name, elsewhere by path.
    loop {
        let before = writes.len();
        for (module, name, body) in &all {
            let reaches = writes
                .iter()
                .any(|(m, n)| (m == module && calls(body, n)) || body.contains(&format!("{m}::{n}(")));
            if reaches {
                writes.insert((module, name.clone()));
            }
        }
        if writes.len() == before {
            return writes;
        }
    }
}

/// The table each `INSERT INTO t`, `DELETE FROM t` and `UPDATE t SET` writes,
/// with the byte offset of the statement.
fn written_tables(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for keyword in ["INSERT INTO ", "DELETE FROM ", "UPDATE "] {
        for (i, _) in src.match_indices(keyword) {
            let rest = &src[i + keyword.len()..];
            let table: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if table.is_empty() {
                continue;
            }
            // `UPDATE` only counts as SQL when a `SET` follows the table name.
            if keyword == "UPDATE " && !rest[table.len()..].trim_start().starts_with("SET ") {
                continue;
            }
            out.push((i, table));
        }
    }
    out
}

/// The names a `use` of a storage module brings in, for every such `use`.
fn imported(src: &str, module: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for prefix in [format!("crate::{module}::"), format!("rust_oidc::{module}::")] {
        for (i, _) in src.match_indices(&prefix) {
            let line_start = src[..i].rfind('\n').map_or(0, |n| n + 1);
            // `use crate::m::…`, `pub use …`, or with an attribute before it.
            if !src[line_start..i].trim_end().ends_with("use") {
                continue;
            }
            let rest = &src[i + prefix.len()..];
            let list = match rest.strip_prefix('{') {
                Some(inner) => &inner[..inner.find('}').unwrap_or(inner.len())],
                None => &rest[..rest.find(';').unwrap_or(rest.len())],
            };
            for item in list.split(',') {
                let name = item.split_whitespace().next().unwrap_or_default();
                if !name.is_empty() {
                    out.push((i, name.to_string()));
                }
            }
        }
    }
    out
}

fn line_of(src: &str, at: usize) -> usize {
    src[..at].matches('\n').count() + 1
}

#[test]
fn the_directory_changes_only_through_the_engine() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let writes = write_functions(root);
    assert!(
        writes.contains(&("users", "create".to_string())) && writes.contains(&("apps", "add_secret".to_string())),
        "the scan no longer finds the storage writes it must: {writes:?}"
    );
    let forbidden = |module: &str, name: &str| {
        writes.contains(&(STORAGE.iter().find(|(m, _)| *m == module).unwrap().0, name.to_string()))
            && !ALLOWED.contains(&(module, name))
    };

    let mut offenders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in guarded_files(root) {
        let text = fs::read_to_string(&file).unwrap();
        let src = without_tests(&text);
        let at = |offset: usize| {
            format!(
                "{}:{}",
                file.strip_prefix(root).unwrap().display(),
                line_of(src, offset)
            )
        };

        // 1. Calls.
        for (module, name) in &writes {
            if ALLOWED.contains(&(module, name.as_str())) {
                continue;
            }
            let call = format!("{module}::{name}(");
            for (i, _) in src.match_indices(&call) {
                if !glued_left(src, i) {
                    offenders.entry(format!("calls {call}")).or_default().push(at(i));
                }
            }
        }
        // 2. Imports by name.
        for (module, _) in STORAGE {
            for (i, name) in imported(src, module) {
                if forbidden(module, &name) {
                    offenders
                        .entry(format!("imports {module}::{name}"))
                        .or_default()
                        .push(at(i));
                }
            }
        }
        // 3. SQL writing a directory table.
        for (i, table) in written_tables(src) {
            if !STATE_TABLES.contains(&table.as_str()) {
                offenders
                    .entry(format!("writes table {table}"))
                    .or_default()
                    .push(at(i));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the directory is changed outside a transaction (src/txn); run the change as a transaction, \
         or move the SQL into a storage module listed in tests/txn_only.rs:\n{offenders:#?}"
    );
}

/// The state tables named above exist, so a renamed table cannot quietly turn a
/// directory table into an unguarded one, or leave a stale exemption behind.
#[test]
fn every_state_table_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut schema = String::new();
    for e in fs::read_dir(root.join("migrations/sqlite")).unwrap() {
        schema.push_str(&fs::read_to_string(e.unwrap().path()).unwrap());
    }
    for table in STATE_TABLES {
        assert!(
            schema.contains(&format!("CREATE TABLE {table} ")) || schema.contains(&format!("CREATE TABLE {table}(")),
            "{table} is listed as state but no migration creates it"
        );
    }
}
