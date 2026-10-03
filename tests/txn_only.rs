//! Guard: no page, route or command-line handler changes the directory except
//! through the transaction engine (`src/txn`).
//!
//! The storage modules' functions that write are found from their source: a
//! function whose body has an `INSERT INTO`, `UPDATE … SET` or `DELETE FROM`,
//! or that calls one of those. Every call `module::function(` to one of them
//! from a handler file fails this test, unless it is one of the deliberate
//! exceptions in [`ALLOWED`]: sign-in bookkeeping and start-up, which are not
//! administrative changes (see `TODO.md`, "Out of scope").
//!
//! What it does not catch, so a clean run is not over-trusted: a write function
//! reached through a `use` of the function itself (`use crate::users::create`),
//! or SQL written in a handler file directly. Neither exists today.

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

/// Writes a handler may make itself, and why.
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

/// The handler files: everything under `src/admin` and `src/routes` that is not
/// a storage module, and the command line.
fn handler_files(root: &Path) -> Vec<PathBuf> {
    let storage: BTreeSet<PathBuf> = STORAGE.iter().map(|(_, p)| root.join(p)).collect();
    let mut out = vec![root.join("src/main.rs")];
    for dir in ["src/admin", "src/routes"] {
        for e in fs::read_dir(root.join(dir)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "rs") && !storage.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// The source without its `#[cfg(test)]` module: tests set data up directly.
fn without_tests(src: &str) -> &str {
    src.find("#[cfg(test)]").map_or(src, |i| &src[..i])
}

/// Each function of a file, by name, with its body (up to the next function).
fn functions(src: &str) -> Vec<(String, String)> {
    let src = without_tests(src);
    let mut starts: Vec<(usize, String)> = Vec::new();
    for (i, _) in src.match_indices("fn ") {
        let before = &src[..i];
        let line_start = before.rfind('\n').map_or(0, |n| n + 1);
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
    body.match_indices(&format!("{name}(")).any(|(i, _)| {
        body[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
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

#[test]
fn handlers_change_the_directory_only_through_the_engine() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let writes = write_functions(root);
    assert!(
        writes.contains(&("users", "create".to_string())) && writes.contains(&("apps", "add_secret".to_string())),
        "the scan no longer finds the storage writes it must: {writes:?}"
    );
    let mut offenders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in handler_files(root) {
        let src = fs::read_to_string(&file).unwrap();
        let src = without_tests(&src);
        for (module, name) in &writes {
            if ALLOWED.contains(&(module, name.as_str())) {
                continue;
            }
            let call = format!("{module}::{name}(");
            for (i, _) in src.match_indices(&call) {
                let glued = src[..i]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if !glued {
                    let line = src[..i].matches('\n').count() + 1;
                    offenders
                        .entry(call.clone())
                        .or_default()
                        .push(format!("{}:{line}", file.strip_prefix(root).unwrap().display()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these handlers write the directory directly instead of running a transaction (src/txn):\n{offenders:#?}"
    );
}
