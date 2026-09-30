//! Guard: every `sqlx::query*` call in `src/` whose SQL literal contains a `?`
//! placeholder must route through `db::sql_stmt`, which rewrites `?` to `$n` on
//! Postgres. Routing is otherwise convention only, and an unwrapped query
//! breaks on Postgres silently. The scan is multi-line aware: it takes the whole
//! call, from `sqlx::query` to its balancing `)`.
//!
//! What it does NOT catch, so a clean run is not over-trusted:
//! - SQL held in a `const`, `let` binding or `format!` and passed by variable:
//!   the literal is not inside the call body, so it is never seen.
//! - An unqualified `query(...)` via `use sqlx::query` (none exist today).
//! - A raw string `r#"..."#` or a `'"'` char literal inside a call, which can
//!   desync the paren/quote tracking.
//!
//! Deliberate loosenesses (the safe direction):
//! - A Rust `?` operator inside `.bind(...)` counts as a placeholder: a false
//!   positive, which fails loudly.
//! - A call holding both a wrapped and an unwrapped literal passes.

use std::fs;
use std::path::Path;

fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Text of the call whose `(` is at `open`, up to the balancing `)`. Parens
/// inside string literals are skipped.
fn call_body(src: &str, open: usize) -> &str {
    let b = src.as_bytes();
    let (mut depth, mut i, mut in_str) = (0i32, open, false);
    while i < b.len() {
        match b[i] {
            b'\\' if in_str => i += 1,
            b'"' => in_str = !in_str,
            b'(' if !in_str => depth += 1,
            b')' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    &src[open..]
}

/// True if `needle` occurs in `body` not glued to a longer identifier on its left.
fn has_token(body: &str, needle: &str, allow_path_before: bool) -> bool {
    body.match_indices(needle).any(|(i, _)| {
        body[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || (c == ':' && !allow_path_before)))
    })
}

/// The call goes through `db::sql_stmt`, `db::q`, or an imported bare `q(`/`sql_stmt(`.
/// A path ending in `::q(` from some other module does not count.
fn routed(body: &str) -> bool {
    has_token(body, "sql_stmt(", true) || has_token(body, "db::q(", true) || has_token(body, "q(", false)
}

/// Offending `sqlx::query*(` calls in `src`, as "line N" strings.
fn unrouted(src: &str) -> Vec<usize> {
    let mut bad = Vec::new();
    let mut from = 0;
    while let Some(off) = src[from..].find("sqlx::query") {
        let at = from + off;
        from = at + 1;
        let Some(paren) = src[at..].find('(').map(|p| at + p) else {
            continue;
        };
        // Only the call head `sqlx::query`, `query_as`, `query_scalar`, `query_as::<..>`.
        let head = &src[at..paren];
        if head.contains([';', '{', '}']) {
            continue;
        }
        let body = call_body(src, paren);
        if body.contains('?') && !routed(body) {
            bad.push(src[..at].matches('\n').count() + 1);
        }
    }
    bad
}

#[test]
fn every_sqlx_query_with_a_placeholder_goes_through_sql_stmt_or_q() {
    let mut files = Vec::new();
    rs_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut offenders = Vec::new();
    for f in files {
        let src = fs::read_to_string(&f).unwrap();
        for line in unrouted(&src) {
            offenders.push(format!("{}:{line}", f.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "sqlx query with `?` not wrapped in db::sql_stmt or db::q (breaks on Postgres):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scanner_flags_multiline_unwrapped_queries_and_passes_wrapped_ones() {
    let bad = "fn f() {\n    sqlx::query(\n        \"UPDATE t SET a = ?\n         WHERE b = ?\",\n    )\n}";
    assert_eq!(unrouted(bad), vec![2]);
    let ok = "sqlx::query(sql_stmt(e, \"UPDATE t SET a = ?\")).bind(1)";
    assert!(unrouted(ok).is_empty());
    let tf_bad = "sqlx::query_as::<_, T>(\"SELECT a FROM t WHERE x = ?\")";
    assert_eq!(unrouted(tf_bad), vec![1]);
    let tf_ok = "sqlx::query_as::<_, T>(sql_stmt(e, \"SELECT a FROM t WHERE x = ?\"))";
    assert!(unrouted(tf_ok).is_empty());
    let none = "sqlx::query(\"SELECT 1\")";
    assert!(unrouted(none).is_empty());
}

#[test]
fn the_scanner_keeps_its_teeth_with_q_wrapping() {
    // Unwrapped: still flagged, plain and turbofish.
    assert_eq!(unrouted("sqlx::query(\"UPDATE t SET a = ?\")"), vec![1]);
    assert_eq!(
        unrouted("sqlx::query_as::<_, T>(\"SELECT a FROM t WHERE x = ?\")"),
        vec![1]
    );
    // Wrapped in db::q: accepted, plain and turbofish, qualified or imported.
    assert!(unrouted("sqlx::query(db::q(pool, \"UPDATE t SET a = ?\"))").is_empty());
    assert!(unrouted("sqlx::query(crate::db::q(pool, \"UPDATE t SET a = ?\"))").is_empty());
    assert!(unrouted("sqlx::query_as::<_, T>(db::q(pool, \"SELECT a FROM t WHERE x = ?\"))").is_empty());
    assert!(unrouted("sqlx::query_as::<_, T>(q(pool, \"SELECT a FROM t WHERE x = ?\"))").is_empty());
    // Look-alikes do not count as routing.
    assert_eq!(unrouted("sqlx::query(other::q(\"UPDATE t SET a = ?\"))"), vec![1]);
    assert_eq!(unrouted("sqlx::query(faq(\"UPDATE t SET a = ?\"))"), vec![1]);
    assert_eq!(unrouted("sqlx::query(mydb::q(pool, \"UPDATE t SET a = ?\"))"), vec![1]);
}
