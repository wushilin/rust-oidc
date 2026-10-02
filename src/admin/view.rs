//! The console's HTML. Server-rendered, no JavaScript, no build step.
//!
//! Plain `format!` against [`crate::html::escape`], the way
//! [`crate::html`] already renders the sign-in pages, rather than a template
//! engine: one fewer dependency, and the console's first pass is small enough
//! that a second rendering mechanism in the same binary would cost more than it
//! saves. Every dynamic value goes through [`e`], and
//! `tests/admin_users.rs::a_display_name_cannot_inject_markup` holds that line.
//!
//! The content security policy is `default-src 'none'`, which is only honest
//! because there is no script and no image anywhere in the console.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::html::escape;

/// Escape a value for HTML. Short because it is used on every interpolation.
pub fn e(s: &str) -> String {
    escape(s)
}

const STYLE: &str = r#"
/* Layout: a band across the top holding the product, the tenant in view and the
   tab strip; the active tab is the colour of the page, so it reads as joined to
   it. Content is left-aligned under the tabs. One accent (petrol) for actions;
   amber is kept for one thing only, the tenant in view. System fonts: the
   content security policy allows no web fonts. */
:root {
  --bg:#f3f5f7; --band:#e6eaee; --surface:#fff; --ink:#17222b; --muted:#5c6b77; --line:#d3dae0;
  --accent:#0d6b73; --on-accent:#fff; --hover:#dce2e7;
  --chip:#fff4d6; --chip-line:#dcb24a; --chip-ink:#5e4300;
  --err:#b3261e; --ok:#1b7a43;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Mono","Segoe UI Mono",Menlo,Consolas,monospace;
  /* kept for markup that still names them */
  --card:var(--surface); --fg:var(--ink); --border:var(--line);
}
@media (prefers-color-scheme: dark) { :root {
  --bg:#0f161b; --band:#0a1014; --surface:#172129; --ink:#e3e9ed; --muted:#91a1ad; --line:#2a3843;
  --accent:#56c2c9; --on-accent:#06262a; --hover:#1c2832;
  --chip:#3a2e10; --chip-line:#8a6d1f; --chip-ink:#f0d58a;
  --err:#f2a39c; --ok:#63d08e;
} }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:14.5px/1.55 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",sans-serif; }
a { color:var(--accent); text-underline-offset:2px; }
code { font-family:var(--mono); font-size:.92em; }

/* ---- the band: product, tenant in view, who, tabs ---- */
header.top { background:var(--band); border-bottom:1px solid var(--line); }
.bar { display:flex; flex-wrap:wrap; gap:10px 16px; align-items:center; justify-content:space-between; padding:12px 24px 10px; }
.brand { font-size:15px; font-weight:650; letter-spacing:-.01em; color:var(--ink); text-decoration:none; }
.ctx { display:flex; flex-wrap:wrap; gap:8px 14px; align-items:center; font-size:13px; color:var(--muted); }
.tenant { display:inline-flex; gap:8px; align-items:center; padding:3px 10px; border:1px solid var(--chip-line); border-radius:3px; background:var(--chip); color:var(--chip-ink); }
.tenant strong { font-weight:650; }
.tenant.none { background:transparent; border-style:dashed; border-color:var(--line); color:var(--muted); }
.ctx button { padding:3px 10px; font-size:13px; }
form.find input { width:210px; padding:3px 10px; font-size:13px; background:var(--surface); }
nav.tabs { display:flex; gap:2px; align-items:flex-end; padding:0 24px; overflow-x:auto; }
nav.tabs a { flex:none; padding:8px 14px; margin-bottom:-1px; font-size:14px; color:var(--muted); text-decoration:none; white-space:nowrap; border:1px solid transparent; border-bottom:none; border-radius:5px 5px 0 0; }
nav.tabs a:hover { color:var(--ink); background:var(--hover); }
nav.tabs a.active { color:var(--ink); font-weight:600; background:var(--bg); border-color:var(--line); box-shadow:inset 0 2px 0 var(--accent); }
nav.tabs a.up { padding-left:0; margin-right:8px; color:var(--accent); }
nav.tabs a.up:hover { background:transparent; text-decoration:underline; }

/* ---- page ---- */
main { max-width:1160px; padding:26px 24px 72px; }
h1 { font-size:24px; font-weight:650; letter-spacing:-.015em; line-height:1.2; margin:0 0 4px; }
h2 { font-size:17px; font-weight:650; margin:34px 0 10px; padding-top:20px; border-top:1px solid var(--line); }
h3 { font-size:14px; font-weight:650; margin:20px 0 6px; }
p { max-width:76ch; }
p.sub { color:var(--muted); margin:0 0 20px; }
.muted { color:var(--muted); }
.error { color:var(--err); margin:12px 0; font-weight:600; }
p.empty { color:var(--muted); margin:0 0 12px; padding:12px 14px; border:1px dashed var(--line); border-radius:6px; max-width:none; }

/* ---- tables: the only boxed thing on a page ---- */
table { border-collapse:separate; border-spacing:0; width:100%; background:var(--surface); border:1px solid var(--line); border-radius:6px; margin:0 0 12px; }
th, td { text-align:left; padding:9px 14px; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-size:12.5px; font-weight:600; color:var(--muted); white-space:nowrap; }
tr:last-child td { border-bottom:none; }
td button { padding:4px 10px; font-size:13px; }
td form.inline + form.inline { margin-left:6px; }
td:last-child:has(form) { text-align:right; white-space:nowrap; }
td.id { white-space:nowrap; }
tr.bad td:first-child { box-shadow:inset 3px 0 0 var(--err); font-weight:600; }

/* ---- forms ---- */
form.inline { display:inline; }
label { display:block; font-size:13px; font-weight:600; margin:14px 0 4px; }
label:has(input[type=checkbox]), label:has(input[type=radio]) { font-weight:400; font-size:14.5px; margin:8px 0 2px; }
input[type=text], input[type=email], input[type=password], input[type=search], input[type=number], select, textarea {
  width:100%; max-width:440px; padding:7px 10px; font:inherit; color:var(--ink); background:var(--surface); border:1px solid var(--line); border-radius:4px; }
textarea { max-width:600px; min-height:130px; font:13px/1.45 var(--mono); }
input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
button { font:inherit; font-weight:600; padding:7px 14px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:var(--on-accent); cursor:pointer; }
button.secondary { background:transparent; color:var(--accent); }
button.danger { background:transparent; border-color:var(--err); color:var(--err); }
button.link { background:none; border:none; padding:0; color:var(--accent); font-weight:400; text-decoration:underline; }
.actions { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-top:18px; }
input + p.muted, select + p.muted, textarea + p.muted, label + p.muted { margin:5px 0 0; font-size:13px; }
form > p.muted:last-child { margin-bottom:0; }
/* A choice whose second option has detail: the detail shows only while that
   option is chosen. No script; a browser without :has() just shows it always. */
fieldset.choice { border:none; margin:14px 0 0; padding:0; }
fieldset.choice legend { padding:0; font-size:13px; font-weight:600; margin-bottom:2px; }
.when-some { margin:6px 0 0 24px; padding:2px 0 6px 14px; border-left:2px solid var(--line); }
fieldset.choice:not(:has(input.some:checked)) .when-some { display:none; }
details.inline-edit { display:inline-block; vertical-align:top; margin-left:6px; }
details.inline-edit summary { cursor:pointer; color:var(--accent); font-size:13px; }
details.inline-edit form { margin-top:6px; }
dl.roles { margin:8px 0 0; font-size:13px; display:grid; grid-template-columns:max-content 1fr; gap:3px 14px; }
dl.roles dt { font-weight:600; }
dl.roles dd { margin:0; color:var(--muted); }
/* User name: the part before the @, then the tenant's domain. A full name typed
   in makes the input match no longer (its pattern excludes @), which is what
   hides the domain beside it. */
.upn { display:flex; flex-wrap:wrap; gap:8px; align-items:center; max-width:640px; }
.upn input { flex:1 1 220px; max-width:none; }
.upn .suffix { display:inline-flex; gap:8px; align-items:center; color:var(--muted); }
.upn .suffix select { width:auto; max-width:260px; }
.upn input:invalid ~ .suffix { display:none; }
/* Short fields side by side, each under its own label. */
.fields { display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:0 18px; max-width:980px; }
.fields input, .fields select { max-width:none; }
/* A list's own controls: find something on the left, make something on the right. */
.toolbar { display:flex; flex-wrap:wrap; gap:10px 16px; align-items:center; justify-content:space-between; margin:0 0 12px; }
.toolbar form { display:flex; gap:8px; align-items:center; flex:1 1 320px; max-width:520px; }
.toolbar form input { max-width:none; }
a.button { display:inline-block; padding:7px 14px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:var(--on-accent); font-weight:600; text-decoration:none; }

/* An add-form folded away until wanted, so a page reads as its tables. */
details.add { margin:0 0 6px; }
details.add > summary { display:inline-block; cursor:pointer; list-style:none; padding:5px 12px; font-size:13.5px; font-weight:600; color:var(--accent); border:1px solid var(--line); border-radius:4px; background:var(--surface); }
details.add > summary::-webkit-details-marker { display:none; }
details.add > summary::before { content:"+ "; }
details.add[open] > summary { border-bottom-left-radius:0; border-bottom-right-radius:0; background:var(--band); }
details.add[open] > summary::before { content:"\2212  "; }
details.add > .fold { border:1px solid var(--line); border-radius:0 6px 6px 6px; margin-top:-1px; padding:4px 18px 18px; background:var(--surface); }

/* ---- small parts ---- */
.pill { display:inline-block; font-size:12.5px; border:1px solid var(--line); border-radius:3px; padding:0 7px; margin:0 4px 4px 0; color:var(--muted); background:var(--surface); }
.pill.good { border-color:var(--ok); color:var(--ok); }
.pill.bad { border-color:var(--err); color:var(--err); font-weight:600; }
.banner, .notice { background:var(--surface); border:1px solid var(--accent); border-left-width:4px; border-radius:4px; padding:12px 16px; margin:0 0 20px; }
.banner { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between; }
.banner.bad { border-color:var(--err); }
.once { display:block; margin:8px 0 0; padding:8px 10px; font:13px/1.45 var(--mono); word-break:break-all; border:1px dashed var(--line); border-radius:4px; }
dl.facts { display:grid; grid-template-columns:max-content 1fr; gap:4px 18px; margin:0 0 10px; }
dl.facts dt { color:var(--muted); }
dl.facts dd { margin:0; word-break:break-all; font-family:var(--mono); font-size:13px; }
pre.raw { margin:0 0 14px; padding:12px 14px; background:var(--surface); border:1px solid var(--line); border-radius:6px; font:13px/1.55 var(--mono); white-space:pre-wrap; word-break:break-all; }
code.wrap { font:13px/1.45 var(--mono); word-break:break-all; }
.id { font-family:var(--mono); font-size:12.5px; color:var(--muted); word-break:break-all; }
.card { background:var(--surface); border:1px solid var(--line); border-radius:6px; padding:24px 28px; max-width:440px; margin:64px auto; }
.card h1 { font-size:20px; }
@media (max-width:640px) {
  .bar, nav.tabs { padding-left:16px; padding-right:16px; }
  main { padding:20px 16px 56px; }
  table { display:block; overflow-x:auto; }
}
"#;

const CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn respond(status: StatusCode, html: String) -> Response {
    let mut resp = (status, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    resp
}

const PRODUCT: &str = "rust-oidc admin";

fn document(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>{title} &middot; {PRODUCT}</title><style>{STYLE}</style></head><body>{body}</body></html>"#,
        title = e(title),
    )
}

/// One tab in the strip under the header. The caller emits a tab only where the
/// action behind it is permitted, so the console never offers what the guard
/// would refuse.
pub struct Tab {
    pub label: &'static str,
    pub href: String,
    /// The page being shown.
    pub active: bool,
}

/// Everything the chrome around a page needs. Built from the request's
/// `AdminContext`, so a page cannot render a different identity than the one that
/// was authorized.
pub struct Chrome<'a> {
    pub base: &'a str,
    pub upn: &'a str,
    pub csrf: &'a str,
    /// The tenant in view: the one the page is about, or the one assumed.
    pub tenant: Option<&'a str>,
    /// Whether that tenant is the assumed one, which is what Leave undoes.
    pub assumed: bool,
    /// Back to the list of tenants, from inside one.
    pub up: Option<String>,
    pub tabs: Vec<Tab>,
}

/// A page inside the console: the band (product, tenant in view, who, tabs) and
/// the body.
pub fn page(c: &Chrome<'_>, status: StatusCode, title: &str, body: &str) -> Response {
    let up =
        c.up.as_ref()
            .map(|href| format!(r#"<a class="up" href="{}">&lsaquo; All tenants</a>"#, e(href)))
            .unwrap_or_default();
    let tabs: String = c
        .tabs
        .iter()
        .map(|t| {
            if t.active {
                format!(
                    r#"<a class="active" aria-current="page" href="{}">{}</a>"#,
                    e(&t.href),
                    e(t.label)
                )
            } else {
                format!(r#"<a href="{}">{}</a>"#, e(&t.href), e(t.label))
            }
        })
        .collect();
    let tenant = match c.tenant {
        Some(name) => {
            let leave = if c.assumed {
                format!(
                    r#"<form method="post" action="{base}/admin/leave" class="inline">{csrf}<button class="secondary" type="submit">Leave</button></form>"#,
                    base = e(c.base),
                    csrf = csrf_input(c.csrf),
                )
            } else {
                String::new()
            };
            format!(
                r#"<span class="tenant">Tenant <strong>{}</strong></span>{leave}"#,
                e(name)
            )
        }
        None => r#"<span class="tenant none">No tenant selected</span>"#.to_string(),
    };
    let body = format!(
        r#"<header class="top"><div class="bar"><a class="brand" href="{base}/admin">{PRODUCT}</a>
<div class="ctx"><form class="find" method="get" action="{base}/admin/find" role="search">
<input name="id" type="search" placeholder="Find by id" aria-label="Find an object by its id"></form>
{tenant}<span>{upn}</span>
<form method="post" action="{base}/admin/signout" class="inline">{csrf}<button class="secondary" type="submit">Sign out</button></form></div></div>
<nav class="tabs" aria-label="Sections">{up}{tabs}</nav></header>
<main>{body}</main>"#,
        upn = e(c.upn),
        base = e(c.base),
        csrf = csrf_input(c.csrf),
        body = without_empty_tables(body),
    );
    respond(status, document(title, &body))
}

/// A table with a heading row and nothing under it says less than a sentence
/// does, so one is replaced by the sentence. Done here, once, rather than at each
/// of the twenty places a table is written.
fn without_empty_tables(body: &str) -> String {
    const OPEN: &str = "<table>";
    const CLOSE: &str = "</table>";
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(OPEN) {
        let Some(len) = rest[start..].find(CLOSE) else {
            break;
        };
        let end = start + len + CLOSE.len();
        out.push_str(&rest[..start]);
        if rest[start..end].contains("<td") {
            out.push_str(&rest[start..end]);
        } else {
            out.push_str(r#"<p class="empty">Nothing here yet.</p>"#);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// A form folded behind its own label, so a page reads as its tables and an
/// "add" form appears only when asked for. No script: this is `<details>`.
/// `open` keeps it unfolded, for a form being shown again with an error.
pub fn expander(label: &str, form: &str, open: bool) -> String {
    if form.is_empty() {
        return String::new();
    }
    format!(
        r#"<details class="add"{open}><summary>{label}</summary><div class="fold">{form}</div></details>"#,
        open = if open { " open" } else { "" },
        label = e(label),
    )
}

/// The hidden field every console form carries.
pub fn csrf_input(csrf: &str) -> String {
    format!(
        r#"<input type="hidden" name="{field}" value="{csrf}">"#,
        field = crate::admin::session::CSRF_FIELD,
        csrf = e(csrf),
    )
}

/// A standalone card page: sign-in, and the refusals that have no chrome because
/// there may be no session behind them.
fn card(status: StatusCode, title: &str, body: &str) -> Response {
    respond(
        status,
        document(title, &format!(r#"<main><div class="card">{body}</div></main>"#)),
    )
}

/// The console's sign-in form.
pub fn sign_in(base: &str, upn: &str, error: Option<&str>, csrf: &str) -> Response {
    let error = error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>{PRODUCT}</h1><p class="sub">Sign in with an administrator account.</p>
<form method="post" action="{base}/admin/signin">
<label for="upn">Email or username</label><input id="upn" name="upn" type="email" autocomplete="username" required value="{upn}" autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
{csrf}{error}<div class="actions"><button type="submit">Sign in</button></div></form>"#,
        base = e(base),
        upn = e(upn),
        csrf = csrf_input(csrf),
    );
    let status = if error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    };
    card(status, "Sign in", &body)
}

/// Signed in, but holding no console role at all.
pub fn no_access(base: &str, upn: &str, csrf: &str) -> Response {
    let body = format!(
        r#"<h1>No access</h1><p class="sub">{upn} is signed in but has no administrative role, so there is nothing to show.</p>
<form method="post" action="{base}/admin/signout">{csrf}<div class="actions"><button type="submit">Sign out</button></div></form>"#,
        upn = e(upn),
        base = e(base),
        csrf = csrf_input(csrf),
    );
    card(StatusCode::FORBIDDEN, "No access", &body)
}

/// Refused by the authorization gate. Deliberately says nothing about what was
/// asked for, so it cannot be used to probe for what exists.
pub fn forbidden() -> Response {
    card(
        StatusCode::FORBIDDEN,
        "Not allowed",
        r#"<h1>Not allowed</h1><p class="sub">Your administrative roles do not cover this.</p>"#,
    )
}

/// Not found, or not visible, which the console deliberately does not distinguish.
pub fn not_found() -> Response {
    card(
        StatusCode::NOT_FOUND,
        "Not found",
        r#"<h1>Not found</h1><p class="sub">There is nothing here.</p>"#,
    )
}

/// A form that failed its CSRF check: a stale page, or a cross-site post.
pub fn bad_request(message: &str) -> Response {
    card(
        StatusCode::BAD_REQUEST,
        "Bad request",
        &format!(r#"<h1>Bad request</h1><p class="sub">{}</p>"#, e(message)),
    )
}

pub fn server_error() -> Response {
    card(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error",
        r#"<h1>Something went wrong</h1><p class="sub">The console could not complete that. The server log has the detail.</p>"#,
    )
}

/// A Unix timestamp as RFC 3339 in UTC, for the pages that show when something
/// was created, retired or expires.
///
/// Falls back to the raw number rather than hiding the column: a timestamp out
/// of range is a storage problem the administrator should be able to see.
pub fn ts(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

/// A page-level error, or nothing when there is none. Every section renders its
/// failures the same way.
pub fn error_block(error: Option<&str>) -> String {
    error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default()
}

/// A value shown exactly once, because it is not stored anywhere it could be
/// shown again: a new client secret.
pub fn shown_once(heading: &str, value: &str, note: &str) -> String {
    format!(
        r#"<div class="notice"><strong>{heading}</strong><code class="once">{value}</code>
<p class="muted">{note}</p></div>"#,
        heading = e(heading),
        value = e(value),
        note = e(note),
    )
}

/// 303 after a form post, so a refresh does not repeat the write.
pub fn see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}
