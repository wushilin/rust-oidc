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
:root { --bg:#f6f7f9; --card:#fff; --fg:#1b1b1b; --muted:#5f6368; --accent:#0f6cbd; --err:#b3261e; --border:#d0d4da; }
@media (prefers-color-scheme: dark) { :root { --bg:#16181c; --card:#212429; --fg:#e8eaed; --muted:#a0a4ab; --accent:#4f9ae8; --err:#f2b8b5; --border:#3a3f46; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
header.top { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between; padding:10px 20px; background:var(--card); border-bottom:1px solid var(--border); }
header.top .who { color:var(--muted); font-size:13px; display:flex; gap:12px; align-items:center; }
nav { display:flex; flex-wrap:wrap; gap:16px; padding:8px 20px; border-bottom:1px solid var(--border); font-size:14px; }
main { max-width:1000px; margin:0 auto; padding:20px 16px 48px; }
h1 { font-size:21px; font-weight:600; margin:0 0 4px; }
h2 { font-size:16px; font-weight:600; margin:28px 0 8px; }
p.sub { color:var(--muted); margin:0 0 18px; }
a { color:var(--accent); }
.banner { background:var(--card); border:1px solid var(--accent); border-left-width:4px; border-radius:4px; padding:10px 14px; margin:0 0 18px; display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between; }
table { border-collapse:collapse; width:100%; background:var(--card); border:1px solid var(--border); border-radius:4px; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
th { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
tr:last-child td { border-bottom:none; }
form.inline { display:inline; }
label { display:block; font-size:13px; margin:14px 0 4px; }
input[type=text], input[type=email], input[type=password], input[type=search], select { width:100%; max-width:420px; padding:8px 10px; font:inherit; color:var(--fg); background:transparent; border:1px solid var(--border); border-radius:4px; }
input:focus, select:focus { outline:2px solid var(--accent); outline-offset:-1px; }
button { font:inherit; padding:7px 14px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer; }
button.secondary { background:transparent; color:var(--accent); }
button.danger { background:transparent; border-color:var(--err); color:var(--err); }
.actions { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-top:20px; }
.error { color:var(--err); margin:12px 0; }
.muted { color:var(--muted); }
.pill { display:inline-block; font-size:12px; border:1px solid var(--border); border-radius:10px; padding:1px 8px; margin:0 4px 4px 0; color:var(--muted); }
.card { background:var(--card); border:1px solid var(--border); border-radius:4px; padding:20px 24px; max-width:460px; margin:48px auto; }
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

/// One navigation entry. The caller emits an entry only where the corresponding
/// action is permitted, so the console never offers what the guard would refuse.
pub struct Nav {
    pub label: String,
    pub href: String,
}

/// Everything the chrome around a page needs. Built from the request's
/// `AdminContext`, so a page cannot render a different identity than the one that
/// was authorized.
pub struct Chrome<'a> {
    pub base: &'a str,
    pub upn: &'a str,
    pub csrf: &'a str,
    /// Name of the tenant being acted in, when one has been assumed.
    pub acting: Option<&'a str>,
    pub nav: Vec<Nav>,
}

/// A page inside the console: chrome, optional assumed-tenant banner, body.
pub fn page(c: &Chrome<'_>, status: StatusCode, title: &str, body: &str) -> Response {
    let nav = c
        .nav
        .iter()
        .map(|n| format!(r#"<a href="{}">{}</a>"#, e(&n.href), e(&n.label)))
        .collect::<Vec<_>>()
        .join("");
    let banner = match c.acting {
        Some(name) => format!(
            r#"<div class="banner"><span>Acting in <strong>{name}</strong>. Everything you do is still recorded as you.</span>
<form method="post" action="{base}/admin/leave" class="inline">{csrf}<button class="secondary" type="submit">Leave tenant</button></form></div>"#,
            name = e(name),
            base = e(c.base),
            csrf = csrf_input(c.csrf),
        ),
        None => String::new(),
    };
    let body = format!(
        r#"<header class="top"><strong>{PRODUCT}</strong><span class="who">{upn}
<form method="post" action="{base}/admin/signout" class="inline">{csrf}<button class="secondary" type="submit">Sign out</button></form></span></header>
<nav>{nav}</nav><main>{banner}{body}</main>"#,
        upn = e(c.upn),
        base = e(c.base),
        csrf = csrf_input(c.csrf),
    );
    respond(status, document(title, &body))
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
pub fn sign_in(base: &str, upn: &str, error: Option<&str>) -> Response {
    let error = error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>{PRODUCT}</h1><p class="sub">Sign in with an administrator account.</p>
<form method="post" action="{base}/admin/signin">
<label for="upn">Email or username</label><input id="upn" name="upn" type="email" autocomplete="username" required value="{upn}" autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
{error}<div class="actions"><button type="submit">Sign in</button></div></form>"#,
        base = e(base),
        upn = e(upn),
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

/// 303 after a form post, so a refresh does not repeat the write.
pub fn see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}
