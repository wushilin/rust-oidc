//! Server-rendered pages for the sign-in flow. Deliberately plain: no scripts
//! except the auto-submit on form_post responses.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::util::{b64url, random_bytes};

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { --bg:#f3f4f6; --card:#fff; --fg:#1b1b1b; --muted:#5f6368; --accent:#0f6cbd; --err:#b3261e; --border:#d0d4da; }
@media (prefers-color-scheme: dark) { :root { --bg:#16181c; --card:#212429; --fg:#e8eaed; --muted:#a0a4ab; --accent:#4f9ae8; --err:#f2b8b5; --border:#3a3f46; } }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--fg); font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { width:100%; max-width:420px; margin:16px; background:var(--card); border:1px solid var(--border); border-radius:8px; padding:36px 40px; }
.tenant { color:var(--muted); font-size:13px; margin:0 0 20px; }
h1 { font-size:22px; font-weight:600; margin:0 0 6px; }
p.sub { color:var(--muted); margin:0 0 20px; }
label { display:block; font-size:13px; margin:14px 0 4px; }
input[type=text], input[type=email], input[type=password] { width:100%; padding:9px 10px; font:inherit; color:var(--fg); background:transparent; border:1px solid var(--border); border-radius:4px; }
input:focus { outline:2px solid var(--accent); outline-offset:-1px; border-color:transparent; }
button { font:inherit; padding:9px 18px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer; }
button.link { background:none; border:none; color:var(--accent); padding:0; }
.actions { display:flex; justify-content:flex-end; align-items:center; gap:16px; margin-top:24px; }
.error { color:var(--err); margin:12px 0 0; font-size:14px; }
.account { display:flex; justify-content:space-between; align-items:center; width:100%; text-align:left; background:none; color:var(--fg); border:1px solid var(--border); padding:12px 14px; margin:8px 0; }
.code { color:var(--muted); font-size:12px; word-break:break-all; margin-top:18px; }
"#;

fn page(title: &str, tenant_name: Option<&str>, body: &str) -> String {
    let tenant = tenant_name
        .map(|t| format!(r#"<p class="tenant">{}</p>"#, escape(t)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>{title}</title><style>{STYLE}</style></head><body><main>{tenant}{body}</main></body></html>"#,
        title = escape(title),
    )
}

fn respond(status: StatusCode, html: String, csp: &str) -> Response {
    let mut resp = (status, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if let Ok(v) = HeaderValue::from_str(csp) {
        h.insert("content-security-policy", v);
    }
    resp
}

const CSP_DEFAULT: &str =
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub struct LoginForm<'a> {
    pub tenant_name: &'a str,
    pub client_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub request: &'a str,
    pub upn: &'a str,
    pub error: Option<&'a str>,
}

pub fn login(f: &LoginForm) -> Response {
    let error = f
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let autofocus_upn = if f.upn.is_empty() { " autofocus" } else { "" };
    let autofocus_pw = if f.upn.is_empty() { "" } else { " autofocus" };
    let body = format!(
        r#"<h1>Sign in</h1><p class="sub">to continue to {client}</p>
<form method="post" action="{action}">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="request" value="{request}"><input type="hidden" name="op" value="login">
<label for="upn">Email or username</label><input id="upn" name="upn" type="email" autocomplete="username" required value="{upn}"{autofocus_upn}>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required{autofocus_pw}>
{error}
<div class="actions"><button type="submit">Sign in</button></div></form>"#,
        client = escape(f.client_name),
        action = escape(f.action),
        csrf = escape(f.csrf),
        request = escape(f.request),
        upn = escape(f.upn),
    );
    let status = if f.error.is_some() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
    respond(status, page("Sign in", Some(f.tenant_name), &body), CSP_DEFAULT)
}

pub struct AccountPicker<'a> {
    pub tenant_name: &'a str,
    pub client_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub request: &'a str,
    pub upn: &'a str,
    pub display_name: &'a str,
}

pub fn account_picker(p: &AccountPicker) -> Response {
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        escape(p.csrf),
        escape(p.request)
    );
    let body = format!(
        r#"<h1>Pick an account</h1><p class="sub">to continue to {client}</p>
<form method="post" action="{action}">{hidden}<input type="hidden" name="op" value="continue">
<button class="account" type="submit"><span><strong>{name}</strong><br><span class="sub">{upn}</span></span><span>&rsaquo;</span></button></form>
<form method="post" action="{action}">{hidden}<input type="hidden" name="op" value="other">
<div class="actions"><button class="link" type="submit">Use another account</button></div></form>"#,
        client = escape(p.client_name),
        action = escape(p.action),
        name = escape(p.display_name),
        upn = escape(p.upn),
    );
    respond(
        StatusCode::OK,
        page("Pick an account", Some(p.tenant_name), &body),
        CSP_DEFAULT,
    )
}

/// Error shown when we must not redirect (unknown client, bad redirect URI, ...).
pub fn error(tenant_name: Option<&str>, message: &str) -> Response {
    let body = format!(
        r#"<h1>Sorry, but we're having trouble signing you in.</h1><p class="code">{}</p>"#,
        escape(message)
    );
    respond(
        StatusCode::BAD_REQUEST,
        page("Sign in error", tenant_name, &body),
        CSP_DEFAULT,
    )
}

pub fn signed_out(tenant_name: Option<&str>) -> Response {
    let body =
        r#"<h1>You signed out of your account</h1><p class="sub">It's a good idea to close all browser windows.</p>"#;
    respond(StatusCode::OK, page("Signed out", tenant_name, body), CSP_DEFAULT)
}

/// `response_mode=form_post`: auto-submitting form to the client.
pub fn form_post(action: &url::Url, params: &[(&str, String)]) -> Response {
    let nonce = b64url(&random_bytes(16));
    let inputs: String = params
        .iter()
        .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, escape(k), escape(v)))
        .collect();
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Working...</title></head><body><form method="POST" name="hiddenform" action="{action}">{inputs}<noscript><p>Script is disabled. Click Submit to continue.</p><input type="submit" value="Submit"></noscript></form><script nonce="{nonce}">document.forms[0].submit()</script></body></html>"#,
        action = escape(action.as_str()),
    );
    let origin = action.origin().ascii_serialization();
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; form-action {origin}; frame-ancestors 'none'; base-uri 'none'"
    );
    respond(StatusCode::OK, html, &csp)
}

// ---- device authorization grant pages ----

pub struct DeviceCodeForm<'a> {
    pub tenant_name: Option<&'a str>,
    pub action: &'a str,
    pub csrf: &'a str,
    pub user_code: &'a str,
    pub error: Option<&'a str>,
}

/// Where the user types the code shown on the device.
pub fn device_code_entry(f: &DeviceCodeForm) -> Response {
    let error = f
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>Enter code</h1><p class="sub">Type the code shown on your device.</p>
<form method="post" action="{action}">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="op" value="code">
<label for="user_code">Code</label><input id="user_code" name="user_code" type="text" autocomplete="off" spellcheck="false" required value="{user_code}" autofocus>
{error}
<div class="actions"><button type="submit">Next</button></div></form>"#,
        action = escape(f.action),
        csrf = escape(f.csrf),
        user_code = escape(f.user_code),
    );
    let status = if f.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    respond(status, page("Enter code", f.tenant_name, &body), CSP_DEFAULT)
}

pub struct DeviceApproval<'a> {
    pub tenant_name: &'a str,
    pub client_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub request: &'a str,
    pub user_code: &'a str,
    pub upn: &'a str,
    pub scopes: &'a [String],
}

/// Confirms which app is being signed in to, before the device is approved.
pub fn device_approval(p: &DeviceApproval) -> Response {
    let scopes = if p.scopes.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="code">Permissions: {}</p>"#,
            escape(&p.scopes.join(", "))
        )
    };
    let body = format!(
        r#"<h1>Are you trying to sign in to {client}?</h1>
<p class="sub">Signed in as {upn}. Only continue if you started this on your device.</p>
<form method="post" action="{action}">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="request" value="{request}">
<p class="code">Code: {user_code}</p>{scopes}
<div class="actions">
<button class="link" type="submit" name="op" value="deny">Cancel</button>
<button type="submit" name="op" value="approve">Continue</button>
</div></form>"#,
        client = escape(p.client_name),
        upn = escape(p.upn),
        action = escape(p.action),
        csrf = escape(p.csrf),
        request = escape(p.request),
        user_code = escape(p.user_code),
    );
    respond(StatusCode::OK, page("Sign in", Some(p.tenant_name), &body), CSP_DEFAULT)
}

/// Terminal page for the device flow: approved, or declined.
pub fn device_result(tenant_name: Option<&str>, heading: &str, message: &str) -> Response {
    let body = format!(
        r#"<h1>{}</h1><p class="sub">{}</p>"#,
        escape(heading),
        escape(message)
    );
    respond(StatusCode::OK, page(heading, tenant_name, &body), CSP_DEFAULT)
}
