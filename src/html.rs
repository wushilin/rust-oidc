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
ul.consent { list-style:none; padding:0; margin:12px 0; }
ul.consent li { border:1px solid var(--border); padding:10px 14px; margin:8px 0; }
.code { color:var(--muted); font-size:12px; word-break:break-all; margin-top:18px; }
ol.steps { padding-left:20px; margin:12px 0; } ol.steps li { margin:10px 0; }
.qr { display:flex; justify-content:center; margin:12px 0; } .qr svg { width:200px; height:200px; background:#fff; padding:6px; border-radius:4px; }
.key { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.06em; word-break:break-all; background:var(--bg); padding:6px 8px; border-radius:4px; }
ul.codes { list-style:none; padding:0; margin:12px 0; display:grid; grid-template-columns:1fr 1fr; gap:6px 18px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:15px; }
a.button { display:inline-block; padding:9px 18px; border-radius:4px; background:var(--accent); color:#fff; text-decoration:none; }
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

/// What a sign-in page's form asks the login endpoint to do, carried in `op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOp {
    /// Carry on as the account already signed in.
    Continue,
    /// Sign in as somebody else.
    Other,
    /// Allow the application the permissions it asked for.
    ConsentAccept,
    /// Refuse them.
    ConsentDeny,
    /// The code at the second step of a sign-in.
    MfaVerify,
    /// The code that confirms a new authenticator.
    MfaEnroll,
    /// A new password, chosen at sign-in because the old one must be replaced.
    ChangePassword,
}

impl LoginOp {
    pub const ALL: &'static [LoginOp] = &[
        Self::Continue,
        Self::Other,
        Self::ConsentAccept,
        Self::ConsentDeny,
        Self::MfaVerify,
        Self::MfaEnroll,
        Self::ChangePassword,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Other => "other",
            Self::ConsentAccept => "consent_accept",
            Self::ConsentDeny => "consent_deny",
            Self::MfaVerify => "mfa_verify",
            Self::MfaEnroll => "mfa_enroll",
            Self::ChangePassword => "change_password",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }
}

/// One permission on the consent page: the scope as requested, and what it
/// means in words.
pub struct ConsentItem {
    pub scope: String,
    pub description: String,
}

pub struct Consent<'a> {
    pub tenant_name: &'a str,
    pub client_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub request: &'a str,
    pub upn: &'a str,
    pub items: &'a [ConsentItem],
}

/// "This application wants these permissions. Allow?"
pub fn consent(p: &Consent) -> Response {
    let hidden = format!(
        r#"<input type="hidden" name="csrf" value="{}"><input type="hidden" name="request" value="{}">"#,
        escape(p.csrf),
        escape(p.request)
    );
    let items: String = p
        .items
        .iter()
        .map(|i| {
            format!(
                r#"<li><strong>{}</strong><br><span class="sub">{}</span></li>"#,
                escape(&i.description),
                escape(&i.scope)
            )
        })
        .collect();
    let body = format!(
        r#"<h1>Permissions requested</h1><p class="sub">{upn}</p>
<p><strong>{client}</strong> would like to:</p>
<ul class="consent">{items}</ul>
<p class="sub">Allowing this lets the application use these permissions for your account. You can
refuse and nothing is shared.</p>
<form method="post" action="{action}">{hidden}
<div class="actions"><button type="submit" name="op" value="{accept}">Allow</button>
<button class="link" type="submit" name="op" value="{deny}">Deny</button></div></form>"#,
        upn = escape(p.upn),
        client = escape(p.client_name),
        action = escape(p.action),
        accept = LoginOp::ConsentAccept.as_str(),
        deny = LoginOp::ConsentDeny.as_str(),
    );
    respond(
        StatusCode::OK,
        page("Permissions requested", Some(p.tenant_name), &body),
        CSP_DEFAULT,
    )
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
<form method="post" action="{action}">{hidden}<input type="hidden" name="op" value="{op_continue}">
<button class="account" type="submit"><span><strong>{name}</strong><br><span class="sub">{upn}</span></span><span>&rsaquo;</span></button></form>
<form method="post" action="{action}">{hidden}<input type="hidden" name="op" value="{op_other}">
<div class="actions"><button class="link" type="submit">Use another account</button></div></form>"#,
        client = escape(p.client_name),
        action = escape(p.action),
        name = escape(p.display_name),
        upn = escape(p.upn),
        op_continue = LoginOp::Continue.as_str(),
        op_other = LoginOp::Other.as_str(),
    );
    respond(
        StatusCode::OK,
        page("Pick an account", Some(p.tenant_name), &body),
        CSP_DEFAULT,
    )
}

/// Error shown when we must not redirect (unknown client, bad redirect URI, ...).
/// The form field a second-step page carries its ticket in.
pub const MFA_TICKET: &str = "mfa_ticket";
/// The form field for the code typed at a second step.
pub const MFA_CODE: &str = "code";

/// The second step of a sign-in: a code from the authenticator, or a recovery
/// code. `hidden` is the page's own hidden fields (CSRF, the request it belongs
/// to), already escaped; the ticket and `op` are added here.
pub struct MfaVerify<'a> {
    pub tenant_name: &'a str,
    pub upn: &'a str,
    pub action: &'a str,
    pub hidden: &'a str,
    pub op_field: &'a str,
    pub op: &'a str,
    pub ticket: &'a str,
    pub error: Option<&'a str>,
}

pub fn mfa_verify(p: &MfaVerify) -> Response {
    let error = p
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>Enter code</h1><p class="sub">{upn}</p>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{op_field}" value="{op}"><input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<label for="code">Code from your authenticator app</label><input id="code" name="{MFA_CODE}" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" required autofocus>
<p class="sub" style="margin-top:8px">Lost your phone? Enter one of your recovery codes instead.</p>
{error}<div class="actions"><button type="submit">Verify</button></div></form>"#,
        upn = escape(p.upn),
        action = escape(p.action),
        hidden = p.hidden,
        op_field = escape(p.op_field),
        op = escape(p.op),
        ticket = escape(p.ticket),
    );
    let status = if p.error.is_some() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
    respond(status, page("Enter code", Some(p.tenant_name), &body), CSP_DEFAULT)
}

/// Setting up an authenticator: the QR code, the key for typing in, and the box
/// for the first code, which confirms it.
pub struct MfaEnroll<'a> {
    pub tenant_name: &'a str,
    pub upn: &'a str,
    pub action: &'a str,
    pub hidden: &'a str,
    pub op_field: &'a str,
    pub op: &'a str,
    pub ticket: &'a str,
    /// The QR code, as inline SVG made by this server.
    pub qr_svg: &'a str,
    pub secret: &'a str,
    pub error: Option<&'a str>,
}

pub fn mfa_enroll(p: &MfaEnroll) -> Response {
    let error = p
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    // The key in groups of four, as authenticator apps print it.
    let grouped: Vec<String> = p
        .secret
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let body = format!(
        r#"<h1>Set up your authenticator</h1><p class="sub">{upn} must use a second step to sign in.</p>
<ol class="steps"><li>Install an authenticator app on your phone, such as Microsoft Authenticator or Google Authenticator.</li>
<li>Scan this code with it:<div class="qr">{qr}</div>or enter this key: <div class="key">{key}</div></li>
<li>Enter the six-digit code the app shows.</li></ol>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{op_field}" value="{op}"><input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<label for="code">Code</label><input id="code" name="{MFA_CODE}" type="text" inputmode="numeric" autocomplete="one-time-code" required autofocus>
{error}<div class="actions"><button type="submit">Confirm</button></div></form>"#,
        upn = escape(p.upn),
        qr = p.qr_svg,
        key = escape(&grouped.join(" ")),
        action = escape(p.action),
        hidden = p.hidden,
        op_field = escape(p.op_field),
        op = escape(p.op),
        ticket = escape(p.ticket),
    );
    let status = if p.error.is_some() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
    respond(
        status,
        page("Set up your authenticator", Some(p.tenant_name), &body),
        CSP_DEFAULT,
    )
}

/// The authenticator is set up: the recovery codes, shown this once, and the way
/// back in. The user has been signed out and signs in again with it.
pub fn mfa_enrolled(tenant_name: &str, codes: &[String], again_href: &str) -> Response {
    let codes: String = codes.iter().map(|c| format!("<li>{}</li>", escape(c))).collect();
    let body = format!(
        r#"<h1>Your authenticator is set up</h1>
<p>Save these recovery codes somewhere safe. Each one signs you in once if you lose your phone. They
are shown only now.</p>
<ul class="codes">{codes}</ul>
<p class="sub">You have been signed out. Sign in again with your password and a code from the app.</p>
<div class="actions"><a class="button" href="{href}">Sign in again</a></div>"#,
        href = escape(again_href),
    );
    respond(
        StatusCode::OK,
        page("Authenticator set up", Some(tenant_name), &body),
        CSP_DEFAULT,
    )
}

/// The form fields of the change-password page.
pub const NEW_PASSWORD: &str = "new_password";
pub const CONFIRM_PASSWORD: &str = "confirm_password";

/// Choosing a new password at sign-in: the old one was set by an administrator,
/// or has to be replaced. Carried by a second-step ticket like the MFA pages.
pub struct ChangePassword<'a> {
    pub tenant_name: &'a str,
    pub upn: &'a str,
    pub action: &'a str,
    pub hidden: &'a str,
    pub op_field: &'a str,
    pub op: &'a str,
    pub ticket: &'a str,
    pub error: Option<&'a str>,
}

pub fn change_password(p: &ChangePassword) -> Response {
    let error = p
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>Update your password</h1><p class="sub">{upn} needs a new password before signing in.</p>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{op_field}" value="{op}"><input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<label for="new_password">New password</label><input id="new_password" name="{NEW_PASSWORD}" type="password" autocomplete="new-password" required autofocus>
<label for="confirm_password">Confirm new password</label><input id="confirm_password" name="{CONFIRM_PASSWORD}" type="password" autocomplete="new-password" required>
{error}<div class="actions"><button type="submit">Sign in</button></div></form>"#,
        upn = escape(p.upn),
        action = escape(p.action),
        hidden = p.hidden,
        op_field = escape(p.op_field),
        op = escape(p.op),
        ticket = escape(p.ticket),
    );
    let status = if p.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    respond(
        status,
        page("Update your password", Some(p.tenant_name), &body),
        CSP_DEFAULT,
    )
}

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
        format!(r#"<p class="code">Permissions: {}</p>"#, escape(&p.scopes.join(", ")))
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
    let body = format!(r#"<h1>{}</h1><p class="sub">{}</p>"#, escape(heading), escape(message));
    respond(StatusCode::OK, page(heading, tenant_name, &body), CSP_DEFAULT)
}
