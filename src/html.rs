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
/* The same palette, type and card as the admin console's sign-in
   (src/admin/view.rs), so every sign-in page looks like one product. */
:root { --bg:#f3f5f7; --card:#fff; --fg:#17222b; --muted:#5c6b77; --accent:#0d6b73; --on-accent:#fff; --err:#b3261e; --border:#d3dae0; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f161b; --card:#172129; --fg:#e3e9ed; --muted:#91a1ad; --accent:#56c2c9; --on-accent:#06262a; --err:#f2a39c; --border:#2a3843; } }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--fg); font:14.5px/1.55 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",sans-serif; }
main { width:100%; max-width:420px; margin:16px; background:var(--card); border:1px solid var(--border); border-radius:8px; padding:36px 40px; }
.tenant { color:var(--muted); font-size:13px; margin:0 0 20px; }
h1 { font-size:22px; font-weight:650; letter-spacing:-.015em; margin:0 0 6px; }
p.sub { color:var(--muted); margin:0 0 20px; }
label { display:block; font-size:13px; font-weight:600; margin:14px 0 4px; }
input[type=text], input[type=email], input[type=password] { width:100%; padding:9px 10px; font:inherit; color:var(--fg); background:transparent; border:1px solid var(--border); border-radius:4px; }
input:focus { outline:2px solid var(--accent); outline-offset:-1px; border-color:transparent; }
button { font:inherit; font-weight:600; padding:9px 18px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:var(--on-accent); cursor:pointer; }
button.link { background:none; border:none; color:var(--accent); padding:0; }
.actions { display:flex; justify-content:flex-end; align-items:center; gap:16px; margin-top:24px; }
.error { color:var(--err); margin:12px 0 0; font-size:14px; }
label.check { display:flex; align-items:flex-start; gap:8px; font-size:14px; margin:18px 0 0; }
label.check input { margin:3px 0 0; }
p.hint { color:var(--muted); font-size:13px; margin:4px 0 0 24px; }
.account { display:flex; justify-content:space-between; align-items:center; width:100%; text-align:left; background:none; color:var(--fg); border:1px solid var(--border); padding:12px 14px; margin:8px 0; }
ul.consent { list-style:none; padding:0; margin:12px 0; }
ul.consent li { border:1px solid var(--border); padding:10px 14px; margin:8px 0; }
.code { color:var(--muted); font-size:12px; word-break:break-all; margin-top:18px; }
main.wide { max-width:600px; }
main.wide h2 { font-size:16px; margin:28px 0 6px; padding-top:18px; border-top:1px solid var(--border); }
dl.profile { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px; margin:8px 0; }
dl.profile dt { color:var(--muted); } dl.profile dd { margin:0; word-break:break-all; }
.notice { border:1px solid var(--accent); border-radius:6px; padding:10px 14px; margin:12px 0; }
button.secondary { background:transparent; color:var(--accent); }
ol.steps { padding-left:20px; margin:12px 0; } ol.steps li { margin:10px 0; }
.qr { display:flex; justify-content:center; margin:12px 0; } .qr svg { width:200px; height:200px; background:#fff; padding:6px; border-radius:4px; }
.key { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.06em; word-break:break-all; background:var(--bg); padding:6px 8px; border-radius:4px; }
ul.codes { list-style:none; padding:0; margin:12px 0; display:grid; grid-template-columns:1fr 1fr; gap:6px 18px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:15px; }
a.button { display:inline-block; padding:9px 18px; border-radius:4px; background:var(--accent); color:var(--on-accent); font-weight:600; text-decoration:none; }
"#;

/// [`page`] with room for a page of sections rather than one form.
fn wide_page(title: &str, tenant_name: Option<&str>, body: &str) -> String {
    page(title, tenant_name, body).replacen("<main>", r#"<main class="wide">"#, 1)
}

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

/// The policy for a sign-in page whose form the server may answer with a
/// redirect to the client. Chrome holds a redirect that follows a form
/// submission to `form-action` too (Firefox and Safari do not), so with
/// `form-action 'self'` alone Chrome silently drops the 302 to the client's
/// redirect URI and the user sees nothing happen. Such a page lists the
/// client's origin beside `'self'`; the rest is [`CSP_DEFAULT`]. Only a
/// redirect URI that the authorize endpoint validated against the application's
/// registered ones is passed here, never the raw request parameter.
fn csp_for_form(redirect_uri: Option<&url::Url>) -> std::borrow::Cow<'static, str> {
    match redirect_uri {
        None => std::borrow::Cow::Borrowed(CSP_DEFAULT),
        Some(uri) => std::borrow::Cow::Owned(format!(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {}; frame-ancestors 'none'; base-uri 'none'",
            csp_source(uri)
        )),
    }
}

/// The CSP source expression that matches `uri`: its origin, or for a URI whose
/// origin is opaque (a native app's custom scheme) the scheme alone, which is
/// the only source expression that can match it.
fn csp_source(uri: &url::Url) -> String {
    match uri.origin() {
        url::Origin::Tuple(..) => uri.origin().ascii_serialization(),
        url::Origin::Opaque(_) => format!("{}:", uri.scheme()),
    }
}

/// The sign-in form's "Keep me signed in" box.
pub const KEEP_SIGNED_IN: &str = "keep_signed_in";
/// The second step's "Don't ask again on this device" box.
pub const REMEMBER_DEVICE: &str = "remember_device";
/// What a ticked box posts.
const TICKED: &str = "1";

/// Whether a box was ticked on the posted form.
pub fn ticked(form: &std::collections::HashMap<String, String>, name: &str) -> bool {
    form.get(name).is_some_and(|v| v == TICKED)
}

const SECS_PER_DAY: i64 = 86_400;

/// "Keep me signed in", where the tenant offers it.
fn keep_signed_in_box() -> String {
    let days = crate::tenant::TenantSettings::KEEP_SIGNED_IN_SECS / SECS_PER_DAY;
    format!(
        r#"<label class="check"><input type="checkbox" name="{KEEP_SIGNED_IN}" value="{TICKED}"> Keep me signed in</label>
<p class="hint">For {days} days on this browser. Don't tick this on a shared computer.</p>"#
    )
}

/// "Don't ask again on this device", where the account's tenant offers it.
fn remember_device_box() -> String {
    let days = crate::tenant::TenantSettings::REMEMBER_MFA_SECS / SECS_PER_DAY;
    format!(
        r#"<label class="check"><input type="checkbox" name="{REMEMBER_DEVICE}" value="{TICKED}"> Don't ask again on this device for {days} days</label>
<p class="hint">You'll still need your password. Applications that ask for a fresh sign-in will ask for a code too.</p>"#
    )
}

pub struct LoginForm<'a> {
    /// The tenant signed in to; none on the server's front door, where the
    /// tenant is not known until the UPN is.
    pub tenant_name: Option<&'a str>,
    pub client_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub request: &'a str,
    pub upn: &'a str,
    pub error: Option<&'a str>,
    /// Show "Keep me signed in": the tenant offers it.
    pub offer_keep_signed_in: bool,
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
}

pub fn login(f: &LoginForm) -> Response {
    let error = f
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let keep = if f.offer_keep_signed_in {
        keep_signed_in_box()
    } else {
        String::new()
    };
    let autofocus_upn = if f.upn.is_empty() { " autofocus" } else { "" };
    let autofocus_pw = if f.upn.is_empty() { "" } else { " autofocus" };
    let body = format!(
        r#"<h1>Sign in</h1><p class="sub">to continue to {client}</p>
<form method="post" action="{action}">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="request" value="{request}"><input type="hidden" name="op" value="login">
<label for="upn">Email or username</label><input id="upn" name="upn" type="email" autocomplete="username" required value="{upn}"{autofocus_upn}>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required{autofocus_pw}>
{keep}{error}
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
    respond(
        status,
        page("Sign in", f.tenant_name, &body),
        &csp_for_form(f.redirect_uri),
    )
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
    /// "Set up an authenticator?": yes, now.
    MfaSetupNow,
    /// "Set up an authenticator?": not now; carry on signing in.
    MfaSetupLater,
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
        Self::MfaSetupNow,
        Self::MfaSetupLater,
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
            Self::MfaSetupNow => "mfa_setup_now",
            Self::MfaSetupLater => "mfa_setup_later",
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
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
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
        &csp_for_form(p.redirect_uri),
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
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
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
        &csp_for_form(p.redirect_uri),
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
    /// Show "Don't ask again on this device": the account's tenant offers it.
    pub offer_remember_device: bool,
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
}

pub fn mfa_verify(p: &MfaVerify) -> Response {
    let error = p
        .error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)))
        .unwrap_or_default();
    let remember = if p.offer_remember_device {
        remember_device_box()
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>Enter code</h1><p class="sub">{upn}</p>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{op_field}" value="{op}"><input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<label for="code">Code from your authenticator app</label><input id="code" name="{MFA_CODE}" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" required autofocus>
<p class="sub" style="margin-top:8px">Lost your phone? Enter one of your recovery codes instead.</p>
{remember}{error}<div class="actions"><button type="submit">Verify</button></div></form>"#,
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
    respond(
        status,
        page("Enter code", Some(p.tenant_name), &body),
        &csp_for_form(p.redirect_uri),
    )
}

/// "Set up an authenticator?", after a password, where nothing requires one.
pub struct MfaSuggest<'a> {
    pub tenant_name: &'a str,
    pub upn: &'a str,
    pub action: &'a str,
    pub hidden: &'a str,
    pub op_field: &'a str,
    pub ticket: &'a str,
    /// How many days "Not now" puts it off.
    pub snooze_days: i64,
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
}

pub fn mfa_suggest(p: &MfaSuggest) -> Response {
    let body = format!(
        r#"<h1>Protect your account</h1><p class="sub">{upn}</p>
<p>Add a second step to signing in: a code from an authenticator app on your phone. Someone who learns your
password still cannot sign in as you.</p>
<p class="sub">It takes a minute. After setting it up you sign in again, with your password and a code.</p>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<div class="actions"><button type="submit" name="{op_field}" value="{now}">Set it up now</button>
<button class="secondary" type="submit" name="{op_field}" value="{later}">Not now</button></div>
<p class="sub">Not now carries on signing you in, and asks again in {days} days.</p></form>"#,
        upn = escape(p.upn),
        action = escape(p.action),
        hidden = p.hidden,
        op_field = escape(p.op_field),
        ticket = escape(p.ticket),
        now = LoginOp::MfaSetupNow.as_str(),
        later = LoginOp::MfaSetupLater.as_str(),
        days = p.snooze_days,
    );
    respond(
        StatusCode::OK,
        page("Protect your account", Some(p.tenant_name), &body),
        &csp_for_form(p.redirect_uri),
    )
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
    /// The tenant the account belongs to: what the app lists it under.
    pub issuer: &'a str,
    pub error: Option<&'a str>,
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
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
        r#"<h1>Set up your authenticator</h1><p class="sub">A second step for signing in as {upn}.</p>
<ol class="steps"><li>Install an authenticator app on your phone, such as Microsoft Authenticator or Google Authenticator.</li>
<li>Scan this code with it:<div class="qr">{qr}</div>or enter this key: <div class="key">{key}</div></li>
<li>Enter the six-digit code the app shows. It lists this account as <strong>{issuer}: {upn}</strong>.</li></ol>
<form method="post" action="{action}">{hidden}<input type="hidden" name="{op_field}" value="{op}"><input type="hidden" name="{MFA_TICKET}" value="{ticket}">
<label for="code">Code</label><input id="code" name="{MFA_CODE}" type="text" inputmode="numeric" autocomplete="one-time-code" required autofocus>
{error}<div class="actions"><button type="submit">Confirm</button></div></form>"#,
        upn = escape(p.upn),
        qr = p.qr_svg,
        issuer = escape(p.issuer),
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
        &csp_for_form(p.redirect_uri),
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
    /// The validated redirect URI of the request this page belongs to, where the
    /// form's answer may send the browser; its origin joins `form-action`.
    /// None where the answer stays on this server.
    pub redirect_uri: Option<&'a url::Url>,
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
        &csp_for_form(p.redirect_uri),
    )
}

/// What My Account shows. Every action posts to `action` with its own `op` and
/// the page's CSRF token, and the ones that need more say so in their forms.
pub struct MyAccount<'a> {
    pub tenant_name: &'a str,
    pub action: &'a str,
    pub csrf: &'a str,
    pub upn: &'a str,
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub email: Option<&'a str>,
    /// When the authenticator was set up, as text; `None` when there is none.
    pub mfa_since: Option<&'a str>,
    pub recovery_codes_left: i64,
    /// Whether MFA is required of this user, for the wording only.
    pub mfa_required: bool,
    /// A message from the last action: done, or why not.
    pub notice: Option<&'a str>,
    pub error: Option<&'a str>,
    /// New recovery codes, shown once.
    pub new_codes: Option<&'a [String]>,
}

/// The `op` values My Account's forms carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOp {
    Password,
    MfaSetup,
    MfaReplace,
    RecoveryCodes,
    SignOutEverywhere,
}

impl AccountOp {
    pub const ALL: &'static [AccountOp] = &[
        Self::Password,
        Self::MfaSetup,
        Self::MfaReplace,
        Self::RecoveryCodes,
        Self::SignOutEverywhere,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "account_password",
            Self::MfaSetup => "account_mfa_setup",
            Self::MfaReplace => "account_mfa_replace",
            Self::RecoveryCodes => "account_recovery_codes",
            Self::SignOutEverywhere => "account_sign_out_everywhere",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }
}

/// My Account's form fields.
pub const CURRENT_PASSWORD: &str = "current_password";

pub fn my_account(p: &MyAccount) -> Response {
    let form = |op: AccountOp, inner: &str, button: &str, class: &str| {
        format!(
            r#"<form method="post" action="{action}"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="op" value="{op}">{inner}<div class="actions"><button type="submit" class="{class}">{button}</button></div></form>"#,
            action = escape(p.action),
            csrf = escape(p.csrf),
            op = op.as_str(),
            button = escape(button),
            class = class,
        )
    };
    let row = |label: &str, value: Option<&str>| match value.filter(|v| !v.is_empty()) {
        Some(v) => format!("<dt>{}</dt><dd>{}</dd>", escape(label), escape(v)),
        None => String::new(),
    };
    let banner = match (p.error, p.notice) {
        (Some(e), _) => format!(r#"<p class="error" role="alert">{}</p>"#, escape(e)),
        (None, Some(n)) => format!(r#"<p class="notice" role="status">{}</p>"#, escape(n)),
        _ => String::new(),
    };
    let codes = p
        .new_codes
        .map(|codes| {
            let items: String = codes.iter().map(|c| format!("<li>{}</li>", escape(c))).collect();
            format!(
                r#"<div class="notice"><strong>Your new recovery codes.</strong> Save them somewhere safe; they are shown only now, and the old ones no longer work.<ul class="codes">{items}</ul></div>"#
            )
        })
        .unwrap_or_default();
    let code_field = |id: &str, label: &str| {
        format!(
            r#"<label for="{id}">{label}</label><input id="{id}" name="{MFA_CODE}" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" required>"#,
            label = escape(label),
        )
    };
    let mfa = match p.mfa_since {
        None => format!(
            r#"<p>{}</p>{}"#,
            if p.mfa_required {
                "Your organisation requires a second step to sign in. You will set up an authenticator at your next sign-in, or now."
            } else {
                "You sign in with your password alone. An authenticator app adds a second step, asked for at every sign-in once it is set up."
            },
            form(AccountOp::MfaSetup, "", "Set up an authenticator", "")
        ),
        Some(since) => format!(
            r#"<p>Authenticator set up {since}. {left} unused recovery code{s}.</p>
<h3 style="font-size:14px;margin:16px 0 0">New phone</h3><p class="sub">Confirm with a code from your current authenticator, or with a recovery code if you no longer have it.</p>{replace}
<h3 style="font-size:14px;margin:16px 0 0">Recovery codes</h3><p class="sub">New codes replace all of the old ones. Confirm with a code from your authenticator.</p>{codes_form}"#,
            since = escape(since),
            left = p.recovery_codes_left,
            s = if p.recovery_codes_left == 1 { "" } else { "s" },
            replace = form(
                AccountOp::MfaReplace,
                &code_field("replace_code", "Authenticator or recovery code"),
                "Set up a new authenticator",
                "secondary"
            ),
            codes_form = form(
                AccountOp::RecoveryCodes,
                &code_field("codes_code", "Authenticator code"),
                "Get new recovery codes",
                "secondary"
            ),
        ),
    };
    let password = form(
        AccountOp::Password,
        &format!(
            r#"<label for="current_password">Current password</label><input id="current_password" name="{CURRENT_PASSWORD}" type="password" autocomplete="current-password" required>
<label for="new_password">New password</label><input id="new_password" name="{NEW_PASSWORD}" type="password" autocomplete="new-password" required>
<label for="confirm_password">Confirm new password</label><input id="confirm_password" name="{CONFIRM_PASSWORD}" type="password" autocomplete="new-password" required>"#
        ),
        "Change password",
        "",
    );
    let body = format!(
        r#"<h1>My account</h1><p class="sub">{upn}</p>{banner}{codes}
<h2>Profile</h2><dl class="profile">{name}{given}{family}{user}{email}</dl>
<p class="sub">Ask an administrator to change these.</p>
<h2>Password</h2>{password}
<h2>Multi-factor authentication</h2>{mfa}
<h2>Sessions</h2><p>Sign out of every browser and application you are signed in to, this one included.
Browsers you told not to ask for a code again will ask again.</p>{everywhere}"#,
        upn = escape(p.upn),
        name = row("Name", p.display_name),
        given = row("Given name", p.given_name),
        family = row("Family name", p.family_name),
        user = row("User name", Some(p.upn)),
        email = row("Email", p.email),
        everywhere = form(AccountOp::SignOutEverywhere, "", "Sign out everywhere", "secondary"),
    );
    let status = if p.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    respond(status, wide_page("My account", Some(p.tenant_name), &body), CSP_DEFAULT)
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
    let origin = csp_source(action);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_that_may_redirect_to_the_client_lists_its_origin_in_form_action() {
        let uri = url::Url::parse("https://venus.example/.tlsproxy/oidc/callback").unwrap();
        let csp = csp_for_form(Some(&uri));
        assert!(csp.contains("form-action 'self' https://venus.example;"), "{csp}");
        // Only form-action differs from the default policy.
        assert_eq!(csp.replace(" https://venus.example;", ";"), CSP_DEFAULT);
    }

    #[test]
    fn a_page_that_stays_on_this_server_keeps_the_default_policy() {
        assert_eq!(csp_for_form(None), CSP_DEFAULT);
        assert!(CSP_DEFAULT.contains("form-action 'self';"));
    }

    #[test]
    fn a_native_redirect_uri_is_matched_by_its_scheme() {
        let uri = url::Url::parse("msauth.com.example.app://auth").unwrap();
        assert_eq!(csp_source(&uri), "msauth.com.example.app:");
        let uri = url::Url::parse("http://localhost:8400/cb").unwrap();
        assert_eq!(csp_source(&uri), "http://localhost:8400");
    }
}
