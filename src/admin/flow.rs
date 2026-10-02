//! The console's flow tester: the readiness page, the start button, and the
//! callback that reads what came back.
//!
//! The landing page is the feature. Before it offers to run anything it states,
//! item by item, what this application needs for the flow that has been chosen,
//! what is configured now, and what to change -- so "why can I not test this yet"
//! is answered on the page instead of guessed at from an AADSTS number. The form
//! is secondary. [`crate::flowtest`] decides what a requirement is; this module
//! only renders it.
//!
//! Three things about the shape of this section:
//!
//! - **Nothing here changes a registration on its own.** Registering the callback
//!   on an application, and registering this tenant's flow tester client, are two
//!   explicit buttons with their own confirmation text and their own audit rows.
//! - **The callback has no CSRF token**, because an identity provider's
//!   `form_post` cannot carry one. The server-generated `state` does that job: it
//!   is unguessable, it is stored only as a hash, and the row it names is bound to
//!   the console session that created it. A callback that cannot name a pending
//!   row is reported as an error and nothing else happens.
//! - **The result page is the one place tokens are shown.** They are never written
//!   to the audit log, never stored, and the page is `no-store` like every other
//!   console page. The pending row is deleted before the exchange is even made.

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, PlatformTab, TenantTab, audited, checked, chrome, field, optional, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{APP_READ, APP_WRITE};
use crate::apps::{self, Application, RedirectPlatform};
use crate::db::Event;
use crate::flowtest::{
    self, APP_FIELD, DecodedToken, Expected, Finding, Fix, HttpCall, Observation, Outcome, PASSWORD_GRANT_FIELD,
    PLATFORM_FIELD, PROMPT_FIELD, Pending, Probe, RESPONSE_MODE_FIELD, RESPONSE_TYPE_FIELD, Readiness, SCOPE_FIELD,
    Verdict,
};
use crate::rbac::Action;
use crate::routes::audit::Channel;
use crate::routes::{Prompt, ResponseMode, ResponseType};
use crate::tenant::Tenant;
use crate::{session, users};

/// What a post to the flow tester asks for.
///
/// An enum, like [`crate::admin::apps::AppOp`], so a new operation cannot be added
/// without deciding which action authorizes it and which event records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOp {
    /// Send the authorize request.
    Start,
    /// Register the console's callback as a redirect URI of this application.
    AddCallback,
    /// Register this tenant's own flow tester client.
    CreateTestClient,
    /// End this browser's remembered sign-in to the tenant, so the next test
    /// starts from the sign-in page.
    ForgetSignIn,
    /// Re-read the requirements for the settings on screen, running nothing.
    Check,
}

impl FlowOp {
    pub const ALL: &'static [FlowOp] = &[
        Self::Start,
        Self::AddCallback,
        Self::CreateTestClient,
        Self::ForgetSignIn,
        Self::Check,
    ];

    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::AddCallback => "add_callback",
            Self::CreateTestClient => "create_test_client",
            Self::ForgetSignIn => "forget_sign_in",
            Self::Check => "check",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// The action that authorizes it.
    ///
    /// Running a flow is `App:Read`: it changes no configuration, and the tokens it
    /// produces are the ones the person signing in could already get from any
    /// browser -- the authorize endpoint makes them authenticate there, and the
    /// console session is no help at all. The two operations that *do* change a
    /// registration are `App:Write`, like every other registration change.
    fn action(self) -> Action {
        match self {
            // Forgetting a sign-in ends only this browser's own session with the
            // tenant, which the browser could do at the logout endpoint anyway.
            Self::Start | Self::ForgetSignIn | Self::Check => APP_READ,
            Self::AddCallback | Self::CreateTestClient => APP_WRITE,
        }
    }
}

fn flow_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/flow", tenant.id)
}

fn app_url(base: &str, tenant: &Tenant, app_id: &str) -> String {
    format!("{base}/admin/tenants/{}/apps/{app_id}", tenant.id)
}

// ---- the landing page ----

pub async fn page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = ctx.require(APP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let form = parse_form(query.unwrap_or_default().as_bytes());
    landing(&st, &ctx, &headers, tenant, &form, None, StatusCode::OK).await
}

/// The chosen configuration, read back from the query string or from the hidden
/// fields of the form that posted. Everything outside its closed set falls back to
/// the default rather than failing the page: this is a form being filled in.
fn probe_from(form: &Params) -> Probe {
    let response_type = ResponseType::parse(field(form, RESPONSE_TYPE_FIELD)).unwrap_or(ResponseType::Code);
    let response_mode =
        ResponseMode::parse(field(form, RESPONSE_MODE_FIELD)).unwrap_or_else(|| Probe::default_mode(response_type));
    Probe {
        response_type,
        response_mode,
        scope: optional(form, SCOPE_FIELD)
            .unwrap_or(flowtest::DEFAULT_SCOPE)
            .to_string(),
        prompt: Prompt::parse(field(form, PROMPT_FIELD)),
        password_grant: checked(form, PASSWORD_GRANT_FIELD),
    }
}

async fn landing(
    st: &AppState,
    ctx: &AdminContext,
    headers: &HeaderMap,
    tenant: &Tenant,
    form: &Params,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let base = st.public_url.base();
    let url = flow_url(base, tenant);
    let registered = match apps::list(&st.pool, &tenant.id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("flow tester could not list applications: {e}");
            return view::server_error();
        }
    };
    let test_client = flowtest::test_client(&st.pool, &tenant.id).await.unwrap_or_default();
    let may_write = ctx.can_in(APP_WRITE, tenant);
    let callback = flowtest::callback_uri(&st.public_url);
    let probe = probe_from(form);

    // Which application: the one named, else this tenant's flow tester client, else
    // the first registration. Nothing is offered when the tenant has none.
    let chosen = optional(form, APP_FIELD)
        .and_then(|id| registered.iter().find(|a| a.app_id.eq_ignore_ascii_case(id)))
        .or_else(|| {
            test_client
                .as_ref()
                .and_then(|t| registered.iter().find(|a| a.app_id == t.app_id))
        })
        .or(registered.first());
    let Some(app) = chosen else {
        let body = format!(
            r#"<h1>Flow tester</h1><p class="sub">{tenant_name}</p>
<p>There is no application registered in this tenant yet, so there is nothing to sign in to.
Register one in the <a href="{apps}">applications</a> section, or let the console register a
client for testing.</p>{create}"#,
            tenant_name = e(&tenant.name),
            apps = e(&format!("{base}/admin/tenants/{}/apps", tenant.id)),
            create = create_test_client_form(&url, &ctx.csrf, &callback, may_write, None),
        );
        return view::page(
            &chrome(st, ctx, At::Tenant(tenant, TenantTab::Flow)),
            status,
            "Flow tester",
            &body,
        );
    };

    // The assignment requirement is about whoever signs in. The administrator is
    // the likely candidate, so it is checked against their account when their
    // account is in this tenant at all.
    let admin_user_id = (ctx.user.tenant_id == tenant.id).then_some(ctx.user.id.as_str());
    let subject = flowtest::Subject {
        tenant,
        app,
        admin_user_id,
    };
    let readiness = match flowtest::readiness(&st.pool, &st.public_url, &subject, &probe).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("flow tester readiness check failed: {e}");
            return view::server_error();
        }
    };

    let is_test_client = test_client.as_ref().is_some_and(|t| t.app_id == app.app_id);
    let body = format!(
        r#"<h1>Flow tester</h1><p class="sub">{tenant_name} &middot; drive a real sign-in against this server and read what comes back</p>
{error}
<p>Pick an application and a flow. The page says what that combination needs, runs the sign-in
with a server-generated <code>state</code>, <code>nonce</code> and PKCE verifier, and checks what comes back.</p>
{form_html}
{readiness_html}
{run_html}
{sign_in_html}
{callback_html}
{ropc_html}"#,
        tenant_name = e(&tenant.name),
        error = view::error_block(error),
        sign_in_html = sign_in_section(st, headers, tenant, &url, &ctx.csrf, &hidden_probe(app, &probe)).await,
        form_html = config_form(&url, &ctx.csrf, &registered, test_client.as_ref(), app, &probe),
        readiness_html = readiness_table(&readiness, base, tenant, app),
        run_html = run_section(&probe, &readiness, is_test_client),
        callback_html = callback_section(
            &url,
            &ctx.csrf,
            &callback,
            app,
            &readiness,
            may_write,
            test_client.as_ref()
        ),
        ropc_html = ropc_section(st, tenant, app, &probe),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Flow)),
        status,
        "Flow tester",
        &body,
    )
}

/// The configuration form. `method="get"`, so filling it in changes nothing and
/// needs no CSRF token -- and, just as importantly, so the session's token never
/// travels in a URL where a proxy log or a `Referer` header could keep it.
fn config_form(
    url: &str,
    csrf: &str,
    registered: &[Application],
    test_client: Option<&Application>,
    chosen: &Application,
    probe: &Probe,
) -> String {
    let apps: String = registered
        .iter()
        .map(|a| {
            let marker = if test_client.is_some_and(|t| t.app_id == a.app_id) {
                " (flow tester client)"
            } else {
                ""
            };
            format!(
                r#"<option value="{id}"{sel}>{name}{marker} &mdash; {id}</option>"#,
                id = e(&a.app_id),
                name = e(&a.display_name),
                sel = selected(a.app_id == chosen.app_id),
            )
        })
        .collect();
    let response_types: String = ResponseType::ALL
        .iter()
        .map(|rt| {
            format!(
                r#"<option value="{v}"{sel}>{v}</option>"#,
                v = e(rt.as_str()),
                sel = selected(*rt == probe.response_type),
            )
        })
        .collect();
    let response_modes: String = ResponseMode::ALL
        .iter()
        .map(|m| {
            format!(
                r#"<option value="{v}"{sel}>{v}{note}</option>"#,
                v = e(m.as_str()),
                sel = selected(*m == probe.response_mode),
                note = match m {
                    ResponseMode::Query => " &mdash; redirect, codes only",
                    ResponseMode::Fragment => " &mdash; not captured here",
                    ResponseMode::FormPost => " &mdash; posted back, required for tokens",
                },
            )
        })
        .collect();
    let prompts: String = std::iter::once(format!(
        r#"<option value=""{sel}>(not sent)</option>"#,
        sel = selected(probe.prompt.is_none())
    ))
    .chain(Prompt::SUPPORTED.iter().map(|p| {
        format!(
            r#"<option value="{v}"{sel}>{v}</option>"#,
            v = e(p.as_str()),
            sel = selected(probe.prompt == Some(*p)),
        )
    }))
    .collect();
    format!(
        r#"<h2>What to test</h2>
<form id="{CONFIG_FORM_ID}" method="post" action="{url}">{csrf}
<div class="fields">
<div><label for="app">Application</label><select id="app" name="{APP_FIELD}">{apps}</select></div>
<div><label for="scope">Scope</label><input id="scope" name="{SCOPE_FIELD}" type="text" value="{scope}"></div>
<div><label for="response_type">Response type</label><select id="response_type" name="{RESPONSE_TYPE_FIELD}">{response_types}</select></div>
<div><label for="response_mode">Response mode</label><select id="response_mode" name="{RESPONSE_MODE_FIELD}">{response_modes}</select></div>
<div><label for="prompt">Prompt</label><select id="prompt" name="{PROMPT_FIELD}">{prompts}</select></div>
</div>
<p class="muted">Prompt: <code>login</code> forces the sign-in page, <code>select_account</code> the account
picker, and <code>consent</code> the permissions page, even with a remembered sign-in.</p>
<label><input type="checkbox" name="{PASSWORD_GRANT_FIELD}"{ropc}> I am also testing the password grant (ROPC)</label>
<div class="actions"><button class="secondary" type="submit" name="{op_field}" value="{check}">Check this configuration</button></div>
</form>"#,
        url = e(url),
        csrf = view::csrf_input(csrf),
        op_field = FlowOp::FIELD,
        check = FlowOp::Check.as_str(),
        scope = e(&probe.scope),
        ropc = if probe.password_grant { " checked" } else { "" },
    )
}

fn selected(on: bool) -> &'static str {
    if on { " selected" } else { "" }
}

fn verdict_pill(verdict: Verdict) -> String {
    let class = match verdict {
        Verdict::Pass => "pill good",
        Verdict::Fail => "pill bad",
        Verdict::Note => "pill",
    };
    format!(r#"<span class="{class}">{}</span>"#, e(verdict.label()))
}

/// The readiness list: one row per requirement, each reading as met or missing,
/// with the remedy beside it.
fn readiness_table(readiness: &Readiness, base: &str, tenant: &Tenant, app: &Application) -> String {
    let app_page = app_url(base, tenant, &app.app_id);
    let rows: String = readiness.findings.iter().map(|f| finding_row(f, &app_page)).collect();
    let summary = if readiness.ready() {
        "Everything this flow needs is configured.".to_string()
    } else {
        format!(
            "{} of {} requirements are not met, so the flow would be refused before it got anywhere useful.",
            readiness.missing(),
            readiness.findings.len(),
        )
    };
    format!(
        r#"<h2>What this needs</h2><p class="sub">{summary}</p>
<table><tr><th>Requirement</th><th>State</th><th>What is configured, and what to change</th></tr>{rows}</table>
<p class="muted">Everything above is read from <a href="{app_page}">this application's registration</a>
and from the tenant. Nothing on this page changes it.</p>"#,
        summary = e(&summary),
        app_page = e(&app_url(base, tenant, &app.app_id)),
    )
}

fn finding_row(f: &Finding, app_page: &str) -> String {
    // Where to go, as a link when there is a page to link to and as a pointer when
    // the thing to change is on this one.
    let fix = match f.fix {
        Some(Fix::ApplicationPage) => format!(
            r#" <a href="{app_page}">Open the application&#x27;s page</a>."#,
            app_page = e(app_page),
        ),
        Some(Fix::CallbackSection) => " See &ldquo;The callback&rdquo; below.".to_string(),
        Some(Fix::ThisForm) => " Change it in the form above.".to_string(),
        None => String::new(),
    };
    let remedy = f
        .remedy
        .as_deref()
        .map(|r| format!(r#"<p class="muted">{}{fix}</p>"#, e(r)))
        .unwrap_or_default();
    format!(
        r#"<tr{class}><td>{title}</td><td>{pill}</td><td>{detail}{remedy}</td></tr>"#,
        class = if f.verdict == Verdict::Fail {
            r#" class="bad""#
        } else {
            ""
        },
        title = e(f.requirement.title()),
        pill = verdict_pill(f.verdict),
        detail = e(&f.detail),
    )
}

/// The start button, or the reason there is none.
fn run_section(probe: &Probe, readiness: &Readiness, is_test_client: bool) -> String {
    if !readiness.ready() {
        return format!(
            r#"<h2>Run it</h2><p>Not yet: {} of the requirements above are not met. Each one says what to change.</p>"#,
            readiness.missing(),
        );
    }
    let captured = probe.response_mode != ResponseMode::Fragment;
    let (button, note) = if captured {
        (
            "Start the flow",
            "You will be taken to this server's sign-in page. Sign in as the user you want to test with \
             -- your console session is no help there, as it should not be -- and the response comes back \
             to the console's callback, where it is checked and shown to you.",
        )
    } else {
        (
            "Show the authorize URL",
            "Fragment mode is not captured server-side: a URL fragment never leaves the browser. \
             The console will show you the URL to open, and the response stays in your address bar.",
        )
    };
    let client_note = if is_test_client {
        r#"<p class="muted">This is the tenant's flow tester client, so nothing you do here touches a real
application's registration.</p>"#
    } else {
        r#"<p class="muted">This is a real application registration. Running a flow does not change it;
it does sign a user in, and that sign-in is recorded in the audit log as any other would be.</p>"#
    };
    format!(
        // The button belongs to the settings form above (the `form` attribute), so it
        // runs what is selected on screen *now*. It used to be a form of its own
        // carrying the last-checked settings in hidden fields, so changing a setting
        // and pressing Start silently ran the old one.
        r#"<h2>Run it</h2>
<p>{note}</p>{client_note}
<p class="muted">This runs the settings as they are shown above right now, whether or not you
pressed Check since changing them.</p>
<div class="actions"><button type="submit" form="{CONFIG_FORM_ID}" name="{field}" value="{op}">{button}</button></div>"#,
        field = FlowOp::FIELD,
        op = FlowOp::Start.as_str(),
        note = e(note),
        button = e(button),
    )
}

/// The chosen configuration, carried into the post that acts on it, so the post
/// runs what the page described rather than a default.
fn hidden_probe(app: &Application, probe: &Probe) -> String {
    let mut out = format!(
        r#"<input type="hidden" name="{APP_FIELD}" value="{app}">
<input type="hidden" name="{RESPONSE_TYPE_FIELD}" value="{rt}">
<input type="hidden" name="{RESPONSE_MODE_FIELD}" value="{rm}">
<input type="hidden" name="{SCOPE_FIELD}" value="{scope}">"#,
        app = e(&app.app_id),
        rt = e(probe.response_type.as_str()),
        rm = e(probe.response_mode.as_str()),
        scope = e(&probe.scope),
    );
    if let Some(prompt) = probe.prompt {
        out.push_str(&format!(
            r#"<input type="hidden" name="{PROMPT_FIELD}" value="{}">"#,
            e(prompt.as_str())
        ));
    }
    if probe.password_grant {
        out.push_str(&format!(
            r#"<input type="hidden" name="{PASSWORD_GRANT_FIELD}" value="on">"#
        ));
    }
    out
}

/// The callback, the exact string that has to be registered, and the two explicit
/// ways to get there.
fn callback_section(
    url: &str,
    csrf: &str,
    callback: &str,
    app: &Application,
    readiness: &Readiness,
    may_write: bool,
    test_client: Option<&Application>,
) -> String {
    let state = match readiness.platform {
        Some(p) => format!("Registered on {} under platform {}.", app.display_name, p.as_str()),
        None => format!("Not registered on {} yet.", app.display_name),
    };
    let add = if readiness.platform.is_some() {
        String::new()
    } else if may_write {
        format!(
            r#"<form method="post" action="{url}">{csrf}
<input type="hidden" name="{APP_FIELD}" value="{app_id}">
<input type="hidden" name="{field}" value="{op}">
{platform}
<div class="actions"><button type="submit">Add this callback to {name}</button></div>
<p class="muted">This adds a redirect URI to a real application registration. It is recorded in the
audit log as a redirect URI addition, and it appears in the application's own page, where it can be
removed again.</p></form>"#,
            url = e(url),
            csrf = view::csrf_input(csrf),
            app_id = e(&app.app_id),
            field = FlowOp::FIELD,
            op = FlowOp::AddCallback.as_str(),
            platform = platform_select(),
            name = e(&app.display_name),
        )
    } else {
        r#"<p class="muted">Your roles allow reading this application but not adding a redirect URI to it.</p>"#
            .to_string()
    };
    format!(
        r#"<h2>The callback</h2>
<p>Exactly this URI has to be one of the application's redirect URIs. It is the console's own
callback, and it is the same for every application and every tenant on this deployment.</p>
<code class="once">{callback}</code>
<p class="muted">{state}</p>{add}{create}"#,
        callback = e(callback),
        state = e(&state),
        create = create_test_client_form(url, csrf, callback, may_write, test_client),
    )
}

/// A `<select>` over the closed set, so the form cannot submit a platform the
/// parse would refuse.
fn platform_select() -> String {
    let options: String = RedirectPlatform::ALL
        .iter()
        .map(|p| {
            format!(
                r#"<option value="{v}"{sel}>{v}</option>"#,
                v = e(p.as_str()),
                // publicClient first in effect: it is the one the console can
                // complete a token exchange for.
                sel = selected(*p == RedirectPlatform::PublicClient),
            )
        })
        .collect();
    format!(
        r#"<label for="callback_platform">Register it under platform</label>
<select id="callback_platform" name="{PLATFORM_FIELD}">{options}</select>"#
    )
}

fn create_test_client_form(
    url: &str,
    csrf: &str,
    callback: &str,
    may_write: bool,
    test_client: Option<&Application>,
) -> String {
    if let Some(existing) = test_client {
        return format!(
            r#"<p class="muted">This tenant already has a flow tester client: {name} ({id}).</p>"#,
            name = e(&existing.display_name),
            id = e(&existing.app_id),
        );
    }
    if !may_write {
        return String::new();
    }
    format!(
        r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">
<div class="actions"><button class="secondary" type="submit">Create a flow tester client for this tenant</button></div>
<p class="muted">Registers one application, named &ldquo;{name}&rdquo;, whose only redirect URI is
<code>{callback}</code>, as a public client so that no secret exists to be needed. That is the
zero-side-effect way to exercise this server: nothing about a real application's registration
changes. It is an ordinary registration and can be deleted in the applications section.</p></form>"#,
        url = e(url),
        csrf = view::csrf_input(csrf),
        field = FlowOp::FIELD,
        op = FlowOp::CreateTestClient.as_str(),
        name = e(flowtest::TEST_CLIENT_NAME),
        callback = e(callback),
    )
}

/// The settings form. The Start button lives further down the page and belongs to
/// this form by id, so there is one set of settings and no hidden copy of them.
const CONFIG_FORM_ID: &str = "flow-config";

/// What the printed `export` line holds until the administrator replaces it.
const SECRET_PLACEHOLDER: &str = "<your-secret>";
/// Variables the printed password-grant command reads the user's credentials from.
const ROPC_USERNAME_VAR: &str = "ROPC_USERNAME";
const ROPC_PASSWORD_VAR: &str = "ROPC_PASSWORD";

/// A value in a printed curl command: either written out, or read from an
/// environment variable the administrator sets first.
enum CurlValue<'a> {
    Literal(&'a str),
    Env(&'a str),
}

/// Quote a value for a POSIX shell. Single quotes take everything literally, so
/// the only character needing care is the single quote itself. This matters: the
/// command is meant to be pasted and run, so a value that escaped its quotes would
/// run as shell.
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The environment variable a printed command reads this application's secret
/// from, named after the application: `Hello World` gives `HELLO_WORLD_SECRET`.
fn secret_env_var(display_name: &str) -> String {
    let mut name = String::new();
    for c in display_name.chars() {
        if c.is_ascii_alphanumeric() {
            name.push(c.to_ascii_uppercase());
        } else if !name.is_empty() && !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name.trim_end_matches('_');
    match name.chars().next() {
        None => "CLIENT_SECRET".to_string(),
        // A shell variable cannot begin with a digit.
        Some(c) if c.is_ascii_digit() => format!("APP_{name}_SECRET"),
        Some(_) => format!("{name}_SECRET"),
    }
}

/// A token request as a curl command that runs as pasted. Values the console
/// knows are written out; anything secret is read from an environment variable,
/// with the `export` lines to fill in printed above the command.
fn curl_command(endpoint: &str, fields: &[(&str, CurlValue<'_>)], exports: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (var, placeholder) in exports {
        out.push_str(&format!("export {var}={}\n", sh_quote(placeholder)));
    }
    if !exports.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("curl -sS {}", sh_quote(endpoint)));
    for (name, value) in fields {
        let arg = match value {
            CurlValue::Literal(v) => sh_quote(&format!("{name}={v}")),
            // Double quotes so the shell substitutes the variable, and nothing else:
            // the name is ours and the variable name is restricted to [A-Z0-9_].
            CurlValue::Env(var) => format!("\"{name}=${var}\""),
        };
        out.push_str(&format!(" \\\n  --data-urlencode {arg}"));
    }
    out.push('\n');
    out
}

/// The password grant, which the console deliberately does not run: it would have
/// to hold a client secret it cannot read and collect a user's password, which it
/// will not do. So it shows the request instead.
fn ropc_section(st: &AppState, tenant: &Tenant, app: &Application, probe: &Probe) -> String {
    if !probe.password_grant {
        return String::new();
    }
    let endpoint = st.public_url.tenant_url(&tenant.id, "oauth2/v2.0/token");
    let secret_var = secret_env_var(&app.display_name);
    let request = curl_command(
        &endpoint,
        &[
            (
                "grant_type",
                CurlValue::Literal(crate::routes::GrantType::Password.as_str()),
            ),
            ("client_id", CurlValue::Literal(&app.app_id)),
            ("scope", CurlValue::Literal(&probe.scope)),
            ("username", CurlValue::Env(ROPC_USERNAME_VAR)),
            ("password", CurlValue::Env(ROPC_PASSWORD_VAR)),
            ("client_secret", CurlValue::Env(&secret_var)),
        ],
        &[
            (&secret_var, SECRET_PLACEHOLDER),
            (ROPC_USERNAME_VAR, "<user-upn>"),
            (ROPC_PASSWORD_VAR, "<user-password>"),
        ],
    );
    format!(
        r#"<h2>The password grant</h2>
<p>The console does not run this one. It would have to send the client secret, which it cannot read
because only a SHA-256 hash of it is stored, and a user's password, which it will not ask you to
type into an administration page. The command is here to run yourself: fill in the three
<code>export</code> lines and paste it. The requirement above tells you whether this application
would accept it.</p>
<pre class="raw">{request}</pre>"#,
        request = e(&request),
    )
}

// ---- the posts ----

pub async fn post(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Some(op) = FlowOp::parse(field(&form, FlowOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    if let Err(resp) = ctx.require(op.action(), On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    match op {
        FlowOp::CreateTestClient => create_test_client(&st, &ctx, &headers, tenant, &form).await,
        FlowOp::AddCallback => add_callback(&st, &ctx, &headers, tenant, &form).await,
        FlowOp::Start => start(&st, &ctx, tenant, &form).await,
        FlowOp::ForgetSignIn => forget_sign_in(&st, &ctx, &headers, tenant, &form).await,
        // Back to the page with these settings in its address, where the readiness
        // check is a plain GET that can be reloaded and bookmarked.
        FlowOp::Check => view::see_other(&with_probe(&flow_url(st.public_url.base(), tenant), &form)),
    }
}

async fn create_test_client(
    st: &AppState,
    ctx: &AdminContext,
    headers: &HeaderMap,
    tenant: &Tenant,
    form: &Params,
) -> Response {
    // A mapping left behind by a deleted application would otherwise block this.
    if flowtest::test_client(&st.pool, &tenant.id)
        .await
        .unwrap_or_default()
        .is_none()
        && let Err(e) = flowtest::forget_test_client(&st.pool, &tenant.id).await
    {
        tracing::error!("flow tester client mapping could not be cleared: {e}");
        return view::server_error();
    }
    match flowtest::create_test_client(&st.pool, &st.public_url, tenant).await {
        Ok(app) => {
            // The ordinary events: this is an application registration and a
            // redirect URI, and an auditor filtering for either must see it.
            audited(
                st,
                ctx,
                &tenant.id,
                Event::AdminAppCreate,
                Some(&app.app_id),
                json!({ "displayName": crate::routes::audit::clip(&app.display_name), "purpose": flowtest::PURPOSE }),
            )
            .await;
            audited(
                st,
                ctx,
                &tenant.id,
                Event::AdminAppRedirectUriAdd,
                Some(&app.app_id),
                json!({
                    "platform": RedirectPlatform::PublicClient.as_str(),
                    "uri": crate::routes::audit::clip(&flowtest::callback_uri(&st.public_url)),
                    "purpose": flowtest::PURPOSE,
                }),
            )
            .await;
            let base = st.public_url.base();
            view::see_other(&format!("{}?{APP_FIELD}={}", flow_url(base, tenant), app.app_id))
        }
        Err(e) => {
            let message = e.to_string();
            landing(st, ctx, headers, tenant, form, Some(&message), StatusCode::BAD_REQUEST).await
        }
    }
}

async fn add_callback(
    st: &AppState,
    ctx: &AdminContext,
    headers: &HeaderMap,
    tenant: &Tenant,
    form: &Params,
) -> Response {
    let Some(platform) = RedirectPlatform::parse(field(form, PLATFORM_FIELD)) else {
        return landing(
            st,
            ctx,
            headers,
            tenant,
            form,
            Some("Choose a platform."),
            StatusCode::BAD_REQUEST,
        )
        .await;
    };
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, field(form, APP_FIELD)).await else {
        return view::not_found();
    };
    let callback = flowtest::callback_uri(&st.public_url);
    match apps::add_redirect_uri(&st.pool, &app, platform, &callback).await {
        Ok(()) => {
            audited(
                st,
                ctx,
                &tenant.id,
                Event::AdminAppRedirectUriAdd,
                Some(&app.app_id),
                json!({
                    "platform": platform.as_str(),
                    "uri": crate::routes::audit::clip(&callback),
                    "purpose": flowtest::PURPOSE,
                }),
            )
            .await;
            view::see_other(&with_probe(&flow_url(st.public_url.base(), tenant), form))
        }
        Err(e) => {
            let message = e.to_string();
            landing(st, ctx, headers, tenant, form, Some(&message), StatusCode::BAD_REQUEST).await
        }
    }
}

/// Carry the configuration back into the redirect after a post, so the page the
/// administrator returns to is the one they were on.
/// End this browser's sign-in to the tenant. The authorize endpoint remembers a
/// sign-in, as it should, so a second flow test goes straight through without
/// asking for a password; this is how the administrator gets the sign-in page back.
async fn forget_sign_in(
    st: &AppState,
    ctx: &AdminContext,
    headers: &HeaderMap,
    tenant: &Tenant,
    form: &Params,
) -> Response {
    let found = match session::find(&st.pool, headers, &tenant.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("flow tester could not read the browser session: {e}");
            return view::server_error();
        }
    };
    if let Err(e) = session::end(&st.pool, headers, &tenant.id).await {
        tracing::error!("flow tester could not end the browser session: {e}");
        return view::server_error();
    }
    // Only a session that existed is an event, as at the logout endpoint.
    if let Some(s) = found {
        audited(
            st,
            ctx,
            &tenant.id,
            Event::SessionEnd,
            Some(&s.user_id),
            json!({ "via": Channel::Console.as_str(), "purpose": flowtest::PURPOSE }),
        )
        .await;
    }
    view::see_other(&with_probe(&flow_url(st.public_url.base(), tenant), form))
}

/// Whether this browser is signed in to the tenant, and the button that ends it.
///
/// Stated on the page because it decides what the next test looks like: with a
/// remembered sign-in the authorize endpoint answers at once, without one it shows
/// the sign-in page.
async fn sign_in_section(
    st: &AppState,
    headers: &HeaderMap,
    tenant: &Tenant,
    url: &str,
    csrf: &str,
    hidden: &str,
) -> String {
    let Ok(Some(s)) = session::find(&st.pool, headers, &tenant.id).await else {
        return r#"<h2>Sign-in</h2><p class="muted">This browser has no sign-in remembered for this tenant, so the next
test starts at the sign-in page.</p>"#
            .to_string();
    };
    let who = match users::find(&st.pool, &tenant.id, &s.user_id).await {
        Ok(Some(u)) => u.upn,
        _ => s.user_id.clone(),
    };
    format!(
        r#"<h2>Sign-in</h2>
<p>This browser is signed in to this tenant as <strong>{who}</strong>, so the next test will go
straight through without asking for a password. Forget the sign-in to test from the sign-in page
again.</p>
<form method="post" action="{url}">{csrf}{hidden}
<input type="hidden" name="{op_field}" value="{op}">
<div class="actions"><button class="secondary" type="submit">Forget this sign-in</button></div></form>"#,
        who = e(&who),
        url = e(url),
        csrf = view::csrf_input(csrf),
        op_field = FlowOp::FIELD,
        op = FlowOp::ForgetSignIn.as_str(),
    )
}

fn with_probe(url: &str, form: &Params) -> String {
    let probe = probe_from(form);
    let mut out = url::Url::parse(url).expect("a console URL parses");
    {
        let mut q = out.query_pairs_mut();
        if let Some(app) = optional(form, APP_FIELD) {
            q.append_pair(APP_FIELD, app);
        }
        q.append_pair(RESPONSE_TYPE_FIELD, probe.response_type.as_str());
        q.append_pair(RESPONSE_MODE_FIELD, probe.response_mode.as_str());
        q.append_pair(SCOPE_FIELD, &probe.scope);
        if let Some(prompt) = probe.prompt {
            q.append_pair(PROMPT_FIELD, prompt.as_str());
        }
        if probe.password_grant {
            q.append_pair(PASSWORD_GRANT_FIELD, "on");
        }
    }
    out.into()
}

async fn start(st: &AppState, ctx: &AdminContext, tenant: &Tenant, form: &Params) -> Response {
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, field(form, APP_FIELD)).await else {
        return view::not_found();
    };
    let probe = probe_from(form);
    let details = |captured: bool| {
        json!({
            "responseType": probe.response_type.as_str(),
            "responseMode": probe.response_mode.as_str(),
            "scope": crate::routes::audit::clip(&probe.scope),
            "captured": captured,
        })
    };
    // Fragment mode is never captured here, so there is nothing to remember and no
    // row to write: the administrator opens the URL themselves.
    if probe.response_mode == ResponseMode::Fragment {
        let built = flowtest::build_request(&st.public_url, tenant, &app.app_id, &probe);
        audited(
            st,
            ctx,
            &tenant.id,
            Event::AdminFlowTestStart,
            Some(&app.app_id),
            details(false),
        )
        .await;
        return fragment_page(st, ctx, tenant, &app, &built.authorize_url);
    }
    match flowtest::start(&st.pool, &st.public_url, tenant, &app.app_id, &probe, &ctx.cookie_hash).await {
        Ok(started) => {
            audited(
                st,
                ctx,
                &tenant.id,
                Event::AdminFlowTestStart,
                Some(&app.app_id),
                details(true),
            )
            .await;
            // 303 to our own authorize endpoint: from here on it is an ordinary
            // sign-in, driven by the browser exactly as a client's would be.
            view::see_other(&started.authorize_url)
        }
        Err(e) => {
            tracing::error!("flow test could not be started: {e}");
            view::server_error()
        }
    }
}

/// Fragment mode: the URL to open, and why the console cannot read the answer.
fn fragment_page(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    app: &Application,
    authorize_url: &str,
) -> Response {
    let body = format!(
        r#"<h1>Open this yourself</h1><p class="sub">{name} in {tenant_name} &middot; response_mode=fragment</p>
<p>A URL fragment never reaches the server, and the console's content security policy is
<code>default-src 'none'</code> with no script, so there is nothing here that could copy
<code>location.hash</code> into a form. Open this URL in a browser and read the response from your
address bar. Nothing was stored, so nothing will be checked for you.</p>
<pre class="raw">{url}</pre>
<p class="muted">Choose <code>form_post</code> on the previous page to have the values arrive here
and be checked instead.</p>
<div class="actions"><a href="{back}">Back to the flow tester</a></div>"#,
        name = e(&app.display_name),
        tenant_name = e(&tenant.name),
        url = e(authorize_url),
        back = e(&flow_url(st.public_url.base(), tenant)),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Flow)),
        StatusCode::OK,
        "Flow tester",
        &body,
    )
}

// ---- the callback ----

/// Where the authorize response comes back. `GET` for `response_mode=query`,
/// `POST` for `form_post`.
///
/// Behind [`AdminContext`] like every other console page, and then behind the
/// pending row, which is bound to this console session and to a tenant this
/// administrator must still be permitted to read.
pub async fn callback(
    ctx: AdminContext,
    State(st): State<AppState>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw = if method == Method::POST {
        body.to_vec()
    } else {
        query.unwrap_or_default().into_bytes()
    };
    let params = parse_form(&raw);
    let state = field(&params, "state");
    let pending = match flowtest::take(&st.pool, &ctx.cookie_hash, state).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            audited(
                &st,
                &ctx,
                &ctx.home_tenant.id,
                Event::AdminFlowTestResult,
                None,
                json!({ "outcome": Outcome::StateUnknown.as_str() }),
            )
            .await;
            return state_mismatch(&st, &ctx, method == Method::POST);
        }
        Err(e) => {
            tracing::error!("pending flow test could not be read: {e}");
            return view::server_error();
        }
    };

    // The pending row names the tenant; the guard still decides. A row created
    // under one administrator's session cannot be completed by another's, and a
    // tenant this administrator may no longer read is refused here even though the
    // flow was theirs.
    let tenant = match crate::tenant::resolve(&st.pool, &pending.tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return view::not_found(),
        Err(e) => {
            tracing::error!("flow test tenant lookup failed: {e}");
            return view::server_error();
        }
    };
    if !ctx.can_in(APP_READ, &tenant) {
        return view::forbidden();
    }
    let Ok(app) = apps::find_in_tenant(&st.pool, &tenant, &pending.client_app_id).await else {
        return view::not_found();
    };

    let result = assemble(&st, &tenant, &app, &pending, &params, method == Method::POST).await;
    audited(
        &st,
        &ctx,
        &tenant.id,
        Event::AdminFlowTestResult,
        Some(&app.app_id),
        json!({
            "responseType": pending.response_type.as_str(),
            "responseMode": pending.response_mode.as_str(),
            "outcome": result.outcome.as_str(),
            "checksFailed": result.failed(),
        }),
    )
    .await;
    // The test just signed someone in, so say so and offer to undo it: otherwise
    // the next test silently reuses this sign-in.
    let again = Probe {
        response_type: pending.response_type,
        response_mode: pending.response_mode,
        scope: pending.scope.clone(),
        prompt: None,
        password_grant: false,
    };
    let sign_in_html = sign_in_section(
        &st,
        &headers,
        &tenant,
        &flow_url(st.public_url.base(), &tenant),
        &ctx.csrf,
        &hidden_probe(&app, &again),
    )
    .await;
    result_page(&st, &ctx, &tenant, &app, &pending, &result, &sign_in_html)
}

fn state_mismatch(st: &AppState, ctx: &AdminContext, posted: bool) -> Response {
    let how = if posted { "form body" } else { "query string" };
    let body = format!(
        r#"<h1>That response does not match a flow test</h1>
<p class="sub">The <code>state</code> in the {how} names no flow test that this console session started
and that has not expired.</p>
<p>This is reported rather than ignored, because <code>state</code> is the only thing binding a
response to the request that asked for it. The three ways to see this: the flow test was started
more than {minutes} minutes ago, it was already answered once (each one is single use), or the
response was not produced by a request this session made at all.</p>
<div class="actions"><a href="{back}">Back to the flow tester</a></div>"#,
        minutes = flowtest::PENDING_LIFETIME_SECS / 60,
        back = e(&flow_url(st.public_url.base(), ctx.default_tenant())),
    );
    // The state matched no pending test, so there is no tenant to show: this page
    // sits at the platform level, where the way back is the list of tenants.
    view::page(
        &chrome(st, ctx, At::Platform(PlatformTab::Tenants)),
        StatusCode::BAD_REQUEST,
        "Flow test result",
        &body,
    )
}

// ---- putting the result together ----

/// Everything the result page shows, gathered before any of it is rendered.
struct FlowResult {
    outcome: Outcome,
    /// How the response arrived.
    posted: bool,
    /// The parameters that came back, in a stable order.
    params: Vec<(String, String)>,
    error: Option<String>,
    code: Option<String>,
    /// The token request, when one was made.
    exchange: Option<HttpCall>,
    /// Why no exchange was attempted, when none was.
    no_exchange: Option<String>,
    /// Every token this flow produced, in the order they arrived. A hybrid flow
    /// produces two ID tokens -- one in the front channel, carrying `c_hash`, and
    /// one from the token endpoint -- and both are shown: collapsing them would
    /// throw away the only check that binds the code to the ID token.
    tokens: Vec<TokenView>,
}

impl FlowResult {
    fn failed(&self) -> usize {
        self.tokens
            .iter()
            .flat_map(|t| &t.observations)
            .filter(|o| o.verdict == Verdict::Fail)
            .count()
    }

    fn checks(&self) -> usize {
        self.tokens.iter().map(|t| t.observations.len()).sum()
    }
}

/// One token, taken apart.
struct TokenView {
    kind: TokenKind,
    /// Where it came from, for the heading.
    source: TokenSource,
    header: String,
    claims: String,
    observations: Vec<Observation>,
    /// Set when the value is not a JWT we could take apart at all.
    undecodable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    IdToken,
    AccessToken,
}

impl TokenKind {
    fn title(self) -> &'static str {
        match self {
            Self::IdToken => "ID token",
            Self::AccessToken => "Access token",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSource {
    FrontChannel,
    TokenEndpoint,
}

impl TokenSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::FrontChannel => "delivered in the authorize response",
            Self::TokenEndpoint => "returned by the token endpoint",
        }
    }
}

async fn assemble(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    pending: &Pending,
    params: &Params,
    posted: bool,
) -> FlowResult {
    let mut ordered: Vec<(String, String)> = params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    ordered.sort();
    let value = |name: &str| params.get(name).cloned().filter(|v| !v.is_empty());
    let error = value("error");
    let code = value("code");
    let front_id_token = value("id_token");
    let front_access_token = value("access_token");
    let issuer = st.public_url.issuer(&tenant.id);

    let mut result = FlowResult {
        outcome: Outcome::FrontChannelOnly,
        posted,
        params: ordered,
        error: error.clone(),
        code: code.clone(),
        exchange: None,
        no_exchange: None,
        tokens: Vec::new(),
    };
    if error.is_some() {
        result.outcome = Outcome::AuthorizeError;
        return result;
    }

    // The front channel first: an ID token delivered here is bound to the request
    // by `nonce`, and to the rest of this response by `c_hash` and `at_hash`.
    if let Some(token) = &front_id_token {
        let expected = Expected {
            issuer: &issuer,
            audience: &app.app_id,
            nonce: Some(&pending.nonce),
            code: code.as_deref(),
            access_token: front_access_token.as_deref(),
        };
        result
            .tokens
            .push(view_id_token(st, token, &expected, TokenSource::FrontChannel).await);
    }
    if let Some(token) = &front_access_token {
        result
            .tokens
            .push(view_access_token(st, tenant, token, &issuer, &pending.scope, TokenSource::FrontChannel).await);
    }

    // Then the code, if there is one and we can authenticate as this client.
    let Some(code) = code else { return result };
    let platform = apps::match_redirect_uri(&st.pool, app, &pending.redirect_uri)
        .await
        .unwrap_or_default();
    let Some(platform) = platform else {
        result.no_exchange = Some(
            "The redirect URI this flow used is no longer registered on the application, so the token \
             endpoint would refuse the redemption."
                .into(),
        );
        return result;
    };
    if platform == RedirectPlatform::Web {
        result.no_exchange = Some(format!(
            "{} is a web client, which has to authenticate at the token endpoint. The console cannot: \
             only a SHA-256 hash of the client secret is stored. The request to make is shown below; \
             the code is in the response above.",
            app.display_name,
        ));
        return result;
    }
    let call = flowtest::exchange(&st.public_url, pending, &code, platform).await;
    let body = call.json();
    result.outcome = match (call.status, &body) {
        (Some(200), Some(_)) => Outcome::Exchanged,
        _ => Outcome::ExchangeFailed,
    };
    if let Some(body) = &body {
        if let Some(token) = body.get("id_token").and_then(Value::as_str) {
            let expected = Expected {
                issuer: &issuer,
                audience: &app.app_id,
                nonce: Some(&pending.nonce),
                // Neither hash claim belongs on a token fetched from the token
                // endpoint: nothing else travelled with it.
                code: None,
                access_token: None,
            };
            result
                .tokens
                .push(view_id_token(st, token, &expected, TokenSource::TokenEndpoint).await);
        }
        if let Some(token) = body.get("access_token").and_then(Value::as_str) {
            result
                .tokens
                .push(view_access_token(st, tenant, token, &issuer, &pending.scope, TokenSource::TokenEndpoint).await);
        }
    }
    result.exchange = Some(call);
    result
}

async fn decode(st: &AppState, token: &str) -> Result<DecodedToken, String> {
    let (header, claims) = flowtest::decode_parts(token).map_err(|e| e.to_string())?;
    // Ignoring expiry deliberately: an expired token's signature is still either
    // right or wrong, and `exp` is a check of its own.
    let signature = st
        .keys
        .verify_ignoring_expiry(token)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    Ok(DecodedToken {
        header,
        claims,
        signature,
    })
}

async fn view_id_token(st: &AppState, token: &str, expected: &Expected<'_>, source: TokenSource) -> TokenView {
    match decode(st, token).await {
        Ok(decoded) => {
            let observations = flowtest::check_id_token(&decoded, expected);
            TokenView {
                kind: TokenKind::IdToken,
                source,
                header: pretty(&decoded.header),
                claims: pretty(&decoded.claims),
                observations,
                undecodable: None,
            }
        }
        Err(e) => undecodable(TokenKind::IdToken, source, e),
    }
}

async fn view_access_token(
    st: &AppState,
    tenant: &Tenant,
    token: &str,
    issuer: &str,
    scope: &str,
    source: TokenSource,
) -> TokenView {
    // The audience is whatever resource the scope named, resolved the same way the
    // token endpoint resolves it.
    let audience = crate::scopes::resolve(&st.pool, tenant, scope)
        .await
        .ok()
        .map(|g| g.resource.audience().to_string());
    match decode(st, token).await {
        Ok(decoded) => {
            let observations = flowtest::check_access_token(&decoded, issuer, audience.as_deref());
            TokenView {
                kind: TokenKind::AccessToken,
                source,
                header: pretty(&decoded.header),
                claims: pretty(&decoded.claims),
                observations,
                undecodable: None,
            }
        }
        Err(e) => undecodable(TokenKind::AccessToken, source, e),
    }
}

fn undecodable(kind: TokenKind, source: TokenSource, why: String) -> TokenView {
    TokenView {
        kind,
        source,
        header: String::new(),
        claims: String::new(),
        observations: Vec::new(),
        undecodable: Some(why),
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

// ---- the result page ----

fn result_page(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    app: &Application,
    pending: &Pending,
    result: &FlowResult,
    sign_in_html: &str,
) -> Response {
    let failed = result.failed();
    let banner = if let Some(error) = &result.error {
        let description = result
            .params
            .iter()
            .find(|(k, _)| k == "error_description")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!(
            r#"<div class="banner bad"><span><strong>The authorize request was refused: {error}.</strong><br>{description}</span></div>"#,
            error = e(error),
            description = e(&description),
        )
    } else if failed > 0 {
        format!(
            r#"<div class="banner bad"><span><strong>{failed} of {total} checks failed.</strong> Each failure is marked below.</span></div>"#,
            total = result.checks(),
        )
    } else if result.checks() > 0 {
        format!(
            r#"<div class="banner"><span><strong>All {total} checks passed.</strong></span></div>"#,
            total = result.checks(),
        )
    } else {
        String::new()
    };

    let arrival = if result.posted {
        "posted back as a form body"
    } else {
        "returned as a query string on a redirect"
    };
    let rows: String = result
        .params
        .iter()
        .map(|(k, v)| {
            format!(
                r#"<tr><td>{k}</td><td><code class="wrap">{v}</code></td></tr>"#,
                k = e(k),
                v = e(v),
            )
        })
        .collect();

    let exchange = match (&result.exchange, &result.no_exchange) {
        (Some(call), _) => exchange_section(call),
        (None, Some(why)) => format!(
            r#"<h2>The token request</h2><p>{why}</p>{manual}"#,
            why = e(why),
            manual = manual_request(st, app, pending, result),
        ),
        (None, None) => r#"<h2>The token request</h2><p class="muted">There was no code to redeem: this
response type delivers everything in the front channel.</p>"#
            .to_string(),
    };

    let body = format!(
        r#"<h1>Flow test result</h1>
<p class="sub">{name} in {tenant_name} &middot; response_type={rt} &middot; response_mode={rm}</p>
{banner}
<h2>The authorize request</h2>
<p class="muted">Sent with a <code>state</code>, a <code>nonce</code> and a PKCE verifier this server
generated and held; everything below is checked against them.</p>
<pre class="raw">{authorize}</pre>
<h2>What came back</h2>
<p class="muted">{arrival} to <code>{callback}</code>.</p>
<table><tr><th>Parameter</th><th>Value</th></tr>{rows}</table>
{exchange}
{tokens}
{sign_in_html}
<div class="actions"><a href="{back}">Run another flow test</a></div>"#,
        name = e(&app.display_name),
        tenant_name = e(&tenant.name),
        rt = e(pending.response_type.as_str()),
        rm = e(pending.response_mode.as_str()),
        authorize = e(&pending.authorize_url),
        callback = e(flowtest::CALLBACK_PATH),
        tokens = result.tokens.iter().map(token_section).collect::<String>(),
        back = e(&flow_url(st.public_url.base(), tenant)),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Flow)),
        StatusCode::OK,
        "Flow test result",
        &body,
    )
}

fn exchange_section(call: &HttpCall) -> String {
    let headers: String = call.headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
    let request = format!("{} {}\n{}\n{}", flowtest::TOKEN_METHOD, call.url, headers, call.body);
    let response = match (&call.transport_error, call.status) {
        (Some(err), _) => format!(r#"<p class="error">The request never got an answer: {}</p>"#, e(err)),
        (None, Some(status)) => {
            let body = call
                .json()
                .map(|v| pretty(&v))
                .unwrap_or_else(|| call.response.clone().unwrap_or_default());
            format!(
                r#"<p class="muted">HTTP {status}</p><pre class="raw">{body}</pre>"#,
                body = e(&body),
            )
        }
        (None, None) => String::new(),
    };
    format!(
        r#"<h2>The token request</h2>
<p class="muted">A real HTTP request to this server's own token endpoint, so what is shown is what a
client would have sent.</p>
<pre class="raw">{request}</pre>
<h2>The token response</h2>{response}"#,
        request = e(&request),
    )
}

/// The request the administrator has to make themselves, when the console cannot:
/// a curl command that runs as pasted once the secret's `export` line is filled in.
fn manual_request(st: &AppState, app: &Application, pending: &Pending, result: &FlowResult) -> String {
    let Some(code) = &result.code else {
        return String::new();
    };
    let secret_var = secret_env_var(&app.display_name);
    let endpoint = st.public_url.tenant_url(&pending.tenant_id, "oauth2/v2.0/token");
    let mut fields = vec![
        (
            "grant_type",
            CurlValue::Literal(crate::routes::GrantType::AuthorizationCode.as_str()),
        ),
        ("client_id", CurlValue::Literal(&pending.client_app_id)),
        ("code", CurlValue::Literal(code)),
        ("redirect_uri", CurlValue::Literal(&pending.redirect_uri)),
        ("scope", CurlValue::Literal(&pending.scope)),
    ];
    if let Some(verifier) = &pending.code_verifier {
        fields.push(("code_verifier", CurlValue::Literal(verifier)));
    }
    fields.push(("client_secret", CurlValue::Env(&secret_var)));
    let request = curl_command(&endpoint, &fields, &[(&secret_var, SECRET_PLACEHOLDER)]);
    format!(
        r#"<p>Put the application's secret in the <code>export</code> line, then paste both into a
terminal.</p>
<pre class="raw">{request}</pre>
<p class="muted">The code is single use and expires in ten minutes.</p>"#,
        request = e(&request),
    )
}

fn token_section(view: &TokenView) -> String {
    let heading = format!("{} &mdash; {}", e(view.kind.title()), e(view.source.as_str()));
    if let Some(why) = &view.undecodable {
        return format!(
            r#"<h2>{heading}</h2><p class="error">This value could not be read as a JWT: {why}</p>"#,
            why = e(why),
        );
    }
    let checks: String = view
        .observations
        .iter()
        .map(|o| {
            format!(
                r#"<tr{class}><td>{title}</td><td>{pill}</td><td><code class="wrap">{detail}</code></td></tr>"#,
                class = if o.verdict == Verdict::Fail {
                    r#" class="bad""#
                } else {
                    ""
                },
                title = e(o.check.title()),
                pill = verdict_pill(o.verdict),
                detail = e(&o.detail),
            )
        })
        .collect();
    format!(
        r#"<h2>{heading}</h2>
<table><tr><th>Check</th><th>Outcome</th><th>What was seen</th></tr>{checks}</table>
<h3>Header</h3><pre class="raw">{header}</pre>
<h3>Claims</h3><pre class="raw">{claims}</pre>"#,
        header = e(&view.header),
        claims = e(&view.claims),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_variable_is_named_after_the_application() {
        assert_eq!(secret_env_var("Hello World"), "HELLO_WORLD_SECRET");
        assert_eq!(secret_env_var("orders-api"), "ORDERS_API_SECRET");
        assert_eq!(secret_env_var("  My  (test)  app! "), "MY_TEST_APP_SECRET");
        // A shell variable cannot start with a digit.
        assert_eq!(secret_env_var("9lives"), "APP_9LIVES_SECRET");
        // Nothing usable in the name at all.
        assert_eq!(secret_env_var("!!!"), "CLIENT_SECRET");
        assert_eq!(secret_env_var(""), "CLIENT_SECRET");
        // Whatever the name, the result is a valid, inert variable name.
        for name in ["$(reboot)", "a;b", "é", "x`y`"] {
            let var = secret_env_var(name);
            assert!(
                var.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "{var}"
            );
        }
    }

    /// The command is meant to be pasted and run, so a value must never be able to
    /// leave its quotes. Checked against a real shell: `curl` is replaced by a
    /// function that prints its arguments, and they must come back unchanged.
    #[test]
    fn a_hostile_value_stays_inside_its_quotes() {
        let hostile = r#"openid'; touch /tmp/pwned; echo '$(id) `id` "x" \ end"#;
        let command = curl_command(
            "https://example.test/token?a=b&c='d'",
            &[
                ("scope", CurlValue::Literal(hostile)),
                ("client_secret", CurlValue::Env("HELLO_WORLD_SECRET")),
            ],
            &[("HELLO_WORLD_SECRET", SECRET_PLACEHOLDER)],
        );
        let script = format!("curl() {{ printf '%s\\n' \"$@\"; }}\n{command}");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let printed = String::from_utf8_lossy(&out.stdout);
        let args: Vec<&str> = printed.lines().collect();
        assert_eq!(
            args,
            vec![
                "-sS",
                "https://example.test/token?a=b&c='d'",
                "--data-urlencode",
                &format!("scope={hostile}"),
                "--data-urlencode",
                "client_secret=<your-secret>",
            ],
            "the shell saw something other than what was written: {printed}"
        );
    }

    #[test]
    fn the_command_reads_the_secret_from_the_environment_and_never_spells_it() {
        let command = curl_command(
            "https://example.test/token",
            &[
                ("grant_type", CurlValue::Literal("authorization_code")),
                ("client_secret", CurlValue::Env("HELLO_WORLD_SECRET")),
            ],
            &[("HELLO_WORLD_SECRET", SECRET_PLACEHOLDER)],
        );
        assert!(
            command.starts_with("export HELLO_WORLD_SECRET='<your-secret>'\n\ncurl -sS "),
            "{command}"
        );
        assert!(
            command.contains("--data-urlencode \"client_secret=$HELLO_WORLD_SECRET\""),
            "{command}"
        );
    }

    #[test]
    fn operations_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for op in FlowOp::ALL {
            assert!(seen.insert(op.as_str()), "two operations are both {}", op.as_str());
            assert_eq!(FlowOp::parse(op.as_str()), Some(*op));
        }
        assert_eq!(FlowOp::parse("something_else"), None);
        assert_eq!(FlowOp::parse(""), None);
    }

    /// Running a flow changes no configuration; registering a callback or a client
    /// does, and must need the action that governs a registration.
    #[test]
    fn only_the_operations_that_change_a_registration_need_app_write() {
        assert_eq!(FlowOp::Start.action(), APP_READ);
        assert_eq!(FlowOp::AddCallback.action(), APP_WRITE);
        assert_eq!(FlowOp::CreateTestClient.action(), APP_WRITE);
    }

    /// A configuration read back from a form is the one that was chosen, and a
    /// value outside a closed set falls back rather than failing the page.
    #[test]
    fn a_probe_round_trips_through_the_form_fields() {
        let mut form = Params::new();
        form.insert(RESPONSE_TYPE_FIELD.into(), "code id_token".into());
        form.insert(RESPONSE_MODE_FIELD.into(), "form_post".into());
        form.insert(SCOPE_FIELD.into(), "openid".into());
        form.insert(PROMPT_FIELD.into(), "login".into());
        form.insert(PASSWORD_GRANT_FIELD.into(), "on".into());
        let probe = probe_from(&form);
        assert_eq!(probe.response_type, ResponseType::CodeIdToken);
        assert_eq!(probe.response_mode, ResponseMode::FormPost);
        assert_eq!(probe.scope, "openid");
        assert_eq!(probe.prompt, Some(Prompt::Login));
        assert!(probe.password_grant);

        // Nothing chosen: the defaults, and a mode that keeps a token out of a
        // query string.
        let empty = probe_from(&Params::new());
        assert_eq!(empty.response_type, ResponseType::Code);
        assert_eq!(empty.response_mode, ResponseMode::Query);
        assert_eq!(empty.scope, flowtest::DEFAULT_SCOPE);
        assert!(!empty.password_grant);

        let mut hybrid = Params::new();
        hybrid.insert(RESPONSE_TYPE_FIELD.into(), "id_token".into());
        assert_eq!(probe_from(&hybrid).response_mode, ResponseMode::FormPost);

        let mut nonsense = Params::new();
        nonsense.insert(RESPONSE_TYPE_FIELD.into(), "code token id_token extra".into());
        assert_eq!(probe_from(&nonsense).response_type, ResponseType::Code);
    }
}
