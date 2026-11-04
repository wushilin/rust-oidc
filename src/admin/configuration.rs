//! Configuration: what an application outside this server is configured with to
//! use it -- the addresses, and what the server supports.
//!
//! Read-only, and nothing here is decided here: the addresses and lists come from
//! [`crate::routes::discovery`], the same definitions the discovery document is
//! built from, so this page cannot say something the server does not do.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::AppState;
use crate::admin::TENANT_READ;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, PlatformTab, TenantTab, chrome};
use crate::admin::view::{self, e};
use crate::routes::Prompt;
use crate::routes::discovery::{self, Endpoint};
use crate::tenant;

/// What stands for the tenant in an address that is the same for every tenant.
const TENANT_PLACEHOLDER: &str = "{tenant}";

fn list(values: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    values
        .into_iter()
        .map(|v| format!("<code>{}</code> ", e(v.as_ref())))
        .collect()
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>) -> Response {
    if let Err(resp) = ctx.require(TENANT_READ, On::Platform) {
        return resp;
    }
    let tenants = match tenant::list(&st.pool).await {
        Ok(t) => t,
        Err(err) => {
            tracing::error!("tenants could not be listed: {err}");
            return view::server_error();
        }
    };
    let url = &st.public_url;

    let endpoints: String = Endpoint::ALL
        .iter()
        .map(|endpoint| {
            format!(
                "<tr><td>{label}</td><td><code>{address}</code></td><td class=\"muted\">{key}</td></tr>",
                label = e(endpoint.label()),
                address = e(&endpoint.url(url, TENANT_PLACEHOLDER)),
                key = endpoint.metadata_key().map(e).unwrap_or_default(),
            )
        })
        .collect();

    let per_tenant: String = tenants
        .iter()
        .map(|(t, domains)| {
            let discovery = Endpoint::Discovery.url(url, &t.id);
            format!(
                r#"<tr><td>{name}{state}</td><td class="id"><code>{id}</code></td><td>{domains}</td><td><code>{issuer}</code><br><a href="{discovery}">Discovery document</a></td></tr>"#,
                name = e(&t.name),
                state = if t.enabled {
                    ""
                } else {
                    r#" <span class="pill">disabled</span>"#
                },
                id = e(&t.id),
                domains = domains.iter().map(|d| e(d)).collect::<Vec<_>>().join(", "),
                issuer = e(&Endpoint::Issuer.url(url, &t.id)),
                discovery = e(&discovery),
            )
        })
        .collect();

    let supported = [
        ("Signing algorithm", list(discovery::SIGNING_ALGORITHMS)),
        ("Grant types", list(discovery::GRANT_TYPES.iter().map(|g| g.as_str()))),
        ("Response types", list(discovery::RESPONSE_TYPES)),
        ("Response modes", list(discovery::RESPONSE_MODES)),
        (
            "Client authentication",
            list(discovery::CLIENT_AUTH_METHODS.iter().map(|m| m.as_str())),
        ),
        ("PKCE methods", list(discovery::CODE_CHALLENGE_METHODS)),
        ("Standard scopes", list(discovery::SCOPES)),
        ("Prompt values", list(Prompt::SUPPORTED.iter().map(|p| p.as_str()))),
    ]
    .iter()
    .map(|(what, values)| format!("<tr><td>{}</td><td>{values}</td></tr>", e(what)))
    .collect::<String>();

    let body = format!(
        r#"<h1>Configuration</h1><p class="sub">What an application is configured with to use this server. Most
libraries need only the discovery document, or the issuer, and find the rest themselves.</p>
<h2>This server</h2>
<table><tr><th>Setting</th><th>Value</th></tr>
<tr><td>Public address</td><td><code>{base}</code></td></tr>
<tr><td>Host</td><td><code>{host}</code></td></tr>
<tr><td>My Account, for users</td><td><code>{my_account}</code></td></tr></table>
<h2>Addresses</h2><p class="sub">The same for every tenant, with the tenant's id in place of
<code>{placeholder}</code>. The tenant's domain works there too, but tokens always name the issuer by id, so
configure the id.</p>
<table><tr><th>What</th><th>Address</th><th>In the discovery document</th></tr>{endpoints}</table>
<h2>Each tenant</h2>
<table><tr><th>Tenant</th><th>Tenant id</th><th>Domain</th><th>Issuer</th></tr>{per_tenant}</table>
<h2>What is supported</h2>
<table><tr><th>Setting</th><th>Values</th></tr>{supported}</table>
<p class="muted">An application also needs its own application (client) id and, unless it is a public
client, a secret or certificate: those are on the application's page inside its tenant. The keys tokens
are signed with are on the Signing keys tab, and applications fetch them from the JWKS address.</p>"#,
        base = e(url.base()),
        host = e(url.host()),
        my_account = e(&url.tenant_url(TENANT_PLACEHOLDER, "myaccount")),
        placeholder = e(TENANT_PLACEHOLDER),
    );
    view::page(
        &chrome(&st, &ctx, At::Platform(PlatformTab::Configuration)),
        StatusCode::OK,
        "Configuration",
        &body,
    )
}

/// A value to copy: selected whole by one click (no script).
fn copy(value: &str) -> String {
    format!(r#"<code class="copy">{}</code>"#, e(value))
}

/// One tenant's configuration, with its id in every address: what an application
/// registered in it is configured with, ready to copy.
pub async fn tenant_page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(TENANT_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(t) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let domains = match tenant::domains(&st.pool, &t.id).await {
        Ok(d) => d,
        Err(err) => {
            tracing::error!("tenant domains could not be read: {err}");
            return view::server_error();
        }
    };
    let url = &st.public_url;
    let tid = t.id.as_str();
    let issuer = Endpoint::Issuer.url(url, tid);
    let discovery_url = Endpoint::Discovery.url(url, tid);

    let rows = |items: &[(&str, String)]| -> String {
        items
            .iter()
            .map(|(what, value)| format!("<tr><td>{}</td><td>{}</td></tr>", e(what), copy(value)))
            .collect()
    };
    let tenant_rows = rows(&[
        ("Tenant id", t.id.clone()),
        ("Issuer", issuer.clone()),
        ("Discovery document", discovery_url.clone()),
    ]);
    let domain_rows: String = domains
        .iter()
        .map(|d| format!("<tr><td>Verified domain</td><td>{}</td></tr>", copy(d)))
        .collect();
    let endpoints: String = Endpoint::ALL
        .iter()
        .map(|endpoint| {
            format!(
                "<tr><td>{label}</td><td>{address}</td><td class=\"muted\">{key}</td></tr>",
                label = e(endpoint.label()),
                address = copy(&endpoint.url(url, tid)),
                key = endpoint.metadata_key().map(e).unwrap_or_default(),
            )
        })
        .collect();
    // Not in the discovery document: the last column says so by being empty.
    let more: String = [
        (
            "Auth API (credential check)",
            url.tenant_url(tid, "api/v1/authenticate"),
        ),
        ("My Account, for this tenant's users", url.tenant_url(tid, "myaccount")),
    ]
    .iter()
    .map(|(what, value)| format!("<tr><td>{}</td><td>{}</td><td></td></tr>", e(what), copy(value)))
    .collect();

    // What the usual libraries are given, filled in. Each is a block to paste.
    let base = format!("{}/", url.base().trim_end_matches('/'));
    let generic = format!("issuer = {issuer}\ndiscovery = {discovery_url}\nclient_id = <application (client) id>");
    let identity_web = format!(
        "\"AzureAd\": {{\n  \"Instance\": \"{base}\",\n  \"TenantId\": \"{tid}\",\n  \"ClientId\": \"<application (client) id>\"\n}}"
    );
    let msal = format!(
        "authority = {}",
        Endpoint::Issuer.url(url, tid).trim_end_matches("/v2.0")
    );
    let snippet = |title: &str, note: &str, text: &str| {
        format!(
            r#"<h3>{}</h3><p class="muted">{}</p><pre class="raw copy">{}</pre>"#,
            e(title),
            e(note),
            e(text)
        )
    };
    let snippets = format!(
        "{}{}{}",
        snippet(
            "Any OpenID Connect library",
            "Most need only the issuer or the discovery document and find everything else.",
            &generic
        ),
        snippet(
            "Microsoft.Identity.Web (appsettings.json)",
            "Instance and TenantId, as for Entra ID.",
            &identity_web
        ),
        snippet(
            "MSAL",
            "The authority, as for Entra ID: the tenant's address without /v2.0.",
            &msal
        ),
    );

    let body = format!(
        r#"<h1>Configuration</h1><p class="sub">{name}: what an application registered here is configured
with. Click a value to select it. Tokens name the issuer by the tenant id, so configure the id rather than a
domain.</p>
<h2>This tenant</h2>
<table><tr><th>Setting</th><th>Value</th></tr>{tenant_rows}{domain_rows}</table>
<h2>Endpoints</h2>
<table><tr><th>What</th><th>Address</th><th>In the discovery document</th></tr>{endpoints}{more_rows}</table>
<h2>For common libraries</h2>{snippets}
<p class="muted">An application also needs its own application (client) id and, unless it is a public
client, a secret or certificate: those are on its page under Applications. What the server supports
(grant types, response types, signing algorithms) is the same for every tenant and is on the
deployment's Configuration page.</p>"#,
        name = e(&t.name),
        more_rows = more,
    );
    view::page(
        &chrome(&st, &ctx, At::Tenant(t, TenantTab::Configuration)),
        StatusCode::OK,
        "Configuration",
        &body,
    )
}
