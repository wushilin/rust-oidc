//! The console's tenants section: the list every administrator sees, and the
//! platform work of creating, renaming, enabling, disabling and verifying
//! domains.
//!
//! **Every write here is authorized at `On::Platform`**, which means an
//! `all`-scope binding and nothing less. That is stricter than the design spec,
//! whose action table has `Tenant:Write` cover "settings and domains" wherever
//! the binding reaches; the stricter reading is deliberate and is recorded in
//! `docs/decisions-log.md`. Two consequences worth naming:
//!
//! - There is no `{tenant}` path segment on these routes, so no scope comparison
//!   happens against a URL-supplied key at all: a platform-scope grant covers
//!   every tenant by definition, and the target is named by a form field.
//! - A disabled tenant does not [`crate::tenant::resolve`], so it could never be
//!   addressed by a `{tenant}` route. Re-enabling one has to live on a route that
//!   does not resolve it, which is this one.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, PlatformTab, audited, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{TENANT_ASSUME, TENANT_CREATE, TENANT_READ, TENANT_WRITE};
use crate::db::Event;
use crate::rbac::Action;
use crate::tenant::{self, Tenant};

/// What a post to the tenants page asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantOp {
    Create,
    Rename,
    Enable,
    Disable,
    DomainChange,
    DomainRemove,
}

impl TenantOp {
    pub const ALL: &'static [TenantOp] = &[
        Self::Create,
        Self::Rename,
        Self::Enable,
        Self::Disable,
        Self::DomainChange,
        Self::DomainRemove,
    ];

    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Rename => "rename",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::DomainChange => "domain_change",
            Self::DomainRemove => "domain_remove",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// Creating a tenant is its own action, held only by the platform role.
    /// Everything else about an existing tenant is `Tenant:Write`.
    fn action(self) -> Action {
        match self {
            Self::Create => TENANT_CREATE,
            Self::Rename | Self::Enable | Self::Disable | Self::DomainChange | Self::DomainRemove => TENANT_WRITE,
        }
    }

    fn event(self) -> Event {
        match self {
            Self::Create => Event::AdminTenantCreate,
            Self::Rename => Event::AdminTenantRename,
            Self::Enable => Event::AdminTenantEnable,
            Self::Disable => Event::AdminTenantDisable,
            Self::DomainChange => Event::AdminTenantDomainChange,
            Self::DomainRemove => Event::AdminTenantDomainRemove,
        }
    }
}

/// Form field names, spelled once.
const TENANT: &str = "tenant";
const NAME: &str = "name";
const DOMAIN: &str = "domain";
/// Set by the tenant's own Settings page, so a change made there returns there.
const BACK: &str = "back";

fn tenants_url(base: &str) -> String {
    format!("{base}/admin/tenants")
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>) -> Response {
    render(&st, &ctx, None, StatusCode::OK).await
}

async fn render(st: &AppState, ctx: &AdminContext, error: Option<&str>, status: StatusCode) -> Response {
    let all = match tenant::list(&st.pool).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("tenant list failed: {err}");
            return view::server_error();
        }
    };
    let base = st.public_url.base();
    let url = tenants_url(base);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_assume = ctx.can(TENANT_ASSUME, On::Platform);
    let may_write = ctx.can(TENANT_WRITE, On::Platform);
    let may_create = ctx.can(TENANT_CREATE, On::Platform);

    // A tenant this administrator cannot read is not listed at all: the console
    // must not be a directory of tenants for a delegated admin.
    let rows: String = all
        .iter()
        .filter(|(t, _)| ctx.can_in(TENANT_READ, t))
        .map(|(t, domains)| {
            // The name opens the tenant, at the first section these roles reach. A
            // disabled tenant has no pages to open.
            let name = match crate::admin::routes::tenant_home(base, ctx, t).filter(|_| t.enabled) {
                Some(href) => format!(r#"<a href="{}">{}</a>"#, e(&href), e(&t.name)),
                None => e(&t.name),
            };
            let domains: String = domains
                .iter()
                .map(|d| format!(r#"<span class="pill">{}</span>"#, e(d)))
                .collect();
            format!(
                "<tr><td>{name}{root}</td><td>{domains}</td><td>{state}</td><td class=\"id\">{id}</td><td>{actions}</td></tr>",
                root = if t.is_root {
                    r#" <span class="pill">root</span>"#
                } else {
                    ""
                },
                state = if t.enabled {
                    "Enabled"
                } else {
                    r#"<span class="pill bad">disabled</span>"#
                },
                id = e(&t.id),
                actions = row_actions(base, &url, &csrf, ctx, t, may_assume, may_write),
            )
        })
        .collect();

    let create = if may_create {
        view::expander(
            "Create a tenant",
            &format!(
                r#"<form method="post" action="{url}">{csrf}
<input type="hidden" name="{field}" value="{create}">
<label for="new_name">Name</label><input id="new_name" name="{NAME}" type="text" required>
<label for="new_domain">First verified domain</label><input id="new_domain" name="{DOMAIN}" type="text" required>
<p class="muted">The domain becomes the tenant's default and must not belong to another tenant.</p>
<div class="actions"><button type="submit">Create tenant</button></div></form>"#,
                url = e(&url),
                field = TenantOp::FIELD,
                create = TenantOp::Create.as_str(),
            ),
            error.is_some(),
        )
    } else {
        String::new()
    };

    let body = if rows.is_empty() && !may_create {
        format!(
            r#"<h1>Tenants</h1><p class="sub">No tenant is listed for you.</p>{error}"#,
            error = view::error_block(error),
        )
    } else {
        format!(
            r#"<h1>Tenants</h1><p class="sub">Open a tenant to work with its users, groups and applications.</p>{error}
<table><tr><th>Tenant</th><th>Verified domains</th><th>State</th><th>Tenant id</th><th></th></tr>{rows}</table>{create}"#,
            error = view::error_block(error),
        )
    };
    view::page(
        &chrome(st, ctx, At::Platform(PlatformTab::Tenants)),
        status,
        "Tenants",
        &body,
    )
}

/// What can be done to a tenant from the list itself: bring a disabled one back
/// (it has no pages of its own to do that from), or assume it.
fn row_actions(
    base: &str,
    url: &str,
    csrf: &str,
    ctx: &AdminContext,
    t: &Tenant,
    may_assume: bool,
    may_write: bool,
) -> String {
    let mut out = String::new();
    if !t.enabled && may_write {
        out.push_str(&format!(
            r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{TENANT}" value="{id}">
<button class="secondary" type="submit" name="{field}" value="{op}">Enable</button></form>"#,
            url = e(url),
            id = e(&t.id),
            field = TenantOp::FIELD,
            op = TenantOp::Enable.as_str(),
        ));
    }
    if t.enabled && may_assume && ctx.acting_tenant.as_ref().is_none_or(|a| a.id != t.id) {
        out.push_str(&format!(
            r#"<form method="post" action="{base}/admin/assume/{id}" class="inline">{csrf}<button class="secondary" type="submit">Assume</button></form>"#,
            base = e(base),
            id = e(&t.id),
        ));
    }
    out
}

/// The tenant's own name, domains and availability, as sections for its Settings
/// page. They post to the tenants page, which owns these operations, and carry
/// the tenant in `BACK` so a successful change returns here rather than to the
/// list.
pub fn manage(base: &str, csrf: &str, t: &Tenant, domains: &[String], may_write: bool) -> String {
    let url = tenants_url(base);
    let hidden = format!(
        r#"{csrf}<input type="hidden" name="{TENANT}" value="{id}"><input type="hidden" name="{BACK}" value="{id}">"#,
        id = e(&t.id),
    );
    // A tenant has one domain. One that still carries several, from before that
    // was so, is shown them all and can withdraw the ones nobody uses; changing
    // the domain brings it down to one.
    let several = domains.len() > 1;
    let domain_rows: String = domains
        .iter()
        .map(|d| {
            let remove = if may_write && several {
                format!(
                    r#"<form method="post" action="{url}" class="inline">{hidden}<input type="hidden" name="{DOMAIN}" value="{domain}">
<button class="danger" type="submit" name="{field}" value="{op}">Remove</button></form>"#,
                    url = e(&url),
                    domain = e(d),
                    field = TenantOp::FIELD,
                    op = TenantOp::DomainRemove.as_str(),
                )
            } else {
                String::new()
            };
            format!("<tr><td>{}</td><td>{remove}</td></tr>", e(d))
        })
        .collect();
    let domain_table = if several {
        format!(
            r#"<p class="muted">This tenant has more than one domain, from before a tenant had exactly one.
Changing the domain moves every account onto the new one.</p>
<table><tr><th>Domain</th><th></th></tr>{domain_rows}</table>"#
        )
    } else {
        format!(
            r#"<p>Every user name in this tenant ends in <strong>@{}</strong>.</p>"#,
            e(domains.first().map(String::as_str).unwrap_or_default())
        )
    };
    if !may_write {
        return format!(r#"<h2>Domain</h2>{domain_table}"#);
    }
    let change_domain = view::expander(
        "Change the domain",
        &format!(
            r#"<form method="post" action="{url}">{hidden}
<label for="new_tenant_domain">New domain</label><input id="new_tenant_domain" name="{DOMAIN}" type="text" required autocapitalize="none" spellcheck="false">
<p class="muted">Every account is renamed in the same step: <em>alice@{old}</em> becomes <em>alice@</em> the new
domain, and that is what people sign in with from then on. Passwords, groups, roles and application
assignments are unaffected, and so are the ids applications see. Applications that address this tenant
by its domain in a URL need the new one; those that use the tenant id do not.</p>
<div class="actions"><button type="submit" name="{field}" value="{op}">Change domain and rename accounts</button></div></form>"#,
            url = e(&url),
            old = e(domains.first().map(String::as_str).unwrap_or_default()),
            field = TenantOp::FIELD,
            op = TenantOp::DomainChange.as_str(),
        ),
        false,
    );
    // The root tenant is never offered a disable button: `tenant::set_enabled`
    // refuses it, and offering what the domain layer would refuse is exactly what
    // the console does not do.
    let availability = if t.is_root {
        r#"<p class="muted">This is the root tenant. It cannot be disabled.</p>"#.to_string()
    } else {
        format!(
            r#"<p>Disabling a tenant stops every sign-in to it and closes these pages. It can be enabled
again from the list of tenants.</p>
<form method="post" action="{url}">{hidden}
<div class="actions"><button class="danger" type="submit" name="{field}" value="{op}">Disable this tenant</button></div></form>"#,
            url = e(&url),
            field = TenantOp::FIELD,
            op = TenantOp::Disable.as_str(),
        )
    };
    format!(
        r#"<h2>Name</h2>
<form method="post" action="{url}">{hidden}
<label for="tenant_name">Tenant name</label><input id="tenant_name" name="{NAME}" type="text" value="{name}" required>
<div class="actions"><button type="submit" name="{field}" value="{rename}">Rename</button></div></form>
<h2>Domain</h2>{domain_table}{change_domain}
<h2>Availability</h2>{availability}"#,
        url = e(&url),
        name = e(&t.name),
        field = TenantOp::FIELD,
        rename = TenantOp::Rename.as_str(),
    )
}

pub async fn post(ctx: AdminContext, State(st): State<AppState>, body: Bytes) -> Response {
    let form = parse_form(&body);
    let Some(op) = TenantOp::parse(field(&form, TenantOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    // Platform scope: an `all`-scope binding and nothing less.
    if let Err(resp) = ctx.require(op.action(), On::Platform) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    match apply(&st, op, &form).await {
        Ok((tenant_id, details)) => {
            audited(&st, &ctx, &tenant_id, op.event(), Some(&tenant_id), details).await;
            let base = st.public_url.base();
            // Back to the tenant's Settings page when that is where it was asked
            // from -- unless the tenant was just disabled, which closes that page.
            let back = field(&form, BACK);
            if !back.is_empty() && back == tenant_id && op != TenantOp::Disable {
                view::see_other(&format!("{base}/admin/tenants/{tenant_id}/settings"))
            } else {
                view::see_other(&tenants_url(base))
            }
        }
        Err(err) => render(&st, &ctx, Some(&err.to_string()), StatusCode::BAD_REQUEST).await,
    }
}

/// Carry out one operation, returning the tenant it was about and what to record.
async fn apply(st: &AppState, op: TenantOp, form: &Params) -> anyhow::Result<(String, serde_json::Value)> {
    // `Create` has no existing tenant to name.
    if op == TenantOp::Create {
        let (name, domain) = (field(form, NAME), field(form, DOMAIN));
        // Never a root tenant: there is exactly one, and the schema's unique
        // index on `is_root` would refuse a second anyway.
        let created = tenant::create(&st.pool, name, domain, false).await?;
        return Ok((
            created.id.clone(),
            json!({ "name": created.name, "domain": crate::routes::audit::clip(domain) }),
        ));
    }
    // Resolves a disabled tenant too, which `tenant::resolve` deliberately does
    // not: re-enabling one is the whole reason this route exists.
    let target = tenant::find_for_admin(&st.pool, field(form, TENANT)).await?;
    match op {
        TenantOp::Create => unreachable!("handled above"),
        TenantOp::Rename => {
            let name = field(form, NAME);
            tenant::set_name(&st.pool, &target.id, name).await?;
            Ok((target.id, json!({ "name": crate::routes::audit::clip(name) })))
        }
        TenantOp::Enable | TenantOp::Disable => {
            let enabled = op == TenantOp::Enable;
            tenant::set_enabled(&st.pool, &target.id, enabled).await?;
            Ok((target.id, json!({ "enabled": enabled })))
        }
        TenantOp::DomainChange => {
            let change = tenant::change_domain(&st.pool, &target.id, field(form, DOMAIN)).await?;
            Ok((
                target.id,
                json!({ "from": change.from, "to": change.to, "renamed": change.renamed }),
            ))
        }
        TenantOp::DomainRemove => {
            let domain = field(form, DOMAIN);
            tenant::remove_domain(&st.pool, &target.id, domain).await?;
            Ok((target.id, json!({ "domain": crate::routes::audit::clip(domain) })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for op in TenantOp::ALL {
            assert!(seen.insert(op.as_str()), "two operations are both {}", op.as_str());
            assert_eq!(TenantOp::parse(op.as_str()), Some(*op));
        }
        assert_eq!(TenantOp::parse("whatever"), None);
    }

    /// Only creating a tenant uses `Tenant:Create`; everything else about an
    /// existing one is `Tenant:Write`.
    #[test]
    fn creating_is_the_only_operation_with_its_own_action() {
        assert_eq!(TenantOp::Create.action(), TENANT_CREATE);
        for op in TenantOp::ALL.iter().filter(|o| **o != TenantOp::Create) {
            assert_eq!(op.action(), TENANT_WRITE, "{op:?}");
        }
    }

    #[test]
    fn every_operation_records_its_own_event() {
        let mut seen = std::collections::HashSet::new();
        for op in TenantOp::ALL {
            assert!(seen.insert(op.event().as_str()), "{op:?} shares an event");
        }
    }
}
