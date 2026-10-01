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
use crate::admin::routes::{Params, audited, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{
    APP_READ, AUDIT_READ, BINDING_READ, GROUP_READ, TENANT_ASSUME, TENANT_CREATE, TENANT_READ, TENANT_WRITE, USER_READ,
};
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
    DomainAdd,
    DomainRemove,
}

impl TenantOp {
    pub const ALL: &'static [TenantOp] = &[
        Self::Create,
        Self::Rename,
        Self::Enable,
        Self::Disable,
        Self::DomainAdd,
        Self::DomainRemove,
    ];

    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Rename => "rename",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::DomainAdd => "domain_add",
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
            Self::Rename | Self::Enable | Self::Disable | Self::DomainAdd | Self::DomainRemove => TENANT_WRITE,
        }
    }

    fn event(self) -> Event {
        match self {
            Self::Create => Event::AdminTenantCreate,
            Self::Rename => Event::AdminTenantRename,
            Self::Enable => Event::AdminTenantEnable,
            Self::Disable => Event::AdminTenantDisable,
            Self::DomainAdd => Event::AdminTenantDomainAdd,
            Self::DomainRemove => Event::AdminTenantDomainRemove,
        }
    }
}

/// Form field names, spelled once.
const TENANT: &str = "tenant";
const NAME: &str = "name";
const DOMAIN: &str = "domain";

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
            format!(
                "<tr><td>{name}{root}</td><td class=\"muted\">{id}</td><td>{domains}</td><td>{state}</td><td>{links}</td></tr>",
                name = e(&t.name),
                root = if t.is_root {
                    r#" <span class="pill">root</span>"#
                } else {
                    ""
                },
                id = e(&t.id),
                domains = domain_cell(&url, &csrf, t, domains, may_write),
                state = state_cell(&url, &csrf, t, may_write),
                links = links_cell(base, &csrf, ctx, t, may_assume),
            )
        })
        .collect();

    let create = if may_create {
        format!(
            r#"<h2>Create a tenant</h2><form method="post" action="{url}">{csrf}
<input type="hidden" name="{field}" value="{create}">
<label for="new_name">Name</label><input id="new_name" name="{NAME}" type="text" required>
<label for="new_domain">First verified domain</label><input id="new_domain" name="{DOMAIN}" type="text" required>
<div class="actions"><button type="submit">Create</button></div>
<p class="muted">The domain becomes the tenant's default and must not belong to another tenant.
The new tenant is never a root tenant: there is exactly one, enforced by the schema.</p></form>"#,
            url = e(&url),
            field = TenantOp::FIELD,
            create = TenantOp::Create.as_str(),
        )
    } else {
        String::new()
    };

    let body = if rows.is_empty() && !may_create {
        format!(
            r#"<h1>Tenants</h1><p class="sub">No tenant is listed for you. Your roles may still cover the
people and objects inside one -- the links above go where they reach.</p>{error}"#,
            error = view::error_block(error),
        )
    } else {
        format!(
            r#"<h1>Tenants</h1><p class="sub">The tenants your roles cover.</p>{error}
<table><tr><th>Name</th><th>Tenant id</th><th>Verified domains</th><th>State</th><th></th></tr>{rows}</table>{create}"#,
            error = view::error_block(error),
        )
    };
    view::page(&chrome(st, ctx), status, "Tenants", &body)
}

/// The verified domains of one tenant, each removable where permitted, plus the
/// box that adds one.
fn domain_cell(url: &str, csrf: &str, t: &Tenant, domains: &[String], may_write: bool) -> String {
    let mut cell = String::new();
    for domain in domains {
        cell.push_str(&format!(r#"<span class="pill">{}</span>"#, e(domain)));
        if may_write {
            cell.push_str(&format!(
                r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{TENANT}" value="{id}"><input type="hidden" name="{DOMAIN}" value="{domain}">
<button class="danger" type="submit" name="{field}" value="{op}">Remove</button></form> "#,
                url = e(url),
                id = e(&t.id),
                domain = e(domain),
                field = TenantOp::FIELD,
                op = TenantOp::DomainRemove.as_str(),
            ));
        }
    }
    if may_write {
        cell.push_str(&format!(
            r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{TENANT}" value="{id}">
<input name="{DOMAIN}" type="text" aria-label="New domain for {name}">
<button class="secondary" type="submit" name="{field}" value="{op}">Add domain</button></form>"#,
            url = e(url),
            id = e(&t.id),
            name = e(&t.name),
            field = TenantOp::FIELD,
            op = TenantOp::DomainAdd.as_str(),
        ));
    }
    cell
}

/// Enabled or disabled, with the button that changes it and the rename box.
fn state_cell(url: &str, csrf: &str, t: &Tenant, may_write: bool) -> String {
    let state = if t.enabled {
        "Enabled".to_string()
    } else {
        r#"<span class="pill">disabled</span>"#.to_string()
    };
    if !may_write {
        return state;
    }
    let (op, label) = if t.enabled {
        (TenantOp::Disable, "Disable")
    } else {
        (TenantOp::Enable, "Enable")
    };
    // The root tenant is never offered a disable button: `tenant::set_enabled`
    // refuses it, and offering what the domain layer would refuse is exactly what
    // the console does not do.
    let toggle = if t.is_root && t.enabled {
        String::new()
    } else {
        format!(
            r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{TENANT}" value="{id}">
<button class="danger" type="submit" name="{field}" value="{op}">{label}</button></form>"#,
            url = e(url),
            id = e(&t.id),
            field = TenantOp::FIELD,
            op = op.as_str(),
            label = e(label),
        )
    };
    format!(
        r#"{state} {toggle}<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{TENANT}" value="{id}">
<input name="{NAME}" type="text" value="{name}" aria-label="Name of {name}">
<button class="secondary" type="submit" name="{field}" value="{rename}">Rename</button></form>"#,
        url = e(url),
        id = e(&t.id),
        name = e(&t.name),
        field = TenantOp::FIELD,
        rename = TenantOp::Rename.as_str(),
    )
}

/// Links into the tenant's own sections, each emitted only where the action
/// behind it is permitted, plus the assume button.
fn links_cell(base: &str, csrf: &str, ctx: &AdminContext, t: &Tenant, may_assume: bool) -> String {
    let mut links = Vec::new();
    for (action, label, path) in [
        (USER_READ, "Users", "users"),
        (GROUP_READ, "Groups", "groups"),
        (APP_READ, "Applications", "apps"),
        (BINDING_READ, "Roles", "roles"),
        (APP_READ, "Flow tester", "flow"),
        (TENANT_WRITE, "Settings", "settings"),
        (AUDIT_READ, "Audit", "audit"),
    ] {
        if ctx.can_in(action, t) {
            links.push(format!(
                r#"<a href="{base}/admin/tenants/{id}/{path}">{label}</a>"#,
                base = e(base),
                id = e(&t.id),
                label = e(label),
            ));
        }
    }
    if may_assume && ctx.acting_tenant.as_ref().is_none_or(|a| a.id != t.id) {
        links.push(format!(
            r#"<form method="post" action="{base}/admin/assume/{id}" class="inline">{csrf}<button class="secondary" type="submit">Assume</button></form>"#,
            base = e(base),
            id = e(&t.id),
        ));
    }
    links.join(" ")
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
            view::see_other(&tenants_url(st.public_url.base()))
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
        TenantOp::DomainAdd => {
            let domain = field(form, DOMAIN);
            tenant::add_domain(&st.pool, &target.id, domain).await?;
            Ok((target.id, json!({ "domain": crate::routes::audit::clip(domain) })))
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
