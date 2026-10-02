//! The audit log viewer, one tenant at a time.
//!
//! Three properties this page is built around:
//!
//! - **A tenant administrator sees only their own tenant's rows.** The action is
//!   `Audit:Read` against the tenant in the URL, and `db::audit_for_tenant` takes
//!   a tenant id that is not optional, so there is no shape of the call that
//!   reads across the boundary or returns the platform's own tenant-less rows.
//! - **The page size is capped.** `audit_log` is append-only, unbounded, and
//!   unauthenticated requests append to it (a failed client authentication is an
//!   event), so the only safe default is a cap: [`crate::db::AUDIT_PAGE_LIMIT`].
//! - **The filters are the indexes.** `0009` added `(tenant_id, created_at)`,
//!   `(tenant_id, action, created_at)` and `(target)` for exactly this page.
//!
//! Actors and targets are shown as the identifiers they are, not resolved to
//! names: resolving would mean a query per row, and a row whose subject has since
//! been deleted would then read as though it had been about nobody.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::AppState;
use crate::admin::AUDIT_READ;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, TenantTab, chrome};
use crate::admin::view::{self, e};
use crate::db::{self, AuditEntry, Event};
use crate::tenant::Tenant;

/// Query parameters. `action` carries an [`Event`]'s wire value; anything else,
/// including the empty string the "any action" option submits, means no filter.
const ACTION_PARAM: &str = "action";
const TARGET_PARAM: &str = "target";

fn audit_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/audit", tenant.id)
}

pub async fn page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    Query(query): Query<Params>,
) -> Response {
    if let Err(resp) = ctx.require(AUDIT_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let raw_action = query.get(ACTION_PARAM).map(String::as_str).unwrap_or_default();
    let raw_target = query.get(TARGET_PARAM).map(String::as_str).unwrap_or_default().trim();
    // An action this build does not know filters nothing rather than filtering
    // everything out: the box is a convenience, not an authorization decision.
    let action = Event::parse(raw_action);
    let target = Some(raw_target).filter(|t| !t.is_empty());

    let entries = match db::audit_for_tenant(&st.pool, &tenant.id, action, target, db::AUDIT_PAGE_LIMIT).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("audit read failed: {err}");
            return view::server_error();
        }
    };

    // Ids become names where this administrator may see what they name. An actor
    // from a tenant they cannot read -- a platform administrator acting here --
    // stays an id: the audit page must not become a way to learn who that is.
    let mut names = crate::admin::find::Names::new();
    let mut rows = String::new();
    for entry in &entries {
        let actor = crate::admin::find::cell(&st, &ctx, &mut names, &entry.actor).await;
        let target = crate::admin::find::cell(&st, &ctx, &mut names, entry.target.as_deref().unwrap_or("")).await;
        rows.push_str(&row(entry, &actor, &target));
    }
    let options: String = std::iter::once(r#"<option value="">Any action</option>"#.to_string())
        .chain(Event::ALL.iter().map(|ev| {
            format!(
                r#"<option value="{v}"{selected}>{v}</option>"#,
                v = e(ev.as_str()),
                selected = if action == Some(*ev) { " selected" } else { "" },
            )
        }))
        .collect();
    let full = if entries.len() as i64 >= db::AUDIT_PAGE_LIMIT {
        format!(
            r#"<p class="muted">Showing the {} most recent matching entries. Narrow the filters to
see older ones; there is no paging.</p>"#,
            db::AUDIT_PAGE_LIMIT
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<h1>Audit log</h1><p class="sub">What was done in this tenant, newest first. A name links to what it is.</p>
<form method="get" action="{url}"><div class="fields">
<div><label for="action">Action</label><select id="action" name="{ACTION_PARAM}">{options}</select></div>
<div><label for="target">Target (an object id, exactly)</label>
<input id="target" name="{TARGET_PARAM}" type="search" value="{target}"></div></div>
<div class="actions"><button class="secondary" type="submit">Filter</button><a href="{url}">Clear</a></div></form>
<table><tr><th>When</th><th>Action</th><th>Actor</th><th>Target</th><th>Details</th></tr>{rows}</table>{full}
<p class="muted">Rows belonging to no tenant -- a signing key rotation is the only one -- are not
shown here. Entries are kept until an operator prunes them.</p>"#,
        url = e(&audit_url(st.public_url.base(), tenant)),
        target = e(raw_target),
    );
    view::page(
        &chrome(&st, &ctx, At::Tenant(tenant, TenantTab::Audit)),
        StatusCode::OK,
        "Audit log",
        &body,
    )
}

/// One entry. `actor` and `target` arrive as finished cells: a name linking to
/// what it is, or the bare id.
fn row(entry: &AuditEntry, actor: &str, target: &str) -> String {
    format!(
        "<tr><td>{when}</td><td>{action}</td><td>{actor}</td><td>{target}</td><td class=\"muted\">{details}</td></tr>",
        when = e(&view::ts(entry.created_at)),
        // The stored string either way; an action a newer build wrote is shown as
        // it stands rather than hidden.
        action = e(&entry.action_raw),
        details = e(entry.details.as_deref().unwrap_or("")),
    )
}
