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
use crate::admin::routes::{Params, chrome};
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

    let rows: String = entries.iter().map(row).collect();
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
        r#"<h1>Audit log</h1><p class="sub">{tenant_name} &middot; newest first.</p>
<form method="get" action="{url}">
<label for="action">Action</label><select id="action" name="{ACTION_PARAM}">{options}</select>
<label for="target">Target (an object id, exactly)</label>
<input id="target" name="{TARGET_PARAM}" type="search" value="{target}">
<div class="actions"><button type="submit">Filter</button><a href="{url}">Clear</a></div></form>
<table><tr><th>When</th><th>Action</th><th>Actor</th><th>Target</th><th>Details</th></tr>{rows}</table>{full}
<p class="muted">Rows belonging to no tenant -- a signing key rotation is the only one -- are not
shown here. Entries are kept until an operator prunes them.</p>"#,
        tenant_name = e(&tenant.name),
        url = e(&audit_url(st.public_url.base(), tenant)),
        target = e(raw_target),
    );
    view::page(&chrome(&st, &ctx), StatusCode::OK, "Audit log", &body)
}

fn row(entry: &AuditEntry) -> String {
    format!(
        "<tr><td>{when}</td><td>{action}</td><td class=\"muted\">{actor}</td><td class=\"muted\">{target}</td><td class=\"muted\">{details}</td></tr>",
        when = e(&view::ts(entry.created_at)),
        // The stored string either way; an action a newer build wrote is shown as
        // it stands rather than hidden.
        action = e(&entry.action_raw),
        actor = e(&entry.actor),
        target = e(entry.target.as_deref().unwrap_or("")),
        details = e(entry.details.as_deref().unwrap_or("")),
    )
}
