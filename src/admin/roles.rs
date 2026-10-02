//! Granting and revoking console roles, per tenant.
//!
//! The page lives under a tenant because that is where a principal can be named:
//! a UPN and a group name are unique within a tenant, not across the deployment.
//! A grant may be scoped to that tenant or, for someone who already holds the
//! action everywhere, to `all`.
//!
//! The two rules that make delegation safe are **not** implemented here. They are
//! [`authz::may_write_binding`] (no widening) and [`authz::delete`] (which applies
//! the no-widening and no-lock-out rules together, so a handler cannot apply one
//! and forget the other). This module decides nothing on its own.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::authz::{self, RefusedReason};
use crate::admin::bindings::{self, StoredBinding};
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, TenantTab, audited, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{BINDING_READ, BINDING_WRITE};
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::rbac::{RoleId, Scope, ScopeKind};
use crate::tenant::Tenant;

/// What a post to the roles page asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleOp {
    Grant,
    Revoke,
}

impl RoleOp {
    pub const ALL: &'static [RoleOp] = &[Self::Grant, Self::Revoke];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    fn event(self) -> Event {
        match self {
            Self::Grant => Event::AdminRoleGrant,
            Self::Revoke => Event::AdminRoleRevoke,
        }
    }
}

/// Form field names, named once.
const PRINCIPAL_TYPE: &str = "principal_type";
const PRINCIPAL: &str = "principal";
const ROLE: &str = "role";
const BINDING: &str = "binding";

fn roles_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/roles", tenant.id)
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(BINDING_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    render(&st, &ctx, tenant, None, StatusCode::OK).await
}

async fn render(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let listed = match bindings::list_for_tenant(&st.pool, &tenant.id).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("binding list failed: {err}");
            return view::server_error();
        }
    };
    let url = roles_url(st.public_url.base(), tenant);
    let csrf = view::csrf_input(&ctx.csrf);
    // A binding at `all` scope is the platform's, not this tenant's, and its
    // principal may administer tenants this viewer cannot see. Only somebody who
    // can read platform-wide is shown it; they have `/admin/bindings` for exactly
    // that question.
    let platform_visible = ctx.can(BINDING_READ, On::Platform);
    let mut rows = String::new();
    for b in listed
        .iter()
        .filter(|b| platform_visible || b.scope.kind() == ScopeKind::Tenants)
    {
        // The revoke button appears only where the no-widening rule would allow
        // it; `authz::delete` checks it again, and the lock-out rule too.
        let revoke = if authz::may_write_binding(ctx.bindings(), &b.scope) {
            format!(
                r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{BINDING}" value="{id}">
<button class="danger" type="submit" name="{op_field}" value="{revoke}">Revoke</button></form>"#,
                url = e(&url),
                id = e(&b.id),
                op_field = RoleOp::FIELD,
                revoke = RoleOp::Revoke.as_str(),
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{who}</td><td>{kind}</td><td>{role}</td><td>{scope}</td><td>{revoke}</td></tr>",
            who = e(&principal_name(st, b).await),
            kind = e(b.principal_type.as_str()),
            role = e(b.role.display_name()),
            scope = scope_cell(&b.scope),
        ));
    }

    let had_error = error.is_some();
    let error = error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default();
    let grant = if ctx.can_in(BINDING_WRITE, tenant) {
        // The roles that are held inside a tenant. Global Administrator is not one
        // of them; it is granted from the Global roles page.
        let tenant_roles = || RoleId::ALL.iter().filter(|r| r.scope_kind() == ScopeKind::Tenants);
        let roles: String = tenant_roles()
            .map(|r| format!(r#"<option value="{}">{}</option>"#, e(r.as_str()), e(r.display_name())))
            .collect();
        let explained: String = tenant_roles()
            .map(|r| format!("<dt>{}</dt><dd>{}</dd>", e(r.display_name()), e(r.summary())))
            .collect();
        view::expander(
            "Grant a role",
            &format!(
                r#"<form method="post" action="{url}">{csrf}
<input type="hidden" name="{op_field}" value="{grant}">
<label for="principal">User name or group name in {tenant_name}</label>
<input id="principal" name="{PRINCIPAL}" type="text" required>
<label for="principal_type">Principal</label>
<select id="principal_type" name="{PRINCIPAL_TYPE}">
<option value="{user}">User</option><option value="{group}">Group</option></select>
<label for="role">Role</label><select id="role" name="{ROLE}">{roles}</select>
<dl class="roles">{explained}</dl>
<div class="actions"><button type="submit">Grant</button></div></form>"#,
                url = e(&url),
                op_field = RoleOp::FIELD,
                grant = RoleOp::Grant.as_str(),
                tenant_name = e(&tenant.name),
                user = e(PrincipalType::User.as_str()),
                group = e(PrincipalType::Group.as_str()),
            ),
            had_error,
        )
    } else {
        r#"<p class="muted">Your roles allow seeing who administers this tenant but not changing it.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>Roles</h1><p class="sub">Who can administer or view {tenant_name} in this console. A role granted here applies to this tenant only.</p>{error}
<table><tr><th>Who</th><th>Type</th><th>Role</th><th>Applies to</th><th></th></tr>{rows}</table>{grant}"#,
        tenant_name = e(&tenant.name),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Roles)),
        status,
        "Roles",
        &body,
    )
}

/// Where a binding listed on this tenant's page applies. A tenant role applies
/// to its holder's own tenant, which is this one; only Global Administrator is
/// wider.
fn scope_cell(scope: &Scope) -> &'static str {
    match scope {
        Scope::All => r#"<span class="pill good">everything</span>"#,
        Scope::Tenants(ids) if ids.is_empty() => r#"<span class="muted">no live tenant</span>"#,
        Scope::Tenants(_) => r#"<span class="pill">this tenant</span>"#,
    }
}

/// The UPN or group name behind a principal id, falling back to the id when the
/// principal has been removed.
/// A principal's name and the tenant it belongs to. The name alone does not say
/// which "Administrators" group a binding is about.
pub async fn principal(st: &AppState, b: &StoredBinding) -> (String, Option<String>) {
    let sql = match b.principal_type {
        PrincipalType::User => "SELECT upn, tenant_id FROM users WHERE id = ? AND deleted_at IS NULL",
        PrincipalType::Group => "SELECT name, tenant_id FROM user_groups WHERE id = ?",
        PrincipalType::ServicePrincipal => return (b.principal_id.clone(), None),
    };
    let found: Option<(String, String)> = sqlx::query_as(crate::db::q(&st.pool, sql))
        .bind(&b.principal_id)
        .fetch_optional(&st.pool)
        .await
        .unwrap_or(None);
    match found {
        Some((name, tenant_id)) => (name, Some(tenant_id)),
        None => (b.principal_id.clone(), None),
    }
}

pub async fn principal_name(st: &AppState, b: &StoredBinding) -> String {
    let sql = match b.principal_type {
        PrincipalType::User => "SELECT upn FROM users WHERE id = ? AND deleted_at IS NULL",
        PrincipalType::Group => "SELECT name FROM user_groups WHERE id = ?",
        // Refused by `bindings::create`, so only a hand-written row reaches this.
        PrincipalType::ServicePrincipal => return b.principal_id.clone(),
    };
    let found: Option<(String,)> = sqlx::query_as(crate::db::q(&st.pool, sql))
        .bind(&b.principal_id)
        .fetch_optional(&st.pool)
        .await
        .unwrap_or(None);
    found.map(|(n,)| n).unwrap_or_else(|| b.principal_id.clone())
}

pub async fn post(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    let form = parse_form(&body);
    let Some(op) = RoleOp::parse(field(&form, RoleOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    // The tenant boundary, then the rules. This check is defence in depth on the
    // write path: the no-widening rule below refuses the same requests on its own
    // (a teeth check confirmed removing this one changes no outcome), but it is the
    // same check every other console write makes and the page should not be the
    // exception.
    if let Err(resp) = ctx.require(BINDING_WRITE, On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };

    let outcome = match op {
        RoleOp::Grant => grant(&st, &ctx, tenant, &form).await,
        RoleOp::Revoke => revoke(&st, &ctx, &form).await,
    };
    match outcome {
        Ok((target, details)) => {
            audited(&st, &ctx, &tenant.id, op.event(), Some(&target), details).await;
            view::see_other(&roles_url(st.public_url.base(), tenant))
        }
        Err(Refusal::Message(m)) => render(&st, &ctx, tenant, Some(&m), StatusCode::BAD_REQUEST).await,
        Err(Refusal::Forbidden) => view::forbidden(),
    }
}

/// Why a grant or revoke did not happen.
enum Refusal {
    /// Something the administrator can fix, shown on the page.
    Message(String),
    /// Their roles do not reach that far.
    Forbidden,
}

impl From<RefusedReason> for Refusal {
    fn from(reason: RefusedReason) -> Self {
        match reason {
            RefusedReason::NotPermitted => Refusal::Forbidden,
            RefusedReason::WouldLockOut => {
                Refusal::Message("That is the last Global Administrator. Make somebody else one first.".into())
            }
        }
    }
}

async fn grant(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    form: &Params,
) -> Result<(String, serde_json::Value), Refusal> {
    let name = field(form, PRINCIPAL);
    let Some(principal_type) = PrincipalType::parse(field(form, PRINCIPAL_TYPE)) else {
        return Err(Refusal::Message("Choose a user or a group.".into()));
    };
    let Some(role) = RoleId::parse(field(form, ROLE)) else {
        return Err(Refusal::Message("Choose a role.".into()));
    };
    if role.scope_kind() != ScopeKind::Tenants {
        return Err(Refusal::Message(format!(
            "{} is not a role of one tenant. It is granted from the All roles page.",
            role.display_name()
        )));
    }
    // Where it applies is not asked: a role granted here applies to this tenant,
    // which is the principal's own. `bindings::create` holds the rule.
    let scope = Scope::Tenants(vec![tenant.id.clone()]);
    // A binding write is authorized against the *target* scope, so no principal
    // can grant reach it does not already hold.
    if !authz::may_write_binding(ctx.bindings(), &scope) {
        return Err(Refusal::Forbidden);
    }

    let principal_id = match principal_type {
        PrincipalType::User => crate::users::find_by_upn(&st.pool, &tenant.id, name)
            .await
            .map_err(|_| Refusal::Message("That user could not be looked up.".into()))?
            .map(|u| u.id),
        PrincipalType::Group => crate::groups::find(&st.pool, &tenant.id, name)
            .await
            .map_err(|_| Refusal::Message("That group could not be looked up.".into()))?,
        PrincipalType::ServicePrincipal => None,
    };
    let Some(principal_id) = principal_id else {
        return Err(Refusal::Message(format!(
            "No {} named '{name}' in {}.",
            principal_type.as_str().to_lowercase(),
            tenant.name
        )));
    };

    let id = bindings::create(&st.pool, principal_type, &principal_id, role, &scope, &ctx.user.id)
        .await
        .map_err(|e| Refusal::Message(e.to_string()))?;
    Ok((
        id,
        json!({
            "role": role.as_str(),
            "scopeKind": scope.kind().as_str(),
            "principalType": principal_type.as_str(),
            "principalId": principal_id,
        }),
    ))
}

async fn revoke(st: &AppState, ctx: &AdminContext, form: &Params) -> Result<(String, serde_json::Value), Refusal> {
    let id = field(form, BINDING).to_string();
    // One call, both rules: no widening, and no locking the platform out.
    authz::delete(&st.pool, ctx.bindings(), &id)
        .await
        .map_err(Refusal::from)?;
    Ok((id, json!({})))
}
