//! Platform roles: every role binding on the deployment, and granting or revoking
//! the ones that reach across tenants.
//!
//! A tenant's own Roles page grants within that tenant. This page is where an
//! account is made an administrator of every tenant, or of a chosen few -- the
//! `[*]` and `['a', 'b']` scopes of the binding model.
//!
//! As on the tenant page, the rules that make delegation safe are not implemented
//! here. They are [`authz::may_write_binding`] (nobody grants reach they do not
//! hold) and [`authz::delete`] (no widening, and no revoking the last binding
//! that can administer the platform). This module decides nothing on its own.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::authz::{self, RefusedReason};
use crate::admin::bindings::{self, StoredBinding};
use crate::admin::context::{AdminContext, On};
use crate::admin::roles::RoleOp;
use crate::admin::routes::{At, PlatformTab, audited, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{BINDING_READ, BINDING_WRITE};
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::rbac::{RoleId, Scope, ScopeKind};
use crate::tenant::{self, Tenant};

/// Form field names, named once.
const ACCOUNT: &str = "account";
const ROLE: &str = "role";
const SCOPE: &str = "scope";
/// Repeated once per ticked tenant.
const TENANT: &str = "tenant";
const BINDING: &str = "binding";

fn page_url(base: &str) -> String {
    format!("{base}/admin/bindings")
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>) -> Response {
    if let Err(resp) = ctx.require(BINDING_READ, On::Platform) {
        return resp;
    }
    render(&st, &ctx, None, StatusCode::OK).await
}

async fn render(st: &AppState, ctx: &AdminContext, error: Option<&str>, status: StatusCode) -> Response {
    let (stored, tenants) = match (bindings::list_all(&st.pool).await, tenant::list(&st.pool).await) {
        (Ok(b), Ok(t)) => (b, t),
        (Err(err), _) | (_, Err(err)) => {
            tracing::error!("platform roles could not be listed: {err}");
            return view::server_error();
        }
    };
    let tenants: Vec<&Tenant> = tenants.iter().map(|(t, _)| t).collect();
    let base = st.public_url.base();
    let url = page_url(base);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_write = ctx.can(BINDING_WRITE, On::Platform);

    let mut rows = String::new();
    for b in &stored {
        let (who, home_id) = crate::admin::roles::principal(st, b).await;
        let home = home_id.as_ref().and_then(|id| tenants.iter().find(|t| &t.id == id));
        let home_cell = match home {
            Some(t) if t.is_root => format!(r#"{} <span class="pill">root</span>"#, e(&t.name)),
            Some(t) => e(&t.name),
            None => r#"<span class="muted">unknown</span>"#.to_string(),
        };
        // Granted before the rule existed, or by hand: kept, but pointed out.
        let beyond = match home {
            Some(t) if !b.scope.may_be_held_by(&t.id, t.is_root) => {
                r#" <span class="pill bad" title="Only a principal of the root tenant can reach beyond its own tenant. This part of the binding grants nothing.">not in effect beyond its tenant</span>"#
            }
            _ => "",
        };
        let revoke = if may_write {
            format!(
                r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{BINDING}" value="{id}">
<button class="danger" type="submit" name="{field}" value="{op}">Revoke</button></form>"#,
                url = e(&url),
                id = e(&b.id),
                field = RoleOp::FIELD,
                op = RoleOp::Revoke.as_str(),
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{who}</td><td>{home_cell}</td><td>{kind}</td><td>{role}</td><td>{scope}{beyond}</td><td>{revoke}</td></tr>",
            who = e(&who),
            kind = e(b.principal_type.as_str()),
            role = e(b.role.display_name()),
            scope = scope_cell(b, &tenants),
        ));
    }

    let grant = if may_write {
        let roles: String = RoleId::ALL
            .iter()
            .map(|r| format!(r#"<option value="{}">{}</option>"#, e(r.as_str()), e(r.display_name())))
            .collect();
        let boxes: String = tenants
            .iter()
            .map(|t| {
                format!(
                    r#"<label><input type="checkbox" name="{TENANT}" value="{id}"> {name}</label>"#,
                    id = e(&t.id),
                    name = e(&t.name),
                )
            })
            .collect();
        view::expander(
            "Grant a role",
            &format!(
                r#"<form method="post" action="{url}">{csrf}
<label for="account">Account</label><input id="account" name="{ACCOUNT}" type="email" required>
<p class="muted">An account in the root tenant, by its sign-in name. Accounts of other tenants are given
roles in their own tenant, from that tenant's Roles tab.</p>
<label for="role">Role</label><select id="role" name="{ROLE}">{roles}</select>
<fieldset class="choice"><legend>Where it applies</legend>
<label><input type="radio" name="{SCOPE}" value="{all}" checked> Every tenant, including ones added later</label>
<label><input type="radio" name="{SCOPE}" value="{some}" class="some"> Only these tenants</label>
<div class="when-some">{boxes}</div></fieldset>
<p class="muted">To grant a role to a group, use the Roles tab inside the root tenant.</p>
<div class="actions"><button type="submit" name="{field}" value="{op}">Grant role</button></div></form>"#,
                url = e(&url),
                all = e(ScopeKind::All.as_str()),
                some = e(ScopeKind::Tenants.as_str()),
                field = RoleOp::FIELD,
                op = RoleOp::Grant.as_str(),
            ),
            error.is_some(),
        )
    } else {
        r#"<p class="muted">Your roles allow seeing who administers the platform but not changing it.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>Platform roles</h1><p class="sub">Who can administer what, across every tenant. A role says what someone
may do; where it applies says in which tenants.</p>{error}
<table><tr><th>Who</th><th>Their tenant</th><th>Type</th><th>Role</th><th>Where it applies</th><th></th></tr>{rows}</table>{grant}"#,
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Platform(PlatformTab::Roles)),
        status,
        "Platform roles",
        &body,
    )
}

/// Where a binding applies, by tenant name. A tenant that no longer exists grants
/// nothing and is shown as such rather than as a bare id.
fn scope_cell(b: &StoredBinding, tenants: &[&Tenant]) -> String {
    match &b.scope {
        Scope::All => r#"<span class="pill good">every tenant</span>"#.to_string(),
        Scope::Tenants(ids) if ids.is_empty() => r#"<span class="muted">no live tenant</span>"#.to_string(),
        Scope::Tenants(ids) => ids
            .iter()
            .map(|id| match tenants.iter().find(|t| &t.id == id) {
                Some(t) => format!(r#"<span class="pill">{}</span>"#, e(&t.name)),
                None => format!(r#"<span class="pill">{}</span>"#, e(id)),
            })
            .collect(),
    }
}

/// Why a write did not happen.
enum Refusal {
    Forbidden,
    Message(String),
}

impl From<RefusedReason> for Refusal {
    fn from(reason: RefusedReason) -> Self {
        match reason {
            RefusedReason::NotPermitted => Refusal::Forbidden,
            RefusedReason::WouldLockOut => Refusal::Message(
                "That is the last binding that can administer the platform. Grant the platform role \
                 to somebody else first."
                    .into(),
            ),
        }
    }
}

pub async fn post(ctx: AdminContext, State(st): State<AppState>, body: Bytes) -> Response {
    let form = parse_form(&body);
    let Some(op) = RoleOp::parse(field(&form, RoleOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    if let Err(resp) = ctx.require(BINDING_WRITE, On::Platform) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let outcome = match op {
        RoleOp::Grant => grant(&st, &ctx, &body).await,
        RoleOp::Revoke => {
            let id = field(&form, BINDING).to_string();
            // One call, both rules: no widening, and no locking the platform out.
            authz::delete(&st.pool, ctx.bindings(), &id)
                .await
                .map(|()| (id, json!({})))
                .map_err(Refusal::from)
        }
    };
    match outcome {
        Ok((target, details)) => {
            // A change to who administers the platform belongs in the root
            // tenant's history: it is not an event of any one other tenant.
            let log_tenant = match tenant::root(&st.pool).await {
                Ok(Some(root)) => root.id,
                _ => ctx.home_tenant.id.clone(),
            };
            let event = match op {
                RoleOp::Grant => Event::AdminRoleGrant,
                RoleOp::Revoke => Event::AdminRoleRevoke,
            };
            audited(&st, &ctx, &log_tenant, event, Some(&target), details).await;
            view::see_other(&page_url(st.public_url.base()))
        }
        Err(Refusal::Message(m)) => render(&st, &ctx, Some(&m), StatusCode::BAD_REQUEST).await,
        Err(Refusal::Forbidden) => view::forbidden(),
    }
}

async fn grant(st: &AppState, ctx: &AdminContext, body: &[u8]) -> Result<(String, serde_json::Value), Refusal> {
    // Read from the raw body: the tenant field repeats once per tick, and the
    // console's usual form map keeps only one value per name.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
    let one = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.trim())
            .unwrap_or_default()
    };
    let account = one(ACCOUNT);
    let Some(role) = RoleId::parse(one(ROLE)) else {
        return Err(Refusal::Message("Choose a role.".into()));
    };
    let scope = match ScopeKind::parse(one(SCOPE)) {
        Some(ScopeKind::All) => Scope::All,
        Some(ScopeKind::Tenants) => {
            let mut ids: Vec<String> = Vec::new();
            for (_, value) in pairs.iter().filter(|(k, _)| k == TENANT) {
                // Resolved, so the binding names tenants that exist and never a
                // domain alias or a stray string.
                match tenant::resolve(&st.pool, value).await {
                    Ok(Some(t)) if !ids.contains(&t.id) => ids.push(t.id),
                    Ok(_) => {}
                    Err(_) => return Err(Refusal::Message("A tenant could not be looked up.".into())),
                }
            }
            if ids.is_empty() {
                return Err(Refusal::Message(
                    "Tick at least one tenant, or choose every tenant.".into(),
                ));
            }
            Scope::Tenants(ids)
        }
        None => return Err(Refusal::Message("Choose where the role applies.".into())),
    };
    // The rule: a binding write is authorized against the *target* scope, so no
    // principal can grant reach it does not already hold.
    if !authz::may_write_binding(ctx.bindings(), &scope) {
        return Err(Refusal::Forbidden);
    }
    if role == RoleId::PlatformAdministrator && scope != Scope::All {
        return Err(Refusal::Message(
            "The platform role only means anything across every tenant. Limited to some tenants it \
             would grant nothing."
                .into(),
        ));
    }

    // The account's tenant is the one that owns the part after the @.
    let Some((_, domain)) = account.rsplit_once('@') else {
        return Err(Refusal::Message(
            "Enter the account's full sign-in name, including the @ part.".into(),
        ));
    };
    let home = tenant::resolve(&st.pool, domain)
        .await
        .map_err(|_| Refusal::Message("That account could not be looked up.".into()))?;
    let user = match &home {
        Some(t) => crate::users::find_by_upn(&st.pool, &t.id, account)
            .await
            .map_err(|_| Refusal::Message("That account could not be looked up.".into()))?,
        None => None,
    };
    let Some(user) = user else {
        return Err(Refusal::Message(format!("There is no account named '{account}'.")));
    };

    let id = bindings::create(&st.pool, PrincipalType::User, &user.id, role, &scope, &ctx.user.id)
        .await
        .map_err(|e| Refusal::Message(e.to_string()))?;
    Ok((
        id,
        json!({
            "role": role.as_str(),
            "scopeKind": scope.kind().as_str(),
            "principalType": PrincipalType::User.as_str(),
            "principalId": user.id,
        }),
    ))
}
