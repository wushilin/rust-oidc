//! All roles: every role binding on the deployment, and granting or revoking them
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
use crate::rbac::{RoleId, Scope};
use crate::tenant::{self, Tenant};

/// Form field names, named once.
const ACCOUNT: &str = "account";
const ROLE: &str = "role";
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
        // Kept from before the rule, or written by hand: shown, and pointed out.
        let beyond = match home {
            Some(t) if b.role.scope_held_by(&t.id, t.is_root).as_ref() != Some(&b.scope) => {
                r#" <span class="pill bad" title="A role applies to the tenant its holder belongs to; only Global Administrator, held from the root tenant, covers more. Whatever this binding says beyond that grants nothing.">not in effect as written</span>"#
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
        let explained: String = RoleId::ALL
            .iter()
            .map(|r| format!("<dt>{}</dt><dd>{}</dd>", e(r.display_name()), e(r.summary())))
            .collect();
        view::expander(
            "Grant a role",
            &format!(
                r#"<form method="post" action="{url}">{csrf}
<label for="account">Account</label><input id="account" name="{ACCOUNT}" type="email" required>
<p class="muted">The account's full sign-in name. The part after the @ says which tenant it belongs to,
and that is the tenant the role applies to. Only Global Administrator covers more, and only an account
in the root tenant can hold it.</p>
<label for="role">Role</label><select id="role" name="{ROLE}">{roles}</select>
<dl class="roles">{explained}</dl>
<p class="muted">To grant a role to a group, use the Roles tab inside the group's tenant.</p>
<div class="actions"><button type="submit" name="{field}" value="{op}">Grant role</button></div></form>"#,
                url = e(&url),
                field = RoleOp::FIELD,
                op = RoleOp::Grant.as_str(),
            ),
            error.is_some(),
        )
    } else {
        r#"<p class="muted">Your roles allow seeing who administers the platform but not changing it.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>All roles</h1><p class="sub">Every role granted on this deployment. A Global Administrator can do
everything; every other role applies to the tenant its holder belongs to.</p>{error}
<table><tr><th>Who</th><th>Their tenant</th><th>Type</th><th>Role</th><th>Applies to</th><th></th></tr>{rows}</table>{grant}"#,
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Platform(PlatformTab::Roles)),
        status,
        "All roles",
        &body,
    )
}

/// Where a binding applies, by tenant name. A tenant that no longer exists grants
/// nothing and is shown as such rather than as a bare id.
fn scope_cell(b: &StoredBinding, tenants: &[&Tenant]) -> String {
    match &b.scope {
        Scope::All => r#"<span class="pill good">everything</span>"#.to_string(),
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
            RefusedReason::WouldLockOut => {
                Refusal::Message("That is the last Global Administrator. Make somebody else one first.".into())
            }
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

    // Where the role applies follows from the role and the account's tenant.
    let Some(scope) = home.as_ref().and_then(|t| role.scope_held_by(&t.id, t.is_root)) else {
        return Err(Refusal::Message(bindings::ScopeRefused::GlobalOutsideRoot.to_string()));
    };
    // A binding write is authorized against the *target* scope, so no principal
    // can grant reach it does not already hold.
    if !authz::may_write_binding(ctx.bindings(), &scope) {
        return Err(Refusal::Forbidden);
    }

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
