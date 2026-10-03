//! Global roles: who is a Global Administrator, and making or unmaking one.
//!
//! Only what is not bound to a tenant is here. A role inside a tenant is that
//! tenant's business and is on its own Roles tab, and nowhere else.
//!
//! The rules that make this safe are not implemented here. They are
//! [`authz::may_write_binding`] (nobody grants reach they do not hold),
//! [`bindings::create`] (the role is held from the root tenant) and
//! [`authz::delete`] (the last Global Administrator stays).

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
/// Whether a user or a group is being made a Global Administrator.
const PRINCIPAL_TYPE: &str = "principal_type";
const GROUP_NAME: &str = "group";
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
    let (stored, tenants) = match (global_bindings(st).await, tenant::list(&st.pool).await) {
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
        let revoke = if may_write {
            view::confirm_post(
                &view::dom_id(&["revoke", &b.id]),
                "Revoke\u{2026}",
                &format!("Revoke {} from {}?", b.role.display_name(), who),
                "It takes effect on their next request.",
                &url,
                &format!(r#"{csrf}<input type="hidden" name="{BINDING}" value="{}">"#, e(&b.id)),
                RoleOp::FIELD,
                RoleOp::Revoke.as_str(),
                "Revoke",
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{who}</td><td>{home_cell}</td><td>{kind}</td><td>{role}</td><td>{revoke}</td></tr>",
            who = e(&who),
            kind = e(b.principal_type.as_str()),
            role = e(b.role.display_name()),
        ));
    }

    let grant = if may_write {
        // The root tenant is where the role is held, so the user name ends in its
        // domain and the group is one of its groups: neither needs choosing.
        let root = tenant::root(&st.pool).await.ok().flatten();
        let root_name = root.as_ref().map(|t| t.name.clone()).unwrap_or_default();
        let root_domain = match &root {
            Some(t) => tenant::domains(&st.pool, &t.id)
                .await
                .ok()
                .and_then(|d| d.into_iter().next())
                .unwrap_or_default(),
            None => String::new(),
        };
        view::expander(
            "Make somebody a Global Administrator",
            &format!(
                r#"<form method="post" action="{url}" class="pick-principal" novalidate>{csrf}
<fieldset class="choice"><legend>Who</legend>
<label><input type="radio" name="{PRINCIPAL_TYPE}" value="{user}" checked> A user</label>
<label><input type="radio" name="{PRINCIPAL_TYPE}" value="{group}" class="is-group"> A group</label></fieldset>
<div class="when-user"><label for="account">User name</label>
<div class="upn"><input id="account" name="{ACCOUNT}" type="text" pattern="[^@]*" autocomplete="off" autocapitalize="none" spellcheck="false">
<span class="suffix">@ <strong>{root_domain}</strong></span></div></div>
<div class="when-group"><label for="group">Group name in {root_name}</label>
<input id="group" name="{GROUP_NAME}" type="text" autocomplete="off" spellcheck="false">
<p class="muted">Everyone in the group is a Global Administrator for as long as they are a member.</p></div>
<p class="muted">{summary} Only users and groups of the root tenant can hold it.</p>
<div class="actions"><button type="submit" name="{field}" value="{op}">Grant</button></div></form>"#,
                url = e(&url),
                user = e(PrincipalType::User.as_str()),
                group = e(PrincipalType::Group.as_str()),
                root_domain = e(&root_domain),
                root_name = e(&root_name),
                summary = e(RoleId::GlobalAdministrator.summary()),
                field = RoleOp::FIELD,
                op = RoleOp::Grant.as_str(),
            ),
            error.is_some(),
        )
    } else {
        r#"<p class="muted">Your roles allow seeing who administers the deployment but not changing it.</p>"#
            .to_string()
    };

    let body = format!(
        r#"<h1>Global roles</h1><p class="sub">Who can do everything on this deployment: tenants, signing keys, and
everything inside every tenant. Roles inside a tenant are on that tenant's Roles tab.</p>{error}
<table><tr><th>Who</th><th>Their tenant</th><th>Type</th><th>Role</th><th></th></tr>{rows}</table>{grant}"#,
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Platform(PlatformTab::Roles)),
        status,
        "Global roles",
        &body,
    )
}

/// The bindings that are not bound to a tenant: the only ones this page shows,
/// and the only ones it will revoke.
async fn global_bindings(st: &AppState) -> anyhow::Result<Vec<StoredBinding>> {
    Ok(bindings::list_all(&st.pool)
        .await?
        .into_iter()
        .filter(|b| b.scope == Scope::All)
        .collect())
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
            // Only what this page lists: a tenant's binding is revoked in that tenant.
            match global_bindings(&st).await {
                Ok(listed) if listed.iter().any(|b| b.id == id) => {}
                Ok(_) => return view::forbidden(),
                Err(err) => {
                    tracing::error!("global roles could not be listed: {err}");
                    return view::server_error();
                }
            }
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
    // The one role this page grants. A form that names another is asking for a
    // tenant role, which is granted in the tenant.
    let role = RoleId::GlobalAdministrator;
    if !matches!(one(ROLE), "" | "GlobalAdministrator") {
        return Err(Refusal::Message(
            "A role inside a tenant is granted from that tenant's Roles tab.".into(),
        ));
    }
    // A user (the default, and what older forms sent) or a group, each of the
    // root tenant, which is where the role is held.
    let Some(root) = tenant::root(&st.pool)
        .await
        .map_err(|_| Refusal::Message("The root tenant could not be looked up.".into()))?
    else {
        return Err(Refusal::Message("There is no root tenant.".into()));
    };
    let lookup_failed = |_| Refusal::Message("That could not be looked up.".to_string());
    let (principal_type, principal_id, home) = match PrincipalType::parse(one(PRINCIPAL_TYPE)) {
        None | Some(PrincipalType::User) => {
            let typed = one(ACCOUNT);
            if typed.is_empty() {
                return Err(Refusal::Message("Enter a user name.".into()));
            }
            // The part before the @ is completed with the root tenant's domain;
            // a full name is taken as typed, and its domain decides its tenant.
            let account = if typed.contains('@') {
                typed.to_string()
            } else {
                let domain = tenant::domains(&st.pool, &root.id)
                    .await
                    .map_err(lookup_failed)?
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                format!("{typed}@{domain}")
            };
            let (_, domain) = account.rsplit_once('@').unwrap_or_default();
            let home = tenant::resolve(&st.pool, domain).await.map_err(lookup_failed)?;
            let user = match &home {
                Some(t) => crate::users::find_by_upn(&st.pool, &t.id, &account)
                    .await
                    .map_err(lookup_failed)?,
                None => None,
            };
            let Some(user) = user else {
                return Err(Refusal::Message(format!("There is no account named '{account}'.")));
            };
            (PrincipalType::User, user.id, home)
        }
        Some(PrincipalType::Group) => {
            let name = one(GROUP_NAME);
            if name.is_empty() {
                return Err(Refusal::Message("Enter a group name.".into()));
            }
            let Some(id) = crate::groups::find(&st.pool, &root.id, name)
                .await
                .map_err(lookup_failed)?
            else {
                return Err(Refusal::Message(format!(
                    "There is no group named '{name}' in {}.",
                    root.name
                )));
            };
            (PrincipalType::Group, id, Some(root.clone()))
        }
        Some(PrincipalType::ServicePrincipal) => {
            return Err(Refusal::Message("Choose a user or a group.".into()));
        }
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
