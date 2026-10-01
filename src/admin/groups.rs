//! The console's groups section: the list, creating one, and membership.
//!
//! A group is tenant-scoped, so every handler authorizes against the tenant in
//! the URL and every lookup is made inside it: `groups::find_by_id` takes the
//! tenant id, so a group's object id from another tenant resolves to nothing even
//! when it is guessed correctly.
//!
//! Membership matters beyond the `groups` claim: a console role binding may name
//! a **group** as its principal, so adding somebody to a group can hand them
//! administrative rights. The page says so where the button is.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{Params, audited, chrome, field, optional, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{GROUP_READ, GROUP_WRITE};
use crate::db::Event;
use crate::groups::{self, Group};
use crate::tenant::Tenant;

/// What a post to a group's page asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberOp {
    Add,
    Remove,
}

impl MemberOp {
    pub const ALL: &'static [MemberOp] = &[Self::Add, Self::Remove];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "member_add",
            Self::Remove => "member_remove",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    fn event(self) -> Event {
        match self {
            Self::Add => Event::AdminGroupMemberAdd,
            Self::Remove => Event::AdminGroupMemberRemove,
        }
    }
}

/// Form field names, spelled once.
const NAME: &str = "name";
const DESCRIPTION: &str = "description";
const UPN: &str = "upn";
const USER: &str = "user";

fn groups_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/groups", tenant.id)
}

fn group_url(base: &str, tenant: &Tenant, group: &Group) -> String {
    format!("{}/{}", groups_url(base, tenant), group.id)
}

// ---- the list ----

pub async fn list_page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(GROUP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    list(&st, &ctx, tenant, None, StatusCode::OK).await
}

async fn list(st: &AppState, ctx: &AdminContext, tenant: &Tenant, error: Option<&str>, status: StatusCode) -> Response {
    let listed = match groups::list(&st.pool, &tenant.id).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("group list failed: {err}");
            return view::server_error();
        }
    };
    let base = st.public_url.base();
    let rows: String = listed
        .iter()
        .map(|g| {
            format!(
                r#"<tr><td><a href="{url}">{name}</a></td><td>{description}</td><td class="muted">{id}</td></tr>"#,
                url = e(&group_url(base, tenant, g)),
                name = e(&g.name),
                description = e(g.description.as_deref().unwrap_or("")),
                id = e(&g.id),
            )
        })
        .collect();
    let create = if ctx.can_in(GROUP_WRITE, tenant) {
        format!(
            r#"<h2>Create a group</h2><form method="post" action="{url}">{csrf}
<label for="name">Name</label><input id="name" name="{NAME}" type="text" required>
<label for="description">Description</label><input id="description" name="{DESCRIPTION}" type="text">
<div class="actions"><button type="submit">Create</button></div>
<p class="muted">The name is what appears in the <code>groups</code> claim, and is unique within
the tenant regardless of case.</p></form>"#,
            url = e(&groups_url(base, tenant)),
            csrf = view::csrf_input(&ctx.csrf),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>Groups</h1><p class="sub">{tenant_name}</p>{error}
<table><tr><th>Name</th><th>Description</th><th>Object id</th></tr>{rows}</table>{create}"#,
        tenant_name = e(&tenant.name),
        error = view::error_block(error),
    );
    view::page(&chrome(st, ctx), status, "Groups", &body)
}

pub async fn create_group(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(resp) = ctx.require(GROUP_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let name = field(&form, NAME);
    match groups::create(&st.pool, tenant, name, optional(&form, DESCRIPTION)).await {
        Ok(id) => {
            audited(
                &st,
                &ctx,
                &tenant.id,
                Event::AdminGroupCreate,
                Some(&id),
                json!({ "name": crate::routes::audit::clip(name) }),
            )
            .await;
            view::see_other(&format!("{}/{id}", groups_url(st.public_url.base(), tenant)))
        }
        Err(err) => list(&st, &ctx, tenant, Some(&err.to_string()), StatusCode::BAD_REQUEST).await,
    }
}

// ---- one group ----

pub async fn detail_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, group_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = ctx.require(GROUP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    match groups::find_by_id(&st.pool, &tenant.id, &group_id).await {
        Ok(Some(group)) => detail(&st, &ctx, tenant, &group, None, StatusCode::OK).await,
        Ok(None) => view::not_found(),
        Err(err) => {
            tracing::error!("group lookup failed: {err}");
            view::server_error()
        }
    }
}

async fn detail(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    group: &Group,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let url = group_url(st.public_url.base(), tenant, group);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_write = ctx.can_in(GROUP_WRITE, tenant);
    let members = groups::members(&st.pool, &group.id).await.unwrap_or_default();

    let rows: String = members
        .iter()
        .map(|m| {
            format!(
                "<tr><td>{upn}</td><td class=\"muted\">{id}</td><td>{remove}</td></tr>",
                upn = e(&m.upn),
                id = e(&m.user_id),
                remove = if may_write {
                    format!(
                        r#"<form method="post" action="{url}" class="inline">{csrf}
<input type="hidden" name="{USER}" value="{id}">
<button class="danger" type="submit" name="{field}" value="{op}">Remove</button></form>"#,
                        url = e(&url),
                        id = e(&m.user_id),
                        field = MemberOp::FIELD,
                        op = MemberOp::Remove.as_str(),
                    )
                } else {
                    String::new()
                },
            )
        })
        .collect();

    let add = if may_write {
        format!(
            r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">
<label for="upn">User name</label><input id="upn" name="{UPN}" type="email" required>
<div class="actions"><button type="submit">Add member</button></div>
<p class="muted">An account of this tenant. A console role may be granted to a group, so adding
somebody to one can give them administrative rights -- check the roles page if in doubt.</p></form>"#,
            url = e(&url),
            field = MemberOp::FIELD,
            op = MemberOp::Add.as_str(),
        )
    } else {
        r#"<p class="muted">Your roles allow seeing this group but not changing its membership.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>{name}</h1><p class="sub">{tenant_name} &middot; object id {id}</p>{error}
<p>{description}</p>
<h2>Members</h2><table><tr><th>User name</th><th>Object id</th><th></th></tr>{rows}</table>{add}"#,
        name = e(&group.name),
        tenant_name = e(&tenant.name),
        id = e(&group.id),
        description = e(group.description.as_deref().unwrap_or("")),
        error = view::error_block(error),
    );
    view::page(&chrome(st, ctx), status, &group.name, &body)
}

pub async fn detail_post(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, group_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Some(op) = MemberOp::parse(field(&form, MemberOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    if let Err(resp) = ctx.require(GROUP_WRITE, On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let group = match groups::find_by_id(&st.pool, &tenant.id, &group_id).await {
        Ok(Some(g)) => g,
        Ok(None) => return view::not_found(),
        Err(err) => {
            tracing::error!("group lookup failed: {err}");
            return view::server_error();
        }
    };

    match apply(&st, tenant, &group, op, &form).await {
        Ok(details) => {
            audited(&st, &ctx, &tenant.id, op.event(), Some(&group.id), details).await;
            view::see_other(&group_url(st.public_url.base(), tenant, &group))
        }
        Err(err) => {
            detail(
                &st,
                &ctx,
                tenant,
                &group,
                Some(&err.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn apply(
    st: &AppState,
    tenant: &Tenant,
    group: &Group,
    op: MemberOp,
    form: &Params,
) -> anyhow::Result<serde_json::Value> {
    match op {
        MemberOp::Add => {
            let upn = field(form, UPN);
            groups::add_member_by_id(&st.pool, &tenant.id, &group.id, upn).await?;
            Ok(json!({ "upn": crate::routes::audit::clip(upn) }))
        }
        MemberOp::Remove => {
            let user_id = field(form, USER);
            if !groups::remove_member(&st.pool, &tenant.id, &group.id, user_id).await? {
                anyhow::bail!("that account is not a member of this group");
            }
            Ok(json!({ "userId": user_id }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for op in MemberOp::ALL {
            assert!(seen.insert(op.as_str()), "two operations are both {}", op.as_str());
            assert_eq!(MemberOp::parse(op.as_str()), Some(*op));
            assert!(seen.insert(op.event().as_str()), "{op:?} shares an event");
        }
        assert_eq!(MemberOp::parse("add"), None);
    }
}
