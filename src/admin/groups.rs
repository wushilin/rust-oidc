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
use crate::admin::bulk;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, TenantTab, audited, chrome, field, optional, parse_form};
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
    /// Delete the group itself. Only an empty one: see [`groups::delete`].
    DeleteGroup,
}

impl MemberOp {
    pub const ALL: &'static [MemberOp] = &[Self::Add, Self::Remove, Self::DeleteGroup];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "member_add",
            Self::Remove => "member_remove",
            Self::DeleteGroup => "group_delete",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    fn event(self) -> Event {
        match self {
            Self::Add => Event::AdminGroupMemberAdd,
            Self::Remove => Event::AdminGroupMemberRemove,
            Self::DeleteGroup => Event::AdminGroupDelete,
        }
    }
}

/// Form field names, spelled once.
const NAME: &str = "name";
const DESCRIPTION: &str = "description";
const UPN: &str = "upn";
const USER: &str = "user";
/// Several user names at once, one per line or separated by commas.
const UPNS: &str = "upns";
/// The forms the tick boxes of the two tables belong to.
const BULK_GROUPS: &str = "bulk-groups";
const BULK_MEMBERS: &str = "bulk-members";

/// What a post to the list of groups asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupListOp {
    Create,
    /// Delete the ticked groups. Only empty ones: see [`groups::delete`].
    Delete,
}

impl GroupListOp {
    pub const ALL: &'static [GroupListOp] = &[Self::Create, Self::Delete];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }
}

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
    let may_write = ctx.can_in(GROUP_WRITE, tenant);
    let rows: String = listed
        .iter()
        .map(|g| {
            format!(
                r#"<tr>{tick}<td><a href="{url}">{name}</a></td><td>{description}</td><td class="muted">{id}</td></tr>"#,
                tick = if may_write {
                    bulk::cell(BULK_GROUPS, &g.id, &g.name)
                } else {
                    String::new()
                },
                url = e(&group_url(base, tenant, g)),
                name = e(&g.name),
                description = e(g.description.as_deref().unwrap_or("")),
                id = e(&g.id),
            )
        })
        .collect();
    let create = if ctx.can_in(GROUP_WRITE, tenant) {
        view::expander(
            "Create a group",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">
<label for="name">Name</label><input id="name" name="{NAME}" type="text" required>
<label for="description">Description</label><input id="description" name="{DESCRIPTION}" type="text">
<div class="actions"><button type="submit">Create</button></div>
<p class="muted">The name is what appears in the <code>groups</code> claim, and is unique within
the tenant regardless of case.</p></form>"#,
                url = e(&groups_url(base, tenant)),
                csrf = view::csrf_input(&ctx.csrf),
                field = GroupListOp::FIELD,
                op = GroupListOp::Create.as_str(),
            ),
            false,
        )
    } else {
        String::new()
    };
    let actions = if may_write && !listed.is_empty() {
        format!(
            r#"<form id="{BULK_GROUPS}" method="post" action="{url}">{csrf}</form>
<div class="bulk"><span>With the ticked groups:</span>{confirm}
<button class="danger" type="submit" form="{BULK_GROUPS}" name="{field}" value="{op}">Delete</button>
<span>A group is deleted only once it has no members.</span></div>"#,
            url = e(&groups_url(base, tenant)),
            csrf = view::csrf_input(&ctx.csrf),
            confirm = bulk::confirm(BULK_GROUPS),
            field = GroupListOp::FIELD,
            op = GroupListOp::Delete.as_str(),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>Groups</h1><p class="sub">{tenant_name}</p>{error}
<table><tr>{head}<th>Name</th><th>Description</th><th>Object id</th></tr>{rows}</table>{actions}{create}"#,
        head = if may_write {
            bulk::head(BULK_GROUPS)
        } else {
            String::new()
        },
        tenant_name = e(&tenant.name),
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Groups)),
        status,
        "Groups",
        &body,
    )
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
    // A form without the field is the create form of an older page.
    let op = match field(&form, GroupListOp::FIELD) {
        "" => GroupListOp::Create,
        raw => match GroupListOp::parse(raw) {
            Some(op) => op,
            None => return view::bad_request("That is not an operation this page offers."),
        },
    };
    if op == GroupListOp::Delete {
        return delete_ticked(&st, &ctx, tenant, &body).await;
    }
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

/// Delete every ticked group that can be deleted, and say which could not.
async fn delete_ticked(st: &AppState, ctx: &AdminContext, tenant: &Tenant, body: &[u8]) -> Response {
    let listed = match groups::list(&st.pool, &tenant.id).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("group list failed: {err}");
            return view::server_error();
        }
    };
    let ticked = bulk::Selection::read(body);
    let chosen = ticked.among(&listed, |g| g.id.as_str());
    if chosen.is_empty() {
        return list(st, ctx, tenant, Some(bulk::NOTHING_TICKED), StatusCode::BAD_REQUEST).await;
    }
    if !ticked.confirmed {
        return list(st, ctx, tenant, Some(bulk::NOT_CONFIRMED), StatusCode::BAD_REQUEST).await;
    }
    let mut tally = bulk::Tally::default();
    for group in chosen {
        match groups::delete(&st.pool, &tenant.id, &group.id).await {
            Ok(_) => {
                audited(
                    st,
                    ctx,
                    &tenant.id,
                    Event::AdminGroupDelete,
                    Some(&group.id),
                    json!({ "name": crate::routes::audit::clip(&group.name) }),
                )
                .await;
                tally.done += 1;
            }
            Err(err) => tally.refuse(&group.name, err),
        }
    }
    match tally.problem("deleted") {
        Some(problem) => list(st, ctx, tenant, Some(&problem), StatusCode::BAD_REQUEST).await,
        None => view::see_other(&groups_url(st.public_url.base(), tenant)),
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
                "<tr>{tick}<td>{upn}</td><td class=\"muted\">{id}</td></tr>",
                tick = if may_write {
                    bulk::cell(BULK_MEMBERS, &m.user_id, &m.upn)
                } else {
                    String::new()
                },
                upn = e(&m.upn),
                id = e(&m.user_id),
            )
        })
        .collect();
    let remove = if may_write && !members.is_empty() {
        format!(
            r#"<form id="{BULK_MEMBERS}" method="post" action="{url}">{csrf}</form>
<div class="bulk"><span>With the ticked members:</span>
<button class="danger" type="submit" form="{BULK_MEMBERS}" name="{field}" value="{op}">Remove from group</button></div>"#,
            url = e(&url),
            field = MemberOp::FIELD,
            op = MemberOp::Remove.as_str(),
        )
    } else {
        String::new()
    };

    let add = if may_write {
        view::expander(
            "Add members",
            &format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">
<label for="upns">User names</label><textarea id="upns" name="{UPNS}" rows="4" required autocapitalize="none" spellcheck="false"></textarea>
<p class="muted">One or many, each on its own line or separated by commas. Accounts of this tenant.</p>
<div class="actions"><button type="submit">Add to group</button></div>
<p class="muted">A console role may be granted to a group, so adding somebody to one can give them
administrative rights -- check the roles page if in doubt. Several accounts can also be ticked on the
Users page and added from there.</p></form>"#,
                url = e(&url),
                field = MemberOp::FIELD,
                op = MemberOp::Add.as_str(),
            ),
            false,
        )
    } else {
        r#"<p class="muted">Your roles allow seeing this group but not changing its membership.</p>"#.to_string()
    };

    let delete = if !may_write {
        String::new()
    } else if members.is_empty() {
        format!(
            r#"<h2>Delete</h2><p>The group has no members. Deleting it also withdraws any console role or
application role granted to it.</p>
<form method="post" action="{url}">{csrf}
<div class="actions"><button class="danger" type="submit" name="{field}" value="{op}">Delete this group</button></div></form>"#,
            url = e(&url),
            field = MemberOp::FIELD,
            op = MemberOp::DeleteGroup.as_str(),
        )
    } else {
        r#"<h2>Delete</h2><p class="muted">A group can be deleted once it has no members.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>{name}</h1><p class="sub">{tenant_name} &middot; object id {id}</p>{error}
<p>{description}</p>
<h2>Members</h2><table><tr>{head}<th>User name</th><th>Object id</th></tr>{rows}</table>{remove}{add}{delete}"#,
        head = if may_write {
            bulk::head(BULK_MEMBERS)
        } else {
            String::new()
        },
        name = e(&group.name),
        tenant_name = e(&tenant.name),
        id = e(&group.id),
        description = e(group.description.as_deref().unwrap_or("")),
        error = view::error_block(error),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Groups)),
        status,
        &group.name,
        &body,
    )
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

    match apply(&st, tenant, &group, op, &form, &body).await {
        Ok(details) => {
            audited(&st, &ctx, &tenant.id, op.event(), Some(&group.id), details).await;
            // A deleted group has no page to go back to.
            if op == MemberOp::DeleteGroup {
                view::see_other(&groups_url(st.public_url.base(), tenant))
            } else {
                view::see_other(&group_url(st.public_url.base(), tenant, &group))
            }
        }
        Err(err) => {
            if let Some(partial) = err.downcast_ref::<Partial>() {
                audited(
                    &st,
                    &ctx,
                    &tenant.id,
                    op.event(),
                    Some(&group.id),
                    partial.details.clone(),
                )
                .await;
            }
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

/// The user names in a box that takes several: split on lines, commas,
/// semicolons and spaces, without repeats.
fn names(raw: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for name in raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

async fn apply(
    st: &AppState,
    tenant: &Tenant,
    group: &Group,
    op: MemberOp,
    form: &Params,
    body: &[u8],
) -> anyhow::Result<serde_json::Value> {
    match op {
        MemberOp::Add => {
            // The box for several, or the single field older forms sent.
            let typed = match field(form, UPNS) {
                "" => field(form, UPN),
                several => several,
            };
            let wanted = names(typed);
            if wanted.is_empty() {
                anyhow::bail!("enter at least one user name");
            }
            let mut tally = bulk::Tally::default();
            let mut added = Vec::new();
            for upn in wanted {
                match groups::add_member_by_id(&st.pool, &tenant.id, &group.id, upn).await {
                    Ok(()) => {
                        tally.done += 1;
                        added.push(crate::routes::audit::clip(upn));
                    }
                    Err(err) => tally.refuse(upn, err),
                }
            }
            match tally.problem("added") {
                // Nothing was added at all: the whole request failed.
                Some(problem) if tally.done == 0 => anyhow::bail!(problem),
                // Some were: they stay added, and the rest are reported.
                Some(problem) => Err(Partial {
                    problem,
                    details: json!({ "upns": added }),
                }
                .into()),
                None => Ok(json!({ "upns": added })),
            }
        }
        MemberOp::Remove => {
            let members = groups::members(&st.pool, &group.id).await?;
            let ticked = bulk::Selection::read(body);
            let mut chosen: Vec<&groups::Member> = ticked.among(&members, |m| m.user_id.as_str());
            // The single field a one-row form sends.
            let one = field(form, USER);
            if let Some(m) = members.iter().find(|m| m.user_id == one)
                && !chosen.iter().any(|c| c.user_id == one)
            {
                chosen.push(m);
            }
            if chosen.is_empty() {
                if one.is_empty() {
                    anyhow::bail!(bulk::NOTHING_TICKED);
                }
                anyhow::bail!("that account is not a member of this group");
            }
            let mut tally = bulk::Tally::default();
            let mut removed = Vec::new();
            for member in chosen {
                match groups::remove_member(&st.pool, &tenant.id, &group.id, &member.user_id).await {
                    Ok(_) => {
                        tally.done += 1;
                        removed.push(member.user_id.clone());
                    }
                    Err(err) => tally.refuse(&member.upn, err),
                }
            }
            match tally.problem("removed") {
                Some(problem) if tally.done == 0 => anyhow::bail!(problem),
                Some(problem) => Err(Partial {
                    problem,
                    details: json!({ "userIds": removed }),
                }
                .into()),
                None => Ok(json!({ "userIds": removed })),
            }
        }
        MemberOp::DeleteGroup => {
            groups::delete(&st.pool, &tenant.id, &group.id).await?;
            Ok(json!({ "name": crate::routes::audit::clip(&group.name) }))
        }
    }
}

/// Some of the rows were done and some were not. What was done is recorded like
/// any other change; the page reports the rest.
#[derive(Debug, thiserror::Error)]
#[error("{problem}")]
struct Partial {
    problem: String,
    details: serde_json::Value,
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
