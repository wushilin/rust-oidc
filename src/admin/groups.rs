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

use crate::AppState;
use crate::admin::bulk;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, Settled, TenantTab, chrome, field, optional, parse_form, row_problem, settle};
use crate::admin::view::{self, e};
use crate::admin::{GROUP_READ, GROUP_WRITE};
use crate::groups::{self, Group};
use crate::tenant::Tenant;
use crate::txn::ops::groups::{AddGroupMember, CreateGroup, DeleteGroup, RemoveGroupMember};
use crate::txn::{self, ops::Account};

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
<div class="bulk">{delete}</div>"#,
            url = e(&groups_url(base, tenant)),
            csrf = view::csrf_input(&ctx.csrf),
            delete = bulk::ask(
                BULK_GROUPS,
                GroupListOp::FIELD,
                GroupListOp::Delete.as_str(),
                "danger",
                "Delete\u{2026}",
                "Delete the ticked groups?",
                r#"<p>Only groups with no members are deleted; the others are left and listed. Roles granted to a deleted group go with it.</p>"#,
                "Delete",
            ),
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
    let create = CreateGroup {
        tenant_id: tenant.id.clone(),
        name: field(&form, NAME).to_string(),
        description: optional(&form, DESCRIPTION).map(str::to_string),
    };
    match settle(txn::run(&st.pool, &ctx.actor(), &create).await) {
        Settled::Done(id) => view::see_other(&format!("{}/{id}", groups_url(st.public_url.base(), tenant))),
        Settled::Refused(message) => list(&st, &ctx, tenant, Some(&message), StatusCode::BAD_REQUEST).await,
        Settled::Respond(resp) => resp,
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
    let mut tally = bulk::Tally::default();
    for group in chosen {
        let delete = DeleteGroup {
            tenant_id: tenant.id.clone(),
            group_id: group.id.clone(),
        };
        match row_problem(&txn::run(&st.pool, &ctx.actor(), &delete).await) {
            None => tally.done += 1,
            Some(why) => tally.refuse(&group.name, why),
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
<div class="bulk">{remove}</div>"#,
            url = e(&url),
            remove = bulk::ask(
                BULK_MEMBERS,
                MemberOp::FIELD,
                MemberOp::Remove.as_str(),
                "danger",
                "Remove from group\u{2026}",
                "Remove the ticked members from this group?",
                r#"<p>They lose whatever this group gives them: roles, and access to applications assigned to it.</p>"#,
                "Remove",
            ),
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
{button}"#,
            button = view::confirm_post(
                "delete-group",
                "Delete this group\u{2026}",
                &format!("Delete the group {}?", group.name),
                "Roles granted to it go with it.",
                &url,
                &csrf,
                MemberOp::FIELD,
                MemberOp::DeleteGroup.as_str(),
                "Delete",
            ),
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

    match apply(&st, &ctx, tenant, &group, op, &form, &body).await {
        Settled::Done(()) => {
            // A deleted group has no page to go back to.
            if op == MemberOp::DeleteGroup {
                view::see_other(&groups_url(st.public_url.base(), tenant))
            } else {
                view::see_other(&group_url(st.public_url.base(), tenant, &group))
            }
        }
        Settled::Refused(message) => detail(&st, &ctx, tenant, &group, Some(&message), StatusCode::BAD_REQUEST).await,
        Settled::Respond(resp) => resp,
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

/// Carry out one operation on the group: a transaction per member added or
/// removed, so each completes or is refused on its own and the page lists the
/// refusals. Anything but done is what to show instead of going back to the group.
async fn apply(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    group: &Group,
    op: MemberOp,
    form: &Params,
    body: &[u8],
) -> Settled<()> {
    let actor = ctx.actor();
    let refused = |m: &str| Settled::Refused(m.to_string());
    // Every row done is done; otherwise the page lists what was not.
    let finished = |problem: Option<String>| problem.map_or(Settled::Done(()), Settled::Refused);
    let mut tally = bulk::Tally::default();
    match op {
        MemberOp::Add => {
            // The box for several, or the single field older forms sent.
            let typed = match field(form, UPNS) {
                "" => field(form, UPN),
                several => several,
            };
            let wanted = names(typed);
            if wanted.is_empty() {
                return refused("Enter at least one user name.");
            }
            for upn in wanted {
                let add = AddGroupMember {
                    tenant_id: tenant.id.clone(),
                    group_id: group.id.clone(),
                    account: Account::Upn(upn.to_string()),
                };
                match row_problem(&txn::run(&st.pool, &actor, &add).await) {
                    None => tally.done += 1,
                    Some(why) => tally.refuse(upn, why),
                }
            }
            finished(tally.problem("added"))
        }
        MemberOp::Remove => {
            let members = match groups::members(&st.pool, &group.id).await {
                Ok(m) => m,
                Err(err) => {
                    tracing::error!("group members lookup failed: {err}");
                    return Settled::Respond(view::server_error());
                }
            };
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
                    return refused(bulk::NOTHING_TICKED);
                }
                return refused("That account is not a member of this group.");
            }
            for member in chosen {
                let remove = RemoveGroupMember {
                    tenant_id: tenant.id.clone(),
                    group_id: group.id.clone(),
                    user_id: member.user_id.clone(),
                };
                match row_problem(&txn::run(&st.pool, &actor, &remove).await) {
                    None => tally.done += 1,
                    Some(why) => tally.refuse(&member.upn, why),
                }
            }
            finished(tally.problem("removed"))
        }
        MemberOp::DeleteGroup => {
            let delete = DeleteGroup {
                tenant_id: tenant.id.clone(),
                group_id: group.id.clone(),
            };
            match settle(txn::run(&st.pool, &actor, &delete).await) {
                Settled::Done(_) => Settled::Done(()),
                Settled::Refused(m) => Settled::Refused(m),
                Settled::Respond(r) => Settled::Respond(r),
            }
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
        }
        assert_eq!(MemberOp::parse("add"), None);
    }
}
