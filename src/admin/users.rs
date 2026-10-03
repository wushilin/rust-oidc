//! The console's users section: list, create, edit, enable/disable, reset and
//! soft delete.
//!
//! Every handler authorizes against the tenant *in the URL*, not against the
//! assumed or home tenant, so there is no path through these pages that reads or
//! writes a tenant the administrator's bindings do not cover. The domain
//! functions in [`crate::users`] take the tenant id in their `WHERE` as a second
//! line of defence.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::bulk;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Params, TenantTab, audited, checked, chrome, field, optional, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{GROUP_READ, GROUP_WRITE, USER_READ, USER_RESET, USER_WRITE};
use crate::db::Event;
use crate::tenant::Tenant;
use crate::users::{self, User, UserAttributes};

/// What a post to the user detail page asks for. An enum rather than a bare
/// string so a new operation cannot be added without deciding which action
/// authorizes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserOp {
    Attributes,
    Enable,
    Disable,
    Reset,
    Delete,
    /// Set which of the tenant's groups the account is in.
    Groups,
    /// Their own MFA setting: Default, Required or Not required.
    MfaPolicy,
    /// Remove their authenticator and recovery codes.
    MfaReset,
}

impl UserOp {
    pub const ALL: &'static [UserOp] = &[
        Self::Attributes,
        Self::Enable,
        Self::Disable,
        Self::Reset,
        Self::Delete,
        Self::Groups,
        Self::MfaPolicy,
        Self::MfaReset,
    ];

    /// The form's `op` field.
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attributes => "attributes",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Reset => "reset",
            Self::Delete => "delete",
            Self::Groups => "groups",
            Self::MfaPolicy => "mfa_policy",
            Self::MfaReset => "mfa_reset",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// The action that authorizes it. Resetting a password is its own verb,
    /// because a help desk can hold it without being able to edit the directory.
    fn action(self) -> crate::rbac::Action {
        match self {
            // Removing an authenticator is a reset of a credential, like a password.
            Self::Reset | Self::MfaReset => USER_RESET,
            Self::MfaPolicy => USER_WRITE,
            Self::Attributes | Self::Enable | Self::Disable | Self::Delete => USER_WRITE,
            // Who is in a group is the group's to change.
            Self::Groups => GROUP_WRITE,
        }
    }

    fn event(self) -> Event {
        match self {
            Self::Attributes => Event::AdminUserUpdate,
            Self::Enable => Event::AdminUserEnable,
            Self::Disable => Event::AdminUserDisable,
            Self::Reset => Event::AdminUserReset,
            Self::Delete => Event::AdminUserDelete,
            // Recorded per group joined or left, not as one entry: see `detail_post`.
            Self::Groups => Event::AdminGroupMemberAdd,
            Self::MfaPolicy => Event::AdminUserMfaPolicy,
            Self::MfaReset => Event::AdminUserMfaReset,
        }
    }
}

/// Whether a password an administrator sets must be replaced at next sign-in.
const REQUIRE_CHANGE: &str = "require_change";

/// The user's MFA setting on their page.
const MFA_POLICY: &str = "mfa_policy";

/// The search box's query parameter.
const QUERY_PARAM: &str = "q";

fn users_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/users", tenant.id)
}

// ---- list ----

/// What the users list can do to the rows ticked on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserListOp {
    Enable,
    Disable,
    Delete,
    AddToGroup,
}

impl UserListOp {
    pub const ALL: &'static [UserListOp] = &[Self::Enable, Self::Disable, Self::Delete, Self::AddToGroup];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Delete => "delete",
            Self::AddToGroup => "add_to_group",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// Membership is the group's to change, the rest are changes to the account.
    fn action(self) -> crate::rbac::Action {
        match self {
            Self::Enable | Self::Disable | Self::Delete => USER_WRITE,
            Self::AddToGroup => GROUP_WRITE,
        }
    }

    /// How the page reports the rows it did.
    fn done_as(self) -> &'static str {
        match self {
            Self::Enable => "enabled",
            Self::Disable => "disabled",
            Self::Delete => "deleted",
            Self::AddToGroup => "added to the group",
        }
    }
}

/// The id of the form the tick boxes and buttons of the list belong to.
const BULK_FORM: &str = "bulk-users";
/// The group picked for "add to group".
const GROUP: &str = "group";

pub async fn list_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    Query(query): Query<Params>,
) -> Response {
    if let Err(resp) = ctx.require(USER_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let search = query.get(QUERY_PARAM).map(String::as_str).unwrap_or_default();
    list(&st, &ctx, tenant, search, None, StatusCode::OK).await
}

/// The accounts the list shows for a search: what "all" means on that page.
async fn listed(st: &AppState, tenant: &Tenant, search: &str) -> anyhow::Result<Vec<User>> {
    users::list(
        &st.pool,
        &tenant.id,
        Some(search).filter(|s| !s.is_empty()),
        users::LIST_LIMIT,
        0,
    )
    .await
}

async fn list(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    search: &str,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let found = match listed(st, tenant, search).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("user list failed: {err}");
            return view::server_error();
        }
    };
    let base = st.public_url.base();
    let may_write = ctx.can_in(USER_WRITE, tenant);
    let may_group = ctx.can_in(GROUP_WRITE, tenant);
    let ticks = may_write || may_group;
    let rows: String = found
        .iter()
        .map(|u| {
            format!(
                r#"<tr>{tick}<td><a href="{url}/{id}">{upn}</a></td><td>{name}</td><td>{state}</td></tr>"#,
                tick = if ticks {
                    bulk::cell(BULK_FORM, &u.id, &u.upn)
                } else {
                    String::new()
                },
                url = e(&users_url(base, tenant)),
                id = e(&u.id),
                upn = e(&u.upn),
                name = e(u.display_name.as_deref().unwrap_or("")),
                state = if u.enabled {
                    "Enabled"
                } else {
                    r#"<span class="pill">disabled</span>"#
                },
            )
        })
        .collect();
    // The create link is emitted only where the action is permitted, so the
    // console never offers what the guard would refuse.
    let create = if may_write {
        format!(
            r#"<a class="button" href="{}/new">New user</a>"#,
            e(&users_url(base, tenant))
        )
    } else {
        String::new()
    };
    let full = if found.len() as i64 >= users::LIST_LIMIT {
        format!(
            r#"<p class="muted">Showing the first {} accounts. Narrow the search to see others.</p>"#,
            users::LIST_LIMIT
        )
    } else {
        String::new()
    };
    // What can be done to the ticked rows. Each button is there only with the
    // action that permits it.
    let actions = if ticks && !found.is_empty() {
        let field = UserListOp::FIELD;
        let mut parts: Vec<String> = Vec::new();
        if may_write {
            parts.push(bulk::button(
                BULK_FORM,
                field,
                UserListOp::Enable.as_str(),
                "secondary",
                "Enable sign-in",
            ));
            parts.push(bulk::button(
                BULK_FORM,
                field,
                UserListOp::Disable.as_str(),
                "secondary",
                "Disable sign-in",
            ));
        }
        if may_group {
            let groups = crate::groups::list(&st.pool, &tenant.id).await.unwrap_or_default();
            if !groups.is_empty() {
                let options: String = groups
                    .iter()
                    .map(|g| format!(r#"<option value="{}">{}</option>"#, e(&g.id), e(&g.name)))
                    .collect();
                parts.push(bulk::ask(
                    BULK_FORM,
                    field,
                    UserListOp::AddToGroup.as_str(),
                    "",
                    "Add to group\u{2026}",
                    "Add the ticked accounts to a group",
                    &format!(
                        r#"<label for="bulk-group">Group</label><select id="bulk-group" name="{GROUP}" form="{BULK_FORM}">{options}</select>"#
                    ),
                    "Add to group",
                ));
            }
        }
        if may_write {
            parts.push(bulk::ask(
                BULK_FORM,
                field,
                UserListOp::Delete.as_str(),
                "danger",
                "Delete\u{2026}",
                "Delete the ticked accounts?",
                r#"<p>They can no longer sign in, and their sessions end. An administrator can restore a deleted account.</p>"#,
                "Delete",
            ));
        }
        format!(
            r#"<form id="{BULK_FORM}" method="post" action="{url}">{csrf}<input type="hidden" name="{QUERY_PARAM}" value="{search}"></form>
<div class="bulk">{parts}</div>"#,
            url = e(&users_url(base, tenant)),
            csrf = view::csrf_input(&ctx.csrf),
            search = e(search),
            parts = parts.concat(),
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1>Users</h1><p class="sub">The accounts that can sign in to this tenant.</p>{error}
<div class="toolbar"><form method="get" action="{url}">
<input id="q" name="{QUERY_PARAM}" type="search" value="{search}" placeholder="Name or user name" aria-label="Search by name or user name">
<button class="secondary" type="submit">Search</button></form>{create}</div>
<table><tr>{head}<th>User name</th><th>Name</th><th>State</th></tr>{rows}</table>{actions}{full}"#,
        error = view::error_block(error),
        url = e(&users_url(base, tenant)),
        search = e(search),
        head = if ticks { bulk::head(BULK_FORM) } else { String::new() },
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Users)),
        status,
        "Users",
        &body,
    )
}

/// Do one thing to every ticked account.
pub async fn list_post(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Some(op) = UserListOp::parse(field(&form, UserListOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    if let Err(resp) = ctx.require(op.action(), On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let search = field(&form, QUERY_PARAM);
    let found = match listed(&st, tenant, search).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("user list failed: {err}");
            return view::server_error();
        }
    };
    let ticked = bulk::Selection::read(&body);
    let chosen = ticked.among(&found, |u| u.id.as_str());
    if chosen.is_empty() {
        return list(
            &st,
            &ctx,
            tenant,
            search,
            Some(bulk::NOTHING_TICKED),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    let group = field(&form, GROUP);
    let mut tally = bulk::Tally::default();
    for user in chosen {
        // The same operations, rules and audit entries as on the account's own page.
        let outcome = match op {
            UserListOp::Enable => apply_checked(&st, &ctx, tenant, user, UserOp::Enable, &form, &[]).await,
            UserListOp::Disable => apply_checked(&st, &ctx, tenant, user, UserOp::Disable, &form, &[]).await,
            UserListOp::Delete => apply_checked(&st, &ctx, tenant, user, UserOp::Delete, &form, &[]).await,
            UserListOp::AddToGroup => crate::groups::add_member_id(&st.pool, &tenant.id, group, &user.id)
                .await
                .map(|()| json!({ "upn": crate::routes::audit::clip(&user.upn) })),
        };
        match outcome {
            Ok(details) => {
                let (event, target) = match op {
                    UserListOp::Enable => (Event::AdminUserEnable, user.id.as_str()),
                    UserListOp::Disable => (Event::AdminUserDisable, user.id.as_str()),
                    UserListOp::Delete => (Event::AdminUserDelete, user.id.as_str()),
                    UserListOp::AddToGroup => (Event::AdminGroupMemberAdd, group),
                };
                audited(&st, &ctx, &tenant.id, event, Some(target), details).await;
                tally.done += 1;
            }
            Err(err) => tally.refuse(&user.upn, err),
        }
    }
    match tally.problem(op.done_as()) {
        Some(problem) => list(&st, &ctx, tenant, search, Some(&problem), StatusCode::BAD_REQUEST).await,
        None => view::see_other(&format!(
            "{}?{}",
            users_url(st.public_url.base(), tenant),
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair(QUERY_PARAM, search)
                .finish()
        )),
    }
}

// ---- create ----

pub async fn new_page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(USER_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    new_user_page(&st, &ctx, tenant, &Params::new(), None, StatusCode::OK).await
}

/// Form field for the domain picked beside the user name.
const UPN_DOMAIN: &str = "upn_domain";

/// The sign-in name a new-user form asks for: what was typed, completed with the
/// domain picked beside it when it has no `@` of its own. Nothing is trusted
/// here; `users::create` checks the result against the tenant's verified domains.
fn submitted_upn(form: &Params) -> String {
    let typed = field(form, "upn").trim();
    if typed.is_empty() || typed.contains('@') {
        typed.to_string()
    } else {
        format!("{typed}@{}", field(form, UPN_DOMAIN).trim())
    }
}

async fn new_user_page(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    form: &Params,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let error = error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default();
    let domains = crate::tenant::domains(&st.pool, &tenant.id).await.unwrap_or_default();
    let chosen = field(form, UPN_DOMAIN);
    let options: String = domains
        .iter()
        .map(|d| {
            format!(
                r#"<option value="{d}"{sel}>{d}</option>"#,
                d = e(d),
                sel = if d == chosen { " selected" } else { "" },
            )
        })
        .collect();
    // A tenant has one domain, so there is nothing to pick. One that still has
    // several is offered them.
    let suffix = match domains.as_slice() {
        [only] => format!(
            r#"<strong>{d}</strong><input type="hidden" name="{UPN_DOMAIN}" value="{d}">"#,
            d = e(only)
        ),
        _ => format!(r#"<select name="{UPN_DOMAIN}" aria-label="Domain">{options}</select>"#),
    };
    // `novalidate`: the user-name box carries a pattern that a full name (one with
    // an @) does not match, purely so the stylesheet can hide the domain beside
    // it. The browser must not refuse to submit on that account. Everything is
    // checked again here, with a message that says what is wrong.
    let body = format!(
        r#"<h1>New user</h1><p class="sub">An account that can sign in to this tenant.</p>
<form method="post" action="{url}/new" novalidate>{csrf}
<label for="upn">User name</label>
<div class="upn"><input id="upn" name="upn" type="text" pattern="[^@]*" value="{upn}" autocomplete="off" autocapitalize="none" spellcheck="false" autofocus>
<span class="suffix">@ {suffix}</span></div>
<p class="muted">What the person signs in with. Type the part before the @; the tenant's domain is added.</p>
<label for="password">Initial password</label><input id="password" name="password" type="password" autocomplete="new-password">
<label><input type="checkbox" name="{REQUIRE_CHANGE}" checked> Require them to choose their own password at first sign-in</label>
<label for="display_name">Display name</label><input id="display_name" name="display_name" type="text" value="{display}">
<div class="fields">
<div><label for="given_name">Given name</label><input id="given_name" name="given_name" type="text" value="{given}"></div>
<div><label for="family_name">Family name</label><input id="family_name" name="family_name" type="text" value="{family}"></div>
</div>
<label for="email">Email address</label><input id="email" name="email" type="text" value="{email}">
<p class="muted">A contact address, <strong>not the sign-in name</strong>: it can be anything, and changing it
later does not change how the person signs in. Left empty, it is set to the user name.</p>
{error}<div class="actions"><button type="submit">Create user</button><a href="{url}">Cancel</a></div></form>"#,
        url = e(&users_url(st.public_url.base(), tenant)),
        csrf = view::csrf_input(&ctx.csrf),
        upn = e(field(form, "upn")),
        display = e(field(form, "display_name")),
        given = e(field(form, "given_name")),
        family = e(field(form, "family_name")),
        email = e(field(form, "email")),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Users)),
        status,
        "New user",
        &body,
    )
}

pub async fn create_user(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(resp) = ctx.require(USER_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let upn = submitted_upn(&form);
    let upn = upn.as_str();
    // An email address is a contact detail and is not required. Left empty it
    // starts out as the user name, which is the usual case and can be changed.
    let email = optional(&form, "email").or(Some(upn)).filter(|v| !v.is_empty());
    // `users::create` validates the UPN against the tenant's verified domains and
    // the password's length; its message names the problem.
    let created = users::create(
        &st.pool,
        tenant,
        users::NewUser {
            upn,
            password: field(&form, "password"),
            display_name: optional(&form, "display_name"),
            given_name: optional(&form, "given_name"),
            family_name: optional(&form, "family_name"),
            email,
        },
    )
    .await;
    let created = match created {
        Ok(user_id) if checked(&form, REQUIRE_CHANGE) => users::set_must_change_password(&st.pool, &user_id, true)
            .await
            .map(|()| user_id),
        other => other,
    };
    match created {
        Ok(user_id) => {
            audited(
                &st,
                &ctx,
                &tenant.id,
                Event::AdminUserCreate,
                Some(&user_id),
                json!({ "upn": crate::routes::audit::clip(upn) }),
            )
            .await;
            view::see_other(&format!("{}/{user_id}", users_url(st.public_url.base(), tenant)))
        }
        Err(err) => {
            new_user_page(
                &st,
                &ctx,
                tenant,
                &form,
                Some(&err.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

// ---- detail ----

pub async fn detail_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = ctx.require(USER_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    match users::find(&st.pool, &tenant.id, &user_id).await {
        Ok(Some(user)) => detail(&st, &ctx, tenant, &user, None, StatusCode::OK).await,
        Ok(None) => view::not_found(),
        Err(err) => {
            tracing::error!("user lookup failed: {err}");
            view::server_error()
        }
    }
}

async fn detail(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    user: &User,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let base = st.public_url.base();
    let url = format!("{}/{}", users_url(base, tenant), user.id);
    let csrf = view::csrf_input(&ctx.csrf);
    let may_write = ctx.can_in(USER_WRITE, tenant);
    let may_reset = ctx.can_in(USER_RESET, tenant);
    let error = error
        .map(|m| format!(r#"<p class="error" role="alert">{}</p>"#, e(m)))
        .unwrap_or_default();
    let disabled = if may_write { "" } else { " disabled" };

    let attributes = format!(
        r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{attrs}">
<label for="display_name">Display name</label><input id="display_name" name="display_name" type="text" value="{display}"{disabled}>
<label for="given_name">Given name</label><input id="given_name" name="given_name" type="text" value="{given}"{disabled}>
<label for="family_name">Family name</label><input id="family_name" name="family_name" type="text" value="{family}"{disabled}>
<label for="email">Email address</label><input id="email" name="email" type="text" value="{email}"{disabled}>
<p class="muted">A contact address, not the sign-in name.</p>
<label><input type="checkbox" name="email_verified"{verified}{disabled}> Email verified</label>
{save}</form>"#,
        url = e(&url),
        op_field = UserOp::FIELD,
        attrs = UserOp::Attributes.as_str(),
        display = e(user.display_name.as_deref().unwrap_or("")),
        given = e(user.given_name.as_deref().unwrap_or("")),
        family = e(user.family_name.as_deref().unwrap_or("")),
        email = e(user.email.as_deref().unwrap_or("")),
        verified = if user.email_verified { " checked" } else { "" },
        save = if may_write {
            r#"<div class="actions"><button type="submit">Save</button></div>"#
        } else {
            r#"<p class="muted">Your roles allow reading this user but not changing them.</p>"#
        },
    );

    let state = if may_write && user.id == ctx.user.id {
        r#"<h2>Sign-in</h2><p class="muted">This is the account you are signed in with, so it cannot be
disabled or deleted from here. Another administrator can.</p>"#
            .to_string()
    } else if may_write {
        let (op, label) = if user.enabled {
            (UserOp::Disable, "Disable sign-in")
        } else {
            (UserOp::Enable, "Enable sign-in")
        };
        format!(
            r#"<h2>Sign-in</h2><form method="post" action="{url}" class="inline">{csrf}
<button class="secondary" type="submit" name="{op_field}" value="{op}">{label}</button></form>
{delete}"#,
            url = e(&url),
            op_field = UserOp::FIELD,
            op = op.as_str(),
            delete = view::confirm_post(
                "delete-user",
                "Delete user\u{2026}",
                &format!("Delete {}?", user.upn),
                "They can no longer sign in, and their sessions end. An administrator can restore a deleted account.",
                &url,
                &csrf,
                UserOp::FIELD,
                UserOp::Delete.as_str(),
                "Delete",
            ),
        )
    } else {
        String::new()
    };

    let reset = if may_reset {
        format!(
            r#"<h2>Password</h2><form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{reset}">
<label for="password">New password</label><input id="password" name="password" type="password" required>
<label><input type="checkbox" name="{REQUIRE_CHANGE}" checked> Require them to choose a new password at their next sign-in</label>
<div class="actions"><button type="submit">Reset password</button></div>
<p class="muted">A reset signs the user out everywhere and revokes their refresh tokens.{pending}</p></form>"#,
            url = e(&url),
            op_field = UserOp::FIELD,
            reset = UserOp::Reset.as_str(),
            pending = if users::must_change_password(&st.pool, &user.id).await.unwrap_or(false) {
                " They have yet to choose their own password since the last reset."
            } else {
                ""
            },
        )
    } else {
        String::new()
    };

    let mfa = {
        let enrolled = crate::mfa::enrolled_at(&st.pool, &user.id).await.unwrap_or(None);
        let left = crate::mfa::recovery_codes_left(&st.pool, &user.id).await.unwrap_or(0);
        let policy = crate::mfa::policy(&st.pool, &user.id)
            .await
            .unwrap_or(crate::mfa::MfaPolicy::Default);
        let status = match enrolled {
            Some(at) => format!(
                "Authenticator set up {}. {left} unused recovery code{}.",
                view::ts(at),
                if left == 1 { "" } else { "s" }
            ),
            None => "No authenticator set up.".to_string(),
        };
        let tenant_rule = if tenant.settings.require_mfa {
            "This tenant requires MFA of everyone."
        } else {
            "This tenant does not require MFA of everyone."
        };
        let setting = if may_write {
            let options: String = crate::mfa::MfaPolicy::ALL
                .iter()
                .map(|p| {
                    format!(
                        r#"<option value="{v}"{sel}>{label}</option>"#,
                        v = e(p.as_str()),
                        sel = if *p == policy { " selected" } else { "" },
                        label = e(p.label()),
                    )
                })
                .collect();
            format!(
                r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<label for="mfa_policy">Requirement</label><select id="mfa_policy" name="{MFA_POLICY}">{options}</select>
<p class="muted">{tenant_rule} An application can also require it.</p>
<div class="actions"><button type="submit">Save</button></div></form>"#,
                url = e(&url),
                op_field = UserOp::FIELD,
                op = UserOp::MfaPolicy.as_str(),
            )
        } else {
            format!(
                r#"<p>Requirement: {}. <span class="muted">{tenant_rule}</span></p>"#,
                e(policy.label())
            )
        };
        let reset = if may_reset && enrolled.is_some() {
            view::confirm_post(
                "mfa-reset",
                "Reset MFA\u{2026}",
                &format!("Remove the authenticator of {}?", user.upn),
                "Their authenticator and recovery codes are removed and they are signed out everywhere. \
                 If MFA is required of them, they set up a new authenticator at their next sign-in.",
                &url,
                &csrf,
                UserOp::FIELD,
                UserOp::MfaReset.as_str(),
                "Reset MFA",
            )
        } else {
            String::new()
        };
        format!(
            r#"<h2>Multi-factor authentication</h2><p>{}</p>{setting}{reset}"#,
            e(&status)
        )
    };

    let groups = if ctx.can_in(GROUP_READ, tenant) {
        let held = crate::groups::for_user(&st.pool, &user.id).await.unwrap_or_default();
        let all = crate::groups::list(&st.pool, &tenant.id).await.unwrap_or_default();
        if ctx.can_in(GROUP_WRITE, tenant) && !all.is_empty() {
            // Every group of the tenant, the ones they are in ticked: membership is
            // set in one go rather than group by group.
            let boxes: String = all
                .iter()
                .map(|g| {
                    format!(
                        r#"<label><input type="checkbox" name="{GROUP}" value="{id}"{on}> {name}</label>"#,
                        id = e(&g.id),
                        name = e(&g.name),
                        on = if held.iter().any(|h| h.id == g.id) {
                            " checked"
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            format!(
                r#"<h2>Groups</h2><form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{op}">
<fieldset class="ticks">{boxes}</fieldset>
<div class="actions"><button type="submit">Save groups</button></div></form>"#,
                url = e(&url),
                op_field = UserOp::FIELD,
                op = UserOp::Groups.as_str(),
            )
        } else {
            let pills = if held.is_empty() {
                r#"<span class="muted">None</span>"#.to_string()
            } else {
                held.iter()
                    .map(|g| format!(r#"<span class="pill">{}</span>"#, e(&g.name)))
                    .collect()
            };
            format!(r#"<h2>Groups</h2><p>{pills}</p>"#)
        }
    } else {
        String::new()
    };

    // The `(target)` index on `audit_log` exists for exactly this question, so
    // the page that can answer it is linked from the person it is about.
    let history = if ctx.can_in(crate::admin::AUDIT_READ, tenant) {
        format!(
            r#"<h2>History</h2><p><a href="{base}/admin/tenants/{tid}/audit?target={id}">Audit entries about this account</a></p>"#,
            base = e(base),
            tid = e(&tenant.id),
            id = e(&user.id),
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<h1>{upn}</h1><p class="sub">{tenant_name} &middot; object id {id}</p>{error}
<h2>Attributes</h2>{attributes}{state}{reset}{mfa}{groups}{history}"#,
        upn = e(&user.upn),
        tenant_name = e(&tenant.name),
        id = e(&user.id),
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Users)),
        status,
        &user.upn,
        &body,
    )
}

pub async fn detail_post(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, user_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let form = parse_form(&body);
    let Some(op) = UserOp::parse(field(&form, UserOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    // The action is the operation's own, so `op=reset` cannot be performed by
    // someone who only holds `User:Write` and the reverse.
    if let Err(resp) = ctx.require(op.action(), On::Tenant(&key)) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let user = match users::find(&st.pool, &tenant.id, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return view::not_found(),
        Err(err) => {
            tracing::error!("user lookup failed: {err}");
            return view::server_error();
        }
    };

    // The group tick boxes repeat one field name, so they are read from the body.
    let ticked: Vec<String> = url::form_urlencoded::parse(&body)
        .filter(|(k, _)| k == GROUP)
        .map(|(_, v)| v.into_owned())
        .collect();
    let outcome = apply_checked(&st, &ctx, tenant, &user, op, &form, &ticked).await;
    match outcome {
        Ok(details) => {
            if op == UserOp::Groups {
                // One entry per group, on the group, exactly as its own page records.
                for (key, event) in [
                    ("added", Event::AdminGroupMemberAdd),
                    ("removed", Event::AdminGroupMemberRemove),
                ] {
                    for group in details[key].as_array().into_iter().flatten() {
                        audited(
                            &st,
                            &ctx,
                            &tenant.id,
                            event,
                            group.as_str(),
                            json!({ "userId": user.id }),
                        )
                        .await;
                    }
                }
            } else {
                audited(&st, &ctx, &tenant.id, op.event(), Some(&user.id), details).await;
            }
            let base = st.public_url.base();
            // A deleted user has no page to go back to.
            if op == UserOp::Delete {
                view::see_other(&users_url(base, tenant))
            } else {
                view::see_other(&format!("{}/{}", users_url(base, tenant), user.id))
            }
        }
        Err(err) => {
            detail(
                &st,
                &ctx,
                tenant,
                &user,
                Some(&err.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

/// [`apply`], after the one rule that is about who is asking: nobody deletes or
/// disables the account they are signed in with. It ends their own session
/// mid-click, and it is how the last administrator goes.
async fn apply_checked(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    user: &User,
    op: UserOp,
    form: &Params,
    groups: &[String],
) -> anyhow::Result<serde_json::Value> {
    if user.id == ctx.user.id && matches!(op, UserOp::Delete | UserOp::Disable) {
        anyhow::bail!("This is the account you are signed in with. Another administrator can disable or delete it.");
    }
    apply(st, tenant, user, op, form, groups).await
}

/// Carry out one operation, returning what to record about it.
async fn apply(
    st: &AppState,
    tenant: &Tenant,
    user: &User,
    op: UserOp,
    form: &Params,
    groups: &[String],
) -> anyhow::Result<serde_json::Value> {
    match op {
        UserOp::Attributes => {
            let attrs = UserAttributes {
                display_name: optional(form, "display_name"),
                given_name: optional(form, "given_name"),
                family_name: optional(form, "family_name"),
                email: optional(form, "email"),
                email_verified: checked(form, "email_verified"),
            };
            users::update_attributes(&st.pool, &tenant.id, &user.id, &attrs).await?;
            // Values, not before-and-after: an audit row is shipped to log systems
            // and the attributes are the user's own data.
            Ok(json!({ "fields": ["displayName", "givenName", "surname", "mail", "mailVerified"] }))
        }
        UserOp::Enable | UserOp::Disable => {
            let enabled = op == UserOp::Enable;
            users::set_enabled(&st.pool, &tenant.id, &user.id, enabled).await?;
            Ok(json!({ "enabled": enabled }))
        }
        UserOp::Reset => {
            let temporary = checked(form, REQUIRE_CHANGE);
            let by = if temporary {
                users::PasswordSetBy::AdminTemporary
            } else {
                users::PasswordSetBy::Admin
            };
            users::change_password(&st.pool, tenant, &user.id, field(form, "password"), by).await?;
            Ok(json!({ "requireChange": temporary }))
        }
        UserOp::Delete => {
            users::soft_delete(&st.pool, &tenant.id, &user.id).await?;
            Ok(json!({ "upn": crate::routes::audit::clip(&user.upn) }))
        }
        UserOp::MfaPolicy => {
            let Some(policy) = crate::mfa::MfaPolicy::parse(field(form, MFA_POLICY)) else {
                anyhow::bail!("choose a setting");
            };
            crate::mfa::set_policy(&st.pool, &tenant.id, &user.id, policy).await?;
            Ok(json!({ "mfaPolicy": policy.as_str() }))
        }
        UserOp::MfaReset => {
            if !crate::mfa::reset(&st.pool, &tenant.id, &user.id).await? {
                anyhow::bail!("this account has no authenticator to remove");
            }
            Ok(json!({}))
        }
        UserOp::Groups => {
            let change = crate::groups::set_for_user(&st.pool, &tenant.id, &user.id, groups).await?;
            Ok(json!({ "added": change.added, "removed": change.removed }))
        }
    }
}
