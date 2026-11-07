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

use crate::AppState;
use crate::admin::bulk;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{
    At, Params, Settled, TenantTab, checked, chrome, field, optional, parse_form, row_problem, settle,
};
use crate::admin::view::{self, e};
use crate::admin::{GROUP_READ, GROUP_WRITE, USER_READ, USER_RESET, USER_WRITE};
use crate::tenant::Tenant;
use crate::txn::ops::Account;
use crate::txn::ops::groups::AddGroupMember;
use crate::txn::ops::users::{
    CreateUser, DeleteUser, DisableUser, EnableUser, Profile, ResetPassword, ResetUserMfa, SetUserCrossTenantPolicy,
    SetUserGroups, SetUserMfaPolicy, UpdateUserAttributes,
};
use crate::txn::{self, Outcome, Refusal};
use crate::users::{self, NewPassword, User};
use crate::util::now;

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
    /// Whether they may sign in to other tenants' applications.
    CrossTenant,
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
        Self::CrossTenant,
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
            Self::CrossTenant => "cross_tenant",
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
            Self::MfaPolicy | Self::CrossTenant => USER_WRITE,
            Self::Attributes | Self::Enable | Self::Disable | Self::Delete => USER_WRITE,
            // Who is in a group is the group's to change.
            Self::Groups => GROUP_WRITE,
        }
    }
}

/// Whether a password an administrator sets must be replaced at next sign-in.
const REQUIRE_CHANGE: &str = "require_change";

/// Where the password an administrator sets comes from: what they typed, or
/// the generator. It is the value of the submit button that sent the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordSource {
    Typed,
    /// [`users::generate_password`], shown once on the page that answers.
    Generated,
}

impl PasswordSource {
    const FIELD: &'static str = "password_source";

    fn as_str(self) -> &'static str {
        match self {
            Self::Typed => "typed",
            Self::Generated => "generated",
        }
    }

    /// The button pressed. Anything but the generator's is a typed password, so
    /// a form posted by Enter in the box sets what is in the box.
    fn of(form: &Params) -> Self {
        if field(form, Self::FIELD) == Self::Generated.as_str() {
            Self::Generated
        } else {
            Self::Typed
        }
    }

    /// The generator's button. `formnovalidate`, because the password box it
    /// stands in for may be empty and marked required.
    fn button(label: &str) -> String {
        format!(
            r#"<button class="secondary" type="submit" name="{field}" value="{value}" formnovalidate>{label}</button>"#,
            field = Self::FIELD,
            value = Self::Generated.as_str(),
            label = e(label),
        )
    }

    /// When the generator was asked for, put a fresh password in the form's
    /// password field in place of whatever the box held, and return it so the
    /// page that answers can show it.
    fn take(form: &mut Params) -> Option<String> {
        match Self::of(form) {
            Self::Typed => None,
            Self::Generated => {
                let generated = users::generate_password();
                form.insert(PASSWORD.to_string(), generated.clone());
                Some(generated)
            }
        }
    }
}

/// The notice holding a generated password, on the one page that shows it.
fn reveal_password(password: &str) -> String {
    view::shown_once(
        "This is the only time this password is shown.",
        password,
        "Only a hash of it is stored, so it cannot be shown again. Copy it now and give it to the user; \
         if it is lost, reset the password again.",
    )
}

/// The password box on the new-user and reset forms.
const PASSWORD: &str = "password";

/// The user's setting for other tenants' applications.
const CROSS_TENANT: &str = "cross_tenant";

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
                    r#"<span class="pill good">Enabled</span>"#
                } else {
                    r#"<span class="pill bad">Disabled</span>"#
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
        // One transaction per row, each the same as on the account's own page.
        let outcome = match op {
            UserListOp::Enable => run_op(&st, &ctx, tenant, user, UserOp::Enable, &form, &[]).await,
            UserListOp::Disable => run_op(&st, &ctx, tenant, user, UserOp::Disable, &form, &[]).await,
            UserListOp::Delete => run_op(&st, &ctx, tenant, user, UserOp::Delete, &form, &[]).await,
            UserListOp::AddToGroup => {
                let add = AddGroupMember {
                    tenant_id: tenant.id.clone(),
                    group_id: group.to_string(),
                    account: Account::Id(user.id.clone()),
                };
                txn::run(&st.pool, &ctx.actor(), &add).await.map_done()
            }
        };
        match row_problem(&outcome) {
            None => tally.done += 1,
            Some(why) => tally.refuse(&user.upn, why),
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

/// The new-user form's generator button.
const CREATE_GENERATED: &str = "Create with a generated password";

/// The reset form's generator button.
const RESET_GENERATED: &str = "Reset to a generated password";

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
<p class="muted">At least {min} characters, or leave it empty and use <strong>{generate}</strong>: a random
{generated}-character password, shown once on the page that follows.</p>
<label><input type="checkbox" name="{REQUIRE_CHANGE}" checked> Require them to choose their own password at first sign-in</label>
<label for="display_name">Display name</label><input id="display_name" name="display_name" type="text" value="{display}">
<div class="fields">
<div><label for="given_name">Given name</label><input id="given_name" name="given_name" type="text" value="{given}"></div>
<div><label for="family_name">Family name</label><input id="family_name" name="family_name" type="text" value="{family}"></div>
</div>
<label for="email">Email address</label><input id="email" name="email" type="text" value="{email}">
<p class="muted">A contact address, <strong>not the sign-in name</strong>: it can be anything, and changing it
later does not change how the person signs in. Left empty, it is set to the user name.</p>
{error}<div class="actions"><button type="submit">Create user</button>{generate_button}<a href="{url}">Cancel</a></div></form>"#,
        url = e(&users_url(st.public_url.base(), tenant)),
        min = users::MIN_PASSWORD_CHARS,
        generated = users::GENERATED_PASSWORD_CHARS,
        generate = CREATE_GENERATED,
        generate_button = PasswordSource::button(CREATE_GENERATED),
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
    let mut form = form;
    let generated = PasswordSource::take(&mut form);
    let upn = submitted_upn(&form);
    // An email address is a contact detail and is not required. Left empty it
    // starts out as the user name, which is the usual case and can be changed.
    let email = optional(&form, "email").or(Some(&upn)).filter(|v| !v.is_empty());
    let by = if checked(&form, REQUIRE_CHANGE) {
        users::PasswordSetBy::AdminTemporary
    } else {
        users::PasswordSetBy::Admin
    };
    // Checked and hashed before the transaction: hashing is slow.
    let outcome = match NewPassword::for_new_account_as(field(&form, PASSWORD), by) {
        Ok(password) => {
            let create = CreateUser {
                tenant_id: tenant.id.clone(),
                upn: upn.clone(),
                password,
                display_name: optional(&form, "display_name").map(str::to_string),
                given_name: optional(&form, "given_name").map(str::to_string),
                family_name: optional(&form, "family_name").map(str::to_string),
                email: email.map(str::to_string),
            };
            txn::run(&st.pool, &ctx.actor(), &create).await
        }
        Err(err) => Outcome::from_error(&err),
    };
    // The storage layer validates the UPN against the tenant's verified domains;
    // its message names the problem.
    match settle(outcome) {
        Settled::Done(created) => match generated {
            // The one exception to "303 after a post": the password lives in
            // this response and nowhere else.
            Some(password) => match users::find(&st.pool, &tenant.id, &created.id).await {
                Ok(Some(user)) => {
                    let notice = Notice::Reveal(&password);
                    detail(&st, &ctx, tenant, &user, UserSection::Password, notice, StatusCode::OK).await
                }
                _ => view::server_error(),
            },
            None => view::see_other(&format!("{}/{}", users_url(st.public_url.base(), tenant), created.id)),
        },
        Settled::Refused(message) => {
            new_user_page(&st, &ctx, tenant, &form, Some(&message), StatusCode::BAD_REQUEST).await
        }
        Settled::Respond(resp) => resp,
    }
}

// ---- detail ----

/// A part of an account's page, each at its own address, with a menu down the
/// side as on an application's page. Entra's user blades split the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSection {
    /// Who the account is, whether it can sign in, and a card per section.
    Overview,
    /// Names and contact details.
    Properties,
    Groups,
    /// Signing in to other tenants' applications.
    Organizations,
    Password,
    /// The authenticator and the account's MFA requirement.
    Authentication,
}

impl UserSection {
    pub const ALL: &'static [UserSection] = &[
        Self::Overview,
        Self::Properties,
        Self::Groups,
        Self::Organizations,
        Self::Password,
        Self::Authentication,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Properties => "Properties",
            Self::Groups => "Groups",
            Self::Organizations => "Other organizations",
            Self::Password => "Password",
            Self::Authentication => "Authentication methods",
        }
    }

    /// The last part of its address; the overview is the account's own.
    pub fn path(self) -> &'static str {
        match self {
            Self::Overview => "",
            Self::Properties => "properties",
            Self::Groups => "groups",
            Self::Organizations => "organizations",
            Self::Password => "password",
            Self::Authentication => "authentication",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.path() == raw)
    }

    /// The heading it sits under in the side menu; the overview has none.
    fn group(self) -> Option<&'static str> {
        match self {
            Self::Overview => None,
            Self::Properties | Self::Groups | Self::Organizations => Some(MENU_MANAGE),
            Self::Password | Self::Authentication => Some(MENU_SIGN_IN),
        }
    }

    /// What it takes to open it, beyond seeing the account.
    fn action(self) -> crate::rbac::Action {
        match self {
            Self::Groups => GROUP_READ,
            _ => USER_READ,
        }
    }
}

const MENU_MANAGE: &str = "Manage";
const MENU_SIGN_IN: &str = "Sign-in";
const MENU_ACTIVITY: &str = "Activity";

impl UserOp {
    /// The section the operation's form is in, and where the page returns to.
    fn section(self) -> UserSection {
        match self {
            Self::Attributes => UserSection::Properties,
            Self::Enable | Self::Disable | Self::Delete => UserSection::Overview,
            Self::Reset => UserSection::Password,
            Self::Groups => UserSection::Groups,
            Self::MfaPolicy | Self::MfaReset => UserSection::Authentication,
            Self::CrossTenant => UserSection::Organizations,
        }
    }
}

/// Whether the account can sign in now, which the page shows at the top of every
/// section: an administrator must never have to infer it from a button label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Enabled,
    Disabled,
    /// Enabled, but locked out after too many wrong passwords, until then.
    LockedOut(i64),
}

impl Standing {
    fn of(user: &User, state: Option<&users::SignInState>, at: i64) -> Self {
        if !user.enabled {
            return Self::Disabled;
        }
        match state.and_then(|s| s.locked_at(at)) {
            Some(until) => Self::LockedOut(until),
            None => Self::Enabled,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Enabled => "Sign-in enabled",
            Self::Disabled => "Sign-in disabled",
            Self::LockedOut(_) => "Locked out",
        }
    }

    fn pill(self) -> String {
        let class = match self {
            Self::Enabled => "good",
            Self::Disabled | Self::LockedOut(_) => "bad",
        };
        format!(r#"<span class="pill {class}">{}</span>"#, e(self.label()))
    }
}

fn user_url(base: &str, tenant: &Tenant, user: &User) -> String {
    format!("{}/{}", users_url(base, tenant), user.id)
}

fn section_url(base: &str, tenant: &Tenant, user: &User, section: UserSection) -> String {
    match section {
        UserSection::Overview => user_url(base, tenant, user),
        other => format!("{}/{}", user_url(base, tenant, user), other.path()),
    }
}

pub async fn detail_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, user_id)): Path<(String, String)>,
) -> Response {
    show(&st, &ctx, &key, &user_id, UserSection::Overview).await
}

/// One section of an account's page.
pub async fn section_page(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, user_id, section)): Path<(String, String, String)>,
) -> Response {
    let Some(section) = UserSection::parse(&section).filter(|s| *s != UserSection::Overview) else {
        return view::not_found();
    };
    show(&st, &ctx, &key, &user_id, section).await
}

async fn show(st: &AppState, ctx: &AdminContext, key: &str, user_id: &str, section: UserSection) -> Response {
    if let Err(resp) = ctx.require(USER_READ, On::Tenant(key)) {
        return resp;
    }
    if let Err(resp) = ctx.require(section.action(), On::Tenant(key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(key) else {
        return view::not_found();
    };
    match users::find(&st.pool, &tenant.id, user_id).await {
        Ok(Some(user)) => detail(st, ctx, tenant, &user, section, Notice::None, StatusCode::OK).await,
        Ok(None) => view::not_found(),
        Err(err) => {
            tracing::error!("user lookup failed: {err}");
            view::server_error()
        }
    }
}

/// What every section's renderer is given.
struct Here<'a> {
    st: &'a AppState,
    ctx: &'a AdminContext,
    tenant: &'a Tenant,
    user: &'a User,
    /// Where the page's forms post.
    url: String,
    csrf: String,
    state: Option<users::SignInState>,
    standing: Standing,
}

impl Here<'_> {
    fn may_write(&self) -> bool {
        self.ctx.can_in(USER_WRITE, self.tenant)
    }

    fn may_reset(&self) -> bool {
        self.ctx.can_in(USER_RESET, self.tenant)
    }

    /// Whether this is the administrator's own account, which they may not
    /// disable or delete.
    fn is_self(&self) -> bool {
        self.user.id == self.ctx.user.id
    }

    /// A form posting one operation, with the given fields and button.
    fn op_form(&self, op: UserOp, inner: &str) -> String {
        format!(
            r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">{inner}</form>"#,
            url = e(&self.url),
            csrf = self.csrf,
            field = UserOp::FIELD,
            op = op.as_str(),
        )
    }

    /// A one-button form, laid out in a row.
    fn op_button(&self, op: UserOp, class: &str, label: &str) -> String {
        format!(
            r#"<form method="post" action="{url}" class="inline">{csrf}<button class="{class}" type="submit" name="{field}" value="{op}">{label}</button></form>"#,
            url = e(&self.url),
            csrf = self.csrf,
            field = UserOp::FIELD,
            op = op.as_str(),
            label = e(label),
        )
    }
}

/// What a user's page shows above its section, besides the section itself.
#[derive(Clone, Copy)]
enum Notice<'a> {
    None,
    /// Why the change just asked for was refused.
    Error(&'a str),
    /// A generated password, shown on this response only.
    Reveal(&'a str),
}

async fn detail(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    user: &User,
    section: UserSection,
    notice: Notice<'_>,
    status: StatusCode,
) -> Response {
    let base = st.public_url.base();
    let state = users::sign_in_state(&st.pool, &tenant.id, &user.id)
        .await
        .unwrap_or(None);
    let standing = Standing::of(user, state.as_ref(), now());
    let here = Here {
        st,
        ctx,
        tenant,
        user,
        url: user_url(base, tenant, user),
        csrf: view::csrf_input(&ctx.csrf),
        state,
        standing,
    };

    let content = match section {
        UserSection::Overview => overview(&here).await,
        UserSection::Properties => properties(&here),
        UserSection::Groups => groups(&here).await,
        UserSection::Organizations => organizations(&here).await,
        UserSection::Password => password(&here),
        UserSection::Authentication => authentication(&here).await,
    };

    // The account's sections down the side, under a heading per group. A heading
    // shows only above a section the administrator may open.
    let mut menu = String::new();
    let mut heading = None;
    let mut open_group = |menu: &mut String, group: Option<&'static str>| {
        if group != heading {
            heading = group;
            if let Some(h) = group {
                menu.push_str(&format!(r#"<div class="group">{}</div>"#, e(h)));
            }
        }
    };
    for s in UserSection::ALL.iter().filter(|s| ctx.can_in(s.action(), tenant)) {
        open_group(&mut menu, s.group());
        let href = e(&section_url(base, tenant, user, *s));
        menu.push_str(&if *s == section {
            format!(
                r#"<a class="active" aria-current="page" href="{href}">{}</a>"#,
                e(s.label())
            )
        } else {
            format!(r#"<a href="{href}">{}</a>"#, e(s.label()))
        });
    }
    // The `(target)` index on `audit_log` exists for exactly this question, so
    // the page that can answer it is linked from the person it is about.
    if ctx.can_in(crate::admin::AUDIT_READ, tenant) {
        open_group(&mut menu, Some(MENU_ACTIVITY));
        menu.push_str(&format!(
            r#"<a href="{}">Audit log</a>"#,
            e(&format!("{base}/admin/tenants/{}/audit?target={}", tenant.id, user.id))
        ));
    }

    let name = user.display_name.as_deref().filter(|n| !n.is_empty());
    let body = format!(
        r#"<p class="crumb"><a href="{list}">Users</a></p><h1>{title}</h1>
<p class="sub">{subtitle}{tenant_name} &middot; user</p><p>{pills}</p>
<div class="split"><nav class="side" aria-label="User">{menu}</nav>
<div class="pane">{banner}{error}{content}</div></div>"#,
        list = e(&users_url(base, tenant)),
        title = e(name.unwrap_or(&user.upn)),
        subtitle = if name.is_some() {
            format!("{} &middot; ", e(&user.upn))
        } else {
            String::new()
        },
        tenant_name = e(&tenant.name),
        pills = pills(&here),
        banner = banner(&here),
        error = match notice {
            Notice::None => String::new(),
            Notice::Error(message) => view::error_block(Some(message)),
            Notice::Reveal(password) => reveal_password(password),
        },
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Users)),
        status,
        &format!("{} \u{b7} {}", user.upn, section.label()),
        &body,
    )
}

/// The account's standing, and anything else that stops or changes its next
/// sign-in, as pills beside its name.
fn pills(here: &Here<'_>) -> String {
    let mut out = here.standing.pill();
    if here.state.as_ref().is_some_and(|s| s.must_change_password) {
        out.push_str(r#"<span class="pill">Must choose a new password</span>"#);
    }
    out
}

/// What is wrong with the account's sign-in, said once at the top of every
/// section, with the way to put it right where the administrator may.
fn banner(here: &Here<'_>) -> String {
    match here.standing {
        Standing::Enabled => String::new(),
        Standing::Disabled => {
            let enable = if here.may_write() {
                here.op_button(UserOp::Enable, "", "Enable sign-in")
            } else {
                String::new()
            };
            format!(
                r#"<div class="banner bad"><span><strong>Sign-in is disabled.</strong> This account cannot sign in
or get tokens, and it has no sessions.</span>{enable}</div>"#
            )
        }
        Standing::LockedOut(until) => {
            let failed = here.state.as_ref().map(|s| s.failed_logins).unwrap_or_default();
            format!(
                r#"<div class="banner bad"><span><strong>Locked out</strong> until {until} after {failed} wrong
password{s}. It unlocks by itself then, or at once when its password is reset.</span></div>"#,
                until = e(&view::ts(until)),
                s = if failed == 1 { "" } else { "s" },
            )
        }
    }
}

/// The overview: who the account is, a card per section saying what is in it,
/// and what can be done to the account as a whole.
async fn overview(here: &Here<'_>) -> String {
    let (st, tenant, user) = (here.st, here.tenant, here.user);
    let base = st.public_url.base();
    let opt = |v: &Option<String>| {
        v.as_deref()
            .filter(|v| !v.is_empty())
            .map(e)
            .unwrap_or_else(|| "&mdash;".into())
    };
    let created = here
        .state
        .as_ref()
        .map(|s| e(&view::ts(s.created_at)))
        .unwrap_or_default();
    let facts = format!(
        r#"<dl class="facts"><dt>User name</dt><dd>{upn}</dd><dt>Object id</dt><dd>{id}</dd>
<dt>Display name</dt><dd>{display}</dd><dt>Email address</dt><dd>{email}</dd>
<dt>Created</dt><dd>{created}</dd><dt>Tenant</dt><dd>{tenant_name}</dd></dl>"#,
        upn = e(&user.upn),
        id = e(&user.id),
        display = opt(&user.display_name),
        email = opt(&user.email),
        tenant_name = e(&tenant.name),
    );

    let enrolled = crate::mfa::enrolled_at(&st.pool, &user.id).await.unwrap_or(None);
    let policy = crate::mfa::policy(&st.pool, &user.id)
        .await
        .unwrap_or(crate::mfa::MfaPolicy::Default);
    let cross = crate::access::policy(&st.pool, &user.id)
        .await
        .unwrap_or(crate::access::CrossTenantPolicy::Default);
    let must_change = here.state.as_ref().is_some_and(|s| s.must_change_password);

    // (section, summary, a warning when something needs attention)
    let mut cards: Vec<(UserSection, String, Option<&str>)> = vec![(
        UserSection::Properties,
        user.email
            .as_deref()
            .filter(|m| !m.is_empty())
            .map(|m| {
                format!(
                    "{m}{}",
                    if user.email_verified {
                        ", verified"
                    } else {
                        ", not verified"
                    }
                )
            })
            .unwrap_or_else(|| "No email address".into()),
        None,
    )];
    if here.ctx.can_in(GROUP_READ, tenant) {
        let memberships = crate::groups::memberships_for_user(&st.pool, &user.id)
            .await
            .unwrap_or_default();
        let direct = memberships.iter().filter(|m| m.via.is_none()).count();
        let nested = memberships.len() - direct;
        let summary = match (direct, nested) {
            (0, 0) => "In no groups".to_string(),
            (d, 0) => format!("Direct member of {d} group{}", if d == 1 { "" } else { "s" }),
            (d, n) => format!("Direct member of {d}, {n} more through nesting"),
        };
        cards.push((UserSection::Groups, summary, None));
    }
    cards.push((UserSection::Organizations, cross.label().to_string(), None));
    cards.push((
        UserSection::Password,
        if must_change {
            "Set by an administrator; not yet replaced".into()
        } else {
            "Chosen by the user or kept as set".into()
        },
        must_change.then_some("Must choose a new password"),
    ));
    cards.push((
        UserSection::Authentication,
        match enrolled {
            Some(at) => format!("Authenticator set up {}", view::ts(at)),
            None => "No authenticator".into(),
        },
        (enrolled.is_none() && (policy == crate::mfa::MfaPolicy::Required || tenant.settings.enforces_mfa()))
            .then_some("MFA required, not set up"),
    ));
    let cards: String = cards
        .iter()
        .map(|(section, summary, warning)| {
            format!(
                r#"<a class="tile" href="{href}"><strong>{label}</strong><span>{summary}</span>{warning}</a>"#,
                href = e(&section_url(base, tenant, user, *section)),
                label = e(section.label()),
                summary = e(summary),
                warning = warning
                    .map(|w| format!(r#"<span class="pill bad">{}</span>"#, e(w)))
                    .unwrap_or_default(),
            )
        })
        .collect();

    format!(
        r#"{facts}<div class="tiles">{cards}</div>{account}"#,
        account = account_actions(here)
    )
}

/// Enable, disable and delete: what is done to the account as a whole.
fn account_actions(here: &Here<'_>) -> String {
    if !here.may_write() {
        return String::new();
    }
    if here.is_self() {
        return r#"<h2>Account</h2><p class="muted">This is the account you are signed in with, so it cannot be
disabled or deleted from here. Another administrator can.</p>"#
            .to_string();
    }
    let toggle = if here.user.enabled {
        here.op_button(UserOp::Disable, "secondary", "Disable sign-in")
    } else {
        here.op_button(UserOp::Enable, "", "Enable sign-in")
    };
    let delete = view::confirm_post(
        "delete-user",
        "Delete user\u{2026}",
        &format!("Delete {}?", here.user.upn),
        "They can no longer sign in, and their sessions end. An administrator can restore a deleted account.",
        &here.url,
        &here.csrf,
        UserOp::FIELD,
        UserOp::Delete.as_str(),
        "Delete",
    );
    format!(
        r#"<h2>Account</h2><p>{standing}. <span class="muted">Disabling ends the account's sessions and refresh
tokens at once; enabling it again lets it sign in, with nothing else changed.</span></p>
<div class="actions">{toggle}{delete}</div>"#,
        standing = e(here.standing.label()),
    )
}

fn properties(here: &Here<'_>) -> String {
    let user = here.user;
    let may_write = here.may_write();
    let disabled = if may_write { "" } else { " disabled" };
    let inner = format!(
        r#"<div class="fields">
<div><label for="display_name">Display name</label><input id="display_name" name="display_name" type="text" value="{display}"{disabled}></div>
<div><label for="given_name">Given name</label><input id="given_name" name="given_name" type="text" value="{given}"{disabled}></div>
<div><label for="family_name">Family name</label><input id="family_name" name="family_name" type="text" value="{family}"{disabled}></div>
<div><label for="email">Email address</label><input id="email" name="email" type="text" value="{email}"{disabled}>
<p class="muted">A contact address, not the sign-in name.</p></div>
</div>
<label><input type="checkbox" name="email_verified"{verified}{disabled}> Email verified</label>
{save}"#,
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
    format!(
        r#"<h2>Properties</h2><dl class="facts"><dt>User name</dt><dd>{upn}</dd><dt>Object id</dt><dd>{id}</dd></dl>{form}"#,
        upn = e(&user.upn),
        id = e(&user.id),
        form = here.op_form(UserOp::Attributes, &inner),
    )
}

fn password(here: &Here<'_>) -> String {
    let must_change = here.state.as_ref().is_some_and(|s| s.must_change_password);
    let changed = here
        .state
        .as_ref()
        .map(|s| s.updated_at)
        .map(|t| format!(" The account was last changed {}.", view::ts(t)))
        .unwrap_or_default();
    let status = if must_change {
        "The current password was set by an administrator, and the user has yet to choose their own: they are asked to at their next sign-in."
    } else {
        "The user signs in with their own password, or one an administrator set for them to keep."
    };
    let form = if here.may_reset() {
        here.op_form(
            UserOp::Reset,
            &format!(
                r#"<label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" required>
<label><input type="checkbox" name="{REQUIRE_CHANGE}" checked> Require them to choose a new password at their next sign-in</label>
<div class="actions"><button type="submit">Reset password</button>{generate_button}</div>
<p class="muted">At least {min} characters, or a random {generated}-character one, shown once on the page that follows. A reset signs the user out everywhere, revokes their refresh tokens and
ends a lockout. It is not checked against the account's recent passwords, which would tell you what they were,
but it is remembered, so the user cannot choose it again themselves.</p>"#,
                min = users::MIN_PASSWORD_CHARS,
                generated = users::GENERATED_PASSWORD_CHARS,
                generate_button = PasswordSource::button(RESET_GENERATED),
            ),
        )
    } else {
        r#"<p class="muted">Your roles do not allow resetting passwords.</p>"#.to_string()
    };
    format!(
        r#"<h2>Password</h2><p>{status}<span class="muted">{changed}</span></p><h3>Reset password</h3>{form}"#,
        status = e(status),
        changed = e(&changed),
    )
}

async fn authentication(here: &Here<'_>) -> String {
    let (st, tenant, user) = (here.st, here.tenant, here.user);
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
    let enforced = tenant.settings.enforces_mfa();
    let tenant_rule = if enforced {
        "This tenant enforces MFA: every sign-in uses it, whatever this account's own setting."
    } else if tenant.settings.require_mfa {
        "This tenant requires MFA of everyone by default."
    } else {
        "This tenant does not require MFA of everyone by default."
    };
    let setting = if enforced {
        // Shown as required and greyed: the account's own setting is kept as it
        // is, and applies again if the tenant goes back to Permissive.
        format!(
            r#"<label for="mfa_policy">Requirement</label><select id="mfa_policy" disabled><option selected>Required (enforced by the tenant)</option></select>
<p class="muted">{tenant_rule} Its own setting, {own}, applies again if the tenant goes back to Permissive.</p>"#,
            own = e(&policy.label().to_lowercase()),
        )
    } else if here.may_write() {
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
        here.op_form(
            UserOp::MfaPolicy,
            &format!(
                r#"<label for="mfa_policy">Requirement</label><select id="mfa_policy" name="{MFA_POLICY}">{options}</select>
<p class="muted">{tenant_rule} An application can also require it.</p>
<div class="actions"><button type="submit">Save</button></div>"#
            ),
        )
    } else {
        format!(
            r#"<p>Requirement: {}. <span class="muted">{tenant_rule}</span></p>"#,
            e(policy.label())
        )
    };
    let reset = if here.may_reset() && enrolled.is_some() {
        view::confirm_post(
            "mfa-reset",
            "Reset MFA\u{2026}",
            &format!("Remove the authenticator of {}?", user.upn),
            "Their authenticator and recovery codes are removed and they are signed out everywhere. \
             If MFA is required of them, they set up a new authenticator at their next sign-in.",
            &here.url,
            &here.csrf,
            UserOp::FIELD,
            UserOp::MfaReset.as_str(),
            "Reset MFA",
        )
    } else {
        String::new()
    };
    format!(
        r#"<h2>Authentication methods</h2><p>{}</p>{reset}<h3>Multi-factor authentication</h3>{setting}"#,
        e(&status)
    )
}

async fn organizations(here: &Here<'_>) -> String {
    use crate::access::CrossTenantPolicy;
    let own = crate::access::policy(&here.st.pool, &here.user.id)
        .await
        .unwrap_or(CrossTenantPolicy::Default);
    let tenant_rule = if here.tenant.settings.allow_cross_tenant_sign_in {
        "This tenant allows its accounts to sign in to other tenants' applications that assign them."
    } else {
        "This tenant does not allow its accounts to sign in to other tenants' applications."
    };
    let setting = if here.may_write() {
        let options: String = CrossTenantPolicy::ALL
            .iter()
            .map(|p| {
                format!(
                    r#"<option value="{v}"{sel}>{label}</option>"#,
                    v = e(p.as_str()),
                    sel = if *p == own { " selected" } else { "" },
                    label = e(p.label()),
                )
            })
            .collect();
        here.op_form(
            UserOp::CrossTenant,
            &format!(
                r#"<label for="cross_tenant">Signing in to other tenants' applications</label><select id="cross_tenant" name="{CROSS_TENANT}">{options}</select>
<p class="muted">{tenant_rule} Only applications that accept other tenants and assign this account let it in.</p>
<div class="actions"><button type="submit">Save</button></div>"#
            ),
        )
    } else {
        format!(r#"<p>{}. <span class="muted">{tenant_rule}</span></p>"#, e(own.label()))
    };
    format!(r#"<h2>Other organizations</h2>{setting}"#)
}

async fn groups(here: &Here<'_>) -> String {
    let (st, ctx, tenant, user) = (here.st, here.ctx, here.tenant, here.user);
    let held = crate::groups::for_user(&st.pool, &user.id).await.unwrap_or_default();
    let all = crate::groups::list(&st.pool, &tenant.id).await.unwrap_or_default();
    let memberships = crate::groups::memberships_for_user(&st.pool, &user.id)
        .await
        .unwrap_or_default();
    let group_href = |id: &str| {
        e(&format!(
            "{}/admin/tenants/{}/groups/{id}",
            st.public_url.base(),
            tenant.id
        ))
    };
    // Through a group inside another: not ticked or unticked here, since only
    // the nesting decides it.
    let inherited: String = memberships
        .iter()
        .filter_map(|m| m.via.as_ref().map(|via| (m, via)))
        .map(|(m, via)| {
            format!(
                r#"<tr><td><a href="{g}">{name}</a></td><td class="muted">via <a href="{v}">{via}</a></td></tr>"#,
                g = group_href(&m.group.id),
                name = view::labelled(crate::directory::PrincipalType::Group, &m.group.name),
                v = group_href(&via.id),
                via = e(&via.name),
            )
        })
        .collect();
    let inherited = if inherited.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h3>Through nested groups</h3><table><tr><th>Group</th><th>Why</th></tr>{inherited}</table>
<p class="muted">These count for the <code>groups</code> claim of applications that carry all groups. They do not
assign the account to applications, or give it roles granted to those groups.</p>"#
        )
    };
    let direct = if ctx.can_in(GROUP_WRITE, tenant) && !all.is_empty() {
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
        here.op_form(
            UserOp::Groups,
            &format!(
                r#"<fieldset class="ticks"><legend>Direct member of</legend>{boxes}</fieldset>
<div class="actions"><button type="submit">Save groups</button></div>"#
            ),
        )
    } else if held.is_empty() {
        r#"<p>Direct member of: <span class="muted">None</span></p>"#.to_string()
    } else {
        let links: String = held
            .iter()
            .map(|g| format!(r#"<a class="pill" href="{}">{}</a>"#, group_href(&g.id), e(&g.name)))
            .collect();
        format!(r#"<p>Direct member of: {links}</p>"#)
    };
    format!(r#"<h2>Groups</h2>{direct}{inherited}"#)
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
    // Only a reset sets a password; a generator button on any other form is
    // ignored rather than minting a password nothing uses.
    let mut form = form;
    let generated = match op {
        UserOp::Reset => PasswordSource::take(&mut form),
        _ => None,
    };
    let outcome = run_op(&st, &ctx, tenant, &user, op, &form, &ticked).await;
    match settle(outcome) {
        Settled::Done(()) if generated.is_some() => {
            let notice = Notice::Reveal(generated.as_deref().unwrap_or_default());
            detail(&st, &ctx, tenant, &user, op.section(), notice, StatusCode::OK).await
        }
        Settled::Done(()) => {
            let base = st.public_url.base();
            // A deleted user has no page to go back to.
            if op == UserOp::Delete {
                view::see_other(&users_url(base, tenant))
            } else {
                view::see_other(&section_url(base, tenant, &user, op.section()))
            }
        }
        Settled::Refused(message) => {
            detail(
                &st,
                &ctx,
                tenant,
                &user,
                op.section(),
                Notice::Error(&message),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Settled::Respond(resp) => resp,
    }
}

/// Carry out one operation on an account, as the signed-in administrator: one
/// transaction, which checks, changes and records it, or does none of that.
async fn run_op(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    user: &User,
    op: UserOp,
    form: &Params,
    groups: &[String],
) -> Outcome<()> {
    let actor = ctx.actor();
    let (tenant_id, user_id) = (tenant.id.clone(), user.id.clone());
    let choose = || Outcome::Refused(Refusal::Invalid("Choose a setting.".into()));
    match op {
        UserOp::Attributes => {
            let profile = Profile {
                display_name: optional(form, "display_name").map(str::to_string),
                given_name: optional(form, "given_name").map(str::to_string),
                family_name: optional(form, "family_name").map(str::to_string),
                email: optional(form, "email").map(str::to_string),
                email_verified: checked(form, "email_verified"),
            };
            let t = UpdateUserAttributes {
                tenant_id,
                user_id,
                profile,
            };
            txn::run(&st.pool, &actor, &t).await
        }
        UserOp::Enable => txn::run(&st.pool, &actor, &EnableUser { tenant_id, user_id }).await,
        UserOp::Disable => txn::run(&st.pool, &actor, &DisableUser { tenant_id, user_id }).await,
        UserOp::Delete => txn::run(&st.pool, &actor, &DeleteUser { tenant_id, user_id })
            .await
            .map_done(),
        UserOp::Reset => {
            let by = if checked(form, REQUIRE_CHANGE) {
                users::PasswordSetBy::AdminTemporary
            } else {
                users::PasswordSetBy::Admin
            };
            // Checked against the history and hashed before the transaction.
            let password = match users::prepare_password(&st.pool, tenant, &user.id, field(form, PASSWORD), by).await {
                Ok(p) => p,
                Err(err) => return Outcome::from_error(&err),
            };
            let account = Account::Id(user_id);
            let t = ResetPassword {
                tenant_id,
                account,
                password,
            };
            txn::run(&st.pool, &actor, &t).await.map_done()
        }
        UserOp::MfaPolicy => {
            let Some(policy) = crate::mfa::MfaPolicy::parse(field(form, MFA_POLICY)) else {
                return choose();
            };
            txn::run(
                &st.pool,
                &actor,
                &SetUserMfaPolicy {
                    tenant_id,
                    user_id,
                    policy,
                },
            )
            .await
        }
        UserOp::CrossTenant => {
            let Some(policy) = crate::access::CrossTenantPolicy::parse(field(form, CROSS_TENANT)) else {
                return choose();
            };
            let t = SetUserCrossTenantPolicy {
                tenant_id,
                user_id,
                policy,
            };
            txn::run(&st.pool, &actor, &t).await
        }
        UserOp::MfaReset => txn::run(&st.pool, &actor, &ResetUserMfa { tenant_id, user_id }).await,
        UserOp::Groups => {
            let t = SetUserGroups {
                tenant_id,
                user_id,
                group_ids: groups.to_vec(),
            };
            txn::run(&st.pool, &actor, &t).await.map_done()
        }
    }
}
