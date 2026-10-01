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
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{Params, audited, checked, chrome, field, optional, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{GROUP_READ, USER_READ, USER_RESET, USER_WRITE};
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
}

impl UserOp {
    pub const ALL: &'static [UserOp] = &[Self::Attributes, Self::Enable, Self::Disable, Self::Reset, Self::Delete];

    /// The form's `op` field.
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attributes => "attributes",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Reset => "reset",
            Self::Delete => "delete",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    /// The action that authorizes it. Resetting a password is its own verb,
    /// because a help desk can hold it without being able to edit the directory.
    fn action(self) -> crate::rbac::Action {
        match self {
            Self::Reset => USER_RESET,
            Self::Attributes | Self::Enable | Self::Disable | Self::Delete => USER_WRITE,
        }
    }

    fn event(self) -> Event {
        match self {
            Self::Attributes => Event::AdminUserUpdate,
            Self::Enable => Event::AdminUserEnable,
            Self::Disable => Event::AdminUserDisable,
            Self::Reset => Event::AdminUserReset,
            Self::Delete => Event::AdminUserDelete,
        }
    }
}

/// The search box's query parameter.
const QUERY_PARAM: &str = "q";

fn users_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/users", tenant.id)
}

// ---- list ----

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
    let found = users::list(
        &st.pool,
        &tenant.id,
        Some(search).filter(|s| !s.is_empty()),
        users::LIST_LIMIT,
        0,
    )
    .await;
    let found = match found {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("user list failed: {err}");
            return view::server_error();
        }
    };
    let base = st.public_url.base();
    let rows: String = found
        .iter()
        .map(|u| {
            format!(
                r#"<tr><td><a href="{url}/{id}">{upn}</a></td><td>{name}</td><td>{state}</td></tr>"#,
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
    let create = if ctx.can_in(USER_WRITE, tenant) {
        format!(r#"<a href="{}/new">New user</a>"#, e(&users_url(base, tenant)))
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
    let body = format!(
        r#"<h1>Users</h1><p class="sub">{tenant_name}</p>
<form method="get" action="{url}"><label for="q">Search by name or user name</label>
<input id="q" name="{QUERY_PARAM}" type="search" value="{search}">
<div class="actions"><button type="submit">Search</button>{create}</div></form>
<table><tr><th>User name</th><th>Name</th><th>State</th></tr>{rows}</table>{full}"#,
        tenant_name = e(&tenant.name),
        url = e(&users_url(base, tenant)),
        search = e(search),
    );
    view::page(&chrome(&st, &ctx), StatusCode::OK, "Users", &body)
}

// ---- create ----

pub async fn new_page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    if let Err(resp) = ctx.require(USER_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    new_user_page(&st, &ctx, tenant, &Params::new(), None, StatusCode::OK)
}

fn new_user_page(
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
    let body = format!(
        r#"<h1>New user</h1><p class="sub">in {tenant_name}. The user name's domain must be one this tenant has verified.</p>
<form method="post" action="{url}/new">{csrf}
<label for="upn">User name</label><input id="upn" name="upn" type="email" required value="{upn}" autofocus>
<label for="password">Initial password</label><input id="password" name="password" type="password" required>
<label for="display_name">Display name</label><input id="display_name" name="display_name" type="text" value="{display}">
<label for="given_name">Given name</label><input id="given_name" name="given_name" type="text" value="{given}">
<label for="family_name">Family name</label><input id="family_name" name="family_name" type="text" value="{family}">
<label for="email">Email</label><input id="email" name="email" type="email" value="{email}">
{error}<div class="actions"><button type="submit">Create</button><a href="{url}">Cancel</a></div></form>"#,
        tenant_name = e(&tenant.name),
        url = e(&users_url(st.public_url.base(), tenant)),
        csrf = view::csrf_input(&ctx.csrf),
        upn = e(field(form, "upn")),
        display = e(field(form, "display_name")),
        given = e(field(form, "given_name")),
        family = e(field(form, "family_name")),
        email = e(field(form, "email")),
    );
    view::page(&chrome(st, ctx), status, "New user", &body)
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
    let upn = field(&form, "upn");
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
            email: optional(&form, "email"),
        },
    )
    .await;
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
        Err(err) => new_user_page(
            &st,
            &ctx,
            tenant,
            &form,
            Some(&err.to_string()),
            StatusCode::BAD_REQUEST,
        ),
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
<label for="email">Email</label><input id="email" name="email" type="email" value="{email}"{disabled}>
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

    let state = if may_write {
        let (op, label) = if user.enabled {
            (UserOp::Disable, "Disable sign-in")
        } else {
            (UserOp::Enable, "Enable sign-in")
        };
        format!(
            r#"<h2>Sign-in</h2><form method="post" action="{url}" class="inline">{csrf}
<button class="secondary" type="submit" name="{op_field}" value="{op}">{label}</button></form>
<form method="post" action="{url}" class="inline">{csrf}
<button class="danger" type="submit" name="{op_field}" value="{delete}">Delete user</button></form>"#,
            url = e(&url),
            op_field = UserOp::FIELD,
            op = op.as_str(),
            delete = UserOp::Delete.as_str(),
        )
    } else {
        String::new()
    };

    let reset = if may_reset {
        format!(
            r#"<h2>Password</h2><form method="post" action="{url}">{csrf}<input type="hidden" name="{op_field}" value="{reset}">
<label for="password">New password</label><input id="password" name="password" type="password" required>
<div class="actions"><button type="submit">Reset password</button></div>
<p class="muted">A reset signs the user out everywhere and revokes their refresh tokens.</p></form>"#,
            url = e(&url),
            op_field = UserOp::FIELD,
            reset = UserOp::Reset.as_str(),
        )
    } else {
        String::new()
    };

    let groups = if ctx.can_in(GROUP_READ, tenant) {
        let names = crate::groups::names_for_user(&st.pool, &user.id)
            .await
            .unwrap_or_default();
        let pills = if names.is_empty() {
            r#"<span class="muted">None</span>"#.to_string()
        } else {
            names
                .iter()
                .map(|n| format!(r#"<span class="pill">{}</span>"#, e(n)))
                .collect()
        };
        format!(
            r#"<h2>Groups</h2><p>{pills}</p>
<p class="muted">Membership is edited on the group's own page, under Groups.</p>"#
        )
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
<h2>Attributes</h2>{attributes}{state}{reset}{groups}{history}"#,
        upn = e(&user.upn),
        tenant_name = e(&tenant.name),
        id = e(&user.id),
    );
    view::page(&chrome(st, ctx), status, &user.upn, &body)
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

    let outcome = apply(&st, tenant, &user, op, &form).await;
    match outcome {
        Ok(details) => {
            audited(&st, &ctx, &tenant.id, op.event(), Some(&user.id), details).await;
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

/// Carry out one operation, returning what to record about it.
async fn apply(
    st: &AppState,
    tenant: &Tenant,
    user: &User,
    op: UserOp,
    form: &Params,
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
            users::set_password(&st.pool, tenant, &user.upn, field(form, "password")).await?;
            Ok(json!({}))
        }
        UserOp::Delete => {
            users::soft_delete(&st.pool, &tenant.id, &user.id).await?;
            Ok(json!({ "upn": crate::routes::audit::clip(&user.upn) }))
        }
    }
}
