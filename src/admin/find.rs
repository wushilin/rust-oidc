//! Find an object by its id.
//!
//! Ids are everywhere -- in tokens, in the audit log, in other systems' error
//! messages -- and an id on its own says nothing about what it is. This answers
//! "what is this": a user, a group, an application, one of its roles or scopes,
//! a service principal, or a tenant, with its name and a way to open it.
//!
//! It is not a way around the tenant boundary. An object is reported only when
//! the administrator could have opened it anyway: its tenant is one their roles
//! read, with the action that kind of object needs. Anything else, and anything
//! that does not exist, gets the same answer.

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::AppState;
use crate::admin::context::AdminContext;
use crate::admin::routes::{At, PlatformTab, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{APP_READ, GROUP_READ, TENANT_READ, USER_READ};
use crate::rbac::Action;
use crate::tenant::{self, Tenant};

/// The query parameter the search box submits.
pub const ID_PARAM: &str = "id";

/// What kind of thing an id turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tenant,
    User,
    Group,
    Application,
    ServicePrincipal,
    AppRole,
    Scope,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tenant => "Tenant",
            Self::User => "User",
            Self::Group => "Group",
            Self::Application => "Application",
            Self::ServicePrincipal => "Service principal",
            Self::AppRole => "App role",
            Self::Scope => "Scope",
        }
    }

    /// What it takes to see one, in its tenant.
    fn action(self) -> Action {
        match self {
            Self::Tenant => TENANT_READ,
            Self::User => USER_READ,
            Self::Group => GROUP_READ,
            Self::Application | Self::ServicePrincipal | Self::AppRole | Self::Scope => APP_READ,
        }
    }
}

/// An object an id resolved to.
pub struct Found {
    pub kind: Kind,
    pub name: String,
    /// What else there is to say: whose role it is, which id matched.
    pub detail: String,
    pub tenant: Tenant,
    /// Its page in the console, where it has one.
    pub href: Option<String>,
}

/// Every object `id` names that this administrator may see. Usually one; an id is
/// looked for as each kind, since nothing about a GUID says which it is.
pub async fn lookup(st: &AppState, ctx: &AdminContext, id: &str) -> Vec<Found> {
    let id = crate::util::fold(id);
    if id.is_empty() {
        return Vec::new();
    }
    let base = st.public_url.base();
    let pool = &st.pool;
    let mut found = Vec::new();

    // (kind, tenant id, name, detail, path under the tenant)
    let mut hits: Vec<(Kind, String, String, String, Option<String>)> = Vec::new();

    type Row3 = (String, String, String);
    type Row4 = (String, String, String, String);

    if let Ok(Some((tid, name))) = sqlx::query_as::<_, (String, String)>(crate::db::q(
        pool,
        "SELECT id, name FROM tenants WHERE id = ? AND deleted_at IS NULL",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((Kind::Tenant, tid, name, String::new(), Some(String::new())));
    }
    if let Ok(Some((uid, tid, upn))) = sqlx::query_as::<_, Row3>(crate::db::q(
        pool,
        "SELECT id, tenant_id, upn FROM users WHERE id = ? AND deleted_at IS NULL",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((Kind::User, tid, upn, String::new(), Some(format!("users/{uid}"))));
    }
    if let Ok(Some((gid, tid, name))) = sqlx::query_as::<_, Row3>(crate::db::q(
        pool,
        "SELECT id, tenant_id, name FROM user_groups WHERE id = ?",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((Kind::Group, tid, name, String::new(), Some(format!("groups/{gid}"))));
    }
    // An application has two ids: its object id and its client id.
    if let Ok(Some((object_id, app_id, tid, name))) = sqlx::query_as::<_, Row4>(crate::db::q(
        pool,
        "SELECT id, app_id, tenant_id, display_name FROM applications
         WHERE (id = ? OR app_id = ?) AND deleted_at IS NULL",
    ))
    .bind(&id)
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        let detail = if object_id == id {
            format!("matched its object id; its client id is {app_id}")
        } else {
            "matched its application (client) id".to_string()
        };
        hits.push((Kind::Application, tid, name, detail, Some(format!("apps/{app_id}"))));
    }
    if let Ok(Some((tid, app_id, name))) = sqlx::query_as::<_, Row3>(crate::db::q(
        pool,
        "SELECT s.tenant_id, s.app_id, a.display_name FROM service_principals s
         JOIN applications a ON a.app_id = s.app_id WHERE s.id = ?",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((
            Kind::ServicePrincipal,
            tid,
            name,
            "the identity of this application in the tenant; the subject of its own tokens".to_string(),
            Some(format!("apps/{app_id}")),
        ));
    }
    if let Ok(Some((value, app_id, tid, app_name))) = sqlx::query_as::<_, Row4>(crate::db::q(
        pool,
        "SELECT r.value, a.app_id, a.tenant_id, a.display_name FROM app_roles r
         JOIN applications a ON a.id = r.application_id WHERE r.id = ?",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((
            Kind::AppRole,
            tid,
            value,
            format!("a role of the application {app_name}"),
            Some(format!("apps/{app_id}")),
        ));
    }
    if let Ok(Some((value, app_id, tid, app_name))) = sqlx::query_as::<_, Row4>(crate::db::q(
        pool,
        "SELECT c.value, a.app_id, a.tenant_id, a.display_name FROM app_scopes c
         JOIN applications a ON a.id = c.application_id WHERE c.id = ?",
    ))
    .bind(&id)
    .fetch_optional(pool)
    .await
    {
        hits.push((
            Kind::Scope,
            tid,
            value,
            format!("a scope exposed by the application {app_name}"),
            Some(format!("apps/{app_id}")),
        ));
    }

    for (kind, tenant_id, name, detail, path) in hits {
        // The boundary: only what this administrator could have opened anyway.
        let Ok(Some(t)) = tenant::resolve(pool, &tenant_id).await else {
            continue;
        };
        if !ctx.can_in(kind.action(), &t) {
            continue;
        }
        let href = match (kind, path) {
            (Kind::Tenant, _) => crate::admin::routes::tenant_home(base, ctx, &t),
            (_, Some(path)) => Some(format!("{base}/admin/tenants/{}/{path}", t.id)),
            (_, None) => None,
        };
        found.push(Found {
            kind,
            name,
            detail,
            tenant: t,
            href,
        });
    }
    found
}

/// A short name for an id, for pages that would otherwise print the id alone:
/// "alice@contoso.com" for a user, "orders-api (application)" for an app. `None`
/// when the id names nothing this administrator may see.
pub async fn label(st: &AppState, ctx: &AdminContext, id: &str) -> Option<String> {
    let first = lookup(st, ctx, id).await.into_iter().next()?;
    Some(match first.kind {
        Kind::User => first.name,
        kind => format!("{} ({})", first.name, kind.label().to_lowercase()),
    })
}

/// Names already looked up while rendering one page, so an id that appears on
/// forty rows is resolved once.
pub type Names = std::collections::HashMap<String, Option<String>>;

/// A table cell for an id. Where the administrator may see what it names, the
/// name, linking to what it is, with the id as the tooltip; otherwise the id
/// itself. Values that are not ids at all (`cli`, `anonymous`) are left as they are.
pub async fn cell(st: &AppState, ctx: &AdminContext, names: &mut Names, id: &str) -> String {
    if id.is_empty() {
        return String::new();
    }
    if !crate::util::is_guid(id) {
        return e(id);
    }
    if !names.contains_key(id) {
        let name = label(st, ctx, id).await;
        names.insert(id.to_string(), name);
    }
    let href = link(st.public_url.base(), id);
    match names.get(id).and_then(|n| n.as_deref()) {
        Some(name) => format!(r#"<a href="{}" title="{}">{}</a>"#, e(&href), e(id), e(name)),
        None => format!(r#"<a class="id" href="{}">{}</a>"#, e(&href), e(id)),
    }
}

fn find_url(base: &str) -> String {
    format!("{base}/admin/find")
}

/// A link to the find page for one id.
pub fn link(base: &str, id: &str) -> String {
    format!("{}?{ID_PARAM}={}", find_url(base), urlencode(id))
}

fn urlencode(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let form = parse_form(query.unwrap_or_default().as_bytes());
    let id = field(&form, ID_PARAM).trim();
    let base = st.public_url.base();

    let results = if id.is_empty() {
        r#"<p class="empty">Paste an id from a token, the audit log or an error message to see what it is.</p>"#
            .to_string()
    } else {
        let found = lookup(&st, &ctx, id).await;
        if found.is_empty() {
            // One answer for "does not exist" and "not yours to see".
            format!(
                r#"<p class="empty">Nothing with the id <code>{}</code> that your roles can see.</p>"#,
                e(id)
            )
        } else {
            let rows: String = found
                .iter()
                .map(|f| {
                    let name = match &f.href {
                        Some(href) => format!(r#"<a href="{}">{}</a>"#, e(href), e(&f.name)),
                        None => e(&f.name),
                    };
                    format!(
                        "<tr><td>{kind}</td><td>{name}</td><td>{tenant}</td><td class=\"muted\">{detail}</td></tr>",
                        kind = e(f.kind.label()),
                        tenant = e(&f.tenant.name),
                        detail = e(&f.detail),
                    )
                })
                .collect();
            format!(
                r#"<p>The id <code>{}</code> is:</p>
<table><tr><th>Kind</th><th>Name</th><th>Tenant</th><th></th></tr>{rows}</table>"#,
                e(id)
            )
        }
    };
    let body = format!(
        r#"<h1>Find by id</h1><p class="sub">What an id is: a user, group, application, role, scope, service principal or tenant.</p>
<div class="toolbar"><form method="get" action="{url}">
<input name="{ID_PARAM}" type="search" value="{id}" placeholder="An object id or application id" aria-label="Id to look up" autofocus>
<button type="submit">Find</button></form></div>
{results}"#,
        url = e(&find_url(base)),
        id = e(id),
    );
    view::page(
        &chrome(&st, &ctx, At::Platform(PlatformTab::Find)),
        StatusCode::OK,
        "Find by id",
        &body,
    )
}
