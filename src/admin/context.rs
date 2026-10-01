//! One request's administrative identity, and the single authorization gate.
//!
//! Every console handler takes an [`AdminContext`] and asks it one question:
//! `require(action, on)`. No handler compares tenant ids, reads a role name or
//! looks at whether a tenant has been assumed. That is the whole point of the
//! type: there is one place where a grant is interpreted, and
//! [`crate::rbac::allowed`] is the only thing underneath it.
//!
//! Two properties are structural rather than remembered:
//!
//! - **Grants are recomputed every request.** The session cookie carries an id
//!   and nothing else, so revoking a binding or a group membership takes effect
//!   on the admin's next click rather than at their next sign-in.
//! - **Scope is compared against a canonical tenant id.** A URL may address a
//!   tenant by GUID or by one of its verified domains, so the extractor resolves
//!   the `{tenant}` segment once and [`On::Tenant`] can only name a key that was
//!   resolved. [`AdminContext::can_in`] takes a resolved [`Tenant`] value, so a
//!   raw URL segment cannot be passed to it even by mistake.

// Refusal pages travel in `Err`, the way the sign-in flow already does it;
// boxing them buys nothing here.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use axum::response::Response;

use crate::AppState;
use crate::admin::{bindings, session, view};
use crate::rbac::{self, Action, EffectiveBinding};
use crate::tenant::{self, Tenant};
use crate::users::{self, User};

/// What an action is being checked against.
pub enum On<'a> {
    /// A specific tenant, named by the key that appeared in the URL.
    Tenant(&'a str),
    /// Platform-wide: only an `All`-scope grant satisfies it.
    Platform,
}

/// The `{tenant}` path parameter, resolved once per request.
const TENANT_PARAM: &str = "tenant";

pub struct AdminContext {
    pub user: User,
    pub home_tenant: Tenant,
    /// The tenant a platform administrator has assumed. Display and defaults only:
    /// it never widens or narrows what is permitted, because the `All`-scope
    /// binding that allowed the assume already covers the tenant.
    pub acting_tenant: Option<Tenant>,
    /// Token every form in this session must echo.
    pub csrf: String,
    /// Identifies the session row, for `set_acting_tenant`.
    pub cookie_hash: String,
    bindings: Vec<EffectiveBinding>,
    /// URL key (GUID or domain) -> the tenant it resolved to, for this request only.
    resolved: HashMap<String, Tenant>,
}

impl AdminContext {
    /// The signed-in administrator's effective bindings, for the rules in
    /// [`crate::admin::authz`] that are about more than one tenant.
    pub fn bindings(&self) -> &[EffectiveBinding] {
        &self.bindings
    }

    /// Whether the action is permitted. The only interpretation of a grant.
    pub fn can(&self, action: Action, on: On<'_>) -> bool {
        match on {
            On::Platform => rbac::allowed_at_all_scope(&self.bindings, action),
            On::Tenant(key) => self.resolved.get(key).is_some_and(|t| self.can_in(action, t)),
        }
    }

    /// [`Self::can`] for a tenant that is already resolved. Taking a [`Tenant`]
    /// rather than a string is what makes an alias impossible to pass here.
    pub fn can_in(&self, action: Action, tenant: &Tenant) -> bool {
        rbac::allowed(&self.bindings, action, &tenant.id)
    }

    /// Fail the request unless the action is permitted.
    ///
    pub fn require(&self, action: Action, on: On<'_>) -> Result<(), Response> {
        if self.can(action, on) {
            Ok(())
        } else {
            Err(view::forbidden())
        }
    }

    /// The tenant a URL key resolved to, or `None` when it named nothing live.
    pub fn tenant(&self, key: &str) -> Option<&Tenant> {
        self.resolved.get(key)
    }

    /// The tenant whose pages the chrome should link to: the assumed one if any,
    /// else the administrator's own.
    pub fn default_tenant(&self) -> &Tenant {
        self.acting_tenant.as_ref().unwrap_or(&self.home_tenant)
    }

    /// Double-submit check: the form must echo the token derived from the session
    /// cookie. A cross-site post cannot know it, and `SameSite=Lax` means it does
    /// not even carry the cookie.
    pub fn check_csrf(&self, form: &HashMap<String, String>) -> Result<(), Response> {
        let submitted = form.get(session::CSRF_FIELD).map(String::as_str).unwrap_or_default();
        if crate::util::ct_eq(submitted, &self.csrf) {
            Ok(())
        } else {
            Err(view::bad_request(
                "That form was stale or did not come from the console. Reload the page and try again.",
            ))
        }
    }
}

impl FromRequestParts<AppState> for AdminContext {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Response> {
        let sign_in = || view::see_other(&format!("{}/admin", st.public_url.base()));

        let Some(cookie) = crate::session::cookie(&parts.headers, session::ADMIN_COOKIE) else {
            return Err(sign_in());
        };
        let found = session::find(&st.pool, &parts.headers).await.map_err(|e| {
            tracing::error!("admin session lookup failed: {e}");
            view::server_error()
        })?;
        let Some(sess) = found else { return Err(sign_in()) };

        // A disabled, soft-deleted or moved account, or a tenant that has since
        // been disabled, is not an administrator: drop the session rather than
        // leave a stale one usable.
        let home = tenant::resolve(&st.pool, &sess.home_tenant).await.map_err(|e| {
            tracing::error!("admin home tenant lookup failed: {e}");
            view::server_error()
        })?;
        let user = match &home {
            Some(home) => users::find(&st.pool, &home.id, &sess.user_id).await.map_err(|e| {
                tracing::error!("admin user lookup failed: {e}");
                view::server_error()
            })?,
            None => None,
        };
        let (Some(home_tenant), Some(user)) = (home, user) else {
            let _ = session::end(&st.pool, &parts.headers).await;
            return Err(sign_in());
        };
        if !user.enabled {
            let _ = session::end(&st.pool, &parts.headers).await;
            return Err(sign_in());
        }

        let bindings = bindings::effective_for_user(&st.pool, &user.id).await.map_err(|e| {
            tracing::error!("effective bindings lookup failed: {e}");
            view::server_error()
        })?;
        let csrf = session::csrf_for(&cookie);
        if bindings.is_empty() {
            return Err(view::no_access(st.public_url.base(), &user.upn, &csrf));
        }

        // An assumed tenant that has gone away simply stops applying.
        let acting_tenant = match &sess.acting_tenant {
            Some(id) => tenant::resolve(&st.pool, id).await.unwrap_or_default(),
            None => None,
        };

        let mut resolved = HashMap::new();
        if let Ok(params) = RawPathParams::from_request_parts(parts, st).await {
            for (name, value) in params.iter() {
                if name == TENANT_PARAM
                    && let Ok(Some(t)) = tenant::resolve(&st.pool, value).await
                {
                    resolved.insert(value.to_string(), t);
                }
            }
        }

        Ok(Self {
            user,
            home_tenant,
            acting_tenant,
            csrf,
            cookie_hash: sess.cookie_hash,
            bindings,
            resolved,
        })
    }
}
