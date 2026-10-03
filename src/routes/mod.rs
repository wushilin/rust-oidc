pub mod audit;
mod authorize;
mod device;
pub mod discovery;
mod logout;
mod myaccount;
mod token;
mod user_grants;
mod userinfo;

use axum::Router;
use axum::http::HeaderValue;
use axum::routing::{get, post};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

pub use authorize::{Prompt, ResponseMode, ResponseType};
pub use token::GrantType;

use crate::AppState;

/// All routes, nested under the public URL's path (e.g. `/rust-oidc`).
/// Paths mirror Entra ID's v2.0 endpoints.
pub fn router(state: AppState) -> Router {
    // Metadata and keys are public and fetched by browser apps (SPAs), as in Entra.
    let public_metadata = Router::new()
        .route(
            "/{tenant}/v2.0/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/{tenant}/discovery/v2.0/keys", get(discovery::keys))
        .route("/oidc/userinfo", get(userinfo::userinfo).post(userinfo::userinfo))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        ));

    let routes = Router::new()
        .merge(public_metadata)
        .route(
            "/{tenant}/oauth2/v2.0/token",
            post(token::token).options(token::preflight),
        )
        .route(
            "/{tenant}/oauth2/v2.0/authorize",
            get(authorize::authorize).post(authorize::authorize),
        )
        .route("/{tenant}/login", post(authorize::login))
        .route("/{tenant}/oauth2/v2.0/devicecode", post(device::devicecode))
        .route(
            "/{tenant}/oauth2/deviceauth",
            get(device::deviceauth_get).post(device::deviceauth_post),
        )
        .route("/{tenant}/oauth2/v2.0/logout", get(logout::logout).post(logout::logout))
        .route("/{tenant}/myaccount", get(myaccount::page).post(myaccount::post))
        .route("/healthz", get(|| async { "ok" }))
        // The admin console. Mounted here so it sits under the public URL's path
        // prefix like every other route.
        .merge(crate::admin::routes::router())
        .with_state(state.clone());

    let prefix = state.public_url.path();
    let app = if prefix.is_empty() {
        routes
    } else {
        Router::new().nest(prefix, routes)
    };
    app.layer(TraceLayer::new_for_http())
}

/// How a user's change to their own account came out, for the sign-in pages and
/// My Account (the console's own sign-in uses the console's `settle`). A
/// refusal is shown on the page the user was on; anything else is an error page.
pub(crate) fn settle_own<T>(outcome: crate::txn::Outcome<T>, tenant_name: &str) -> crate::admin::routes::Settled<T> {
    use crate::admin::routes::Settled;
    use crate::txn::{Outcome, Refusal};
    match outcome {
        Outcome::Done(v) => Settled::Done(v),
        // Only the user may change their own account; anything else is ours.
        Outcome::Refused(Refusal::NotPermitted) | Outcome::Failed(_) => Settled::Respond(crate::html::error(
            Some(tenant_name),
            &crate::error::AadError::server_error().description(),
        )),
        Outcome::Refused(r) => Settled::Refused(r.to_string()),
    }
}

/// The user chooses a new password for their own account, `home` being its
/// tenant: checked against their history and hashed first, then stored by the
/// engine with its audit row.
pub(crate) async fn change_own_password(
    st: &AppState,
    home: &crate::tenant::Tenant,
    user_id: &str,
    password: &str,
    via: audit::Channel,
) -> crate::txn::Outcome<()> {
    use crate::users::{self, PasswordSetBy};
    let password = match users::prepare_password(&st.pool, home, user_id, password, PasswordSetBy::User).await {
        Ok(p) => p,
        Err(e) => return crate::txn::Outcome::from_error(&e),
    };
    let change = crate::txn::ops::self_service::ChangeOwnPassword {
        tenant_id: home.id.clone(),
        user_id: user_id.to_string(),
        password,
        via,
    };
    crate::txn::run(&st.pool, &own(user_id), &change).await
}

/// The user's authenticator, confirmed with a code from it, becomes theirs:
/// recovery codes are made first, and the engine stores both with the audit row.
/// The output is the recovery codes, to show once.
pub(crate) async fn enroll_own_authenticator(
    st: &AppState,
    home_id: &str,
    user_id: &str,
    secret: &str,
    via: audit::Channel,
    voluntary: bool,
) -> crate::txn::Outcome<Vec<String>> {
    let enroll = crate::txn::ops::self_service::EnrollAuthenticator {
        tenant_id: home_id.to_string(),
        user_id: user_id.to_string(),
        secret: secret.to_string(),
        codes: crate::mfa::NewRecoveryCodes::generate(),
        via,
        voluntary,
    };
    crate::txn::run(&st.pool, &own(user_id), &enroll).await
}

/// The actor for a user's change to their own account.
pub(crate) fn own(user_id: &str) -> crate::txn::Actor {
    crate::txn::Actor::User {
        user_id: user_id.to_string(),
    }
}
