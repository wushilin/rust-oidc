mod discovery;
mod token;

use axum::Router;
use axum::http::HeaderValue;
use axum::routing::{get, post};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

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
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        ));

    let routes = Router::new()
        .merge(public_metadata)
        .route("/{tenant}/oauth2/v2.0/token", post(token::token))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());

    let prefix = state.public_url.path();
    let app = if prefix.is_empty() {
        routes
    } else {
        Router::new().nest(prefix, routes)
    };
    app.layer(TraceLayer::new_for_http())
}
