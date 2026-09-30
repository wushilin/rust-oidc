//! Resolving a requested `scope` string the way Entra ID v2 does:
//!
//! - `openid`, `profile`, `email`, `offline_access` are OIDC scopes.
//! - `{resource}/{value}` asks for delegated permission `value` of the API whose
//!   identifier URI (or appId) is `{resource}`. `{resource}/.default` means every
//!   permission the API exposes (consent is implicit here).
//! - A request may target only one resource.
//! - Without a resource, Entra issues a Microsoft Graph token; we do the same with
//!   Graph's appId as audience, and that token is what `/oidc/userinfo` accepts.
//!   Bare names like `User.Read` are Graph scopes, as in Entra.

use crate::db::DbPool;

use crate::apps::{self, Application, ServicePrincipal};
use crate::error::{AadError, Aadsts};
use crate::tenant::Tenant;

pub const OIDC_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];
pub const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
const GRAPH_RESOURCE: &str = "https://graph.microsoft.com";
const GRAPH_SCOPES: [&str; 1] = ["User.Read"];

#[derive(Debug, Clone)]
pub enum Resource {
    Graph,
    App { app: Application, sp: ServicePrincipal },
}

impl Resource {
    pub fn audience(&self) -> &str {
        match self {
            Resource::Graph => GRAPH_APP_ID,
            Resource::App { app, .. } => &app.app_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    /// Requested OIDC scopes, in canonical order.
    pub oidc: Vec<&'static str>,
    pub resource: Resource,
    /// Values for the access token's `scp` claim.
    pub scp: Vec<String>,
    /// Scopes to report back in the token response's `scope` field.
    pub granted: Vec<String>,
}

impl Grant {
    pub fn has(&self, oidc_scope: &str) -> bool {
        self.oidc.contains(&oidc_scope)
    }
}

fn invalid_scope(scope: &str) -> AadError {
    AadError::invalid_scope(
        Aadsts::InvalidScope,
        format!("The provided value for the input parameter 'scope' is not valid. The scope '{scope}' is not valid."),
    )
}

pub async fn resolve(pool: &DbPool, tenant: &Tenant, scope: &str) -> Result<Grant, AadError> {
    let mut oidc = Vec::new();
    let mut graph_scopes: Vec<String> = Vec::new();
    // (identifier as requested, resolved resource, requested values)
    let mut app_resource: Option<(String, Application, ServicePrincipal, Vec<String>)> = None;
    let mut saw_graph_resource = false;

    for item in scope.split_whitespace() {
        if let Some(s) = OIDC_SCOPES.iter().find(|s| s.eq_ignore_ascii_case(item)) {
            if !oidc.contains(s) {
                oidc.push(*s);
            }
            continue;
        }
        let (resource, value) = match item.rsplit_once('/') {
            Some((r, v)) if !r.is_empty() && !v.is_empty() => (Some(r), v),
            _ => (None, item),
        };
        let is_graph = match resource {
            None => true,
            Some(r) => {
                r.trim_end_matches('/').eq_ignore_ascii_case(GRAPH_RESOURCE) || r.eq_ignore_ascii_case(GRAPH_APP_ID)
            }
        };
        if is_graph {
            saw_graph_resource = true;
            if value == ".default" {
                graph_scopes.extend(GRAPH_SCOPES.iter().map(|s| s.to_string()));
            } else if let Some(s) = GRAPH_SCOPES.iter().find(|s| s.eq_ignore_ascii_case(value)) {
                graph_scopes.push(s.to_string());
            } else {
                return Err(invalid_scope(item));
            }
            continue;
        }
        let resource = resource.expect("non-graph scopes have a resource");
        match &mut app_resource {
            Some((existing, _, _, values)) if existing == resource => values.push(value.to_string()),
            Some(_) => return Err(more_than_one_resource()),
            None => {
                let (app, sp) = apps::resolve_resource(pool, &tenant.id, resource)
                    .await?
                    .ok_or_else(|| AadError::resource_not_found(resource, &tenant.name))?;
                app_resource = Some((resource.to_string(), app, sp, vec![value.to_string()]));
            }
        }
    }
    if app_resource.is_some() && saw_graph_resource {
        return Err(more_than_one_resource());
    }
    oidc.sort_by_key(|s| OIDC_SCOPES.iter().position(|o| o == s));

    let mut granted: Vec<String> = oidc.iter().map(|s| s.to_string()).collect();
    let (resource, scp) = match app_resource {
        Some((identifier, app, sp, values)) => {
            let exposed = apps::enabled_scopes(pool, &app).await?;
            let mut scp = Vec::new();
            for value in values {
                if value == ".default" {
                    scp.extend(exposed.iter().cloned());
                } else if let Some(s) = exposed.iter().find(|s| **s == value) {
                    scp.push(s.clone());
                } else {
                    return Err(invalid_scope(&format!("{identifier}/{value}")));
                }
            }
            scp.sort();
            scp.dedup();
            granted.extend(scp.iter().map(|v| format!("{identifier}/{v}")));
            (Resource::App { app, sp }, scp)
        }
        None => {
            graph_scopes.sort();
            graph_scopes.dedup();
            granted.extend(graph_scopes.iter().cloned());
            // Graph tokens also carry the OIDC scopes in scp, as Entra's do.
            let mut scp: Vec<String> = oidc
                .iter()
                .filter(|s| **s != "offline_access")
                .map(|s| s.to_string())
                .collect();
            scp.extend(graph_scopes);
            (Resource::Graph, scp)
        }
    };
    Ok(Grant {
        oidc,
        resource,
        scp,
        granted,
    })
}

fn more_than_one_resource() -> AadError {
    AadError::invalid_scope(
        Aadsts::MultipleResourcesInScope,
        "Provided value for the input parameter scope is not valid because it contains more than one resource.",
    )
}
