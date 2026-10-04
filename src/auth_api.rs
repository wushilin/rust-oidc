//! The built-in Auth API: application permissions an administrator grants to an
//! application, for things a browser sign-in cannot do.
//!
//! Its one permission today is [`AuthApiPermission::CredentialsVerify`]: check
//! the password and authenticator code of a user assigned to the calling
//! application (`POST /{tenant}/api/v1/authenticate`, see
//! [`crate::routes::auth_api`]), for login prompts such as Linux PAM that cannot
//! run a browser flow.
//!
//! It works like Microsoft Graph's application permissions: the Auth API has a
//! fixed app id, present in every tenant without being registered; an
//! administrator grants a permission to an application (that grant is the
//! consent); the application signs in as itself with the client credentials
//! grant for `{AUTH_API_APP_ID}/.default` and receives a token whose `roles`
//! carry its permissions. Entra has no such API; this is a deliberate extension
//! (`docs/decisions-log.md`, 40).

use crate::db::Handle;
use crate::util::now;

/// The Auth API's app id: the audience of its tokens, and one of the two names a
/// client may ask for it by. Fixed and published, the same in every deployment,
/// like Microsoft Graph's `00000003-0000-0000-c000-000000000000`: it must never
/// change, or every integration breaks.
pub const AUTH_API_APP_ID: &str = "3bc73980-9fde-4fa7-9f74-9d421f0a127d";

/// The Auth API's readable name, as Graph is also `https://graph.microsoft.com`:
/// `scope=api://auth-api/.default`. Reserved: no application may register it as
/// an identifier URI ([`is_reserved_identifier_uri`]). Fixed like the app id.
pub const AUTH_API_IDENTIFIER_URI: &str = "api://auth-api";

/// What the console calls it.
pub const AUTH_API_NAME: &str = "Auth API";

/// The Auth API's application permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthApiPermission {
    /// Verify the password and authenticator code of a user assigned to the
    /// calling application.
    CredentialsVerify,
}

impl AuthApiPermission {
    pub const ALL: &'static [AuthApiPermission] = &[Self::CredentialsVerify];

    /// Its value: the `roles` claim, and the stored grant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialsVerify => "Credentials.Verify",
        }
    }

    /// Its fixed id: the `role_ids` claim, as an app role's id would be.
    pub fn id(self) -> &'static str {
        match self {
            Self::CredentialsVerify => "91a71692-0c7d-4a42-a890-e8b231028a6e",
        }
    }

    /// What granting it allows, in the console.
    pub fn description(self) -> &'static str {
        match self {
            Self::CredentialsVerify => {
                "Check the password and authenticator code of users assigned to this application, \
                 and read their profile, groups and roles when the check succeeds."
            }
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }

    /// As an app role, for the access token's `roles` and `role_ids`.
    pub fn role(self) -> crate::apps::RoleRef {
        crate::apps::RoleRef {
            id: self.id().to_string(),
            value: self.as_str().to_string(),
        }
    }
}

/// Whether a scope's resource names the Auth API, by its app id or its
/// identifier URI.
pub fn is_resource(resource: &str) -> bool {
    let resource = resource.trim_end_matches('/');
    resource.eq_ignore_ascii_case(AUTH_API_APP_ID) || resource.eq_ignore_ascii_case(AUTH_API_IDENTIFIER_URI)
}

/// Whether an identifier URI is the Auth API's, which no application may take:
/// a scope naming it must always mean the built-in API.
pub fn is_reserved_identifier_uri(uri: &str) -> bool {
    uri.trim_end_matches('/').eq_ignore_ascii_case(AUTH_API_IDENTIFIER_URI)
}

/// The Auth API permissions granted to a client service principal.
pub async fn granted<'c>(db: impl Handle<'c>, client_sp_id: &str) -> anyhow::Result<Vec<AuthApiPermission>> {
    let mut conn = db.acquire().await?;
    granted_in(&mut conn, client_sp_id).await
}

pub(crate) async fn granted_in(
    conn: &mut crate::db::Conn,
    client_sp_id: &str,
) -> anyhow::Result<Vec<AuthApiPermission>> {
    let rows: Vec<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT permission FROM auth_api_grants WHERE client_sp_id = ? ORDER BY permission",
    ))
    .bind(client_sp_id)
    .fetch_all(&mut *conn)
    .await?;
    // A value this build does not know grants nothing.
    Ok(rows
        .into_iter()
        .filter_map(|(p,)| AuthApiPermission::parse(&p))
        .collect())
}

/// Whether a client service principal holds a permission now.
pub async fn holds<'c>(db: impl Handle<'c>, client_sp_id: &str, permission: AuthApiPermission) -> anyhow::Result<bool> {
    Ok(granted(db, client_sp_id).await?.contains(&permission))
}

/// Grant a permission. Granting one already held changes nothing and is not an
/// error. False when it was already held.
pub(crate) async fn grant_in(
    conn: &mut crate::db::Conn,
    tenant_id: &str,
    client_sp_id: &str,
    permission: AuthApiPermission,
) -> anyhow::Result<bool> {
    // Looked for first: inside a transaction a broken primary key is a database
    // failure, not a no-op.
    if granted_in(&mut *conn, client_sp_id).await?.contains(&permission) {
        return Ok(false);
    }
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO auth_api_grants (client_sp_id, permission, tenant_id, created_at) VALUES (?, ?, ?, ?)",
    ))
    .bind(client_sp_id)
    .bind(permission.as_str())
    .bind(tenant_id)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

/// Withdraw a permission. False when it was not held.
pub(crate) async fn revoke_in(
    conn: &mut crate::db::Conn,
    client_sp_id: &str,
    permission: AuthApiPermission,
) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM auth_api_grants WHERE client_sp_id = ? AND permission = ?",
    ))
    .bind(client_sp_id)
    .bind(permission.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_round_trip_and_have_distinct_ids() {
        let mut ids = std::collections::HashSet::new();
        for p in AuthApiPermission::ALL {
            assert_eq!(AuthApiPermission::parse(p.as_str()), Some(*p));
            assert!(ids.insert(p.id()));
            assert_ne!(p.id(), AUTH_API_APP_ID);
        }
    }

    #[test]
    fn the_resource_is_named_by_its_app_id_or_its_identifier_uri() {
        assert!(is_resource(AUTH_API_APP_ID));
        assert!(is_resource(&AUTH_API_APP_ID.to_uppercase()));
        assert!(is_resource("api://auth-api"));
        assert!(is_resource("API://Auth-API/"));
        assert!(!is_resource("api://auth-api-2"));
        assert!(!is_resource(crate::scopes::GRAPH_APP_ID));
    }

    /// The published names: changing either breaks every integration.
    #[test]
    fn the_published_names_do_not_change() {
        assert_eq!(AUTH_API_APP_ID, "3bc73980-9fde-4fa7-9f74-9d421f0a127d");
        assert_eq!(AUTH_API_IDENTIFIER_URI, "api://auth-api");
        assert_eq!(AuthApiPermission::CredentialsVerify.as_str(), "Credentials.Verify");
        assert_eq!(
            AuthApiPermission::CredentialsVerify.id(),
            "91a71692-0c7d-4a42-a890-e8b231028a6e"
        );
    }
}
