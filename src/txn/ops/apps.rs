//! Changes to application registrations: the registration itself, its
//! credentials, URIs, scopes and roles, its sign-in switches, and who is assigned
//! to it.
//!
//! Every one locks the application it changes, so a change that checks
//! something about it (stopping accepting other tenants while none of theirs is
//! assigned) cannot interleave with one that changes what it checked.

use serde_json::json;

use super::tenant;
use crate::admin::{APP_ROTATE, APP_WRITE, ASSIGNMENT_WRITE};
use crate::apps::{
    self, Application, MemberType, NewSecret, PreparedSecret, Principal, RedirectPlatform, ScopeConsent,
};
use crate::auth_api::AuthApiPermission;
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::routes::audit::clip;
use crate::tenant::Tenant;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

const NO_SUCH_APP: &str = "There is no such application in this tenant.";

/// Refused when a pasted certificate carries its private key: it would be stored
/// as the certificate and the administrator would never know.
const PRIVATE_KEY_PASTED: &str = "that is a private key; paste only the certificate";
const PRIVATE_KEY_MARKER: &str = "PRIVATE KEY";

/// The tenant and one of its applications, or abort.
async fn application(cx: &mut Cx<'_>, tenant_id: &str, app_id: &str) -> Step<(Tenant, Application)> {
    let tenant = tenant(cx, tenant_id).await?;
    let found = apps::find_in(cx.conn(), app_id).await;
    match cx.check(found)? {
        Some(app) if app.tenant_id == tenant.id => Ok((tenant, app)),
        _ => Err(cx.fail(Refusal::NotFound(NO_SUCH_APP.into()))),
    }
}

/// The audit row of a change to one application: the tenant's, aimed at the app.
fn on_app(tenant_id: &str, app_id: &str, details: serde_json::Value) -> Audit {
    Audit {
        tenant_id: Some(tenant_id.to_string()),
        target: Some(app_id.to_string()),
        details,
    }
}

/// How a principal is named, for the audit row.
fn named(principal: &Principal) -> (PrincipalType, &str) {
    match principal {
        Principal::User(n) => (PrincipalType::User, n),
        Principal::Group(n) => (PrincipalType::Group, n),
        Principal::App(n) => (PrincipalType::ServicePrincipal, n),
    }
}

/// The parts every transaction on one application shares.
macro_rules! on_application {
    () => {
        fn scope(&self) -> Scope {
            Scope::Tenant(self.tenant_id.clone())
        }

        fn locks(&self) -> Vec<LockTarget> {
            vec![LockTarget::App(self.app_id.clone())]
        }
    };
}

/// Register an application: the application object, its default identifier URI
/// and its home tenant's service principal.
pub struct CreateApp {
    pub tenant_id: String,
    pub display_name: String,
}

impl Transaction for CreateApp {
    /// The new application.
    type Output = Application;
    const INFO: KindInfo = KindInfo {
        name: "Create application",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppCreate,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Application> {
        let tenant = tenant(cx, &self.tenant_id).await?;
        let name = self.display_name.trim();
        cx.ensure(!name.is_empty(), || {
            Refusal::Invalid("An application needs a display name.".into())
        })?;
        let created = apps::create_in(cx.conn(), &tenant, name).await;
        Ok(cx.check(created)?.application)
    }

    fn audit(&self, app: &Application) -> Audit {
        on_app(
            &self.tenant_id,
            &app.app_id,
            json!({ "displayName": clip(&app.display_name) }),
        )
    }
}

/// The *Sign-in and grants* switches, saved together: every one or none.
pub struct SaveAppFlags {
    pub tenant_id: String,
    pub app_id: String,
    /// Accounts of other tenants may be assigned and sign in. Refused off while
    /// any of theirs are assigned.
    pub accept_other_tenants: bool,
    pub mfa_required: bool,
    pub allow_password_grant: bool,
    pub allow_id_token_implicit: bool,
    pub allow_access_token_implicit: bool,
}

impl Transaction for SaveAppFlags {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Save application sign-in and grants",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppFlags,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (tenant, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::set_password_grant_allowed_in(cx.conn(), &app, self.allow_password_grant).await;
        cx.check(done)?;
        let done = apps::set_implicit_allowed_in(
            cx.conn(),
            &app,
            self.allow_id_token_implicit,
            self.allow_access_token_implicit,
        )
        .await;
        cx.check(done)?;
        let sp = apps::service_principal_in(cx.conn(), &tenant.id, &app.app_id).await;
        if let Some(sp) = cx.check(sp)? {
            let done = apps::set_mfa_required_in(cx.conn(), &sp.id, self.mfa_required).await;
            cx.check(done)?;
            // Read under the application's lock, so no assignment of another
            // tenant's account can arrive between the check and the write.
            let done = apps::set_accept_other_tenants_in(cx.conn(), &sp, self.accept_other_tenants).await;
            cx.check(done)?;
        }
        Ok(())
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "acceptOtherTenants": self.accept_other_tenants,
                "requireMfa": self.mfa_required,
                "allowPasswordGrant": self.allow_password_grant,
                "allowIdTokenImplicit": self.allow_id_token_implicit,
                "allowAccessTokenImplicit": self.allow_access_token_implicit,
            }),
        )
    }
}

/// Whether only assigned accounts may sign in to the application, in its home
/// tenant (Entra's "Assignment required?").
pub struct SetAssignmentRequired {
    pub tenant_id: String,
    pub app_id: String,
    pub required: bool,
}

impl Transaction for SetAssignmentRequired {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set assignment required",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppAssignmentRequired,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (tenant, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let sp = apps::service_principal_in(cx.conn(), &tenant.id, &app.app_id).await;
        let Some(sp) = cx.check(sp)? else {
            return Err(cx.fail(Refusal::NotFound(NO_SUCH_APP.into())));
        };
        let done = apps::set_assignment_required_in(cx.conn(), &sp.id, self.required).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "required": self.required }))
    }
}

/// Add a client secret, made before the transaction began. The output carries the
/// value to show once; the audit row has only its key id and expiry.
pub struct AddAppSecret {
    pub tenant_id: String,
    pub app_id: String,
    pub secret: PreparedSecret,
    pub valid_days: i64,
    pub display_name: Option<String>,
}

impl Transaction for AddAppSecret {
    type Output = NewSecret;
    const INFO: KindInfo = KindInfo {
        name: "Add client secret",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSecretAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<NewSecret> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let added = apps::add_prepared_secret_in(
            cx.conn(),
            &app,
            self.display_name.as_deref(),
            self.valid_days,
            &self.secret,
        )
        .await;
        cx.check(added)
    }

    fn audit(&self, created: &NewSecret) -> Audit {
        // The key id and the expiry, never the value and never a prefix of it.
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "keyId": created.key_id, "endsAt": created.end_at }),
        )
    }
}

/// Remove a client secret.
pub struct RemoveAppSecret {
    pub tenant_id: String,
    pub app_id: String,
    pub key_id: String,
}

impl Transaction for RemoveAppSecret {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove client secret",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSecretRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::remove_secret_in(cx.conn(), &app, &self.key_id).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "keyId": self.key_id }))
    }
}

/// Register a certificate for `private_key_jwt`, or replace the one with its
/// thumbprint.
pub struct AddAppCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate_pem: String,
    pub display_name: Option<String>,
}

impl Transaction for AddAppCertificate {
    /// Its key id (the thumbprint).
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Add certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppKeyAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let pasted_key = self.certificate_pem.contains(PRIVATE_KEY_MARKER);
        cx.ensure(!pasted_key, || Refusal::Invalid(PRIVATE_KEY_PASTED.into()))?;
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let added =
            apps::add_key_credential_in(cx.conn(), &app, &self.certificate_pem, self.display_name.as_deref()).await;
        cx.check(added)
    }

    fn audit(&self, key_id: &String) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "keyId": key_id }))
    }
}

/// Remove a certificate.
pub struct RemoveAppCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub key_id: String,
}

impl Transaction for RemoveAppCertificate {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppKeyRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::remove_key_credential_in(cx.conn(), &app, &self.key_id).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || {
            Refusal::NotFound("no certificate with that thumbprint is registered".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "keyId": self.key_id }))
    }
}

/// Register a redirect URI under a platform.
pub struct AddRedirectUri {
    pub tenant_id: String,
    pub app_id: String,
    pub platform: RedirectPlatform,
    pub uri: String,
}

impl Transaction for AddRedirectUri {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Add redirect URI",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppRedirectUriAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::add_redirect_uri_in(cx.conn(), &app, self.platform, &self.uri).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "platform": self.platform.as_str(), "uri": clip(&self.uri) }),
        )
    }
}

/// Remove a redirect URI from a platform.
pub struct RemoveRedirectUri {
    pub tenant_id: String,
    pub app_id: String,
    pub platform: RedirectPlatform,
    pub uri: String,
}

impl Transaction for RemoveRedirectUri {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove redirect URI",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppRedirectUriRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::remove_redirect_uri_in(cx.conn(), &app, self.platform, &self.uri).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || {
            Refusal::NotFound("that redirect URI is not registered under that platform".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "platform": self.platform.as_str(), "uri": clip(&self.uri) }),
        )
    }
}

/// Add an Application ID URI.
pub struct AddIdentifierUri {
    pub tenant_id: String,
    pub app_id: String,
    pub uri: String,
}

impl Transaction for AddIdentifierUri {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Add identifier URI",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppIdentifierUriAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::add_identifier_uri_in(cx.conn(), &app, &self.uri).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "uri": clip(&self.uri) }))
    }
}

/// Remove an Application ID URI; not the last one.
pub struct RemoveIdentifierUri {
    pub tenant_id: String,
    pub app_id: String,
    pub uri: String,
}

impl Transaction for RemoveIdentifierUri {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove identifier URI",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppIdentifierUriRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::remove_identifier_uri_in(cx.conn(), &app, &self.uri).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "uri": clip(&self.uri) }))
    }
}

/// Expose a delegated permission scope. Its display name defaults to its value.
pub struct AddAppScope {
    pub tenant_id: String,
    pub app_id: String,
    pub value: String,
    pub consent: ScopeConsent,
    pub display_name: Option<String>,
}

impl Transaction for AddAppScope {
    /// The scope's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Add scope",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppScopeAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let display = self.display_name.as_deref().unwrap_or(&self.value);
        let added = apps::add_scope_in(cx.conn(), &app, &self.value, display, self.consent).await;
        cx.check(added)
    }

    fn audit(&self, id: &String) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "id": id, "value": clip(&self.value), "consent": self.consent.as_str() }),
        )
    }
}

/// Define an app role. Its display name defaults to its value.
pub struct AddAppRole {
    pub tenant_id: String,
    pub app_id: String,
    pub value: String,
    pub member_types: Vec<MemberType>,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

impl Transaction for AddAppRole {
    /// The role's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Add app role",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppRoleAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let display = self.display_name.as_deref().unwrap_or(&self.value);
        let added = apps::add_role_in(
            cx.conn(),
            &app,
            &self.value,
            display,
            self.description.as_deref(),
            &self.member_types,
        )
        .await;
        cx.check(added)
    }

    fn audit(&self, id: &String) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "id": id,
                "value": clip(&self.value),
                "allowedMemberTypes": self.member_types.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            }),
        )
    }
}

/// Assign a user or group to the application with these roles; for one already
/// assigned, its roles become these.
pub struct AssignApp {
    pub tenant_id: String,
    pub app_id: String,
    pub principal: Principal,
    pub roles: Vec<String>,
}

impl Transaction for AssignApp {
    /// The assignment's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Assign to application",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAppAssign,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        cx.ensure(!matches!(self.principal, Principal::App(_)), || {
            Refusal::Invalid("choose a user or a group".into())
        })?;
        let (tenant, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        // `assign` resolves the principal within this tenant, checks each role,
        // and refuses another tenant's unless the application accepts them.
        let done = apps::assign_in(cx.conn(), &tenant, &app, &self.principal, &self.roles).await;
        cx.check(done)
    }

    fn audit(&self, id: &String) -> Audit {
        let (kind, name) = named(&self.principal);
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "assignmentId": id,
                "principalType": kind.as_str(),
                "principal": clip(name),
                "roles": self.roles.iter().map(|r| clip(r)).collect::<Vec<_>>(),
            }),
        )
    }
}

/// Withdraw a user's or group's assignment, with its roles.
pub struct UnassignApp {
    pub tenant_id: String,
    pub app_id: String,
    pub assignment_id: String,
}

impl Transaction for UnassignApp {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Unassign from application",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAppUnassign,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::unassign_in(cx.conn(), &self.tenant_id, &app, &self.assignment_id).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || Refusal::NotFound("that assignment no longer exists".into()))
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "assignmentId": self.assignment_id }),
        )
    }
}

/// Grant one of the application's roles to a client application (an
/// application permission). People are assigned with [`AssignApp`].
pub struct GrantAppRole {
    pub tenant_id: String,
    pub app_id: String,
    pub role: String,
    /// The client application, by its appId.
    pub client_app_id: String,
}

impl Transaction for GrantAppRole {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Grant application permission",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAppRoleAssign,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (tenant, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let client = Principal::App(self.client_app_id.clone());
        // `assign_role` resolves the client within this tenant and checks the
        // role's allowed member types.
        let done = apps::assign_role_in(cx.conn(), &tenant, &app, &self.role, &client).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "role": clip(&self.role),
                "principalType": PrincipalType::ServicePrincipal.as_str(),
                "principal": clip(&self.client_app_id),
            }),
        )
    }
}

/// Withdraw an application permission.
pub struct RevokeAppRole {
    pub tenant_id: String,
    pub app_id: String,
    pub assignment_id: String,
}

impl Transaction for RevokeAppRole {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Revoke application permission",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAppRoleUnassign,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app) = application(cx, &self.tenant_id, &self.app_id).await?;
        let done = apps::remove_role_assignment_in(cx.conn(), &self.tenant_id, &app, &self.assignment_id).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || {
            Refusal::NotFound("that role assignment no longer exists".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "assignmentId": self.assignment_id }),
        )
    }
}

/// Grant an application a permission of the built-in Auth API. Granting one it
/// already holds completes and changes nothing.
pub struct GrantAuthApiPermission {
    pub tenant_id: String,
    pub app_id: String,
    pub permission: AuthApiPermission,
}

/// The application's service principal in its home tenant, or abort.
async fn client_sp(cx: &mut Cx<'_>, tenant_id: &str, app_id: &str) -> Step<apps::ServicePrincipal> {
    let (tenant, app) = application(cx, tenant_id, app_id).await?;
    let sp = apps::service_principal_in(cx.conn(), &tenant.id, &app.app_id).await;
    match cx.check(sp)? {
        Some(sp) => Ok(sp),
        None => Err(cx.fail(Refusal::NotFound(NO_SUCH_APP.into()))),
    }
}

impl Transaction for GrantAuthApiPermission {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Grant Auth API permission",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAuthApiGrant,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let sp = client_sp(cx, &self.tenant_id, &self.app_id).await?;
        let done = crate::auth_api::grant_in(cx.conn(), &self.tenant_id, &sp.id, self.permission).await;
        cx.check(done)?;
        Ok(())
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "api": crate::auth_api::AUTH_API_APP_ID, "permission": self.permission.as_str() }),
        )
    }
}

/// Withdraw an Auth API permission from an application. Tokens it already holds
/// keep the role until they expire, but the API checks the grant on every call,
/// so it stops working at once.
pub struct RevokeAuthApiPermission {
    pub tenant_id: String,
    pub app_id: String,
    pub permission: AuthApiPermission,
}

impl Transaction for RevokeAuthApiPermission {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Revoke Auth API permission",
        need: Need::Action(ASSIGNMENT_WRITE),
        event: Event::AdminAuthApiRevoke,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let sp = client_sp(cx, &self.tenant_id, &self.app_id).await?;
        let done = crate::auth_api::revoke_in(cx.conn(), &sp.id, self.permission).await;
        let revoked = cx.check(done)?;
        cx.ensure(revoked, || {
            Refusal::NotFound("This application does not hold that permission.".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "api": crate::auth_api::AUTH_API_APP_ID, "permission": self.permission.as_str() }),
        )
    }
}
