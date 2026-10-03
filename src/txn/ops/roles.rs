//! Console role grants: a tenant's roles, and Global Administrator.
//!
//! The rules are not implemented here. No widening is
//! [`authz::BindingWriter::may_write`] (an administrator cannot grant or revoke
//! reach they do not hold; the operator at the command line is not bound by it),
//! where a role is held is [`bindings::create_in`], and the last Global
//! Administrator is [`authz::delete_in`] and the engine's own end-of-run check.
//!
//! Both kinds lock [`LockTarget::Administrators`], so two changes to who
//! administers never interleave: two revocations of the last two Global
//! Administrators run one after the other, and the second is refused.

use serde_json::json;

use super::tenant;
use crate::admin::BINDING_WRITE;
use crate::admin::authz::{self, BindingWriter, RefusedReason};
use crate::admin::bindings;
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::rbac::{RoleId, Scope as RoleScope, ScopeKind};
use crate::tenant::Tenant;
use crate::txn::{Actor, Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

/// Refused when a revocation would take the last Global Administrator away.
const LAST_GLOBAL_ADMINISTRATOR: &str = "That is the last Global Administrator. Make somebody else one first.";

/// Which page a role is granted or revoked from: a tenant's Roles tab, or the
/// Global roles page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolePage {
    /// A role held inside this tenant, by one of its users or groups.
    Tenant(String),
    /// Global Administrator, held by a user or group of the root tenant.
    Global,
}

/// Who a role is granted to, by the name the administrator typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A user name. On the Global roles page, a name without a domain is
    /// completed with the root tenant's.
    User(String),
    /// A group name, in the tenant (or, for the Global roles page, the root tenant).
    Group(String),
}

/// The binding writer the actor is: an administrator is held to no-widening, the
/// command line is not.
fn writer(actor: &Actor) -> BindingWriter<'_> {
    match actor {
        Actor::Cli => BindingWriter::Operator,
        other => BindingWriter::Admin(other.bindings()),
    }
}

/// The tenant a change to the Global roles belongs to in the audit log: the
/// root tenant's history, as it is not an event of any one other tenant; when
/// there is none, the administrator's own; from the command line, none.
async fn global_log_tenant(cx: &mut Cx<'_>) -> Step<Option<String>> {
    let root = crate::tenant::root_in(cx.conn()).await;
    if let Some(root) = cx.check(root)? {
        return Ok(Some(root.id));
    }
    let Some(user_id) = cx.actor().user_id().map(str::to_string) else {
        return Ok(None);
    };
    let me = crate::users::find_by_id_in(cx.conn(), &user_id).await;
    Ok(cx.check(me)?.map(|u| u.tenant_id))
}

/// Grant a console role.
pub struct GrantRole {
    pub page: RolePage,
    pub principal: Principal,
    pub role: RoleId,
}

/// What a grant wrote.
#[derive(Debug)]
pub struct GrantedRole {
    pub binding_id: String,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub scope_kind: ScopeKind,
    /// The tenant the audit row belongs to.
    pub log_tenant: Option<String>,
}

impl GrantRole {
    /// A tenant role, granted to a user or group of that tenant, applies to it.
    async fn in_tenant(&self, cx: &mut Cx<'_>, tenant: &Tenant) -> Step<(PrincipalType, String, RoleScope)> {
        if self.role.scope_kind() != ScopeKind::Tenants {
            return Err(cx.fail(Refusal::Invalid(format!(
                "{} is not a role of one tenant. It is granted from the Global roles page.",
                self.role.display_name()
            ))));
        }
        let (principal_type, name, found) = match &self.principal {
            Principal::User(name) => {
                let found = crate::users::find_by_upn_in(cx.conn(), &tenant.id, name).await;
                (PrincipalType::User, name, found.map(|u| u.map(|u| u.id)))
            }
            Principal::Group(name) => {
                let found = crate::groups::find_in(cx.conn(), &tenant.id, name).await;
                (PrincipalType::Group, name, found)
            }
        };
        let Some(principal_id) = cx.check(found)? else {
            return Err(cx.fail(Refusal::NotFound(format!(
                "No {} named '{name}' in {}.",
                principal_type.as_str().to_lowercase(),
                tenant.name
            ))));
        };
        Ok((
            principal_type,
            principal_id,
            RoleScope::Tenants(vec![tenant.id.clone()]),
        ))
    }

    /// Global Administrator, to a user or group of the root tenant; a user of
    /// another tenant is refused by where the role can be held.
    async fn global(&self, cx: &mut Cx<'_>) -> Step<(PrincipalType, String, RoleScope)> {
        if self.role.scope_kind() != ScopeKind::All {
            return Err(cx.fail(Refusal::Invalid(
                "A role inside a tenant is granted from that tenant's Roles tab.".into(),
            )));
        }
        let root = crate::tenant::root_in(cx.conn()).await;
        let Some(root) = cx.check(root)? else {
            return Err(cx.fail(Refusal::Invalid("There is no root tenant.".into())));
        };
        let (principal_type, principal_id, home) = match &self.principal {
            Principal::User(typed) => {
                let typed = typed.trim();
                cx.ensure(!typed.is_empty(), || Refusal::Invalid("Enter a user name.".into()))?;
                // The part before the @ is completed with the root tenant's
                // domain; a full name is taken as typed, and its domain decides
                // its tenant.
                let account = if typed.contains('@') {
                    typed.to_string()
                } else {
                    let domains = crate::tenant::domains_in(cx.conn(), &root.id).await;
                    let domain = cx.check(domains)?.into_iter().next().unwrap_or_default();
                    format!("{typed}@{domain}")
                };
                let (_, domain) = account.rsplit_once('@').unwrap_or_default();
                let home = crate::tenant::resolve_in(cx.conn(), domain).await;
                let home = cx.check(home)?;
                let user = match &home {
                    Some(t) => {
                        let found = crate::users::find_by_upn_in(cx.conn(), &t.id, &account).await;
                        cx.check(found)?
                    }
                    None => None,
                };
                let Some(user) = user else {
                    return Err(cx.fail(Refusal::NotFound(format!("There is no account named '{account}'."))));
                };
                (PrincipalType::User, user.id, home)
            }
            Principal::Group(name) => {
                let name = name.trim();
                cx.ensure(!name.is_empty(), || Refusal::Invalid("Enter a group name.".into()))?;
                let found = crate::groups::find_in(cx.conn(), &root.id, name).await;
                let Some(id) = cx.check(found)? else {
                    return Err(cx.fail(Refusal::NotFound(format!(
                        "There is no group named '{name}' in {}.",
                        root.name
                    ))));
                };
                (PrincipalType::Group, id, Some(root.clone()))
            }
        };
        // Where the role applies follows from the role and the principal's tenant.
        let Some(scope) = home.as_ref().and_then(|t| self.role.scope_held_by(&t.id, t.is_root)) else {
            return Err(cx.fail(Refusal::Invalid(bindings::ScopeRefused::GlobalOutsideRoot.to_string())));
        };
        Ok((principal_type, principal_id, scope))
    }
}

impl Transaction for GrantRole {
    type Output = GrantedRole;
    const INFO: KindInfo = KindInfo {
        name: "Grant role",
        need: Need::Action(BINDING_WRITE),
        event: Event::AdminRoleGrant,
    };

    fn scope(&self) -> Scope {
        match &self.page {
            RolePage::Tenant(id) => Scope::Tenant(id.clone()),
            RolePage::Global => Scope::Platform,
        }
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<GrantedRole> {
        let (principal_type, principal_id, scope, log_tenant) = match &self.page {
            RolePage::Tenant(tenant_id) => {
                let tenant = tenant(cx, tenant_id).await?;
                let (t, id, scope) = self.in_tenant(cx, &tenant).await?;
                (t, id, scope, Some(tenant.id))
            }
            RolePage::Global => {
                let (t, id, scope) = self.global(cx).await?;
                let log_tenant = global_log_tenant(cx).await?;
                (t, id, scope, log_tenant)
            }
        };
        // A binding write is authorized against the *target* scope, so nobody
        // grants reach they do not already hold.
        let permitted = writer(cx.actor()).may_write(&scope);
        cx.ensure(permitted, || Refusal::NotPermitted)?;
        let created_by = cx
            .actor()
            .user_id()
            .unwrap_or(crate::db::Actor::Cli.as_str())
            .to_string();
        let created =
            bindings::create_in(cx.conn(), principal_type, &principal_id, self.role, &scope, &created_by).await;
        let binding_id = cx.check(created)?;
        Ok(GrantedRole {
            binding_id,
            principal_type,
            principal_id,
            scope_kind: scope.kind(),
            log_tenant,
        })
    }

    fn audit(&self, out: &GrantedRole) -> Audit {
        Audit {
            tenant_id: out.log_tenant.clone(),
            target: Some(out.binding_id.clone()),
            details: json!({
                "role": self.role.as_str(),
                "scopeKind": out.scope_kind.as_str(),
                "principalType": out.principal_type.as_str(),
                "principalId": out.principal_id,
            }),
        }
    }
}

/// Revoke a console role binding, from the page it is listed on.
pub struct RevokeRole {
    pub page: RolePage,
    pub binding_id: String,
}

/// What a revocation came to.
#[derive(Debug)]
pub struct RevokedRole {
    /// The tenant the audit row belongs to.
    pub log_tenant: Option<String>,
}

impl Transaction for RevokeRole {
    type Output = RevokedRole;
    const INFO: KindInfo = KindInfo {
        name: "Revoke role",
        need: Need::Action(BINDING_WRITE),
        event: Event::AdminRoleRevoke,
    };

    fn scope(&self) -> Scope {
        match &self.page {
            RolePage::Tenant(id) => Scope::Tenant(id.clone()),
            RolePage::Global => Scope::Platform,
        }
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<RevokedRole> {
        // Only a binding the page lists: a tenant's role is revoked in that
        // tenant, Global Administrator on the Global roles page.
        let (listed, log_tenant) = match &self.page {
            RolePage::Tenant(tenant_id) => {
                let tenant = tenant(cx, tenant_id).await?;
                let found = bindings::list_for_tenant_in(cx.conn(), &tenant.id).await;
                let listed = cx
                    .check(found)?
                    .iter()
                    .any(|b| b.id == self.binding_id && b.scope.kind() == ScopeKind::Tenants);
                (listed, Some(tenant.id))
            }
            RolePage::Global => {
                let found = bindings::list_all_in(cx.conn()).await;
                let listed = cx
                    .check(found)?
                    .iter()
                    .any(|b| b.id == self.binding_id && b.scope == RoleScope::All);
                (listed, global_log_tenant(cx).await?)
            }
        };
        cx.ensure(listed, || Refusal::NotPermitted)?;
        // One call, both rules: no widening, and no locking the platform out.
        let actor = cx.actor().clone();
        match authz::delete_in(cx.conn(), writer(&actor), &self.binding_id).await {
            Ok(()) => Ok(RevokedRole { log_tenant }),
            Err(RefusedReason::NotPermitted) => Err(cx.fail(Refusal::NotPermitted)),
            Err(RefusedReason::WouldLockOut) => Err(cx.fail(Refusal::RuleBroken(LAST_GLOBAL_ADMINISTRATOR.into()))),
        }
    }

    fn audit(&self, out: &RevokedRole) -> Audit {
        Audit {
            tenant_id: out.log_tenant.clone(),
            target: Some(self.binding_id.clone()),
            details: json!({}),
        }
    }
}
