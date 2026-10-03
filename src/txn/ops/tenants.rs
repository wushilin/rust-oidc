//! Changes to tenants: creating one, its name, whether it is enabled, its
//! domain, and its settings.
//!
//! Everything but the settings is platform work: authorized at
//! [`Scope::Platform`], an every-tenant grant and nothing less, as the console
//! has always done it (see `admin::tenants` and `docs/decisions-log.md`). The
//! settings are the tenant's own, authorized against the tenant.

use serde_json::json;

use super::tenant;
use crate::admin::{TENANT_CREATE, TENANT_WRITE};
use crate::db::Event;
use crate::routes::audit::clip;
use crate::tenant::{self as store, DomainChange, Tenant, TenantSettings};
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

/// A tenant by id, enabled or not: a disabled one has to be found to be enabled
/// again. Only the id names it here, so the lock taken on it is the tenant's own.
async fn any_tenant(cx: &mut Cx<'_>, tenant_id: &str) -> Step<Tenant> {
    let found = store::find_for_admin_in(cx.conn(), tenant_id).await;
    let found = cx.check(found)?;
    cx.ensure(found.id == tenant_id, || {
        Refusal::NotFound(format!("tenant '{tenant_id}' not found"))
    })?;
    Ok(found)
}

fn tenant_audit(tenant_id: &str, details: serde_json::Value) -> Audit {
    Audit {
        tenant_id: Some(tenant_id.to_string()),
        target: Some(tenant_id.to_string()),
        details,
    }
}

/// Create a tenant with its first domain. Never the root tenant: there is
/// exactly one, made at bootstrap.
pub struct CreateTenant {
    pub name: String,
    pub domain: String,
}

impl Transaction for CreateTenant {
    type Output = Tenant;
    const INFO: KindInfo = KindInfo {
        name: "Create tenant",
        need: Need::Action(TENANT_CREATE),
        event: Event::AdminTenantCreate,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Tenant> {
        let created = store::create_in(cx.conn(), &self.name, &self.domain, false).await;
        cx.check(created)
    }

    fn audit(&self, out: &Tenant) -> Audit {
        tenant_audit(&out.id, json!({ "name": out.name, "domain": clip(&self.domain) }))
    }
}

/// Rename a tenant: its display name only.
pub struct RenameTenant {
    pub tenant_id: String,
    pub name: String,
}

impl Transaction for RenameTenant {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Rename tenant",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantRename,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        any_tenant(cx, &self.tenant_id).await?;
        let done = store::set_name_in(cx.conn(), &self.tenant_id, &self.name).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        tenant_audit(&self.tenant_id, json!({ "name": clip(&self.name) }))
    }
}

/// Turn a disabled tenant back on.
pub struct EnableTenant {
    pub tenant_id: String,
}

impl Transaction for EnableTenant {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Enable tenant",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantEnable,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        any_tenant(cx, &self.tenant_id).await?;
        let done = store::set_enabled_in(cx.conn(), &self.tenant_id, true).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        tenant_audit(&self.tenant_id, json!({ "enabled": true }))
    }
}

/// Turn a tenant off: nobody signs in to it or administers it until it is
/// enabled again. Never the root tenant (the storage layer refuses it), and,
/// like every change that can take administrators away, serialised with the
/// others and checked by the engine's last-Global-Administrator rule.
pub struct DisableTenant {
    pub tenant_id: String,
}

impl Transaction for DisableTenant {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Disable tenant",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantDisable,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        any_tenant(cx, &self.tenant_id).await?;
        let done = store::set_enabled_in(cx.conn(), &self.tenant_id, false).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        tenant_audit(&self.tenant_id, json!({ "enabled": false }))
    }
}

/// Give a tenant a new domain, renaming every account onto it.
pub struct ChangeTenantDomain {
    pub tenant_id: String,
    pub domain: String,
}

impl Transaction for ChangeTenantDomain {
    type Output = DomainChange;
    const INFO: KindInfo = KindInfo {
        name: "Change tenant domain",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantDomainChange,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<DomainChange> {
        any_tenant(cx, &self.tenant_id).await?;
        let done = store::change_domain_in(cx.conn(), &self.tenant_id, &self.domain).await;
        cx.check(done)
    }

    fn audit(&self, change: &DomainChange) -> Audit {
        tenant_audit(
            &self.tenant_id,
            json!({ "from": change.from, "to": change.to, "renamed": change.renamed }),
        )
    }
}

/// Withdraw a surplus domain from a tenant that still has several.
pub struct RemoveTenantDomain {
    pub tenant_id: String,
    pub domain: String,
}

impl Transaction for RemoveTenantDomain {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove tenant domain",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantDomainRemove,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        any_tenant(cx, &self.tenant_id).await?;
        let done = store::remove_domain_in(cx.conn(), &self.tenant_id, &self.domain).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        tenant_audit(&self.tenant_id, json!({ "domain": clip(&self.domain) }))
    }
}

/// Replace a live tenant's settings. The storage layer checks the bounds.
pub struct SaveTenantSettings {
    pub tenant_id: String,
    pub settings: TenantSettings,
}

impl Transaction for SaveTenantSettings {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Save tenant settings",
        need: Need::Action(TENANT_WRITE),
        event: Event::AdminTenantSettings,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        tenant(cx, &self.tenant_id).await?;
        let done = store::save_settings_in(cx.conn(), &self.tenant_id, &self.settings).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        // Lifetimes are configuration, not anyone's personal data, so the values
        // themselves are safe to record and are what makes the row useful.
        let s = &self.settings;
        tenant_audit(
            &self.tenant_id,
            json!({
                "accessTokenLifetimeSecs": s.access_token_lifetime_secs,
                "sessionLifetimeSecs": s.session_lifetime_secs,
                "refreshTokenLifetimeSecs": s.refresh_token_lifetime_secs,
            }),
        )
    }
}
