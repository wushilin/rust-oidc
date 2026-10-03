//! Setting up a new deployment: its root tenant and first Global Administrator.

use serde_json::json;

use crate::admin::TENANT_CREATE;
use crate::db::Event;
use crate::directory::PrincipalType;
use crate::rbac::{RoleId, Scope as RoleScope};
use crate::routes::audit::clip;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};
use crate::users::{NewAccount, NewPassword};

/// Who made the first binding, as the binding records it.
const BOOTSTRAP: &str = "bootstrap";

/// Create the root tenant, its first account and that account's Global
/// Administrator role, together: a deployment with a root tenant but nobody who
/// can administer it is not left behind by a failure part-way.
pub struct Bootstrap {
    pub name: String,
    pub domain: String,
    pub admin_upn: String,
    pub password: NewPassword,
}

/// What bootstrapping made.
#[derive(Debug)]
pub struct Bootstrapped {
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for Bootstrap {
    type Output = Bootstrapped;
    const INFO: KindInfo = KindInfo {
        name: "Bootstrap",
        need: Need::Action(TENANT_CREATE),
        event: Event::Bootstrap,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Bootstrapped> {
        let root = crate::tenant::root_in(cx.conn()).await;
        let exists = cx.check(root)?.is_some();
        cx.ensure(!exists, || {
            Refusal::Conflict("Already bootstrapped: a root tenant exists.".into())
        })?;
        let tenant = crate::tenant::create_in(cx.conn(), &self.name, &self.domain, true).await;
        let tenant = cx.check(tenant)?;
        let account = NewAccount {
            upn: &self.admin_upn,
            display_name: Some("Administrator"),
            given_name: None,
            family_name: None,
            email: None,
        };
        let user_id = crate::users::create_in(cx.conn(), &tenant, &account, &self.password).await;
        let user_id = cx.check(user_id)?;
        let bound = crate::admin::bindings::create_in(
            cx.conn(),
            PrincipalType::User,
            &user_id,
            RoleId::GlobalAdministrator,
            &RoleScope::All,
            BOOTSTRAP,
        )
        .await;
        cx.check(bound)?;
        Ok(Bootstrapped {
            tenant_id: tenant.id,
            user_id,
        })
    }

    fn audit(&self, out: &Bootstrapped) -> Audit {
        Audit {
            tenant_id: Some(out.tenant_id.clone()),
            target: Some(out.user_id.clone()),
            details: json!({ "upn": clip(&self.admin_upn) }),
        }
    }
}
