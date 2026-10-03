//! The flow tester's writes to the directory: registering the console's callback
//! on an application, and registering the tenant's own test client.
//!
//! Starting a test, forgetting a sign-in and checking readiness change no
//! directory data and are not transactions.

use serde_json::json;

use super::tenant;
use crate::admin::APP_WRITE;
use crate::apps::RedirectPlatform;
use crate::db::Event;
use crate::flowtest::{self, PURPOSE};
use crate::routes::audit::clip;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

/// Register the console's callback as a redirect URI of an application.
pub struct AddFlowCallback {
    pub tenant_id: String,
    pub app_id: String,
    pub platform: RedirectPlatform,
    /// The console's callback URI, from the public URL.
    pub callback: String,
}

impl Transaction for AddFlowCallback {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Add flow tester callback",
        need: Need::Action(APP_WRITE),
        event: Event::AdminFlowTestCallbackAdd,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::App(self.app_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let tenant = tenant(cx, &self.tenant_id).await?;
        let found = crate::apps::find_in(cx.conn(), &self.app_id).await;
        let app = match cx.check(found)? {
            Some(app) if app.tenant_id == tenant.id => app,
            _ => {
                return Err(cx.fail(Refusal::NotFound("There is no such application in this tenant.".into())));
            }
        };
        let done = crate::apps::add_redirect_uri_in(cx.conn(), &app, self.platform, &self.callback).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.app_id.clone()),
            details: json!({
                "platform": self.platform.as_str(),
                "uri": clip(&self.callback),
                "purpose": PURPOSE,
            }),
        }
    }
}

/// Register the tenant's flow tester client, or return the one it has.
pub struct CreateFlowTestClient {
    pub tenant_id: String,
    /// The console's callback URI, from the public URL.
    pub callback: String,
}

impl Transaction for CreateFlowTestClient {
    type Output = flowtest::TestClient;
    const INFO: KindInfo = KindInfo {
        name: "Create flow tester client",
        need: Need::Action(APP_WRITE),
        event: Event::AdminFlowTestClientCreate,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<flowtest::TestClient> {
        let tenant = tenant(cx, &self.tenant_id).await?;
        let made = flowtest::create_test_client_in(cx.conn(), &self.callback, &tenant).await;
        cx.check(made)
    }

    fn audit(&self, out: &flowtest::TestClient) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(out.application.app_id.clone()),
            details: json!({
                "displayName": clip(&out.application.display_name),
                "created": out.created,
                "platform": RedirectPlatform::PublicClient.as_str(),
                "uri": clip(&self.callback),
                "purpose": PURPOSE,
            }),
        }
    }
}
