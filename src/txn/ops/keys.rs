//! The token signing keys, shared by every tenant: rotating and pruning them.
//!
//! Both are platform changes, authorized by `Key:Rotate` everywhere (there is no
//! `Key:Prune`; see `admin/keys.rs`). The audit row is attributed to the
//! administrator's own tenant, as the console has always recorded it: the keys
//! belong to no tenant, and a row with none would be on no tenant's history. From
//! the command line there is no such tenant, and the row has none.

use serde_json::json;

use crate::admin::KEY_ROTATE;
use crate::db::Event;
use crate::keys::{self, NewKey, Rotated};
use crate::txn::{Audit, Cx, KindInfo, Need, Refusal, Scope, Step, Transaction};

/// Seconds in a day, for the prune age.
const SECS_PER_DAY: i64 = 86_400;

/// The tenant the audit row of a key change belongs to: the actor's own.
async fn log_tenant(cx: &mut Cx<'_>) -> Step<Option<String>> {
    let Some(user_id) = cx.actor().user_id().map(str::to_string) else {
        return Ok(None);
    };
    let me = crate::users::find_by_id_in(cx.conn(), &user_id).await;
    Ok(cx.check(me)?.map(|u| u.tenant_id))
}

/// Rotate the signing key: active -> retired, next -> active, and a new next.
pub struct RotateKeys {
    /// The new next key, generated before the transaction began (RSA generation
    /// is slow).
    pub fresh: NewKey,
}

/// What a rotation did.
#[derive(Debug)]
pub struct RotatedKeys {
    pub rotated: Rotated,
    pub log_tenant: Option<String>,
}

impl Transaction for RotateKeys {
    type Output = RotatedKeys;
    const INFO: KindInfo = KindInfo {
        name: "Rotate signing key",
        need: Need::Action(KEY_ROTATE),
        event: Event::AdminKeyRotate,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<RotatedKeys> {
        let done = keys::rotate_in(cx.conn(), &self.fresh).await;
        let rotated = cx.check(done)?;
        let log_tenant = log_tenant(cx).await?;
        Ok(RotatedKeys { rotated, log_tenant })
    }

    fn audit(&self, out: &RotatedKeys) -> Audit {
        Audit {
            tenant_id: out.log_tenant.clone(),
            target: None,
            details: json!({}),
        }
    }
}

/// Delete the keys retired for at least this many days.
pub struct PruneKeys {
    pub older_than_days: i64,
}

/// What pruning did.
#[derive(Debug)]
pub struct PrunedKeys {
    pub deleted: u64,
    pub log_tenant: Option<String>,
}

impl Transaction for PruneKeys {
    type Output = PrunedKeys;
    const INFO: KindInfo = KindInfo {
        name: "Prune signing keys",
        need: Need::Action(KEY_ROTATE),
        event: Event::AdminKeyPrune,
    };

    fn scope(&self) -> Scope {
        Scope::Platform
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<PrunedKeys> {
        // Zero or negative would delete a key retired moments ago, whose tokens
        // are certainly still alive.
        cx.ensure(self.older_than_days >= 1, || {
            Refusal::Invalid("the age must be at least one day".into())
        })?;
        let Some(secs) = self.older_than_days.checked_mul(SECS_PER_DAY) else {
            return Err(cx.fail(Refusal::Invalid("the age is too large".into())));
        };
        let done = keys::prune_in(cx.conn(), secs).await;
        let deleted = cx.check(done)?;
        let log_tenant = log_tenant(cx).await?;
        Ok(PrunedKeys { deleted, log_tenant })
    }

    fn audit(&self, out: &PrunedKeys) -> Audit {
        Audit {
            tenant_id: out.log_tenant.clone(),
            target: None,
            details: json!({ "olderThanDays": self.older_than_days, "deleted": out.deleted }),
        }
    }
}
