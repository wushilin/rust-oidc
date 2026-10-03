//! A user's changes to their own account: a new password (in My Account, or the
//! one they must choose at sign-in), an authenticator, new recovery codes, and
//! signing out everywhere.
//!
//! The actor is the user ([`crate::txn::Actor::User`]), and the scope their own
//! account, so only they can run these. The audit row belongs to their home
//! tenant and names them as both actor and target. The slow or random parts (a
//! password checked against history and hashed, recovery codes made and hashed)
//! are done before the transaction and passed in; the plain recovery codes are
//! the output, shown once, and never recorded.
//!
//! Sign-in bookkeeping (failed attempts, lockout, sessions made at sign-in,
//! pending-step tickets) is not a change to the directory and stays outside.

use serde_json::json;

use super::{Account, user};
use crate::db::Event;
use crate::mfa::NewRecoveryCodes;
use crate::routes::audit::Channel;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};
use crate::users::{self, NewPassword, PasswordSetBy};

/// Refused when the account was disabled since the user signed in.
const DISABLED: &str = "Your account has been disabled. (AADSTS50057)";

/// The user's own account, live and enabled, or abort.
async fn own_account(cx: &mut Cx<'_>, tenant_id: &str, user_id: &str) -> Step<()> {
    let account = user(cx, tenant_id, &Account::Id(user_id.to_string())).await?;
    cx.ensure(account.enabled, || Refusal::Conflict(DISABLED.into()))
}

fn own_audit(tenant_id: &str, user_id: &str, details: serde_json::Value) -> Audit {
    Audit {
        tenant_id: Some(tenant_id.to_string()),
        target: Some(user_id.to_string()),
        details,
    }
}

/// The user chooses a new password: in My Account (having re-entered the current
/// one), or at sign-in when they must. Checked against their history and hashed
/// before the transaction. Like any new password it ends every session and
/// revokes every refresh token.
pub struct ChangeOwnPassword {
    /// The user's home tenant.
    pub tenant_id: String,
    pub user_id: String,
    pub password: NewPassword,
    /// Where they changed it.
    pub via: Channel,
}

impl Transaction for ChangeOwnPassword {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Change own password",
        need: Need::SelfService,
        event: Event::PasswordChanged,
    };

    fn scope(&self) -> Scope {
        Scope::Own(self.user_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        // A user's own password is never a temporary one.
        cx.ensure(self.password.by() == PasswordSetBy::User, || {
            Refusal::Invalid("A password you choose yourself cannot be a temporary one.".into())
        })?;
        own_account(cx, &self.tenant_id, &self.user_id).await?;
        let stored = users::store_password_in(cx.conn(), &self.tenant_id, &self.user_id, &self.password).await;
        let found = cx.check(stored)?;
        cx.ensure(found, || Refusal::NotFound(super::NO_SUCH_ACCOUNT.into()))
    }

    fn audit(&self, _: &()) -> Audit {
        own_audit(&self.tenant_id, &self.user_id, json!({ "via": self.via.as_str() }))
    }
}

/// The user sets up an authenticator (or moves it to a new phone), confirmed
/// with a code from it before the transaction. Any old authenticator and its
/// recovery codes are replaced. Set up at sign-in (not `voluntary`), the user is
/// then signed out everywhere, to sign in again with it.
pub struct EnrollAuthenticator {
    /// The user's home tenant.
    pub tenant_id: String,
    pub user_id: String,
    /// The TOTP secret the confirming code was checked against.
    pub secret: String,
    pub codes: NewRecoveryCodes,
    pub via: Channel,
    /// Started from My Account by a signed-in user, rather than required at
    /// sign-in.
    pub voluntary: bool,
}

impl Transaction for EnrollAuthenticator {
    /// The recovery codes, to show once.
    type Output = Vec<String>;
    const INFO: KindInfo = KindInfo {
        name: "Set up authenticator",
        need: Need::SelfService,
        event: Event::MfaEnrolled,
    };

    fn scope(&self) -> Scope {
        Scope::Own(self.user_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Vec<String>> {
        own_account(cx, &self.tenant_id, &self.user_id).await?;
        let enrolled = crate::mfa::enroll_in(cx.conn(), &self.user_id, &self.secret, &self.codes).await;
        cx.check(enrolled)?;
        if !self.voluntary {
            let ended = users::end_sessions_in(cx.conn(), &self.user_id).await;
            cx.check(ended)?;
        }
        Ok(self.codes.plain().to_vec())
    }

    fn audit(&self, _: &Vec<String>) -> Audit {
        // Never the secret or the codes.
        own_audit(
            &self.tenant_id,
            &self.user_id,
            json!({ "via": self.via.as_str(), "voluntary": self.voluntary }),
        )
    }
}

/// The user replaces their recovery codes, having confirmed with a code from
/// their authenticator before the transaction.
pub struct ReplaceRecoveryCodes {
    /// The user's home tenant.
    pub tenant_id: String,
    pub user_id: String,
    pub codes: NewRecoveryCodes,
}

impl Transaction for ReplaceRecoveryCodes {
    /// The new codes, to show once.
    type Output = Vec<String>;
    const INFO: KindInfo = KindInfo {
        name: "Replace recovery codes",
        need: Need::SelfService,
        event: Event::MfaRecoveryCodesReplaced,
    };

    fn scope(&self) -> Scope {
        Scope::Own(self.user_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Vec<String>> {
        own_account(cx, &self.tenant_id, &self.user_id).await?;
        let replaced = crate::mfa::replace_recovery_codes_in(cx.conn(), &self.user_id, &self.codes).await;
        cx.check(replaced)?;
        Ok(self.codes.plain().to_vec())
    }

    fn audit(&self, _: &Vec<String>) -> Audit {
        own_audit(&self.tenant_id, &self.user_id, json!({}))
    }
}

/// The user ends every session and refresh token they hold, from My Account.
pub struct SignOutEverywhere {
    /// The user's home tenant.
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for SignOutEverywhere {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Sign out everywhere",
        need: Need::SelfService,
        event: Event::SessionEndEverywhere,
    };

    fn scope(&self) -> Scope {
        Scope::Own(self.user_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        // Live, but not necessarily enabled: signing out is always allowed.
        user(cx, &self.tenant_id, &Account::Id(self.user_id.clone())).await?;
        let ended = users::end_sessions_in(cx.conn(), &self.user_id).await;
        cx.check(ended)
    }

    fn audit(&self, _: &()) -> Audit {
        own_audit(
            &self.tenant_id,
            &self.user_id,
            json!({ "via": Channel::MyAccount.as_str() }),
        )
    }
}
