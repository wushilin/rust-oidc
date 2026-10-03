//! Changes to accounts.

use serde_json::json;

use super::{Account, NO_SUCH_ACCOUNT, tenant, user};
use crate::access::CrossTenantPolicy;
use crate::admin::{GROUP_WRITE, USER_RESET, USER_WRITE};
use crate::db::Event;
use crate::groups::MembershipChange;
use crate::mfa::MfaPolicy;
use crate::routes::audit::clip;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};
use crate::users::{self, NewAccount, NewPassword, UserAttributes};

/// Refused when an administrator would disable or delete the account they are
/// signed in with: it ends their own session mid-click, and it is how the last
/// administrator goes.
const OWN_ACCOUNT: &str = "This is the account you are signed in with. Another administrator can disable or delete it.";

/// The lock for an account: its row when named by id; named by user name, which
/// is resolved only inside the transaction, its tenant's.
fn account_lock(tenant_id: &str, account: &Account) -> LockTarget {
    match account {
        Account::Id(id) => LockTarget::User(id.clone()),
        Account::Upn(_) => LockTarget::Tenant(tenant_id.to_string()),
    }
}

fn not_found() -> Refusal {
    Refusal::NotFound(NO_SUCH_ACCOUNT.into())
}

/// Refuse when the actor is the account itself.
fn not_self(cx: &mut Cx<'_>, user_id: &str) -> Step<()> {
    let own = cx.actor().user_id() == Some(user_id);
    cx.ensure(!own, || Refusal::Conflict(OWN_ACCOUNT.into()))
}

/// Create an account. Its password was checked and hashed before the
/// transaction began; a temporary one makes them choose their own at first
/// sign-in.
pub struct CreateUser {
    pub tenant_id: String,
    pub upn: String,
    pub password: NewPassword,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
}

/// What creating an account produced.
#[derive(Debug)]
pub struct CreatedUser {
    pub id: String,
    /// The user name as stored: domain normalised.
    pub upn: String,
}

impl Transaction for CreateUser {
    type Output = CreatedUser;
    const INFO: KindInfo = KindInfo {
        name: "Create user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserCreate,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<CreatedUser> {
        let tenant = tenant(cx, &self.tenant_id).await?;
        let account = NewAccount {
            upn: &self.upn,
            display_name: self.display_name.as_deref(),
            given_name: self.given_name.as_deref(),
            family_name: self.family_name.as_deref(),
            email: self.email.as_deref(),
        };
        let created = users::create_in(cx.conn(), &tenant, &account, &self.password).await;
        let id = cx.check(created)?;
        let stored = user(cx, &self.tenant_id, &Account::Id(id.clone())).await?;
        Ok(CreatedUser { id, upn: stored.upn })
    }

    fn audit(&self, out: &CreatedUser) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(out.id.clone()),
            details: json!({
                "upn": clip(&out.upn),
                "requireChange": self.password.by() == users::PasswordSetBy::AdminTemporary,
            }),
        }
    }
}

/// Turn sign-in on for an account.
pub struct EnableUser {
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for EnableUser {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Enable user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserEnable,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let done = users::set_enabled_in(cx.conn(), &self.tenant_id, &self.user_id, true).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "enabled": true }),
        }
    }
}

/// Turn sign-in off for an account: its sessions end and its refresh tokens
/// are revoked. Not the actor's own, and not the last Global Administrator.
pub struct DisableUser {
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for DisableUser {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Disable user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserDisable,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        not_self(cx, &self.user_id)?;
        let done = users::set_enabled_in(cx.conn(), &self.tenant_id, &self.user_id, false).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "enabled": false }),
        }
    }
}

/// Set an account's password. Like Entra, this signs them out everywhere.
pub struct ResetPassword {
    pub tenant_id: String,
    pub account: Account,
    pub password: NewPassword,
}

impl Transaction for ResetPassword {
    /// The account's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Reset password",
        need: Need::Action(USER_RESET),
        event: Event::AdminUserReset,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![account_lock(&self.tenant_id, &self.account)]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let target = user(cx, &self.tenant_id, &self.account).await?;
        let stored = users::store_password_in(cx.conn(), &self.tenant_id, &target.id, &self.password).await;
        let found = cx.check(stored)?;
        cx.ensure(found, not_found)?;
        Ok(target.id)
    }

    fn audit(&self, user_id: &String) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(user_id.clone()),
            details: json!({ "requireChange": self.password.by() == users::PasswordSetBy::AdminTemporary }),
        }
    }
}

/// Delete an account (softly: it can be restored). Its sessions end and its
/// refresh tokens are revoked. Not the actor's own, and not the last Global
/// Administrator.
pub struct DeleteUser {
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for DeleteUser {
    /// The user name of the account deleted.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Delete user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserDelete,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        not_self(cx, &self.user_id)?;
        let target = user(cx, &self.tenant_id, &Account::Id(self.user_id.clone())).await?;
        let done = users::soft_delete_in(cx.conn(), &self.tenant_id, &self.user_id).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)?;
        Ok(target.upn)
    }

    fn audit(&self, upn: &String) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "upn": clip(upn) }),
        }
    }
}

/// Bring back a deleted account, enabled.
pub struct RestoreUser {
    pub tenant_id: String,
    pub account: Account,
}

impl Transaction for RestoreUser {
    /// The account's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Restore user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserRestore,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![account_lock(&self.tenant_id, &self.account)]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let id = match &self.account {
            Account::Id(id) => id.clone(),
            Account::Upn(upn) => {
                let found = users::deleted_id_in(cx.conn(), &self.tenant_id, upn).await;
                match cx.check(found)? {
                    Some(id) => id,
                    None => return Err(cx.fail(Refusal::NotFound("There is no deleted account by that name.".into()))),
                }
            }
        };
        let done = users::restore_id_in(cx.conn(), &self.tenant_id, &id).await;
        let restored = cx.check(done)?;
        cx.ensure(restored, || {
            Refusal::NotFound("That account is not a deleted one of this tenant.".into())
        })?;
        Ok(id)
    }

    fn audit(&self, user_id: &String) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(user_id.clone()),
            details: json!({}),
        }
    }
}

/// An account's profile, as the console edits it.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
}

/// Overwrite an account's profile.
pub struct UpdateUserAttributes {
    pub tenant_id: String,
    pub user_id: String,
    pub profile: Profile,
}

impl Transaction for UpdateUserAttributes {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Update user",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserUpdate,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let p = &self.profile;
        let attrs = UserAttributes {
            display_name: p.display_name.as_deref(),
            given_name: p.given_name.as_deref(),
            family_name: p.family_name.as_deref(),
            email: p.email.as_deref(),
            email_verified: p.email_verified,
        };
        let done = users::update_attributes_in(cx.conn(), &self.tenant_id, &self.user_id, &attrs).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)
    }

    fn audit(&self, _: &()) -> Audit {
        // Which fields, not their values: an audit row is shipped to log systems
        // and the attributes are the user's own data.
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "fields": ["displayName", "givenName", "surname", "mail", "mailVerified"] }),
        }
    }
}

/// An account's own MFA setting.
pub struct SetUserMfaPolicy {
    pub tenant_id: String,
    pub user_id: String,
    pub policy: MfaPolicy,
}

impl Transaction for SetUserMfaPolicy {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set MFA requirement",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserMfaPolicy,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let done = crate::mfa::set_policy_in(cx.conn(), &self.tenant_id, &self.user_id, self.policy).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "mfaPolicy": self.policy.as_str() }),
        }
    }
}

/// Whether an account may sign in to other tenants' applications.
pub struct SetUserCrossTenantPolicy {
    pub tenant_id: String,
    pub user_id: String,
    pub policy: CrossTenantPolicy,
}

impl Transaction for SetUserCrossTenantPolicy {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set sign-in to other tenants",
        need: Need::Action(USER_WRITE),
        event: Event::AdminUserCrossTenantPolicy,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let done = crate::access::set_policy_in(cx.conn(), &self.tenant_id, &self.user_id, self.policy).await;
        let found = cx.check(done)?;
        cx.ensure(found, not_found)
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "crossTenantPolicy": self.policy.as_str() }),
        }
    }
}

/// Remove an account's authenticator and recovery codes, and sign them out
/// everywhere, in one step.
pub struct ResetUserMfa {
    pub tenant_id: String,
    pub user_id: String,
}

impl Transaction for ResetUserMfa {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Reset MFA",
        need: Need::Action(USER_RESET),
        event: Event::AdminUserMfaReset,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let done = crate::mfa::reset_in(cx.conn(), &self.tenant_id, &self.user_id).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || {
            Refusal::Conflict("This account has no authenticator to remove.".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({}),
        }
    }
}

/// Make an account a member of exactly these of its tenant's groups.
pub struct SetUserGroups {
    pub tenant_id: String,
    pub user_id: String,
    pub group_ids: Vec<String>,
}

impl Transaction for SetUserGroups {
    type Output = MembershipChange;
    const INFO: KindInfo = KindInfo {
        name: "Set groups",
        need: Need::Action(GROUP_WRITE),
        event: Event::AdminUserGroups,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::User(self.user_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<MembershipChange> {
        let done = crate::groups::set_for_user_in(cx.conn(), &self.tenant_id, &self.user_id, &self.group_ids).await;
        cx.check(done)
    }

    fn audit(&self, change: &MembershipChange) -> Audit {
        // Group ids, resolved: `set_for_user_in` only ever adds or removes
        // groups of the tenant.
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.user_id.clone()),
            details: json!({ "added": change.added, "removed": change.removed }),
        }
    }
}
