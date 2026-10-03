//! Changes to groups and who is in them.

use serde_json::json;

use super::{Account, tenant, user};
use crate::admin::GROUP_WRITE;
use crate::db::Event;
use crate::routes::audit::clip;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

const NO_SUCH_GROUP: &str = "There is no such group in this tenant.";

fn no_group() -> Refusal {
    Refusal::NotFound(NO_SUCH_GROUP.into())
}

/// The group, or abort.
async fn group(cx: &mut Cx<'_>, tenant_id: &str, group_id: &str) -> Step<crate::groups::Group> {
    let found = crate::groups::find_by_id_in(cx.conn(), tenant_id, group_id).await;
    match cx.check(found)? {
        Some(g) => Ok(g),
        None => Err(cx.fail(no_group())),
    }
}

/// Create a group.
pub struct CreateGroup {
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
}

impl Transaction for CreateGroup {
    /// The new group's id.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Create group",
        need: Need::Action(GROUP_WRITE),
        event: Event::AdminGroupCreate,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Tenant(self.tenant_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let tenant = tenant(cx, &self.tenant_id).await?;
        let created = crate::groups::create_in(cx.conn(), &tenant, &self.name, self.description.as_deref()).await;
        cx.check(created)
    }

    fn audit(&self, id: &String) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(id.clone()),
            details: json!({ "name": clip(self.name.trim()) }),
        }
    }
}

/// Delete a group that has no members. Roles granted to it go with it.
pub struct DeleteGroup {
    pub tenant_id: String,
    pub group_id: String,
}

impl Transaction for DeleteGroup {
    /// The name of the group deleted.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Delete group",
        need: Need::Action(GROUP_WRITE),
        event: Event::AdminGroupDelete,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::Group(self.group_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let found = group(cx, &self.tenant_id, &self.group_id).await?;
        let done = crate::groups::delete_in(cx.conn(), &self.tenant_id, &self.group_id).await;
        let deleted = cx.check(done)?;
        cx.ensure(deleted, no_group)?;
        Ok(found.name)
    }

    fn audit(&self, name: &String) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.group_id.clone()),
            details: json!({ "name": clip(name) }),
        }
    }
}

/// Add an account of the tenant to one of its groups.
pub struct AddGroupMember {
    pub tenant_id: String,
    pub group_id: String,
    pub account: Account,
}

/// Who was added.
#[derive(Debug)]
pub struct AddedMember {
    pub user_id: String,
    pub upn: String,
}

impl Transaction for AddGroupMember {
    type Output = AddedMember;
    const INFO: KindInfo = KindInfo {
        name: "Add group member",
        need: Need::Action(GROUP_WRITE),
        event: Event::AdminGroupMemberAdd,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Group(self.group_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<AddedMember> {
        group(cx, &self.tenant_id, &self.group_id).await?;
        let member = user(cx, &self.tenant_id, &self.account).await?;
        let done = crate::groups::add_member_id_in(cx.conn(), &self.tenant_id, &self.group_id, &member.id).await;
        cx.check(done)?;
        Ok(AddedMember {
            user_id: member.id,
            upn: member.upn,
        })
    }

    fn audit(&self, added: &AddedMember) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.group_id.clone()),
            details: json!({ "userId": added.user_id, "upn": clip(&added.upn) }),
        }
    }
}

/// Take an account out of a group. Not the last Global Administrator's way in.
pub struct RemoveGroupMember {
    pub tenant_id: String,
    pub group_id: String,
    pub user_id: String,
}

impl Transaction for RemoveGroupMember {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Remove group member",
        need: Need::Action(GROUP_WRITE),
        event: Event::AdminGroupMemberRemove,
    };

    fn scope(&self) -> Scope {
        Scope::Tenant(self.tenant_id.clone())
    }

    fn locks(&self) -> Vec<LockTarget> {
        vec![LockTarget::Administrators, LockTarget::Group(self.group_id.clone())]
    }

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        group(cx, &self.tenant_id, &self.group_id).await?;
        let done = crate::groups::remove_member_in(cx.conn(), &self.tenant_id, &self.group_id, &self.user_id).await;
        let removed = cx.check(done)?;
        cx.ensure(removed, || {
            Refusal::NotFound("That account is not a member of this group.".into())
        })
    }

    fn audit(&self, _: &()) -> Audit {
        Audit {
            tenant_id: Some(self.tenant_id.clone()),
            target: Some(self.group_id.clone()),
            details: json!({ "userId": self.user_id }),
        }
    }
}
