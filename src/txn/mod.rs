//! Every administrative change is a transaction, run by one engine.
//!
//! The house rules (AGENT.md) in code:
//!
//! - **A transaction is a type.** Each change is a struct implementing
//!   [`Transaction`]: required parameters are plain fields, optional ones
//!   `Option<T>`, and it declares its own `Output`. [`Txn`] lists every one.
//! - **All or nothing.** The engine runs it inside one database transaction and
//!   commits only when the run, the global rules and the audit row all succeed;
//!   anything else rolls everything back.
//! - **Aborting needs a reason.** A run aborts only through [`Cx::fail`] (or
//!   [`Cx::check`], which classifies an error and calls it): [`Aborted`] cannot
//!   be made any other way, so there is no abort without a recorded reason.
//! - **One standard result**, [`Outcome`]: done, refused (the actor can fix it)
//!   or failed (our fault).
//! - **No audit, no change.** The audit row is written in the transaction.
//! - **Batches commit once**: [`run_batch`] runs several in one transaction.
//! - **Locks**: a transaction declares its own ([`Transaction::locks`]); the
//!   engine takes every lock of the run or batch before anything runs, in one
//!   fixed order, so two transactions never wait on each other in a cycle. Every
//!   wait times out ([`LOCK_TIMEOUT_SECS`]) as [`Refusal::Busy`].

mod engine;
pub mod ops;

pub use engine::{BatchOutcome, run, run_batch};

use std::future::Future;

use serde_json::Value;

use crate::db::{Conn, Engine, Event};
use crate::rbac::{Action, EffectiveBinding};

/// How long a transaction waits for a lock before giving up.
pub const LOCK_TIMEOUT_SECS: u64 = 5;

/// Who is running a transaction.
#[derive(Debug, Clone)]
pub enum Actor {
    /// A signed-in administrator, with the roles they hold.
    Admin {
        user_id: String,
        bindings: Vec<EffectiveBinding>,
    },
    /// A user acting on their own account (My Account).
    User { user_id: String },
    /// The command line, run by an operator with access to the database.
    Cli,
}

impl Actor {
    fn audit_actor(&self) -> crate::db::Actor<'_> {
        match self {
            Self::Admin { user_id, .. } | Self::User { user_id } => crate::db::Actor::Id(user_id),
            Self::Cli => crate::db::Actor::Cli,
        }
    }

    pub fn user_id(&self) -> Option<&str> {
        match self {
            Self::Admin { user_id, .. } | Self::User { user_id } => Some(user_id),
            Self::Cli => None,
        }
    }

    pub fn bindings(&self) -> &[EffectiveBinding] {
        match self {
            Self::Admin { bindings, .. } => bindings,
            _ => &[],
        }
    }
}

/// Where a transaction acts, which is what its authorization is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Inside one tenant, by id.
    Tenant(String),
    /// The whole deployment: only an every-tenant grant covers it.
    Platform,
    /// The actor's own account.
    Own(String),
}

/// What it takes to run a kind of transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// This action, at the transaction's scope.
    Action(Action),
    /// Being the user it is about.
    SelfService,
}

/// What every transaction of one kind shares.
#[derive(Debug, Clone, Copy)]
pub struct KindInfo {
    pub name: &'static str,
    pub need: Need,
    pub event: Event,
}

/// Why a transaction did not complete, when the actor can do something about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotPermitted,
    NotFound(String),
    Invalid(String),
    Conflict(String),
    /// A global rule would not hold afterwards.
    RuleBroken(String),
    /// A lock was not granted in time; trying again is safe.
    Busy(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPermitted => f.write_str("Your roles do not allow this."),
            Self::NotFound(m) | Self::Invalid(m) | Self::Conflict(m) | Self::RuleBroken(m) => f.write_str(m),
            Self::Busy(what) => write!(
                f,
                "{what} is being changed by someone else right now. Nothing was changed; try again."
            ),
        }
    }
}

/// How a run ended without completing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Refused(Refusal),
    /// Our fault: a database error, a broken lock order. The message is for logs.
    Internal(String),
}

/// The standard result of running a transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    /// Committed, with its audit row.
    Done(T),
    /// Rolled back; the actor can fix it.
    Refused(Refusal),
    /// Rolled back; our fault.
    Failed(String),
}

impl<T> Outcome<T> {
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done(_))
    }

    /// The same outcome without its output, to compare or print.
    pub fn map_done(self) -> Outcome<()> {
        match self {
            Self::Done(_) => Outcome::Done(()),
            Self::Refused(r) => Outcome::Refused(r),
            Self::Failed(m) => Outcome::Failed(m),
        }
    }

    /// The outcome of something that failed before a transaction began (checking
    /// and hashing a password, say), classified like an error inside one.
    pub fn from_error(e: &anyhow::Error) -> Self {
        Self::from_failure(classify(e))
    }

    fn from_failure(failure: Failure) -> Self {
        match failure {
            Failure::Refused(r) => Self::Refused(r),
            Failure::Internal(m) => {
                tracing::error!("transaction failed: {m}");
                Self::Failed(m)
            }
        }
    }

    /// For callers that treat any non-completion as an error (the CLI, tests).
    pub fn into_result(self) -> anyhow::Result<T> {
        match self {
            Self::Done(v) => Ok(v),
            Self::Refused(r) => Err(anyhow::anyhow!("{r}")),
            Self::Failed(m) => Err(anyhow::anyhow!("internal error: {m}")),
        }
    }
}

/// The only proof that a run aborted. Made only by [`Cx::fail`], so every abort
/// has a reason recorded in the context.
#[derive(Debug)]
pub struct Aborted(());

pub type Step<T> = Result<T, Aborted>;

/// What a completed transaction writes to the audit log.
pub struct Audit {
    /// The tenant the row belongs to; `None` for the platform's own (signing keys).
    pub tenant_id: Option<String>,
    pub target: Option<String>,
    pub details: Value,
}

/// One kind of change.
pub trait Transaction: Send + Sync {
    type Output: Send;
    const INFO: KindInfo;
    /// Where it acts.
    fn scope(&self) -> Scope;
    /// What it must hold while it runs: the rows its checks read and its writes
    /// change. The engine takes them before the run begins and releases them
    /// when the transaction ends.
    fn locks(&self) -> Vec<LockTarget> {
        Vec::new()
    }
    /// The checks and the writes, on the context's connection.
    fn run(&self, cx: &mut Cx<'_>) -> impl Future<Output = Step<Self::Output>> + Send;
    /// The audit row for a completed run.
    fn audit(&self, out: &Self::Output) -> Audit;
}

/// Something a transaction can lock. The order of the variants, then the id, is
/// the one order every lock is taken in (the derived `Ord`), which is what makes
/// a deadlock between two transactions impossible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockTarget {
    /// Every change that can affect who administers the deployment (role grants,
    /// and accounts and groups that may hold them) takes this first.
    Administrators,
    Tenant(String),
    User(String),
    Group(String),
    App(String),
}

impl LockTarget {
    fn describe(&self) -> String {
        match self {
            Self::Administrators => "The list of administrators".into(),
            Self::Tenant(_) => "This tenant".into(),
            Self::User(_) => "This account".into(),
            Self::Group(_) => "This group".into(),
            Self::App(_) => "This application".into(),
        }
    }
}

/// The locks of a run or a batch, in the order they are taken: sorted, each once.
pub fn lock_order(mut targets: Vec<LockTarget>) -> Vec<LockTarget> {
    targets.sort();
    targets.dedup();
    targets
}

/// The context a transaction runs in.
pub struct Cx<'t> {
    conn: &'t mut Conn,
    engine: Engine,
    actor: &'t Actor,
    failure: Option<Failure>,
}

impl<'t> Cx<'t> {
    pub fn conn(&mut self) -> &mut Conn {
        self.conn
    }

    pub fn engine(&self) -> Engine {
        self.engine
    }

    pub fn actor(&self) -> &Actor {
        self.actor
    }

    /// Abort with a reason. The only way to make an [`Aborted`].
    pub fn fail(&mut self, refusal: Refusal) -> Aborted {
        self.failure.get_or_insert(Failure::Refused(refusal));
        Aborted(())
    }

    /// Abort with `refusal` unless `ok`.
    pub fn ensure(&mut self, ok: bool, refusal: impl FnOnce() -> Refusal) -> Step<()> {
        if ok { Ok(()) } else { Err(self.fail(refusal())) }
    }

    /// Continue with a storage result, or abort with the error, classified: a
    /// lock not granted is `Busy`, a database error is internal, a broken global
    /// rule is `RuleBroken`, anything else (the storage layer's own refusals) is
    /// `Invalid` with its message.
    pub fn check<T>(&mut self, result: anyhow::Result<T>) -> Step<T> {
        result.map_err(|e| {
            let failure = classify(&e);
            self.failure.get_or_insert(failure);
            Aborted(())
        })
    }
}

/// What an error from the storage layer means for the actor.
pub fn classify(e: &anyhow::Error) -> Failure {
    if let Some(db) = e.downcast_ref::<sqlx::Error>() {
        if engine::is_contention(db) {
            return Failure::Refused(Refusal::Busy("The data".into()));
        }
        return Failure::Internal(db.to_string());
    }
    if e.downcast_ref::<crate::admin::lockout::WouldLockOut>().is_some() {
        return Failure::Refused(Refusal::RuleBroken(e.to_string()));
    }
    Failure::Refused(Refusal::Invalid(e.to_string()))
}

/// Declare every transaction kind once: the [`Txn`] enum, the [`TxnKind`] list,
/// the [`TxnOutput`] of each, and their dispatch.
macro_rules! transactions {
    ($( $variant:ident ( $ty:path ) ),* $(,)?) => {
        /// Every transaction there is.
        pub enum Txn { $( $variant($ty), )* }

        /// Every kind of transaction, for listing and checking them all.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TxnKind { $( $variant, )* }

        /// The output of any transaction, for batches.
        pub enum TxnOutput { $( $variant(<$ty as Transaction>::Output), )* }

        impl TxnKind {
            pub const ALL: &'static [TxnKind] = &[ $( TxnKind::$variant, )* ];
            pub fn info(self) -> KindInfo {
                match self { $( TxnKind::$variant => <$ty as Transaction>::INFO, )* }
            }
        }

        impl Txn {
            pub fn kind(&self) -> TxnKind {
                match self { $( Txn::$variant(_) => TxnKind::$variant, )* }
            }
            pub fn scope(&self) -> Scope {
                match self { $( Txn::$variant(t) => t.scope(), )* }
            }
            pub fn locks(&self) -> Vec<LockTarget> {
                match self { $( Txn::$variant(t) => t.locks(), )* }
            }
            async fn run_one(&self, cx: &mut Cx<'_>) -> Step<(TxnOutput, Audit)> {
                match self {
                    $( Txn::$variant(t) => {
                        let out = t.run(cx).await?;
                        let audit = t.audit(&out);
                        Ok((TxnOutput::$variant(out), audit))
                    } )*
                }
            }
        }

        $( impl From<$ty> for Txn {
            fn from(t: $ty) -> Self { Txn::$variant(t) }
        } )*
    };
}

transactions! {
    CreateUser(ops::users::CreateUser),
    EnableUser(ops::users::EnableUser),
    DisableUser(ops::users::DisableUser),
    ResetPassword(ops::users::ResetPassword),
    DeleteUser(ops::users::DeleteUser),
    RestoreUser(ops::users::RestoreUser),
    UpdateUserAttributes(ops::users::UpdateUserAttributes),
    SetUserMfaPolicy(ops::users::SetUserMfaPolicy),
    SetUserCrossTenantPolicy(ops::users::SetUserCrossTenantPolicy),
    ResetUserMfa(ops::users::ResetUserMfa),
    SetUserGroups(ops::users::SetUserGroups),
    CreateGroup(ops::groups::CreateGroup),
    DeleteGroup(ops::groups::DeleteGroup),
    AddGroupMember(ops::groups::AddGroupMember),
    RemoveGroupMember(ops::groups::RemoveGroupMember),
    CreateTenant(ops::tenants::CreateTenant),
    RenameTenant(ops::tenants::RenameTenant),
    EnableTenant(ops::tenants::EnableTenant),
    DisableTenant(ops::tenants::DisableTenant),
    ChangeTenantDomain(ops::tenants::ChangeTenantDomain),
    RemoveTenantDomain(ops::tenants::RemoveTenantDomain),
    SaveTenantSettings(ops::tenants::SaveTenantSettings),
    ChangeOwnPassword(ops::self_service::ChangeOwnPassword),
    EnrollAuthenticator(ops::self_service::EnrollAuthenticator),
    ReplaceRecoveryCodes(ops::self_service::ReplaceRecoveryCodes),
    SignOutEverywhere(ops::self_service::SignOutEverywhere),
    CreateApp(ops::apps::CreateApp),
    SaveAppFlags(ops::apps::SaveAppFlags),
    AddAppSecret(ops::apps::AddAppSecret),
    RemoveAppSecret(ops::apps::RemoveAppSecret),
    AddAppCertificate(ops::apps::AddAppCertificate),
    RemoveAppCertificate(ops::apps::RemoveAppCertificate),
    AddRedirectUri(ops::apps::AddRedirectUri),
    RemoveRedirectUri(ops::apps::RemoveRedirectUri),
    AddIdentifierUri(ops::apps::AddIdentifierUri),
    RemoveIdentifierUri(ops::apps::RemoveIdentifierUri),
    AddAppScope(ops::apps::AddAppScope),
    AddAppRole(ops::apps::AddAppRole),
    AssignApp(ops::apps::AssignApp),
    UnassignApp(ops::apps::UnassignApp),
    GrantAppRole(ops::apps::GrantAppRole),
    RevokeAppRole(ops::apps::RevokeAppRole),
    SetAssignmentRequired(ops::apps::SetAssignmentRequired),
}
