//! The one engine every transaction runs through.

use sqlx::{Connection, Executor};

use super::{
    Actor, Audit, Cx, Failure, LOCK_TIMEOUT_SECS, LockTarget, Need, Outcome, Refusal, Scope, Transaction, Txn,
    TxnOutput, lock_order,
};
use crate::admin::lockout;
use crate::db::{Conn, DbPool, Engine};

/// Whether the actor may run a transaction of this kind at this scope.
fn authorized(actor: &Actor, need: Need, scope: &Scope) -> bool {
    match (actor, need, scope) {
        (Actor::Cli, _, _) => true,
        (Actor::Admin { bindings, .. }, Need::Action(action), Scope::Tenant(tenant_id)) => {
            crate::rbac::allowed(bindings, action, tenant_id)
        }
        (Actor::Admin { bindings, .. }, Need::Action(action), Scope::Platform) => {
            crate::rbac::allowed_at_all_scope(bindings, action)
        }
        (Actor::User { user_id }, Need::SelfService, Scope::Own(owner)) => user_id == owner,
        _ => false,
    }
}

/// Begin a transaction that holds its locks from the start, with the lock
/// timeout set: SQLite takes the database write lock at once (`BEGIN IMMEDIATE`,
/// waiting at most the connection's busy timeout); Postgres and MySQL wait for a
/// row lock at most [`LOCK_TIMEOUT_SECS`].
async fn begin(conn: &mut Conn, engine: Engine) -> Result<sqlx::Transaction<'_, sqlx::Any>, sqlx::Error> {
    match engine {
        Engine::Sqlite => conn.begin_with("BEGIN IMMEDIATE").await,
        Engine::MySql => {
            conn.execute(sqlx::AssertSqlSafe(format!(
                "SET SESSION innodb_lock_wait_timeout = {LOCK_TIMEOUT_SECS}"
            )))
            .await?;
            conn.begin().await
        }
        Engine::Postgres => {
            let mut tx = conn.begin().await?;
            tx.execute(sqlx::AssertSqlSafe(format!(
                "SET LOCAL lock_timeout = '{LOCK_TIMEOUT_SECS}s'"
            )))
            .await?;
            Ok(tx)
        }
    }
}

/// Whether a database error is contention: a lock not granted in time, or a
/// deadlock the database broke. Either way nothing was changed and trying again
/// is safe.
pub(super) fn is_contention(e: &sqlx::Error) -> bool {
    let sqlx::Error::Database(db) = e else {
        return false;
    };
    // Postgres: lock_not_available, deadlock_detected, serialization_failure.
    // SQLite: SQLITE_BUSY, SQLITE_LOCKED. MySQL reports the SQLSTATE, and the
    // numbered error in its message.
    if let Some(code) = db.code()
        && matches!(code.as_ref(), "55P03" | "40P01" | "40001" | "5" | "6" | "517")
    {
        return true;
    }
    let message = db.message().to_ascii_lowercase();
    [
        "database is locked",
        "lock wait timeout",
        "deadlock",
        "could not obtain lock",
        "lock timeout",
    ]
    .iter()
    .any(|m| message.contains(m))
}

/// Take every lock, in [`lock_order`]. The first not granted in time is `Busy`.
async fn take_locks(conn: &mut Conn, engine: Engine, targets: Vec<LockTarget>) -> Result<(), Failure> {
    for target in lock_order(targets) {
        if let Err(e) = lock(conn, engine, &target).await {
            return Err(if is_contention(&e) {
                Failure::Refused(Refusal::Busy(target.describe()))
            } else {
                Failure::Internal(format!("lock {target:?}: {e}"))
            });
        }
    }
    Ok(())
}

/// Take one lock. On SQLite the transaction already holds the database, so there
/// is nothing more to take.
async fn lock(conn: &mut Conn, engine: Engine, target: &LockTarget) -> Result<(), sqlx::Error> {
    if engine == Engine::Sqlite {
        return Ok(());
    }
    let (sql, key): (&'static str, &str) = match target {
        LockTarget::Administrators => (
            "SELECT name FROM txn_locks WHERE name = ? FOR UPDATE",
            ADMINISTRATORS_LOCK,
        ),
        LockTarget::Tenant(id) => ("SELECT id FROM tenants WHERE id = ? FOR UPDATE", id),
        LockTarget::User(id) => ("SELECT id FROM users WHERE id = ? FOR UPDATE", id),
        LockTarget::Group(id) => ("SELECT id FROM user_groups WHERE id = ? FOR UPDATE", id),
        LockTarget::App(id) => ("SELECT id FROM applications WHERE app_id = ? FOR UPDATE", id),
    };
    sqlx::query(crate::db::sql_stmt(engine, sql))
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(())
}

/// The row of `txn_locks` that serialises changes to who administers.
const ADMINISTRATORS_LOCK: &str = "administrators";

fn failure_of(cx: &mut Cx<'_>) -> Failure {
    cx.failure
        .take()
        .unwrap_or_else(|| Failure::Internal("aborted without a reason".into()))
}

fn sql_failure(e: sqlx::Error, what: &str) -> Failure {
    if is_contention(&e) {
        Failure::Refused(Refusal::Busy("The data".into()))
    } else {
        Failure::Internal(format!("{what}: {e}"))
    }
}

fn outcome<T>(failure: Failure) -> Outcome<T> {
    Outcome::from_failure(failure)
}

async fn write_audit(
    conn: &mut Conn,
    engine: Engine,
    actor: &Actor,
    event: crate::db::Event,
    audit: &Audit,
) -> Result<(), sqlx::Error> {
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO audit_log (tenant_id, actor, action, target, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(audit.tenant_id.as_deref())
    .bind(actor.audit_actor().as_str())
    .bind(event.as_str())
    .bind(audit.target.as_deref())
    .bind(audit.details.to_string())
    .bind(crate::util::now())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Run one transaction: authorize, run, check the global rules, audit, commit.
/// Anything but success rolls everything back.
pub async fn run<T: Transaction>(pool: &DbPool, actor: &Actor, txn: &T) -> Outcome<T::Output> {
    if !authorized(actor, T::INFO.need, &txn.scope()) {
        return Outcome::Refused(Refusal::NotPermitted);
    }
    let engine = crate::db::engine_of(pool);
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return outcome(sql_failure(e, "acquire")),
    };
    let mut tx = match begin(&mut conn, engine).await {
        Ok(tx) => tx,
        Err(e) => return outcome(sql_failure(e, "begin")),
    };
    if let Err(failure) = take_locks(&mut tx, engine, txn.locks()).await {
        return outcome(failure);
    }
    let admins_before = match lockout::global_administrators(&mut tx, engine).await {
        Ok(n) => n,
        Err(e) => return outcome(Failure::Internal(e.to_string())),
    };
    let mut cx = Cx {
        conn: &mut tx,
        engine,
        actor,
        failure: None,
    };
    let result = txn.run(&mut cx).await;
    let output = match result {
        Ok(out) if cx.failure.is_none() => out,
        // An abort, or a run that recorded a failure and carried on regardless:
        // both roll back.
        _ => return outcome(failure_of(&mut cx)),
    };
    if let Err(e) = lockout::ensure_one_remains(&mut tx, engine, admins_before).await {
        return outcome(super::classify(&e));
    }
    if let Err(e) = write_audit(&mut tx, engine, actor, T::INFO.event, &txn.audit(&output)).await {
        return outcome(sql_failure(e, "audit"));
    }
    if let Err(e) = tx.commit().await {
        return outcome(sql_failure(e, "commit"));
    }
    Outcome::Done(output)
}

/// What a batch came to.
pub enum BatchOutcome {
    /// Every transaction ran and the batch committed.
    Done(Vec<TxnOutput>),
    /// The transaction at `index` did not complete; nothing was committed.
    Aborted { index: usize, outcome: Outcome<()> },
}

/// Run several transactions as one: one database transaction, one commit after
/// the last succeeds, and the global rules checked once against the final state.
/// Every transaction is authorized before any runs.
pub async fn run_batch(pool: &DbPool, actor: &Actor, txns: &[Txn]) -> BatchOutcome {
    for (index, txn) in txns.iter().enumerate() {
        if !authorized(actor, txn.kind().info().need, &txn.scope()) {
            return BatchOutcome::Aborted {
                index,
                outcome: Outcome::Refused(Refusal::NotPermitted),
            };
        }
    }
    let at = |index: usize, failure: Failure| BatchOutcome::Aborted {
        index,
        outcome: outcome(failure),
    };
    let last = txns.len().saturating_sub(1);
    let engine = crate::db::engine_of(pool);
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return at(0, sql_failure(e, "acquire")),
    };
    let mut tx = match begin(&mut conn, engine).await {
        Ok(tx) => tx,
        Err(e) => return at(0, sql_failure(e, "begin")),
    };
    // Every lock of the batch, before any of it runs: taking them as each
    // transaction came to them could take them out of order.
    let locks = txns.iter().flat_map(Txn::locks).collect();
    if let Err(failure) = take_locks(&mut tx, engine, locks).await {
        return at(0, failure);
    }
    let admins_before = match lockout::global_administrators(&mut tx, engine).await {
        Ok(n) => n,
        Err(e) => return at(0, Failure::Internal(e.to_string())),
    };
    let batch_id = crate::util::new_guid();
    let mut outputs = Vec::with_capacity(txns.len());
    let mut audits = Vec::with_capacity(txns.len());
    {
        let mut cx = Cx {
            conn: &mut tx,
            engine,
            actor,
            failure: None,
        };
        for (index, txn) in txns.iter().enumerate() {
            match txn.run_one(&mut cx).await {
                Ok((out, audit)) if cx.failure.is_none() => {
                    outputs.push(out);
                    audits.push((txn.kind().info().event, audit));
                }
                _ => return at(index, failure_of(&mut cx)),
            }
        }
    }
    if let Err(e) = lockout::ensure_one_remains(&mut tx, engine, admins_before).await {
        return at(last, super::classify(&e));
    }
    for (index, (event, mut audit)) in audits.into_iter().enumerate() {
        if txns.len() > 1
            && let serde_json::Value::Object(map) = &mut audit.details
        {
            map.insert("batch".into(), serde_json::json!(batch_id));
        }
        if let Err(e) = write_audit(&mut tx, engine, actor, event, &audit).await {
            return at(index, sql_failure(e, "audit"));
        }
    }
    if let Err(e) = tx.commit().await {
        return at(last, sql_failure(e, "commit"));
    }
    BatchOutcome::Done(outputs)
}
