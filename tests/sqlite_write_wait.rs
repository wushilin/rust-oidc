//! A storage write that reads before it writes waits for another writer on
//! SQLite instead of failing with "database is locked".
//!
//! SQLite will not upgrade a read lock to a write lock while another connection
//! holds the write lock, and does not wait in that case: a deferred transaction
//! fails at once. Storage functions therefore begin their own transactions with
//! `BEGIN IMMEDIATE` (`db::begin_write`). This failed intermittently in CI when
//! a refused write's rollback released its lock a moment late.

mod common;

use common::*;
use rust_oidc::users;
use sqlx::Connection;

#[tokio::test]
async fn a_read_then_write_waits_for_the_other_writer() {
    let s = TestServer::start().await;
    if rust_oidc::db::engine_of(&s.pool) != rust_oidc::db::Engine::Sqlite {
        // The behaviour under test is SQLite's; Postgres and MySQL lock rows, and
        // their waits are covered by the engine's `a_lock_not_granted_in_time_is_busy`.
        eprintln!("skipping: SQLite's lock upgrade only");
        return;
    }
    let f = user_fixture(&s).await;

    // Another connection holds the write lock, briefly.
    let mut holder = s.pool.acquire().await.unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let release = tokio::spawn(async move {
        let tx = holder.begin_with("BEGIN IMMEDIATE").await.unwrap();
        held_tx.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tx.rollback().await.unwrap();
    });
    held_rx.await.unwrap();

    // Reads (who administers), then writes: it must wait, not fail.
    let done = users::set_enabled(&s.pool, &f.tenant.id, &f.user_id, false).await;
    release.await.unwrap();
    assert!(done.unwrap(), "the account was disabled once the lock was free");
}
