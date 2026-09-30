mod common;

use axum::http::HeaderMap;
use rust_oidc::db::DbPool;
use rust_oidc::{apps, groups, session, tenant, users};

const TASKS: usize = 8;

/// Fire `TASKS` copies of one future at once and return their results. A barrier
/// releases them together so the writes genuinely contend.
async fn contend<T, F, Fut>(make: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(TASKS));
    let mut tasks = Vec::new();
    for i in 0..TASKS {
        let b = barrier.clone();
        let fut = make(i);
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            fut.await
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

async fn fixture(pool: &DbPool) -> (tenant::Tenant, String, apps::Application) {
    let t = tenant::create(pool, "Contoso", "contoso.com", false).await.unwrap();
    let uid = users::create(
        pool,
        &t,
        users::NewUser {
            upn: "alice@contoso.com",
            password: "Correct-Horse-9",
            display_name: None,
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    let created = apps::create(pool, &t, "web").await.unwrap();
    (t, uid, created.application)
}

/// The neutral pattern replaces atomic ON CONFLICT, so it must neither lose a
/// write nor surface a unique violation under concurrency.
#[tokio::test]
async fn concurrent_upserts_of_one_row_all_succeed_and_agree() {
    for pool in common::all_engine_pools().await {
        let results = contend(|_| {
            let p = pool.clone();
            async move {
                rust_oidc::secrets::Secrets::new(p)
                    .pairwise_sub("user-1", "app-1")
                    .await
            }
        })
        .await;
        let mut seen = std::collections::HashSet::new();
        for r in results {
            seen.insert(r.expect("no upsert should fail"));
        }
        assert_eq!(seen.len(), 1, "every caller must derive the same pairwise sub");
    }
}

#[tokio::test]
async fn concurrent_session_creates_for_one_cookie_all_succeed() {
    for pool in common::all_engine_pools().await {
        let (t, uid, _) = fixture(&pool).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("{}=shared-cookie", session::SESSION_COOKIE).parse().unwrap(),
        );
        let results = contend(|_| {
            let (p, h, tid, uid) = (pool.clone(), headers.clone(), t.id.clone(), uid.clone());
            async move { session::create(&p, &h, &tid, &uid, &["pwd"], 3600).await }
        })
        .await;
        for r in results {
            assert_eq!(r.expect("no session create should fail"), "shared-cookie");
        }
        let (n,): (i64,) = sqlx::query_as(rust_oidc::db::sql_stmt(
            rust_oidc::db::engine_of(&pool),
            "SELECT COUNT(*) FROM sessions WHERE tenant_id = ?",
        ))
        .bind(&t.id)
        .fetch_one(&*pool)
        .await
        .unwrap();
        assert_eq!(n, 1);
        assert!(session::find(&pool, &headers, &t.id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn concurrent_certificate_registrations_leave_one_row_with_last_writer_fields() {
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let pem = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key_pair)
        .unwrap()
        .pem();
    for pool in common::all_engine_pools().await {
        let (_, _, app) = fixture(&pool).await;
        let results = contend(|i| {
            let (p, a, pem) = (pool.clone(), app.clone(), pem.clone());
            async move { apps::add_key_credential(&p, &a, &pem, Some(&format!("name-{i}"))).await }
        })
        .await;
        for r in results {
            r.expect("no registration should fail");
        }
        assert_eq!(apps::key_credentials(&pool, &app).await.unwrap().len(), 1);
        // A later registration of the same certificate refreshes it in place.
        apps::add_key_credential(&pool, &app, &pem, Some("renamed"))
            .await
            .unwrap();
        let creds = apps::key_credentials(&pool, &app).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].display_name.as_deref(), Some("renamed"));
        // Re-registering with identical arguments changes nothing. MySQL reports 0 affected
        // rows for that unless sqlx sets CLIENT_FOUND_ROWS, which the upsert relies on.
        apps::add_key_credential(&pool, &app, &pem, Some("renamed"))
            .await
            .expect("no-change re-registration");
        assert_eq!(apps::key_credentials(&pool, &app).await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn concurrent_and_repeated_membership_is_idempotent() {
    for pool in common::all_engine_pools().await {
        let (t, _, _) = fixture(&pool).await;
        groups::create(&pool, &t, "Admins", None).await.unwrap();
        let results = contend(|_| {
            let (p, t) = (pool.clone(), t.clone());
            async move { groups::add_member(&p, &t, "Admins", "alice@contoso.com").await }
        })
        .await;
        for r in results {
            r.expect("adding an existing member is not an error");
        }
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_members")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }
}

#[tokio::test]
async fn a_non_duplicate_insert_failure_is_not_swallowed() {
    for pool in common::all_engine_pools().await {
        let (t, _, _) = fixture(&pool).await;
        groups::create(&pool, &t, "Admins", None).await.unwrap();
        // Unknown user: a lookup error, not silently ignored.
        assert!(
            groups::add_member(&pool, &t, "Admins", "nobody@contoso.com")
                .await
                .is_err()
        );
    }
}
