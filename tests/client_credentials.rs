mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{TestServer, aadsts};
use rust_oidc::apps::{MEMBER_APPLICATION, MEMBER_USER};

#[tokio::test]
async fn issues_entra_v2_app_only_token() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "orders-api").await;
    let worker = s.app(&t, "billing-worker").await;
    s.add_role(&t, &api, "Orders.Read", &[MEMBER_APPLICATION]).await;
    s.add_role(&t, &api, "Orders.Write", &[MEMBER_APPLICATION]).await;
    s.add_role(&t, &api, "Orders.Admin", &[MEMBER_USER]).await;
    s.assign_to_app(&t, &api, "Orders.Read", &worker).await;
    s.assign_to_app(&t, &api, "Orders.Write", &worker).await;

    let (status, body) = s
        .client_credentials(&t.id, &worker, &format!("api://{}/.default", api.app_id))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3599);
    assert_eq!(body["ext_expires_in"], 3599);
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());

    let token = body["access_token"].as_str().unwrap();
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert_eq!(header.kid, header.x5t);

    let claims = s.verify(&t.id, token, &api.app_id).await;
    assert_eq!(claims["ver"], "2.0");
    assert_eq!(claims["tid"], t.id.as_str());
    assert_eq!(claims["azp"], worker.app_id.as_str());
    assert_eq!(claims["azpacr"], "1");
    assert_eq!(claims["idtyp"], "app");
    assert_eq!(claims["oid"], worker.sp_id.as_str());
    assert_eq!(claims["sub"], worker.sp_id.as_str());
    assert_eq!(claims["roles"], serde_json::json!(["Orders.Read", "Orders.Write"]));
    assert!(claims["uti"].as_str().unwrap().len() >= 16);
    assert!(claims.get("scp").is_none(), "app-only tokens carry roles, never scp");
}

#[tokio::test]
async fn resource_may_be_named_by_app_id_or_custom_uri() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "orders-api").await;
    let worker = s.app(&t, "billing-worker").await;
    let app = rust_oidc::apps::find(&s.pool, &api.app_id).await.unwrap().unwrap();
    rust_oidc::apps::add_identifier_uri(&s.pool, &app, "https://orders.contoso.com")
        .await
        .unwrap();

    for scope in [
        format!("{}/.default", api.app_id),
        "https://orders.contoso.com/.default".to_string(),
    ] {
        let (status, body) = s.client_credentials("contoso.com", &worker, &scope).await;
        assert_eq!(status, 200, "{scope}: {body}");
        let claims = s
            .verify(&t.id, body["access_token"].as_str().unwrap(), &api.app_id)
            .await;
        assert!(claims.get("roles").is_none(), "no roles assigned -> no roles claim");
    }
}

#[tokio::test]
async fn client_secret_basic() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "api").await;
    let worker = s.app(&t, "worker").await;
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/token", t.id)))
        .basic_auth(&worker.app_id, Some(&worker.secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", &format!("api://{}/.default", api.app_id)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Both methods at once is rejected.
    let basic = STANDARD.encode(format!("{}:{}", worker.app_id, worker.secret));
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/token", t.id)))
        .header("authorization", format!("Basic {basic}"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_secret", worker.secret.as_str()),
            ("scope", &format!("api://{}/.default", api.app_id)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn client_authentication_errors() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "api").await;
    let worker = s.app(&t, "worker").await;
    let scope = format!("api://{}/.default", api.app_id);

    // Wrong secret: 401 AADSTS7000215, correlation id echoed.
    let resp = s
        .http
        .post(s.url(&format!("/{}/oauth2/v2.0/token", t.id)))
        .header("client-request-id", "7d3c0c38-5a6b-4f53-9d0e-0c1d7a3f1a11")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", worker.app_id.as_str()),
            ("client_secret", "wrong"),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()["client-request-id"],
        "7d3c0c38-5a6b-4f53-9d0e-0c1d7a3f1a11"
    );
    assert_eq!(resp.headers()["cache-control"], "no-store, no-cache");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(aadsts(&body), 7000215);
    assert_eq!(body["correlation_id"], "7d3c0c38-5a6b-4f53-9d0e-0c1d7a3f1a11");

    // No secret: 401 AADSTS7000218.
    let (status, body) = s
        .token(
            &t.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &worker.app_id),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!((status, aadsts(&body)), (401, 7000218));

    // Unknown client: AADSTS700016.
    let (status, body) = s
        .token(
            &t.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "3f0b8a55-0000-4000-8000-000000000000"),
                ("client_secret", "x"),
                ("scope", &scope),
            ],
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap(), aadsts(&body)),
        (400, "unauthorized_client", 700016)
    );

    // Expired secret: AADSTS7000222.
    sqlx::query("UPDATE app_secrets SET end_at = 1")
        .execute(&s.pool)
        .await
        .unwrap();
    let (status, body) = s.client_credentials(&t.id, &worker, &scope).await;
    assert_eq!((status, aadsts(&body)), (401, 7000222));
}

#[tokio::test]
async fn request_validation_errors() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "api").await;
    let worker = s.app(&t, "worker").await;

    let (status, body) = s.token(&t.id, &[("client_id", &worker.app_id)]).await;
    assert_eq!((status, aadsts(&body)), (400, 900144));

    let (status, body) = s.token(&t.id, &[("grant_type", "urn:made:up")]).await;
    assert_eq!(
        (status, body["error"].as_str().unwrap(), aadsts(&body)),
        (400, "unsupported_grant_type", 70003)
    );

    let (status, body) = s
        .token(
            &t.id,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &worker.app_id),
                ("client_secret", &worker.secret),
            ],
        )
        .await;
    assert_eq!((status, aadsts(&body)), (400, 900144), "missing scope");

    let (status, body) = s
        .client_credentials(&t.id, &worker, &format!("api://{}/Orders.Read", api.app_id))
        .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap(), aadsts(&body)),
        (400, "invalid_scope", 1002012)
    );

    let two = format!("api://{0}/.default api://{0}/.default", api.app_id);
    let (status, body) = s.client_credentials(&t.id, &worker, &two).await;
    assert_eq!((status, aadsts(&body)), (400, 70011));

    let (status, body) = s.client_credentials(&t.id, &worker, "api://unknown/.default").await;
    assert_eq!(
        (status, body["error"].as_str().unwrap(), aadsts(&body)),
        (400, "invalid_resource", 500011)
    );
}

#[tokio::test]
async fn disabled_service_principal_is_rejected() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&t, "api").await;
    let worker = s.app(&t, "worker").await;
    sqlx::query("UPDATE service_principals SET enabled = 0 WHERE id = ?")
        .bind(&worker.sp_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let (status, body) = s
        .client_credentials(&t.id, &worker, &format!("api://{}/.default", api.app_id))
        .await;
    assert_eq!((status, aadsts(&body)), (400, 7000112));
}
