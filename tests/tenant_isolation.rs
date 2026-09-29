mod common;

use common::{TestServer, aadsts};
use rust_oidc::apps::{self, MEMBER_APPLICATION, Principal};

#[tokio::test]
async fn client_from_other_tenant_is_not_found() {
    let s = TestServer::start().await;
    let a = s.tenant("Contoso", "contoso.com").await;
    let b = s.tenant("Fabrikam", "fabrikam.com").await;
    let api_b = s.app(&b, "api").await;
    let worker_a = s.app(&a, "worker").await;

    // Tenant A's client, valid secret, at tenant B's token endpoint.
    let (status, body) = s
        .client_credentials(&b.id, &worker_a, &format!("api://{}/.default", api_b.app_id))
        .await;
    assert_eq!((status, aadsts(&body)), (400, 700016));
    let (status, body) = s
        .client_credentials("fabrikam.com", &worker_a, &format!("api://{}/.default", api_b.app_id))
        .await;
    assert_eq!((status, aadsts(&body)), (400, 700016));
}

#[tokio::test]
async fn resource_from_other_tenant_is_not_found() {
    let s = TestServer::start().await;
    let a = s.tenant("Contoso", "contoso.com").await;
    let b = s.tenant("Fabrikam", "fabrikam.com").await;
    let api_b = s.app(&b, "api").await;
    let worker_a = s.app(&a, "worker").await;

    for scope in [
        format!("api://{}/.default", api_b.app_id),
        format!("{}/.default", api_b.app_id),
    ] {
        let (status, body) = s.client_credentials(&a.id, &worker_a, &scope).await;
        assert_eq!((status, aadsts(&body)), (400, 500011), "{scope}");
    }
}

#[tokio::test]
async fn identifier_uris_are_tenant_scoped() {
    let s = TestServer::start().await;
    let a = s.tenant("Contoso", "contoso.com").await;
    let b = s.tenant("Fabrikam", "fabrikam.com").await;
    let api_a = s.app(&a, "api").await;
    let api_b = s.app(&b, "api").await;
    let worker_a = s.app(&a, "worker").await;
    // The same identifier URI in two tenants resolves per tenant.
    for api in [&api_a, &api_b] {
        let app = apps::find(&s.pool, &api.app_id).await.unwrap().unwrap();
        apps::add_identifier_uri(&s.pool, &app, "https://shared.example/api")
            .await
            .unwrap();
    }
    let (status, body) = s
        .client_credentials(&a.id, &worker_a, "https://shared.example/api/.default")
        .await;
    assert_eq!(status, 200);
    let claims = s
        .verify(&a.id, body["access_token"].as_str().unwrap(), &api_a.app_id)
        .await;
    assert_eq!(claims["aud"], api_a.app_id.as_str());
}

#[tokio::test]
async fn tokens_carry_their_own_tenant_issuer() {
    let s = TestServer::start().await;
    let a = s.tenant("Contoso", "contoso.com").await;
    let b = s.tenant("Fabrikam", "fabrikam.com").await;
    let api_a = s.app(&a, "api").await;
    let worker_a = s.app(&a, "worker").await;

    let (_, body) = s
        .client_credentials(&a.id, &worker_a, &format!("api://{}/.default", api_a.app_id))
        .await;
    let token = body["access_token"].as_str().unwrap();
    let claims = s.verify(&a.id, token, &api_a.app_id).await;
    assert_eq!(claims["iss"], s.issuer(&a.id));
    assert_eq!(claims["tid"], a.id.as_str());

    // A resource API configured for tenant B rejects tenant A's token even
    // though the signing keys are shared: the issuer differs.
    let key = {
        let (_, jwks) = s.get_json(&format!("/{}/discovery/v2.0/keys", b.id)).await;
        let kid = jsonwebtoken::decode_header(token).unwrap().kid.unwrap();
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == kid.as_str())
            .unwrap()
            .clone();
        jsonwebtoken::DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap()).unwrap()
    };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&api_a.app_id]);
    validation.set_issuer(&[s.issuer(&b.id)]);
    let err = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).unwrap_err();
    assert!(matches!(err.kind(), jsonwebtoken::errors::ErrorKind::InvalidIssuer));
}

#[tokio::test]
async fn cannot_assign_roles_across_tenants() {
    let s = TestServer::start().await;
    let a = s.tenant("Contoso", "contoso.com").await;
    let b = s.tenant("Fabrikam", "fabrikam.com").await;
    let api_a = s.app(&a, "api").await;
    let worker_b = s.app(&b, "worker").await;
    s.add_role(&a, &api_a, "Orders.Read", &[MEMBER_APPLICATION]).await;
    let app = apps::find(&s.pool, &api_a.app_id).await.unwrap().unwrap();
    let err = apps::assign_role(
        &s.pool,
        &a,
        &app,
        "Orders.Read",
        &Principal::App(worker_b.app_id.clone()),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test]
async fn domains_are_unique_across_tenants() {
    let s = TestServer::start().await;
    s.tenant("Contoso", "contoso.com").await;
    let err = rust_oidc::tenant::create(&s.pool, "Imposter", "CONTOSO.com", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already registered"), "{err}");
}
