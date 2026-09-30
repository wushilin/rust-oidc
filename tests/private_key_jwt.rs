//! Certificate client authentication (private_key_jwt), in Entra's shape:
//! the client signs a short-lived assertion with the private key matching a
//! registered certificate, and we identify the certificate by its `x5t`.

mod common;

use common::*;
use rust_oidc::apps;
use rust_oidc::apps::MemberType;
use serde_json::Value;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A client certificate and the key to sign assertions with.
struct ClientCert {
    cert_pem: String,
    key_pem: String,
    key_id: String,
}

fn make_cert(common_name: &str) -> ClientCert {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_id = apps::parse_certificate(&cert_pem).unwrap().key_id;
    ClientCert {
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        key_id,
    }
}

struct Assertion<'a> {
    cert: &'a ClientCert,
    issuer: &'a str,
    subject: &'a str,
    audience: String,
    jti: String,
    /// Seconds from now; negative for an already-expired assertion.
    expires_in: i64,
}

fn sign(a: &Assertion) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.x5t = Some(a.cert.key_id.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": a.issuer,
        "sub": a.subject,
        "aud": a.audience,
        "jti": a.jti,
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + a.expires_in,
    });
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(a.cert.key_pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

/// Register `cert` on `app` and return the token endpoint URL assertions must target.
async fn register(s: &TestServer, tenant: &rust_oidc::tenant::Tenant, app_id: &str, cert: &ClientCert) -> String {
    let app = apps::find_in_tenant(&s.pool, tenant, app_id).await.unwrap();
    apps::add_key_credential(&s.pool, &app, &cert.cert_pem, Some("test cert"))
        .await
        .unwrap();
    s.url(&format!("/{}/oauth2/v2.0/token", tenant.id))
}

async fn assert_with(s: &TestServer, tenant_key: &str, client_id: &str, assertion: &str, scope: &str) -> (u16, Value) {
    s.token(
        tenant_key,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion),
            ("scope", scope),
        ],
    )
    .await
}

struct Fixture {
    tenant: rust_oidc::tenant::Tenant,
    api: TestApp,
    client: TestApp,
    cert: ClientCert,
    token_url: String,
    scope: String,
}

async fn fixture(s: &TestServer) -> Fixture {
    let tenant = s.tenant("Contoso", "contoso.com").await;
    let api = s.app(&tenant, "orders-api").await;
    let client = s.app(&tenant, "billing-worker").await;
    s.add_role(&tenant, &api, "Orders.Read", &[MemberType::Application])
        .await;
    s.assign_to_app(&tenant, &api, "Orders.Read", &client).await;
    let cert = make_cert("billing-worker");
    let token_url = register(s, &tenant, &client.app_id, &cert).await;
    let scope = format!("api://{}/.default", api.app_id);
    Fixture {
        tenant,
        api,
        client,
        cert,
        token_url,
        scope,
    }
}

#[tokio::test]
async fn certificate_client_auth_issues_a_token() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-happy-path".into(),
        expires_in: 300,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 200, "{body}");
    let claims = s
        .verify(&f.tenant.id, body["access_token"].as_str().unwrap(), &f.api.app_id)
        .await;
    // azpacr 2 means the client authenticated with a certificate.
    assert_eq!(claims["azpacr"], "2");
    assert_eq!(claims["azp"], f.client.app_id);
    assert_eq!(claims["roles"][0], "Orders.Read");
}

#[tokio::test]
async fn replaying_a_jti_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-used-twice".into(),
        expires_in: 300,
    });
    let (status, _) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 200);
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "a replayed assertion must be refused: {body}");
    assert_eq!(body["error"], "invalid_client");

    // The replay is audited by its jti (an identifier), never by the assertion.
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, details FROM audit_log WHERE tenant_id = ? AND action = ?",
    ))
    .bind(&f.tenant.id)
    .bind("token.assertion_replayed")
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.client.app_id);
    let details = rows[0].1.as_deref().unwrap();
    assert!(details.contains("jti-used-twice") && !details.contains(&assertion));
}

#[tokio::test]
async fn assertion_for_another_audience_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: "https://login.microsoftonline.com/somewhere/oauth2/v2.0/token".into(),
        jti: "jti-wrong-aud".into(),
        expires_in: 300,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn assertion_signed_by_an_unregistered_key_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    // A different certificate, never registered on the app.
    let other = make_cert("attacker");
    let assertion = sign(&Assertion {
        cert: &other,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-unknown-key".into(),
        expires_in: 300,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn expired_assertion_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-expired".into(),
        expires_in: -60,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn assertion_issued_for_a_different_client_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    // iss/sub must be the client itself; here they name the API instead.
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.api.app_id,
        subject: &f.api.app_id,
        audience: f.token_url.clone(),
        jti: "jti-wrong-subject".into(),
        expires_in: 300,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn assertion_valid_for_too_long_is_rejected() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    // A long-lived assertion would stay replayable and force us to remember its
    // jti for just as long, so the lifetime is capped.
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-too-long".into(),
        expires_in: 24 * 60 * 60,
    });
    let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn certificate_auth_works_for_a_domain_addressed_tenant() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    // Same assertion audience (the GUID token endpoint), tenant addressed by domain.
    let assertion = sign(&Assertion {
        cert: &f.cert,
        issuer: &f.client.app_id,
        subject: &f.client.app_id,
        audience: f.token_url.clone(),
        jti: "jti-domain-tenant".into(),
        expires_in: 300,
    });
    let (status, body) = assert_with(&s, "contoso.com", &f.client.app_id, &assertion, &f.scope).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn thumbprint_is_matched_across_spellings() {
    let s = TestServer::start().await;
    let f = fixture(&s).await;
    // MSAL emits base64url *with* padding; other clients use standard base64 or
    // hex. All denote the same bytes, so all must match the stored credential.
    let padded = format!("{}=", f.cert.key_id);
    let standard = f.cert.key_id.replace('-', "+").replace('_', "/");
    let hex = {
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&f.cert.key_id)
            .unwrap();
        raw.iter().map(|b| format!("{b:02X}")).collect::<String>()
    };
    for (label, spelling) in [
        ("padded base64url", padded),
        ("standard base64", standard),
        ("hex", hex),
    ] {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.x5t = Some(spelling.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = serde_json::json!({
            "iss": f.client.app_id,
            "sub": f.client.app_id,
            "aud": f.token_url,
            "jti": format!("jti-{label}"),
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now + 300,
        });
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(f.cert.key_pem.as_bytes()).unwrap();
        let assertion = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        let (status, body) = assert_with(&s, &f.tenant.id, &f.client.app_id, &assertion, &f.scope).await;
        assert_eq!(status, 200, "{label} x5t ({spelling}) should be accepted: {body}");
    }
}
