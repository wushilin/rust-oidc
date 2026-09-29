mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{TestServer, aadsts};
use sha1::{Digest, Sha1};

#[tokio::test]
async fn discovery_by_guid_and_domain_uses_guid_issuer() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;

    for key in [t.id.as_str(), "contoso.com", "CONTOSO.com"] {
        let (status, doc) = s
            .get_json(&format!("/{key}/v2.0/.well-known/openid-configuration"))
            .await;
        assert_eq!(status, 200, "{key}");
        assert_eq!(doc["issuer"], s.issuer(&t.id));
        assert_eq!(doc["token_endpoint"], s.url(&format!("/{}/oauth2/v2.0/token", t.id)));
        assert_eq!(doc["jwks_uri"], s.url(&format!("/{}/discovery/v2.0/keys", t.id)));
        assert_eq!(
            doc["authorization_endpoint"],
            s.url(&format!("/{}/oauth2/v2.0/authorize", t.id))
        );
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(doc["subject_types_supported"], serde_json::json!(["pairwise"]));
    }
}

#[tokio::test]
async fn unknown_tenant_is_aadsts90002() {
    let s = TestServer::start().await;
    for key in ["nope.example", "00000000-0000-0000-0000-000000000000"] {
        let (status, body) = s
            .get_json(&format!("/{key}/v2.0/.well-known/openid-configuration"))
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["error"], "invalid_tenant");
        assert_eq!(aadsts(&body), 90002);
        assert!(body["error_description"].as_str().unwrap().starts_with("AADSTS90002:"));
    }
}

#[tokio::test]
async fn disabled_tenant_does_not_resolve() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    sqlx::query("UPDATE tenants SET enabled = 0 WHERE id = ?")
        .bind(&t.id)
        .execute(&s.pool)
        .await
        .unwrap();
    let (status, body) = s
        .get_json(&format!("/{}/v2.0/.well-known/openid-configuration", t.id))
        .await;
    assert_eq!(status, 400);
    assert_eq!(aadsts(&body), 90002);
}

#[tokio::test]
async fn jwks_matches_entra_shape() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let (status, jwks) = s.get_json(&format!("/{}/discovery/v2.0/keys", t.id)).await;
    assert_eq!(status, 200);
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "active + pre-published next key");
    for k in keys {
        assert_eq!(k["kty"], "RSA");
        assert_eq!(k["use"], "sig");
        assert_eq!(k["e"], "AQAB");
        assert_eq!(k["issuer"], s.issuer(&t.id));
        // kid == x5t == base64url(SHA-1(certificate DER)), as in Entra.
        let cert = STANDARD.decode(k["x5c"][0].as_str().unwrap()).unwrap();
        let thumbprint = URL_SAFE_NO_PAD.encode(Sha1::digest(&cert));
        assert_eq!(k["x5t"], thumbprint.as_str());
        assert_eq!(k["kid"], thumbprint.as_str());
    }
}

#[tokio::test]
async fn common_keys_use_issuer_template() {
    let s = TestServer::start().await;
    let (status, jwks) = s.get_json("/common/discovery/v2.0/keys").await;
    assert_eq!(status, 200);
    assert_eq!(jwks["keys"][0]["issuer"], s.issuer("{tenantid}"));
}

#[tokio::test]
async fn metadata_allows_cors() {
    let s = TestServer::start().await;
    let t = s.tenant("Contoso", "contoso.com").await;
    let resp = s
        .http
        .get(s.url(&format!("/{}/discovery/v2.0/keys", t.id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
}
