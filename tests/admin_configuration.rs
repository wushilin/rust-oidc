//! The Configuration page: what an outside application is configured with.

mod common;

use common::*;
use serde_json::Value;

#[tokio::test]
async fn the_page_gives_the_addresses_the_discovery_document_gives() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;

    let page = b.get(&s.url("/admin/configuration")).await;
    assert_eq!(page.status, 200, "{}", page.body);

    // Every address in a tenant's discovery document is on the page: in its
    // general form, with a placeholder where the tenant goes.
    let document: Value = reqwest::get(s.url(&format!("/{}/v2.0/.well-known/openid-configuration", other.id)))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for key in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    ] {
        let address = document[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} in the document"));
        let general = address.replace(&other.id, "{tenant}");
        assert!(
            page.body.contains(&format!("<code>{general}</code>")),
            "{key}: {general} is not on the page: {}",
            page.body
        );
        assert!(page.body.contains(key), "{key} is named: {}", page.body);
    }
    // And each tenant's own issuer and discovery document, by id.
    for t in [&f.tenant, &other] {
        assert!(
            page.body.contains(&format!(
                "<code>{}</code>",
                document["issuer"].as_str().unwrap().replace(&other.id, &t.id)
            )),
            "{}: {}",
            t.name,
            page.body
        );
        assert!(
            page.body.contains(&format!(
                r#"/{}/v2.0/.well-known/openid-configuration">Discovery document</a>"#,
                t.id
            )),
            "{}",
            page.body
        );
    }
    // What is supported is what the document advertises.
    for key in ["grant_types_supported", "response_types_supported", "scopes_supported"] {
        for value in document[key].as_array().unwrap() {
            let value = value.as_str().unwrap();
            assert!(
                page.body.contains(&format!("<code>{value}</code>")),
                "{key} {value}: {}",
                page.body
            );
        }
    }
    // Nothing secret is on it: no key material.
    assert!(!page.body.contains("BEGIN"), "{}", page.body);
}

#[tokio::test]
async fn the_page_is_a_global_administrators() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    assert_eq!(b.get(&s.url("/admin/configuration")).await.status, 403);
    let tenants = b.get(&s.url("/admin/tenants")).await;
    assert!(!tenants.body.contains(">Configuration<"), "no tab: {}", tenants.body);
}
