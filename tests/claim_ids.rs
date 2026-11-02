//! `role_ids` sits beside `roles`, same members in the same order, so an
//! application can key on an id that survives a rename and still read the value
//! next to it. (`groups` carries ids itself, as in Entra; see `group_claims.rs`.)

mod common;

use common::*;
use rust_oidc::apps;
use serde_json::Value;

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

async fn ropc(s: &TestServer, f: &UserFixture, client: &TestApp, scope: &str) -> Value {
    let app = apps::find_in_tenant(&s.pool, &f.tenant, &client.app_id).await.unwrap();
    apps::set_password_grant_allowed(&s.pool, &app, true).await.unwrap();
    let (status, body) = s
        .token(
            &f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &client.app_id),
                ("client_secret", &client.secret),
                ("username", &f.upn),
                ("password", &f.password),
                ("scope", scope),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    body
}

#[tokio::test]
async fn role_ids_line_up_with_role_values() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    // The fixture gives alice `Orders.Approver` on the API. Its id is what the
    // token must carry beside the value.
    let api = apps::find(&s.pool, &f.api.app_id).await.unwrap().unwrap();
    let roles = apps::roles(&s.pool, &api).await.unwrap();
    let approver = roles
        .iter()
        .find(|r| r.value == "Orders.Approver")
        .expect("the fixture role");

    let scope = format!("openid api://{}/Orders.Read", f.api.app_id);
    let body = ropc(&s, &f, &f.web, &scope).await;
    let access = decode_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(strings(&access["roles"]), ["Orders.Approver"]);
    assert_eq!(strings(&access["role_ids"]), std::slice::from_ref(&approver.id));
}

#[tokio::test]
async fn an_application_token_carries_role_ids_too() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let api_app = apps::find(&s.pool, &f.api.app_id).await.unwrap().unwrap();
    for value in ["Orders.Write", "Orders.Archive"] {
        apps::add_role(&s.pool, &api_app, value, value, None, &[apps::MemberType::Application])
            .await
            .unwrap();
    }
    s.assign_to_app(&f.tenant, &f.api, "Orders.Write", &f.web).await;
    s.assign_to_app(&f.tenant, &f.api, "Orders.Archive", &f.web).await;

    let (status, body) = s
        .client_credentials(&f.tenant.id, &f.web, &format!("api://{}/.default", f.api.app_id))
        .await;
    assert_eq!(status, 200, "{body}");
    let claims = decode_unverified(body["access_token"].as_str().unwrap());
    let values = strings(&claims["roles"]);
    let ids = strings(&claims["role_ids"]);
    assert_eq!(values, ["Orders.Archive", "Orders.Write"], "ordered by value");
    assert_eq!(ids.len(), values.len());

    let api = apps::find(&s.pool, &f.api.app_id).await.unwrap().unwrap();
    let defined = apps::roles(&s.pool, &api).await.unwrap();
    for (value, id) in values.iter().zip(&ids) {
        let role = defined.iter().find(|r| &r.value == value).unwrap();
        assert_eq!(&role.id, id, "{value} is paired with its own id");
    }
}

/// Nothing is emitted for nothing: no empty arrays, and never an id list
/// without its names.
#[tokio::test]
async fn neither_claim_appears_without_its_names() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let body = ropc(&s, &f, &f.web, "openid").await;
    let id = decode_unverified(body["id_token"].as_str().unwrap());
    assert!(id.get("groups").is_none() && id.get("group_ids").is_none(), "{id}");
    assert!(id.get("roles").is_none() && id.get("role_ids").is_none(), "{id}");
}
