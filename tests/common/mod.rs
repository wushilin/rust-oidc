#![allow(dead_code)]

use std::net::SocketAddr;

use rust_oidc::apps::{self, Principal};
use rust_oidc::config::PublicUrl;
use rust_oidc::tenant::{self, Tenant};
use rust_oidc::{AppState, db, keys, routes};
use serde_json::Value;
use sqlx::SqlitePool;

pub struct TestServer {
    pub base: String,
    pub pool: SqlitePool,
    pub http: reqwest::Client,
    _dir: tempfile::TempDir,
}

pub struct TestApp {
    pub app_id: String,
    pub sp_id: String,
    pub secret: String,
}

impl TestServer {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        let pool = db::connect(&url).await.unwrap();
        keys::ensure(&pool).await.unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}/rust-oidc", addr.port());
        let state = AppState::new(pool.clone(), PublicUrl::parse(&base).unwrap());
        let app = routes::router(state);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        Self {
            base,
            pool,
            http: reqwest::Client::new(),
            _dir: dir,
        }
    }

    pub async fn tenant(&self, name: &str, domain: &str) -> Tenant {
        tenant::create(&self.pool, name, domain, false).await.unwrap()
    }

    pub async fn app(&self, tenant: &Tenant, name: &str) -> TestApp {
        let created = apps::create(&self.pool, tenant, name).await.unwrap();
        let secret = apps::add_secret(&self.pool, &created.application, None, 30)
            .await
            .unwrap();
        TestApp {
            app_id: created.application.app_id,
            sp_id: created.service_principal_id,
            secret: secret.secret,
        }
    }

    pub async fn add_role(&self, tenant: &Tenant, resource: &TestApp, value: &str, types: &[&str]) {
        let app = apps::find_in_tenant(&self.pool, tenant, &resource.app_id)
            .await
            .unwrap();
        apps::add_role(&self.pool, &app, value, value, None, types)
            .await
            .unwrap();
    }

    pub async fn assign_to_app(&self, tenant: &Tenant, resource: &TestApp, value: &str, client: &TestApp) {
        let app = apps::find_in_tenant(&self.pool, tenant, &resource.app_id)
            .await
            .unwrap();
        apps::assign_role(&self.pool, tenant, &app, value, &Principal::App(client.app_id.clone()))
            .await
            .unwrap();
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn issuer(&self, tid: &str) -> String {
        format!("{}/{tid}/v2.0", self.base)
    }

    pub async fn get_json(&self, path: &str) -> (u16, Value) {
        let resp = self.http.get(self.url(path)).send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap())
    }

    pub async fn token(&self, tenant_key: &str, form: &[(&str, &str)]) -> (u16, Value) {
        let resp = self
            .http
            .post(self.url(&format!("/{tenant_key}/oauth2/v2.0/token")))
            .form(form)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap())
    }

    pub async fn client_credentials(&self, tenant_key: &str, client: &TestApp, scope: &str) -> (u16, Value) {
        self.token(
            tenant_key,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client.app_id),
                ("client_secret", &client.secret),
                ("scope", scope),
            ],
        )
        .await
    }

    /// Verify a JWT against the tenant's published JWKS, the way a resource API would.
    pub async fn verify(&self, tid: &str, token: &str, audience: &str) -> Value {
        let header = jsonwebtoken::decode_header(token).unwrap();
        let (_, jwks) = self.get_json(&format!("/{tid}/discovery/v2.0/keys")).await;
        let kid = header.kid.expect("kid");
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == kid.as_str())
            .expect("kid published in JWKS");
        let key =
            jsonwebtoken::DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
                .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[self.issuer(tid)]);
        jsonwebtoken::decode::<Value>(token, &key, &validation).unwrap().claims
    }
}

pub fn aadsts(body: &Value) -> u64 {
    body["error_codes"][0].as_u64().unwrap_or(0)
}
