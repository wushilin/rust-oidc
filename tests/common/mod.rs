#![allow(dead_code)]

use std::net::SocketAddr;

use rust_oidc::apps::{self, Principal};
use rust_oidc::config::PublicUrl;
use rust_oidc::tenant::{self, Tenant};
use rust_oidc::{AppState, db, keys, routes};
use serde_json::Value;
use rust_oidc::db::DbPool;

pub struct TestServer {
    pub base: String,
    pub pool: DbPool,
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

// ---- interactive sign-in helpers ----

pub struct Browser {
    pub http: reqwest::Client,
}

pub struct Page {
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
    pub headers: reqwest::header::HeaderMap,
}

impl Page {
    /// Value of a hidden/input field in the page (HTML-unescaped).
    pub fn field(&self, name: &str) -> Option<String> {
        let marker = format!(r#"name="{name}" value=""#);
        let start = self.body.find(&marker)? + marker.len();
        let end = self.body[start..].find('"')? + start;
        Some(unescape(&self.body[start..end]))
    }

    pub fn form_action(&self) -> String {
        let start = self.body.find(r#"action=""#).unwrap() + 8;
        let end = self.body[start..].find('"').unwrap() + start;
        unescape(&self.body[start..end])
    }

    /// Query (or fragment) parameters of the redirect.
    pub fn redirect_params(&self) -> std::collections::HashMap<String, String> {
        let loc = self.location.as_deref().expect("expected a redirect");
        let url = url::Url::parse(loc).unwrap();
        let mut map: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        if let Some(fragment) = url.fragment() {
            map.extend(url::form_urlencoded::parse(fragment.as_bytes()).into_owned());
        }
        map
    }
}

pub fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

impl Browser {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self { http }
    }

    async fn page(resp: reqwest::Response) -> Page {
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let location = headers.get("location").map(|v| v.to_str().unwrap().to_string());
        Page {
            status,
            location,
            body: resp.text().await.unwrap(),
            headers,
        }
    }

    pub async fn get(&self, url: &str) -> Page {
        Self::page(self.http.get(url).send().await.unwrap()).await
    }

    pub async fn authorize(&self, s: &TestServer, tenant: &str, params: &[(&str, &str)]) -> Page {
        let mut url = url::Url::parse(&s.url(&format!("/{tenant}/oauth2/v2.0/authorize"))).unwrap();
        url.query_pairs_mut().extend_pairs(params);
        self.get(url.as_str()).await
    }

    /// Submit the login form on `page`.
    pub async fn login(&self, page: &Page, upn: &str, password: &str) -> Page {
        assert!(
            page.field("csrf").is_some(),
            "expected the login page, got {} {:?}",
            page.status,
            page.location
        );
        let form = [
            ("csrf", page.field("csrf").unwrap()),
            ("request", page.field("request").unwrap()),
            ("op", "login".to_string()),
            ("upn", upn.to_string()),
            ("password", password.to_string()),
        ];
        Self::page(self.http.post(page.form_action()).form(&form).send().await.unwrap()).await
    }

    pub async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Page {
        Self::page(self.http.post(url).form(form).send().await.unwrap()).await
    }
}

pub struct UserFixture {
    pub tenant: Tenant,
    pub web: TestApp,
    pub api: TestApp,
    pub user_id: String,
    pub upn: String,
    pub password: String,
}

pub const REDIRECT: &str = "https://app.example.com/callback";
pub const SPA_REDIRECT: &str = "https://spa.example.com/";

/// Tenant `contoso.com` with user alice, a web app (secret + redirect URI),
/// an API exposing `Orders.Read` and user role `Orders.Approver` held by alice.
pub async fn user_fixture(s: &TestServer) -> UserFixture {
    let tenant = s.tenant("Contoso", "contoso.com").await;
    user_fixture_in(s, tenant, "alice@contoso.com").await
}

pub async fn user_fixture_in(s: &TestServer, tenant: Tenant, upn: &str) -> UserFixture {
    use rust_oidc::users;
    let password = "Correct-Horse-9".to_string();
    let user_id = users::create(
        &s.pool,
        &tenant,
        users::NewUser {
            upn,
            password: &password,
            display_name: Some("Alice Smith"),
            given_name: Some("Alice"),
            family_name: Some("Smith"),
            email: Some("alice.smith@example.org"),
        },
    )
    .await
    .unwrap();
    let web = s.app(&tenant, "web-app").await;
    let api = s.app(&tenant, "orders-api").await;
    let web_app = apps::find(&s.pool, &web.app_id).await.unwrap().unwrap();
    apps::add_redirect_uri(&s.pool, &web_app, apps::PLATFORM_WEB, REDIRECT)
        .await
        .unwrap();
    apps::add_redirect_uri(&s.pool, &web_app, apps::PLATFORM_SPA, SPA_REDIRECT)
        .await
        .unwrap();
    let api_app = apps::find(&s.pool, &api.app_id).await.unwrap().unwrap();
    apps::add_scope(&s.pool, &api_app, "Orders.Read", "Read orders", "User")
        .await
        .unwrap();
    apps::add_role(
        &s.pool,
        &api_app,
        "Orders.Approver",
        "Approver",
        None,
        &[apps::MEMBER_USER],
    )
    .await
    .unwrap();
    apps::assign_role(
        &s.pool,
        &tenant,
        &api_app,
        "Orders.Approver",
        &Principal::User(upn.to_string()),
    )
    .await
    .unwrap();
    UserFixture {
        tenant,
        web,
        api,
        user_id,
        upn: upn.to_string(),
        password,
    }
}

pub fn pkce() -> (String, String) {
    use base64::Engine;
    use sha2::Digest;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more-entropy".to_string();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn decode_unverified(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}
