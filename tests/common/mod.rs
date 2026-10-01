#![allow(dead_code)]

use std::net::SocketAddr;

use rust_oidc::apps::{self, MemberType, Principal, ScopeConsent};
use rust_oidc::config::PublicUrl;
use rust_oidc::db::DbPool;
use rust_oidc::tenant::{self, Tenant};
use rust_oidc::{AppState, db, keys, routes};
use serde_json::Value;

pub struct TestServer {
    pub base: String,
    pub pool: DbPool,
    pub http: reqwest::Client,
    _guard: EnginePool,
}

pub struct TestApp {
    pub app_id: String,
    pub sp_id: String,
    pub secret: String,
}

impl TestServer {
    pub async fn start() -> Self {
        let engine = match std::env::var(ENV_SERVER_ENGINE) {
            Ok(raw) => db::Engine::parse(&raw).unwrap_or_else(|| panic!("{ENV_SERVER_ENGINE}={raw} is not an engine")),
            Err(_) => db::Engine::Sqlite,
        };
        let guard = pool_for(engine).await.unwrap_or_else(|| {
            panic!(
                "{ENV_SERVER_ENGINE}={} but its database env var is not set",
                engine.as_str()
            )
        });
        let pool = (*guard).clone();
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
            _guard: guard,
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

    pub async fn add_role(&self, tenant: &Tenant, resource: &TestApp, value: &str, types: &[MemberType]) {
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
    apps::add_redirect_uri(&s.pool, &web_app, apps::RedirectPlatform::Web, REDIRECT)
        .await
        .unwrap();
    apps::add_redirect_uri(&s.pool, &web_app, apps::RedirectPlatform::Spa, SPA_REDIRECT)
        .await
        .unwrap();
    let api_app = apps::find(&s.pool, &api.app_id).await.unwrap().unwrap();
    apps::add_scope(&s.pool, &api_app, "Orders.Read", "Read orders", ScopeConsent::User)
        .await
        .unwrap();
    apps::add_role(
        &s.pool,
        &api_app,
        "Orders.Approver",
        "Approver",
        None,
        &[apps::MemberType::User],
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

/// Env var holding an admin URL for a scratch Postgres server (`postgres://user:pw@host:port/postgres`).
pub const ENV_POSTGRES: &str = "RUST_OIDC_TEST_POSTGRES";
/// Env var holding an admin URL for a scratch MySQL server (`mysql://root:pw@host:port/`).
pub const ENV_MYSQL: &str = "RUST_OIDC_TEST_MYSQL";
/// Env var selecting the engine `TestServer::start` runs on (`sqlite` when unset).
pub const ENV_SERVER_ENGINE: &str = "RUST_OIDC_TEST_ENGINE";

static DB_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A freshly migrated pool on its own empty database, dropped with this value.
/// Derefs to the pool, so it is used exactly like one.
pub struct EnginePool {
    pool: DbPool,
    cleanup: Cleanup,
}

enum Cleanup {
    Dir(std::path::PathBuf),
    /// Admin URL and the name of the database to drop.
    Database(String, String),
}

impl std::ops::Deref for EnginePool {
    type Target = DbPool;
    fn deref(&self) -> &DbPool {
        &self.pool
    }
}

impl Drop for EnginePool {
    fn drop(&mut self) {
        match &self.cleanup {
            Cleanup::Dir(dir) => {
                let _ = std::fs::remove_dir_all(dir);
            }
            Cleanup::Database(admin, name) => {
                let (admin, name) = (admin.clone(), name.clone());
                // The owning runtime may already be winding down, so use a private one.
                // Do NOT `pool.close().await` here: the pool's connection tasks live on the
                // owning runtime, which is blocked on this thread's join, so it deadlocks.
                // Instead the drop terminates the pool's sessions itself (PG `FORCE`).
                let _ = std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(drop_database(&admin, &name));
                })
                .join();
            }
        }
    }
}

fn database_url(admin: &str, name: &str) -> String {
    let (base, query) = match admin.split_once('?') {
        Some((b, q)) => (b, format!("?{q}")),
        None => (admin, String::new()),
    };
    let (server, _) = base
        .rsplit_once('/')
        .expect("admin URL needs a path: scheme://user:pw@host:port/db");
    format!("{server}/{name}{query}")
}

async fn admin_connection(admin: &str) -> sqlx::AnyConnection {
    use sqlx::Connection;
    db::install_drivers();
    sqlx::AnyConnection::connect(admin)
        .await
        .expect("cannot reach the admin database")
}

async fn drop_database(admin: &str, name: &str) {
    use sqlx::{Executor, Row};
    // A test that panicked mid-transaction leaves a session holding metadata locks
    // that would block DROP DATABASE forever, so kill the sessions first (MySQL;
    // Postgres does it with `WITH (FORCE)`), and never wait more than a little.
    let work = async {
        let mut conn = admin_connection(admin).await;
        let stmt = match db::Engine::from_url(admin) {
            Some(db::Engine::Postgres) => format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
            _ => {
                let rows = sqlx::query("SELECT id FROM information_schema.processlist WHERE db = ?")
                    .bind(name)
                    .fetch_all(&mut conn)
                    .await
                    .unwrap_or_default();
                for row in rows {
                    if let Ok(id) = row.try_get::<i64, _>(0) {
                        let _ = conn.execute(sqlx::AssertSqlSafe(format!("KILL {id}"))).await;
                    }
                }
                format!("DROP DATABASE IF EXISTS {name}")
            }
        };
        if let Err(e) = conn.execute(sqlx::AssertSqlSafe(stmt)).await {
            eprintln!("could not drop test database {name}: {e}");
        }
    };
    if tokio::time::timeout(std::time::Duration::from_secs(30), work)
        .await
        .is_err()
    {
        eprintln!("timed out dropping test database {name}");
    }
}

async fn fresh_server_database(engine: db::Engine, admin: &str, migrate: bool) -> EnginePool {
    use sqlx::Executor;
    let name = format!(
        "rust_oidc_t_{}_{}_{}",
        std::process::id(),
        DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        rand_suffix()
    );
    let mut conn = admin_connection(admin).await;
    let create = match engine {
        // Postgres: match the server default; MySQL: utf8mb4 is what the migrations assume.
        db::Engine::MySql => format!("CREATE DATABASE {name} CHARACTER SET utf8mb4"),
        _ => format!("CREATE DATABASE {name}"),
    };
    conn.execute(sqlx::AssertSqlSafe(create))
        .await
        .expect("create test database");
    drop(conn);
    let url = database_url(admin, &name);
    let pool = if migrate {
        db::connect(&url).await.expect("connect + migrate")
    } else {
        sqlx::any::AnyPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect")
    };
    EnginePool {
        pool,
        cleanup: Cleanup::Database(admin.to_string(), name),
    }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "{:x}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()
    )
}

async fn fresh_sqlite() -> EnginePool {
    let dir = tempfile::tempdir().unwrap().keep();
    let url = format!("sqlite://{}", dir.join("engine.db").display());
    EnginePool {
        pool: db::connect(&url).await.unwrap(),
        cleanup: Cleanup::Dir(dir),
    }
}

/// A fresh pool on one specific engine, or `None` when that engine is not configured.
pub async fn pool_for(engine: db::Engine) -> Option<EnginePool> {
    match engine {
        db::Engine::Sqlite => Some(fresh_sqlite().await),
        db::Engine::Postgres => match std::env::var(ENV_POSTGRES) {
            Ok(admin) => Some(fresh_server_database(engine, &admin, true).await),
            Err(_) => None,
        },
        db::Engine::MySql => match std::env::var(ENV_MYSQL) {
            Ok(admin) => Some(fresh_server_database(engine, &admin, true).await),
            Err(_) => None,
        },
    }
}

/// A pool on an empty, UNMIGRATED database, for tests that apply migration files
/// by hand. `None` when the engine is not configured.
pub async fn blank_pool_for(engine: db::Engine) -> Option<EnginePool> {
    match engine {
        db::Engine::Sqlite => {
            let dir = tempfile::tempdir().unwrap().keep();
            db::install_drivers();
            let url = format!("sqlite://{}?mode=rwc", dir.join("blank.db").display());
            let pool = sqlx::any::AnyPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            sqlx::raw_sql("PRAGMA foreign_keys = ON").execute(&pool).await.unwrap();
            Some(EnginePool {
                pool,
                cleanup: Cleanup::Dir(dir),
            })
        }
        db::Engine::Postgres => match std::env::var(ENV_POSTGRES) {
            Ok(admin) => Some(fresh_server_database(engine, &admin, false).await),
            Err(_) => None,
        },
        db::Engine::MySql => match std::env::var(ENV_MYSQL) {
            Ok(admin) => Some(fresh_server_database(engine, &admin, false).await),
            Err(_) => None,
        },
    }
}

/// One freshly migrated pool per engine available to this run: SQLite always,
/// Postgres and MySQL when their env vars are set. Each pool has its own empty
/// database, dropped when the value is dropped. Skipped engines are announced so
/// a green run can never silently mean "SQLite only".
pub async fn all_engine_pools() -> Vec<EnginePool> {
    let mut pools = Vec::new();
    for engine in db::Engine::ALL {
        match pool_for(*engine).await {
            Some(p) => pools.push(p),
            None => {
                let var = if *engine == db::Engine::Postgres {
                    ENV_POSTGRES
                } else {
                    ENV_MYSQL
                };
                // Straight to the stderr handle: `eprintln!` is swallowed by the test
                // harness's output capture on passing tests, which would defeat the point.
                use std::io::Write;
                let _ = writeln!(std::io::stderr(), "skipping {}: {var} not set", engine.as_str());
            }
        }
    }
    pools
}

// ---- admin console helpers ----

use rust_oidc::admin::bindings::{self, PrincipalType};
use rust_oidc::admin::session as admin_session;
use rust_oidc::rbac::{RoleId, Scope};

/// Give a user a console role at a scope.
pub async fn bind(s: &TestServer, user_id: &str, role: RoleId, scope: Scope) -> String {
    bindings::create(&s.pool, PrincipalType::User, user_id, role, &scope, "test")
        .await
        .unwrap()
}

/// A super administrator: tenant admin everywhere, plus the platform role that
/// can create and assume tenants. The shape of `admin@wushilin.net` on the
/// deployed service.
pub async fn admin_fixture(s: &TestServer) -> UserFixture {
    let f = user_fixture(s).await;
    bind(s, &f.user_id, RoleId::GlobalAdministrator, Scope::All).await;
    bind(s, &f.user_id, RoleId::PlatformAdministrator, Scope::All).await;
    f
}

/// A delegated administrator: Global Administrator of one tenant and nothing
/// else. The fixture the isolation tests are about.
pub async fn tenant_admin_fixture(s: &TestServer) -> UserFixture {
    let f = user_fixture(s).await;
    bind(
        s,
        &f.user_id,
        RoleId::GlobalAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    f
}

/// Read everything, change nothing.
pub async fn reader_fixture(s: &TestServer) -> UserFixture {
    let f = user_fixture(s).await;
    bind(s, &f.user_id, RoleId::GlobalReader, Scope::All).await;
    f
}

/// A browser signed in to the console, carrying that session's CSRF token so
/// every form post this helper makes is a well-formed one.
pub struct AdminBrowser {
    pub b: Browser,
    pub csrf: String,
}

impl AdminBrowser {
    pub async fn get(&self, url: &str) -> Page {
        self.b.get(url).await
    }

    /// Post a console form, with the session's CSRF token added.
    pub async fn post(&self, url: &str, form: &[(&str, &str)]) -> Page {
        let mut fields: Vec<(&str, &str)> = form.to_vec();
        fields.push((admin_session::CSRF_FIELD, &self.csrf));
        self.b.post_form(url, &fields).await
    }

    /// Post without the token, for the tests that are about the token.
    pub async fn post_raw(&self, url: &str, form: &[(&str, &str)]) -> Page {
        self.b.post_form(url, form).await
    }
}

/// Sign in to the console as this fixture's user.
pub async fn signed_in_admin(s: &TestServer, f: &UserFixture) -> AdminBrowser {
    let b = Browser::new();
    // Fetch the form first, as a browser does: it carries the single-use nonce
    // that protects sign-in, and sets the cookie the nonce is checked against.
    let form = b.get(&s.url("/admin")).await;
    let nonce = form
        .field(admin_session::CSRF_FIELD)
        .expect("the sign-in form carries a login nonce");
    let page = b
        .post_form(
            &s.url("/admin/signin"),
            &[
                ("upn", f.upn.as_str()),
                ("password", f.password.as_str()),
                (admin_session::CSRF_FIELD, nonce.as_str()),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "console sign-in failed: {}", page.body);
    let cookie = admin_cookie(&page).expect("the sign-in set a console session cookie");
    AdminBrowser {
        b,
        csrf: admin_session::csrf_for(&cookie),
    }
}

/// Value of the console session cookie a response set, if any.
pub fn admin_cookie(page: &Page) -> Option<String> {
    let prefix = format!("{}=", admin_session::ADMIN_COOKIE);
    page.headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.strip_prefix(&prefix))
        .filter_map(|v| v.split(';').next())
        .find(|v| !v.is_empty())
        .map(str::to_string)
}

/// Rows of the audit trail with this action, newest first.
pub async fn audit_rows(s: &TestServer, action: &str) -> Vec<(String, Option<String>, Option<String>)> {
    sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT actor, target, tenant_id FROM audit_log WHERE action = ? ORDER BY created_at DESC, id DESC",
    ))
    .bind(action)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}
