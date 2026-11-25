//! Application logos, and My Account's tabs where My apps shows them.

mod common;

use common::*;
use rust_oidc::apps;
use rust_oidc::apps::Principal;
use rust_oidc::db::Event;
use rust_oidc::logos::{self, Image, LibraryIcon, Logo, Shown};
use rust_oidc::txn::ops::apps::SetAppLogo;
use rust_oidc::txn::ops::saml::SetAppSignOnUrl;
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use serde_json::Value;

/// The smallest real PNG: one transparent pixel.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49,
    0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];
const SVG: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;

struct World {
    s: TestServer,
    f: UserFixture,
}

/// Alice is assigned the web app, which has a Sign on URL, so it is on her My apps.
async fn world() -> World {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    apps::assign(&s.pool, &f.tenant, &app, &Principal::User(f.upn.clone()), &[])
        .await
        .unwrap();
    let url = SetAppSignOnUrl {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        sign_on_url: Some("https://app.example.com/start".into()),
    };
    txn::run(&s.pool, &Actor::Cli, &url).await.into_result().unwrap();
    World { s, f }
}

impl World {
    async fn set(&self, logo: Option<Logo>) -> Outcome<()> {
        let t = SetAppLogo {
            tenant_id: self.f.tenant.id.clone(),
            app_id: self.f.web.app_id.clone(),
            logo,
        };
        txn::run(&self.s.pool, &Actor::Cli, &t).await
    }

    async fn shown(&self) -> Option<Shown> {
        let app = apps::find(&self.s.pool, &self.f.web.app_id).await.unwrap().unwrap();
        logos::shown(&self.s.pool, &app.id).await.unwrap()
    }

    fn account(&self, tab: &str) -> String {
        self.s.url(&format!("/{}/myaccount{tab}", self.f.tenant.id))
    }

    async fn signed_in(&self) -> Browser {
        let b = Browser::new();
        let login = b.get(&self.account("")).await;
        let page = b.login(&login, &self.f.upn, &self.f.password).await;
        assert!(page.body.contains("<h1>My account</h1>"), "{}", page.body);
        b
    }
}

fn png() -> Logo {
    Logo::Image(Image::from_upload(PNG.to_vec()).unwrap())
}

async fn audit(s: &TestServer) -> Vec<Value> {
    let raw: Vec<(String,)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(Event::AdminAppLogo.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap();
    raw.into_iter().map(|(d,)| serde_json::from_str(&d).unwrap()).collect()
}

#[tokio::test]
async fn a_logo_is_set_replaced_and_removed_each_with_an_audit_row_without_the_image() {
    let w = world().await;
    assert_eq!(w.shown().await, None);

    w.set(Some(png())).await.into_result().unwrap();
    assert!(matches!(w.shown().await, Some(Shown::Image { .. })));
    let app = apps::find(&w.s.pool, &w.f.web.app_id).await.unwrap().unwrap();
    assert_eq!(logos::image(&w.s.pool, &app.id).await.unwrap().unwrap().bytes, PNG);

    w.set(Some(Logo::Library(LibraryIcon::Chart)))
        .await
        .into_result()
        .unwrap();
    assert_eq!(w.shown().await, Some(Shown::Library(LibraryIcon::Chart)));
    assert_eq!(
        logos::image(&w.s.pool, &app.id).await.unwrap(),
        None,
        "the image is gone"
    );

    w.set(None).await.into_result().unwrap();
    assert_eq!(w.shown().await, None);

    let rows = audit(&w.s).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0]["logo"], "image");
    assert_eq!(rows[0]["contentType"], "image/png");
    assert_eq!(rows[0]["bytes"], PNG.len());
    assert_eq!(rows[0]["sha256"], rust_oidc::util::sha256_hex(PNG));
    assert_eq!(
        rows[0].as_object().unwrap().len(),
        4,
        "nothing else, and never the image: {rows:?}"
    );
    assert_eq!(rows[1]["icon"], "chart");
    assert_eq!(rows[2]["logo"], "none");
}

#[tokio::test]
async fn a_file_that_is_not_an_accepted_image_is_refused_and_changes_nothing() {
    let w = world().await;
    w.set(Some(Logo::Library(LibraryIcon::Mail)))
        .await
        .into_result()
        .unwrap();
    // Claimed to be a PNG, but SVG (which can carry script) underneath.
    let disguised = Logo::Image(Image {
        kind: logos::ImageType::Png,
        bytes: SVG.to_vec(),
    });
    let outcome = w.set(Some(disguised)).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    let mut big = PNG.to_vec();
    big.resize(logos::MAX_IMAGE_BYTES + 1, 0);
    let outcome = w
        .set(Some(Logo::Image(Image {
            kind: logos::ImageType::Png,
            bytes: big,
        })))
        .await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert_eq!(w.shown().await, Some(Shown::Library(LibraryIcon::Mail)), "unchanged");
    assert_eq!(audit(&w.s).await.len(), 1);
}

#[tokio::test]
async fn my_account_has_a_tab_each_for_apps_profile_and_security() {
    let w = world().await;
    let b = w.signed_in().await;

    let apps = b.get(&w.account("")).await;
    assert!(apps.body.contains(r#"<a href=""#), "{}", apps.body);
    assert!(
        apps.body
            .contains(r#"/myaccount/apps" aria-current="page">My apps</a>"#),
        "{}",
        apps.body
    );
    assert!(
        apps.body
            .contains(r#"class="tile" href="https://app.example.com/start""#),
        "{}",
        apps.body
    );
    assert!(!apps.body.contains("Change password"), "{}", apps.body);
    assert_eq!(
        b.get(&w.account("/apps")).await.body.matches("class=\"tile\"").count(),
        1
    );

    let profile = b.get(&w.account("/profile")).await;
    assert!(
        profile.body.contains(r#"aria-current="page">Profile</a>"#),
        "{}",
        profile.body
    );
    assert!(
        profile.body.contains("Ask an administrator to change these."),
        "{}",
        profile.body
    );
    assert!(!profile.body.contains("class=\"tile\""), "{}", profile.body);

    let security = b.get(&w.account("/security")).await;
    assert!(
        security.body.contains(r#"aria-current="page">Security</a>"#),
        "{}",
        security.body
    );
    assert!(security.body.contains("Change password"), "{}", security.body);
    assert!(security.body.contains("Sign out everywhere"), "{}", security.body);

    assert_eq!(b.get(&w.account("/nope")).await.status, 400);
    // Signed out, a tab asks for the sign-in.
    let signed_out = Browser::new().get(&w.account("/security")).await;
    assert!(signed_out.field("csrf").is_some(), "{}", signed_out.body);
    assert!(!signed_out.body.contains("Change password"));
}

#[tokio::test]
async fn a_tile_shows_its_initials_its_library_icon_or_its_uploaded_image() {
    let w = world().await;
    let b = w.signed_in().await;
    let tile = || async { b.get(&w.account("")).await.body };

    // "web-app" is one word: one initial.
    assert!(tile().await.contains(r#"aria-hidden="true">W</span>"#));

    w.set(Some(Logo::Library(LibraryIcon::Cloud)))
        .await
        .into_result()
        .unwrap();
    let body = tile().await;
    assert!(body.contains(r#"<svg class="logo""#), "{body}");

    w.set(Some(png())).await.into_result().unwrap();
    let body = tile().await;
    let src = body
        .split(r#"<img class="logo" src=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no image: {body}"));
    let src = unescape(src);
    assert!(
        src.contains(&format!("/myaccount/apps/{}/logo?v=", w.f.web.app_id)),
        "{src}"
    );

    let served = b.http.get(&src).send().await.unwrap();
    assert_eq!(served.status(), 200);
    let h = served.headers().clone();
    assert_eq!(h["content-type"], "image/png");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h["content-security-policy"].to_str().unwrap().contains("sandbox"));
    assert_eq!(served.bytes().await.unwrap().as_ref(), PNG);

    // My Account's own policy lets the page load it, and nothing else.
    let page = b.get(&w.account("")).await;
    let csp = page.headers["content-security-policy"].to_str().unwrap().to_string();
    assert!(csp.contains("img-src 'self'"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
}

#[tokio::test]
async fn an_uploaded_logo_is_served_only_to_a_user_whose_apps_list_it() {
    let w = world().await;
    w.set(Some(png())).await.into_result().unwrap();
    let path = w.account(&format!("/apps/{}/logo?v=1", w.f.web.app_id));

    assert_eq!(
        Browser::new().http.get(&path).send().await.unwrap().status(),
        404,
        "signed out"
    );

    let bob = user_fixture_in(&w.s, w.f.tenant.clone(), "bob@contoso.com").await;
    let b = Browser::new();
    let login = b.get(&w.account("")).await;
    b.login(&login, &bob.upn, &bob.password).await;
    assert_eq!(b.http.get(&path).send().await.unwrap().status(), 404, "not assigned");

    let alice = w.signed_in().await;
    assert_eq!(alice.http.get(&path).send().await.unwrap().status(), 200);
    // The api app is in the tenant but not on her My apps.
    let other = w.account(&format!("/apps/{}/logo?v=1", w.f.api.app_id));
    assert_eq!(alice.http.get(&other).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn the_console_uploads_a_logo_chooses_an_icon_and_removes_it() {
    let w = world().await;
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::TenantAdministrator).await;
    let a = signed_in_admin(&w.s, &w.f).await;
    let url =
        w.s.url(&format!("/admin/tenants/{}/apps/{}", w.f.tenant.id, w.f.web.app_id));

    let overview = a.get(&url).await;
    assert!(overview.body.contains("<h2>Logo</h2>"), "{}", overview.body);
    assert!(
        overview.body.contains(r#"value="chart""#),
        "the library is offered: {}",
        overview.body
    );

    let uploaded = a
        .post_bytes(
            &url,
            &[("op", "logo"), ("choice", "upload")],
            ("logo", "logo.png", "image/png", PNG),
        )
        .await;
    assert_eq!(uploaded.status, 303, "{}", uploaded.body);
    assert!(matches!(w.shown().await, Some(Shown::Image { .. })));
    let overview = a.get(&url).await;
    assert!(
        overview
            .body
            .contains(r#"<img class="logo" src="data:image/png;base64,"#),
        "{}",
        overview.body
    );
    let csp = overview.headers["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("img-src data:"), "{csp}");

    // An SVG named as a PNG: refused with the reason, and the image stays.
    let refused = a
        .post_bytes(
            &url,
            &[("op", "logo"), ("choice", "upload")],
            ("logo", "logo.png", "image/png", SVG),
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.body.contains(logos::NOT_AN_IMAGE), "{}", refused.body);
    assert!(matches!(w.shown().await, Some(Shown::Image { .. })));

    let chosen = a
        .post(&url, &[("op", "logo"), ("choice", "icon"), ("icon", "shield")])
        .await;
    assert_eq!(chosen.status, 303, "{}", chosen.body);
    assert_eq!(w.shown().await, Some(Shown::Library(LibraryIcon::Shield)));

    let removed = a.post(&url, &[("op", "logo"), ("choice", "remove")]).await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert_eq!(w.shown().await, None);
}
