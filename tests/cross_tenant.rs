//! Signing in to an application of another tenant: the application accepts other
//! tenants, the account is assigned, and the account's own tenant (or its own
//! setting) lets it.

mod common;

use common::*;
use rust_oidc::access::{self, CrossTenantPolicy};
use rust_oidc::apps::{self, Principal};
use rust_oidc::tenant;
use serde_json::Value;

/// Contoso (the application's tenant, with alice and the web app) and Fabrikam
/// (zed's), with zed's password grant allowed on the web app.
struct World {
    s: TestServer,
    f: UserFixture,
    zed: UserFixture,
}

async fn world() -> World {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let fabrikam = s.tenant("Fabrikam", "fabrikam.test").await;
    let zed = user_fixture_in(&s, fabrikam, "zed@fabrikam.test").await;
    World { s, f, zed }
}

impl World {
    async fn sp(&self) -> apps::ServicePrincipal {
        apps::service_principal(&self.s.pool, &self.f.tenant.id, &self.f.web.app_id)
            .await
            .unwrap()
            .unwrap()
    }
    async fn app(&self) -> apps::Application {
        apps::find_in_tenant(&self.s.pool, &self.f.tenant, &self.f.web.app_id)
            .await
            .unwrap()
    }
    async fn accept_others(&self, on: bool) -> anyhow::Result<()> {
        apps::set_accept_other_tenants(&self.s.pool, &self.sp().await, on).await
    }
    async fn fabrikam_allows(&self, on: bool) {
        let mut t = tenant::find_for_admin(&self.s.pool, &self.zed.tenant.id)
            .await
            .unwrap()
            .settings;
        t.allow_cross_tenant_sign_in = on;
        tenant::save_settings(&self.s.pool, &self.zed.tenant.id, &t)
            .await
            .unwrap();
    }
    async fn assign_zed(&self, roles: &[&str]) -> anyhow::Result<String> {
        let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
        apps::assign(
            &self.s.pool,
            &self.f.tenant,
            &self.app().await,
            &Principal::User(self.zed.upn.clone()),
            &roles,
        )
        .await
    }
    /// zed signs in to Contoso's web app in a browser; the page that follows.
    async fn browser_sign_in(&self, b: &Browser) -> Page {
        let (_, challenge) = pkce();
        let login = b
            .authorize(
                &self.s,
                &self.f.tenant.id,
                &[
                    ("client_id", self.f.web.app_id.as_str()),
                    ("response_type", "code"),
                    ("redirect_uri", REDIRECT),
                    ("scope", "openid profile offline_access"),
                    ("code_challenge", challenge.as_str()),
                    ("code_challenge_method", "S256"),
                ],
            )
            .await;
        b.login(&login, &self.zed.upn, &self.zed.password).await
    }
    async fn redeem(&self, page: &Page) -> Value {
        let (verifier, _) = pkce();
        let (status, body) = self
            .s
            .token(
                &self.f.tenant.id,
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", &self.f.web.app_id),
                    ("client_secret", &self.f.web.secret),
                    ("code", &page.redirect_params()["code"]),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", &verifier),
                ],
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }
}

#[tokio::test]
async fn an_application_of_one_tenant_takes_nobody_else() {
    let w = world().await;
    let err = w.assign_zed(&[]).await.unwrap_err();
    assert!(err.downcast_ref::<apps::OtherTenantsNotAccepted>().is_some(), "{err}");
    // Signing in says it is not an account here, without checking the password.
    let page = w.browser_sign_in(&Browser::new()).await;
    assert_eq!(page.status, 401);
    assert!(page.body.contains("is not an account of Contoso"), "{}", page.body);
}

/// The whole of it: accepted, assigned, allowed by Fabrikam; the token is
/// Contoso's, says where zed is from, and carries the roles given here.
#[tokio::test]
async fn an_assigned_account_of_another_tenant_signs_in_when_its_tenant_allows() {
    let w = world().await;
    apps::add_role(
        &w.s.pool,
        &w.app().await,
        "Reader",
        "Reader",
        None,
        &[apps::MemberType::User],
    )
    .await
    .unwrap();
    w.accept_others(true).await.unwrap();
    w.assign_zed(&["Reader"]).await.unwrap();

    // Fabrikam has not allowed it yet: refused, saying who decides.
    let page = w.browser_sign_in(&Browser::new()).await;
    assert!(page.body.contains("AADSTS500213"), "{}", page.body);
    assert!(
        page.body.contains("Fabrikam does not allow its accounts"),
        "{}",
        page.body
    );

    w.fabrikam_allows(true).await;
    let page = w.browser_sign_in(&Browser::new()).await;
    assert_eq!(page.status, 302, "{}", page.body);
    let tokens = w.redeem(&page).await;
    let id = decode_unverified(tokens["id_token"].as_str().unwrap());
    let issuer = |tid: &str| w.s.url(&format!("/{tid}/v2.0"));
    assert_eq!(id["iss"], issuer(&w.f.tenant.id));
    assert_eq!(id["tid"], w.f.tenant.id);
    assert_eq!(id["idp"], issuer(&w.zed.tenant.id), "{id}");
    assert_eq!(id["acct"], 1);
    assert_eq!(id["oid"], w.zed.user_id);
    assert_eq!(id["roles"], serde_json::json!(["Reader"]));
    assert!(id.get("groups").is_none(), "Fabrikam's groups mean nothing here: {id}");

    // Refreshing re-decides: once Fabrikam turns it off, the refresh token stops.
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    w.fabrikam_allows(false).await;
    let (status, body) =
        w.s.token(
            &w.f.tenant.id,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &w.f.web.app_id),
                ("client_secret", &w.f.web.secret),
                ("refresh_token", &refresh),
            ],
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS500213"),
        "{body}"
    );
}

#[tokio::test]
async fn the_users_own_setting_overrides_their_tenants_either_way() {
    let w = world().await;
    w.accept_others(true).await.unwrap();
    w.assign_zed(&[]).await.unwrap();
    let set = |p| {
        let (pool, t, u) = (w.s.pool.clone(), w.zed.tenant.id.clone(), w.zed.user_id.clone());
        async move { access::set_policy(&pool, &t, &u, p).await.unwrap() }
    };

    set(CrossTenantPolicy::Allow).await; // Fabrikam's default is off
    assert_eq!(w.browser_sign_in(&Browser::new()).await.status, 302);
    w.fabrikam_allows(true).await;
    set(CrossTenantPolicy::Disallow).await;
    let page = w.browser_sign_in(&Browser::new()).await;
    assert!(page.body.contains("AADSTS500213"), "{}", page.body);
    set(CrossTenantPolicy::Default).await;
    assert_eq!(w.browser_sign_in(&Browser::new()).await.status, 302);
}

#[tokio::test]
async fn assignment_is_needed_and_an_outside_group_assigns_its_members() {
    let w = world().await;
    w.accept_others(true).await.unwrap();
    w.fabrikam_allows(true).await;
    // Accepted and allowed, but not assigned.
    let page = w.browser_sign_in(&Browser::new()).await;
    assert!(page.body.contains("AADSTS50105"), "{}", page.body);

    // Through a group of Fabrikam, named group@domain.
    let fabrikam = tenant::find_for_admin(&w.s.pool, &w.zed.tenant.id).await.unwrap();
    rust_oidc::groups::create(&w.s.pool, &fabrikam, "Partners", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&w.s.pool, &fabrikam, "Partners", &w.zed.upn)
        .await
        .unwrap();
    apps::assign(
        &w.s.pool,
        &w.f.tenant,
        &w.app().await,
        &Principal::Group("Partners@fabrikam.test".into()),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(w.browser_sign_in(&Browser::new()).await.status, 302);
    let listed = apps::assignments(&w.s.pool, &w.f.tenant.id, &w.app().await)
        .await
        .unwrap();
    let outside = listed[0].outside.as_ref().expect("marked as another tenant's");
    assert_eq!(outside.tenant_name, "Fabrikam");
    assert_eq!(outside.domain, "fabrikam.test");
}

#[tokio::test]
async fn the_application_cannot_stop_accepting_others_while_theirs_are_assigned() {
    let w = world().await;
    w.accept_others(true).await.unwrap();
    let id = w.assign_zed(&[]).await.unwrap();
    let err = w.accept_others(false).await.unwrap_err();
    assert!(err.downcast_ref::<apps::OutsideAssignmentsRemain>().is_some(), "{err}");
    assert!(w.sp().await.accept_other_tenants, "unchanged");
    assert!(
        apps::unassign(&w.s.pool, &w.f.tenant.id, &w.app().await, &id)
            .await
            .unwrap()
    );
    w.accept_others(false).await.unwrap();
    assert!(!w.sp().await.accept_other_tenants);
}

/// The password grant and MFA follow the account's own tenant.
#[tokio::test]
async fn the_password_grant_and_mfa_follow_the_accounts_own_tenant() {
    let w = world().await;
    w.accept_others(true).await.unwrap();
    w.fabrikam_allows(true).await;
    w.assign_zed(&[]).await.unwrap();
    apps::set_password_grant_allowed(&w.s.pool, &w.app().await, true)
        .await
        .unwrap();
    let ropc = || async {
        w.s.token(
            &w.f.tenant.id,
            &[
                ("grant_type", "password"),
                ("client_id", &w.f.web.app_id),
                ("client_secret", &w.f.web.secret),
                ("username", &w.zed.upn),
                ("password", &w.zed.password),
                ("scope", "openid"),
            ],
        )
        .await
    };
    let (status, body) = ropc().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        decode_unverified(body["id_token"].as_str().unwrap())["tid"],
        w.f.tenant.id
    );

    // Fabrikam requires MFA of everyone: its rule, not Contoso's.
    let mut t = tenant::find_for_admin(&w.s.pool, &w.zed.tenant.id)
        .await
        .unwrap()
        .settings;
    t.require_mfa = true;
    tenant::save_settings(&w.s.pool, &w.zed.tenant.id, &t).await.unwrap();
    let (status, body) = ropc().await;
    assert_eq!(status, 400);
    assert!(
        body["error_description"].as_str().unwrap().contains("AADSTS50079"),
        "{body}"
    );
    let page = w.browser_sign_in(&Browser::new()).await;
    assert!(page.body.contains("Set up your authenticator"), "{}", page.body);
    // The authenticator is zed's, so it is listed under zed's tenant, not the
    // application's.
    assert!(
        page.body.contains("<strong>Fabrikam: zed@fabrikam.test</strong>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Contoso: zed"), "{}", page.body);
}

/// Check sign-in: every check, the real assignments, and nothing about an
/// account of another tenant that is not assigned here.
#[tokio::test]
async fn check_sign_in_says_why_and_keeps_other_tenants_to_themselves() {
    let w = world().await;
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::ApplicationAdministrator).await;
    let b = signed_in_admin(&w.s, &w.f).await;
    let check = |upn: &str| {
        w.s.url(&format!(
            "/admin/tenants/{}/apps/{}/check?upn={upn}",
            w.f.tenant.id, w.f.web.app_id
        ))
    };

    // A local account: it can, with password alone.
    let page = b.get(&check(&w.f.upn)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("alice@contoso.com can sign in to"), "{}", page.body);
    assert!(page.body.contains("Works with their password"), "{}", page.body);

    // Another tenant's account, not assigned: that and nothing else.
    w.accept_others(true).await.unwrap();
    for upn in [w.zed.upn.as_str(), "nobody@fabrikam.test"] {
        let page = b.get(&check(upn)).await;
        assert!(page.body.contains("is not assigned to"), "{upn}: {}", page.body);
        assert!(
            !page.body.contains("Locked") && !page.body.contains("Enabled"),
            "{upn}: {}",
            page.body
        );
    }

    // Assigned: the whole breakdown, including what Fabrikam decides.
    w.assign_zed(&[]).await.unwrap();
    let page = b.get(&check(&w.zed.upn)).await;
    assert!(page.body.contains("zed@fabrikam.test cannot sign in"), "{}", page.body);
    assert!(page.body.contains("Assigned directly"), "{}", page.body);
    assert!(
        page.body.contains("Fabrikam does not let it sign in to other tenants"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Password grant"), "{}", page.body);

    w.fabrikam_allows(true).await;
    let page = b.get(&check(&w.zed.upn)).await;
    assert!(page.body.contains("zed@fabrikam.test can sign in"), "{}", page.body);
    // The same decision the sign-in makes.
    assert_eq!(w.browser_sign_in(&Browser::new()).await.status, 302);
}

/// The console: the switch, assignment by user: and group: addresses, and the
/// rows saying whose they are.
#[tokio::test]
async fn the_console_assigns_other_tenants_accounts_and_groups() {
    let w = world().await;
    let fabrikam = tenant::find_for_admin(&w.s.pool, &w.zed.tenant.id).await.unwrap();
    rust_oidc::groups::create(&w.s.pool, &fabrikam, "Partners", None)
        .await
        .unwrap();
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::TenantAdministrator).await;
    let b = signed_in_admin(&w.s, &w.f).await;
    let url =
        w.s.url(&format!("/admin/tenants/{}/apps/{}", w.f.tenant.id, w.f.web.app_id));

    let refused = b
        .post(
            &url,
            &[
                ("op", "assign"),
                ("principal_type", "User"),
                ("principal", "user:zed@fabrikam.test"),
            ],
        )
        .await;
    assert_eq!(refused.status, 400);
    assert!(
        refused.body.contains("accepts only accounts of its own tenant"),
        "{}",
        refused.body
    );

    let on = b.post(&url, &[("op", "flags"), ("accept_other_tenants", "on")]).await;
    assert_eq!(on.status, 303, "{}", on.body);
    for name in ["user:zed@fabrikam.test", "group:Partners@fabrikam.test"] {
        let done = b
            .post(
                &url,
                &[("op", "assign"), ("principal_type", "User"), ("principal", name)],
            )
            .await;
        assert_eq!(done.status, 303, "{name}: {}", done.body);
    }
    let page = b.get(&format!("{url}/users")).await;
    assert!(page.body.contains("membership managed by Fabrikam"), "{}", page.body);
    assert!(
        page.body.contains("Fabrikam does not allow it to sign in here"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Partners@fabrikam.test"), "{}", page.body);

    // Turning it off is refused while they are assigned, and nothing else saved.
    let off = b.post(&url, &[("op", "flags")]).await;
    assert_eq!(off.status, 400);
    assert!(off.body.contains("of other tenants are assigned"), "{}", off.body);
    assert!(w.sp().await.accept_other_tenants);
}
