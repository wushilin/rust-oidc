//! The console's applications section, through HTTP.
//!
//! Two things here are security properties rather than features, and are written
//! as attacks:
//!
//! - **A client secret exists in exactly one response.** Only its SHA-256 hash is
//!   stored, so the page that creates it is the only place the value can ever
//!   appear. These tests hold that line against the page *and* against
//!   `audit_log`.
//! - **A tenant administrator cannot reach another tenant's applications**, by
//!   GUID or by domain alias, for reading or for writing.
//!
//! A third is about actions rather than tenants: `App:Rotate` is separate from
//! `App:Write` precisely so a role can administer a registration without being
//! able to mint a credential for it, and `CloudApplicationAdministrator` is the
//! built-in role that holds the one and not the other.

mod common;

use common::*;
use rust_oidc::apps::{self, MemberType, RedirectPlatform, ScopeConsent, SecretCheck};
use rust_oidc::rbac::{RoleId, Scope};

/// A self-signed RSA certificate and the matching private key PEM, for the
/// certificate-credential tests.
struct TestCert {
    cert_pem: String,
    key_pem: String,
    key_id: String,
}

fn make_cert() -> TestCert {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "console test");
    params.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_id = apps::parse_certificate(&cert_pem).unwrap().key_id;
    TestCert {
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        key_id,
    }
}

/// The value a page shows exactly once, from the one element that carries it.
fn shown_once(page: &Page) -> Option<String> {
    let marker = r#"<code class="once">"#;
    let start = page.body.find(marker)? + marker.len();
    let end = page.body[start..].find("</code>")? + start;
    Some(unescape(&page.body[start..end]))
}

/// Every `details` object written to the audit trail, as stored.
async fn all_audit_details(s: &TestServer) -> Vec<String> {
    let rows: Vec<(Option<String>,)> =
        sqlx::query_as(rust_oidc::db::q(&s.pool, "SELECT details FROM audit_log ORDER BY id"))
            .fetch_all(&s.pool)
            .await
            .unwrap();
    rows.into_iter().flat_map(|(d,)| d).collect()
}

/// The appId of the application a create redirected to.
fn created_app_id(page: &Page) -> String {
    page.location
        .as_deref()
        .expect("a redirect to the new application")
        .rsplit('/')
        .next()
        .expect("a last path segment")
        .to_string()
}

#[tokio::test]
async fn an_application_is_registered_and_configured_through_the_console() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let apps_url = s.url(&format!("/admin/tenants/{}/apps", f.tenant.id));

    let created = b.post(&apps_url, &[("name", "Invoices API")]).await;
    assert_eq!(created.status, 303, "{}", created.body);
    let app_id = created_app_id(&created);
    let app = apps::find(&s.pool, &app_id).await.unwrap().expect("registered");
    assert_eq!(app.display_name, "Invoices API");
    assert_eq!(app.tenant_id, f.tenant.id);
    // Registering brings the service principal and the default identifier URI
    // with it, the same way `app create` does.
    assert!(
        apps::service_principal(&s.pool, &f.tenant.id, &app_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        apps::identifier_uris(&s.pool, &app).await.unwrap(),
        vec![format!("api://{app_id}")]
    );

    let url = format!("{apps_url}/{app_id}");
    // Redirect URIs, per platform.
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "redirect_uri_add"),
                ("platform", "web"),
                ("uri", "https://invoices.example.com/callback"),
            ]
        )
        .await
        .status,
        303
    );
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "redirect_uri_add"),
                ("platform", "spa"),
                ("uri", "https://invoices.example.com/"),
            ]
        )
        .await
        .status,
        303
    );
    assert_eq!(
        apps::redirect_uris(&s.pool, &app).await.unwrap(),
        vec![
            (RedirectPlatform::Spa, "https://invoices.example.com/".to_string()),
            (
                RedirectPlatform::Web,
                "https://invoices.example.com/callback".to_string()
            ),
        ]
    );
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "redirect_uri_remove"),
                ("platform", "spa"),
                ("uri", "https://invoices.example.com/"),
            ]
        )
        .await
        .status,
        303
    );
    assert_eq!(apps::redirect_uris(&s.pool, &app).await.unwrap().len(), 1);

    // An Application ID URI, and the refusal that keeps the last one.
    assert_eq!(
        b.post(
            &url,
            &[("op", "identifier_uri_add"), ("uri", "api://invoices.example.com")]
        )
        .await
        .status,
        303
    );
    assert_eq!(apps::identifier_uris(&s.pool, &app).await.unwrap().len(), 2);

    // An exposed scope, with the consent type stored as asked.
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "scope_add"),
                ("value", "Invoices.Read"),
                ("display_name", "Read invoices"),
                ("consent", "Admin"),
            ]
        )
        .await
        .status,
        303
    );
    let scopes = apps::scopes(&s.pool, &app).await.unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].value, "Invoices.Read");
    assert_eq!(scopes[0].consent, Some(ScopeConsent::Admin));
    assert!(scopes[0].enabled);

    // An app role, and the member types the checkboxes chose.
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "role_add"),
                ("value", "Invoices.Approver"),
                ("display_name", "Approver"),
                ("member_User", "on"),
            ]
        )
        .await
        .status,
        303
    );
    let roles = apps::roles(&s.pool, &app).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert!(roles[0].allows(MemberType::User));
    assert!(
        !roles[0].allows(MemberType::Application),
        "only the ticked member type was stored"
    );

    // The grant flags, saved together: a box left unticked stays off.
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "flags"),
                ("allow_password_grant", "on"),
                ("allow_id_token_implicit", "on"),
            ]
        )
        .await
        .status,
        303
    );
    let app = apps::find(&s.pool, &app_id).await.unwrap().unwrap();
    assert!(app.allow_password_grant);
    assert!(app.allow_id_token_implicit);
    assert!(!app.allow_access_token_implicit);

    // Assigning the role to a user, then withdrawing it.
    assert_eq!(
        b.post(
            &url,
            &[
                ("op", "role_assign"),
                ("role", "Invoices.Approver"),
                ("principal_type", "User"),
                ("principal", &f.upn),
            ]
        )
        .await
        .status,
        303
    );
    let assigned = apps::role_assignments(&s.pool, &f.tenant.id, &app).await.unwrap();
    assert_eq!(assigned.len(), 1);
    assert_eq!(assigned[0].role_value, "Invoices.Approver");
    assert_eq!(assigned[0].principal_name, f.upn);
    assert_eq!(
        b.post(&url, &[("op", "role_unassign"), ("assignment", &assigned[0].id)])
            .await
            .status,
        303
    );
    assert!(
        apps::role_assignments(&s.pool, &f.tenant.id, &app)
            .await
            .unwrap()
            .is_empty()
    );

    // Every one of those is attributable to the administrator personally.
    for action in [
        "admin.app.create",
        "admin.app.redirect_uri.add",
        "admin.app.redirect_uri.remove",
        "admin.app.identifier_uri.add",
        "admin.app.scope.add",
        "admin.app.role.add",
        "admin.app.flags",
        "admin.app.role.assign",
        "admin.app.role.unassign",
    ] {
        let rows = audit_rows(&s, action).await;
        assert!(!rows.is_empty(), "{action} was not recorded at all");
        for row in &rows {
            assert_eq!(row.0, f.user_id, "{action} named the wrong actor");
            assert_eq!(row.2.as_deref(), Some(f.tenant.id.as_str()), "{action}");
        }
    }

    // The page shows what was configured.
    let page = b.get(&url).await;
    assert_eq!(page.status, 200);
    for expected in [
        "Invoices API",
        "https://invoices.example.com/callback",
        "api://invoices.example.com",
        "Invoices.Read",
        "Invoices.Approver",
    ] {
        assert!(page.body.contains(expected), "{expected} is missing: {}", page.body);
    }
}

#[tokio::test]
async fn the_last_application_id_uri_cannot_be_removed() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let only = apps::identifier_uris(&s.pool, &app).await.unwrap();
    assert_eq!(only.len(), 1);

    let page = b
        .post(&url, &[("op", "identifier_uri_remove"), ("uri", &only[0])])
        .await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(page.body.contains("at least one"), "{}", page.body);
    assert_eq!(
        apps::identifier_uris(&s.pool, &app).await.unwrap(),
        only,
        "the URI is still registered"
    );
}

/// The secret value exists in one response and nowhere else: not in a later page,
/// not in a form field that could repost it, and not in the audit trail.
#[tokio::test]
async fn a_new_client_secret_is_shown_exactly_once_and_recorded_nowhere() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();

    // The one post in the console that answers with a page rather than a
    // redirect, because the value lives in that response.
    let page = b
        .post(&url, &[("op", "secret_add"), ("name", "deploy"), ("days", "30")])
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    let secret = shown_once(&page).expect("the new secret is shown once");
    assert!(secret.len() > 30, "that is not a client secret: {secret:?}");
    // It is a working credential, so what was shown is the real value.
    assert_eq!(
        apps::verify_secret(&s.pool, &app, &secret).await.unwrap(),
        SecretCheck::Valid
    );
    // And it is not sitting in a form field that a resubmission could replay.
    assert!(
        !page.body.contains(&format!(r#"value="{secret}""#)),
        "the secret is in a form field"
    );

    // Asked for again, the page has the hint and not the value.
    let again = b.get(&url).await;
    assert_eq!(again.status, 200);
    assert!(!again.body.contains(&secret), "the secret came back: {}", again.body);
    assert!(
        again.body.contains(&secret[..3]),
        "the three-character hint is shown: {}",
        again.body
    );
    assert!(again.body.contains("deploy"), "the description is shown");

    // Nothing in the audit trail carries it, nor a prefix long enough to matter.
    let recorded = audit_rows(&s, "admin.app.secret.add").await;
    assert_eq!(recorded.len(), 1);
    let stored = apps::secrets(&s.pool, &app).await.unwrap();
    let key_id = stored
        .iter()
        .find(|x| x.display_name.as_deref() == Some("deploy"))
        .map(|x| x.key_id.clone())
        .expect("the secret was stored");
    for details in all_audit_details(&s).await {
        assert!(!details.contains(&secret), "the secret is in an audit row: {details}");
        assert!(
            !details.contains(&secret[..6]),
            "a prefix of the secret is in an audit row: {details}"
        );
    }
    // What the row does carry is the key id, which is what makes it useful.
    let rows: Vec<(Option<String>,)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT details FROM audit_log WHERE action = ?",
    ))
    .bind("admin.app.secret.add")
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert!(rows[0].0.as_deref().unwrap_or_default().contains(&key_id));

    // Deleting it stops it working.
    let removed = b.post(&url, &[("op", "secret_remove"), ("key_id", &key_id)]).await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert_eq!(
        apps::verify_secret(&s.pool, &app, &secret).await.unwrap(),
        SecretCheck::Invalid
    );
}

#[tokio::test]
async fn a_certificate_is_registered_by_thumbprint_and_a_private_key_is_refused() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    let cert = make_cert();

    let page = b
        .post(
            &url,
            &[
                ("op", "certificate_add"),
                ("name", "assertion signing"),
                ("certificate", &cert.cert_pem),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let credentials = apps::key_credentials(&s.pool, &app).await.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].key_id, cert.key_id);
    // The audit row names the thumbprint, which is public: it is the `x5t` a
    // client puts in its own assertion header.
    let rows = audit_rows(&s, "admin.app.key.add").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, f.user_id);

    // A pasted key pair is refused, and the PEM is not echoed back into the page.
    let both = format!("{}{}", cert.cert_pem, cert.key_pem);
    let refused = b.post(&url, &[("op", "certificate_add"), ("certificate", &both)]).await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.body.contains("private key"), "{}", refused.body);
    assert!(
        !refused.body.contains("PRIVATE KEY"),
        "the submitted PEM was rendered back into the page"
    );
    for details in all_audit_details(&s).await {
        assert!(!details.contains("PRIVATE KEY"), "a key reached the audit trail");
    }

    let removed = b
        .post(&url, &[("op", "certificate_remove"), ("key_id", &cert.key_id)])
        .await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert!(apps::key_credentials(&s.pool, &app).await.unwrap().is_empty());
}

/// `App:Rotate` is a separate action so that a role can administer a registration
/// without being able to mint a credential for it. Cloud Application
/// Administrator is the built-in role that holds the one and not the other.
#[tokio::test]
async fn a_role_without_app_rotate_can_configure_an_app_but_not_credential_it() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind(
        &s,
        &f.user_id,
        RoleId::CloudApplicationAdministrator,
        Scope::Tenants(vec![f.tenant.id.clone()]),
    )
    .await;
    let b = signed_in_admin(&s, &f).await;
    let url = s.url(&format!("/admin/tenants/{}/apps/{}", f.tenant.id, f.web.app_id));
    let app = apps::find(&s.pool, &f.web.app_id).await.unwrap().unwrap();
    let before = apps::secrets(&s.pool, &app).await.unwrap().len();

    // The registration: permitted.
    let wrote = b
        .post(
            &url,
            &[
                ("op", "redirect_uri_add"),
                ("platform", "web"),
                ("uri", "https://configured.example.com/cb"),
            ],
        )
        .await;
    assert_eq!(wrote.status, 303, "{}", wrote.body);

    // The credentials: refused, both kinds.
    let cert = make_cert();
    for form in [
        vec![("op", "secret_add"), ("days", "30")],
        vec![("op", "secret_remove"), ("key_id", "whatever")],
        vec![("op", "certificate_add"), ("certificate", cert.cert_pem.as_str())],
    ] {
        let page = b.post(&url, &form).await;
        assert_eq!(page.status, 403, "{form:?} was allowed: {}", page.body);
    }
    assert_eq!(
        apps::secrets(&s.pool, &app).await.unwrap().len(),
        before,
        "no secret was added or removed"
    );
    assert!(apps::key_credentials(&s.pool, &app).await.unwrap().is_empty());

    // And the page offers neither button, so the console never shows what the
    // guard would refuse.
    let page = b.get(&url).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("Add a client secret"), "{}", page.body);
    assert!(!page.body.contains("Upload a certificate"), "{}", page.body);
    // What it may do is still offered.
    assert!(page.body.contains("Add a redirect URI"), "{}", page.body);
}

/// The isolation test for this section: every route, aimed at a tenant the
/// administrator is not bound to, by GUID and by domain alias.
#[tokio::test]
async fn a_tenant_admin_cannot_reach_another_tenants_applications() {
    let s = TestServer::start().await;
    let f = tenant_admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let victim = s.app(&other, "fabrikam-api").await;
    let b = signed_in_admin(&s, &f).await;

    let list = format!("/admin/tenants/{}/apps", other.id);
    let detail = format!("{list}/{}", victim.app_id);
    let aliased = format!("/admin/tenants/fabrikam.test/apps/{}", victim.app_id);
    for path in [list.clone(), detail.clone(), aliased.clone()] {
        let page = b.get(&s.url(&path)).await;
        assert!(
            page.status == 403 || page.status == 404,
            "GET {path} leaked with {}: {}",
            page.status,
            page.body
        );
        assert!(
            !page.body.contains("fabrikam-api") && !page.body.contains(&victim.app_id),
            "GET {path} leaked the application: {}",
            page.body
        );
    }

    let cert = make_cert();
    let posts: Vec<(String, Vec<(&str, &str)>)> = vec![
        (list.clone(), vec![("name", "mole")]),
        (detail.clone(), vec![("op", "secret_add"), ("days", "30")]),
        (
            detail.clone(),
            vec![("op", "certificate_add"), ("certificate", cert.cert_pem.as_str())],
        ),
        (detail.clone(), vec![("op", "flags"), ("allow_password_grant", "on")]),
        (
            detail.clone(),
            vec![
                ("op", "redirect_uri_add"),
                ("platform", "web"),
                ("uri", "https://attacker.example.com/cb"),
            ],
        ),
        (
            detail.clone(),
            vec![("op", "scope_add"), ("value", "Everything.Read"), ("consent", "User")],
        ),
        (
            detail.clone(),
            vec![("op", "role_add"), ("value", "Owner"), ("member_User", "on")],
        ),
        (
            aliased.clone(),
            vec![
                ("op", "redirect_uri_add"),
                ("platform", "web"),
                ("uri", "https://attacker.example.com/aliased"),
            ],
        ),
    ];
    for (path, form) in posts {
        let page = b.post(&s.url(&path), &form).await;
        assert!(
            page.status == 403 || page.status == 404,
            "POST {path} {form:?} leaked with {}: {}",
            page.status,
            page.body
        );
    }

    // The other tenant is exactly as it was.
    let registered = apps::list(&s.pool, &other.id).await.unwrap();
    assert_eq!(registered.len(), 1, "nothing was registered in the other tenant");
    let app = apps::find(&s.pool, &victim.app_id).await.unwrap().unwrap();
    assert!(!app.allow_password_grant, "the grant flags were not changed");
    assert!(
        apps::redirect_uris(&s.pool, &app).await.unwrap().is_empty(),
        "no redirect URI was added"
    );
    assert!(apps::scopes(&s.pool, &app).await.unwrap().is_empty());
    assert!(apps::roles(&s.pool, &app).await.unwrap().is_empty());
    assert!(apps::key_credentials(&s.pool, &app).await.unwrap().is_empty());
    assert_eq!(
        apps::secrets(&s.pool, &app).await.unwrap().len(),
        1,
        "only the fixture's own secret exists"
    );
    // Their own tenant's applications are still reachable, so the check is on
    // identity and not on the shape of the URL.
    let own = b.get(&s.url(&format!("/admin/tenants/{}/apps", f.tenant.id))).await;
    assert_eq!(own.status, 200, "{}", own.body);
    assert!(own.body.contains("web-app"), "{}", own.body);
}
