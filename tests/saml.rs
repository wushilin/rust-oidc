//! SAML single sign-on, end to end over HTTP, and each configuration change
//! through the transaction engine.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use rust_oidc::apps::{self, MemberType, Principal};
use rust_oidc::db::Event;
use rust_oidc::saml::{self, BasicConfig, NewCertificate, ReplyUrl};
use rust_oidc::saml_protocol::{self as protocol, NS_ASSERTION, NS_PROTOCOL, Node, Signer, SigningAlgorithm};
use rust_oidc::txn::ops::apps::SetAssignmentRequired;
use rust_oidc::txn::ops::saml::{
    ActivateSamlCertificate, AddSamlCertificate, AddSamlVerificationCertificate, DisableSamlSso, EnableSamlSso,
    RemoveSamlCertificate, SaveSamlBasic, SaveSamlSigning, SetAppSignOnUrl, SetAppVisibility, SetSamlRequireSigned,
};
use rust_oidc::txn::{self, Actor, Outcome};

const ENTITY: &str = "https://sp.example/metadata";
const ACS: &str = "https://sp.example/acs";
const SECOND_ACS: &str = "https://sp.example/acs2";
const LOGOUT: &str = "https://sp.example/slo";

struct World {
    s: TestServer,
    f: UserFixture,
    app_id: String,
}

fn basic(entity: &str) -> BasicConfig {
    BasicConfig {
        identifiers: vec![entity.to_string()],
        reply_urls: ReplyUrl::listed([ACS.to_string(), SECOND_ACS.to_string()]),
        sign_on_url: None,
        relay_state: None,
        logout_url: Some(LOGOUT.to_string()),
    }
}

async fn saml_app(s: &TestServer, f: &UserFixture, name: &str, entity: &str) -> String {
    let app = s.app(&f.tenant, name).await;
    let certificate = NewCertificate::generate(saml::CERT_VALIDITY_DAYS).unwrap();
    let enable = EnableSamlSso {
        tenant_id: f.tenant.id.clone(),
        app_id: app.app_id.clone(),
        certificate,
    };
    txn::run(&s.pool, &Actor::Cli, &enable).await.into_result().unwrap();
    let save = SaveSamlBasic {
        tenant_id: f.tenant.id.clone(),
        app_id: app.app_id.clone(),
        basic: basic(entity),
    };
    txn::run(&s.pool, &Actor::Cli, &save).await.into_result().unwrap();
    app.app_id
}

async fn world() -> World {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let app_id = saml_app(&s, &f, "legacy-app", ENTITY).await;
    World { s, f, app_id }
}

fn authn_request(attrs: &str, body: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_req1" Version="2.0" IssueInstant="2026-11-23T00:00:00Z" {attrs}><saml:Issuer>{ENTITY}</saml:Issuer>{body}</samlp:AuthnRequest>"#
    )
}

fn redirect_url(s: &TestServer, tenant: &str, xml: &str, relay: Option<&str>) -> String {
    let mut url = url::Url::parse(&s.url(&format!("/{tenant}/saml2"))).unwrap();
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &protocol::encode_redirect(xml).unwrap());
    if let Some(relay) = relay {
        url.query_pairs_mut().append_pair("RelayState", relay);
    }
    url.to_string()
}

/// The decoded `<samlp:Response>` a page posts to the application.
fn response_of(page: &Page) -> Node {
    let encoded = page
        .field("SAMLResponse")
        .unwrap_or_else(|| panic!("no SAML response on: {}", page.body));
    let xml = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    protocol::parse_xml(&xml).unwrap()
}

/// The raw XML of the `<samlp:Response>` a page posts to the application.
fn response_xml(page: &Page) -> String {
    let encoded = page.field("SAMLResponse").unwrap();
    String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap()
}

/// The certificate the application's responses are signed with.
async fn idp_signing_cert(w: &World) -> Vec<u8> {
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    saml::active_key(&w.s.pool, &app).await.unwrap().unwrap().cert_der
}

fn status_codes(response: &Node) -> Vec<String> {
    let mut out = Vec::new();
    let mut code = response
        .child(NS_PROTOCOL, "Status")
        .and_then(|s| s.child(NS_PROTOCOL, "StatusCode"));
    while let Some(c) = code {
        out.push(c.attr("Value").unwrap().to_string());
        code = c.child(NS_PROTOCOL, "StatusCode");
    }
    out
}

fn attribute(assertion: &Node, name: &str) -> Vec<String> {
    assertion
        .child(NS_ASSERTION, "AttributeStatement")
        .map(|st| {
            st.children
                .iter()
                .filter(|a| a.attr("Name") == Some(name))
                .flat_map(|a| a.children.iter().map(|v| v.text.clone()))
                .collect()
        })
        .unwrap_or_default()
}

async fn signed_in(w: &World) -> (Browser, Page) {
    let b = Browser::new();
    let xml = authn_request(&format!(r#"AssertionConsumerServiceURL="{ACS}""#), "");
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &xml, Some("next-page")))
        .await;
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    (b, page)
}

#[tokio::test]
async fn sp_initiated_sign_in_posts_a_signed_assertion_to_the_reply_url() {
    let w = world().await;
    let (_, page) = signed_in(&w).await;
    assert_eq!(page.form_action(), ACS);
    assert_eq!(page.field("RelayState").as_deref(), Some("next-page"));
    let response = response_of(&page);
    assert_eq!(response.attr("InResponseTo"), Some("_req1"));
    assert_eq!(response.attr("Destination"), Some(ACS));
    assert_eq!(status_codes(&response), vec![protocol::STATUS_SUCCESS]);
    let assertion = response.child(NS_ASSERTION, "Assertion").unwrap();
    assert!(
        assertion
            .child("http://www.w3.org/2000/09/xmldsig#", "Signature")
            .is_some()
    );
    let subject = assertion.child(NS_ASSERTION, "Subject").unwrap();
    assert_eq!(subject.child(NS_ASSERTION, "NameID").unwrap().text, w.f.upn);
    let audience = assertion
        .child(NS_ASSERTION, "Conditions")
        .and_then(|c| c.child(NS_ASSERTION, "AudienceRestriction"))
        .and_then(|a| a.child(NS_ASSERTION, "Audience"))
        .unwrap();
    assert_eq!(audience.text, ENTITY);
    assert_eq!(
        attribute(
            assertion,
            "http://schemas.microsoft.com/identity/claims/objectidentifier"
        ),
        vec![w.f.user_id.clone()]
    );
}

#[tokio::test]
async fn an_unregistered_reply_url_gets_no_assertion() {
    let w = world().await;
    let b = Browser::new();
    let xml = authn_request(r#"AssertionConsumerServiceURL="https://evil.example/acs""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    assert!(page.field("SAMLResponse").is_none());
    assert!(page.body.contains("AADSTS50011"), "{}", page.body);
    assert!(!page.body.contains("evil.example"));
}

#[tokio::test]
async fn a_tampered_login_form_cannot_change_the_reply_url() {
    let w = world().await;
    let b = Browser::new();
    let xml = authn_request("", "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    let evil = authn_request(r#"AssertionConsumerServiceURL="https://evil.example/acs""#, "");
    let request = format!(
        "SAMLRequest={}",
        url::form_urlencoded::byte_serialize(protocol::encode_redirect(&evil).unwrap().as_bytes()).collect::<String>()
    );
    let form = [
        ("csrf", page.field("csrf").unwrap()),
        ("request", request),
        ("op", "login".to_string()),
        ("upn", w.f.upn.clone()),
        ("password", w.f.password.clone()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let answer = b.post_form(&page.form_action(), &form).await;
    assert!(answer.field("SAMLResponse").is_none(), "{}", answer.body);
}

#[tokio::test]
async fn the_acs_index_selects_a_registered_reply_url() {
    let w = world().await;
    let b = Browser::new();
    let xml = authn_request(r#"AssertionConsumerServiceIndex="1""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    assert_eq!(page.form_action(), SECOND_ACS);
}

#[tokio::test]
async fn is_passive_without_a_session_answers_no_passive() {
    let w = world().await;
    let b = Browser::new();
    let xml = authn_request(r#"IsPassive="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    let response = response_of(&page);
    assert_eq!(
        status_codes(&response),
        vec![protocol::STATUS_RESPONDER, protocol::STATUS_NO_PASSIVE]
    );
    assert!(response.child(NS_ASSERTION, "Assertion").is_none());
}

#[tokio::test]
async fn force_authn_asks_for_the_password_again() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let again = authn_request("", "");
    assert!(
        b.get(&redirect_url(&w.s, &w.f.tenant.id, &again, None))
            .await
            .field("SAMLResponse")
            .is_some()
    );
    let forced = authn_request(r#"ForceAuthn="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &forced, None)).await;
    assert!(page.field("SAMLResponse").is_none());
    assert!(page.field("csrf").is_some());
}

#[tokio::test]
async fn assignment_required_keeps_an_unassigned_user_out() {
    let w = world().await;
    let set = SetAssignmentRequired {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        required: true,
    };
    txn::run(&w.s.pool, &Actor::Cli, &set).await.into_result().unwrap();
    let (_, page) = signed_in(&w).await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
    assert!(page.body.contains("AADSTS50105"), "{}", page.body);
}

/// The check on an existing session, which never passes through the password
/// step's own check.
#[tokio::test]
async fn a_session_that_predates_assignment_required_is_refused_too() {
    let w = world().await;
    let (b, first) = signed_in(&w).await;
    assert!(first.field("SAMLResponse").is_some());
    let set = SetAssignmentRequired {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        required: true,
    };
    txn::run(&w.s.pool, &Actor::Cli, &set).await.into_result().unwrap();
    let again = authn_request("", "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &again, None)).await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
    assert!(page.body.contains("AADSTS50105"), "{}", page.body);
}

#[tokio::test]
async fn assigned_roles_and_groups_reach_the_assertion() {
    let w = world().await;
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    apps::add_role(&w.s.pool, &app, "Legacy.Admin", "Admin", None, &[MemberType::User])
        .await
        .unwrap();
    apps::assign(
        &w.s.pool,
        &w.f.tenant,
        &app,
        &Principal::User(w.f.upn.clone()),
        &["Legacy.Admin".to_string()],
    )
    .await
    .unwrap();
    let group = rust_oidc::groups::create(&w.s.pool, &w.f.tenant, "legacy-users", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&w.s.pool, &w.f.tenant, "legacy-users", &w.f.upn)
        .await
        .unwrap();
    apps::set_group_membership_claims(&w.s.pool, &app, apps::GroupMembershipClaims::All)
        .await
        .unwrap();
    let (_, page) = signed_in(&w).await;
    let response = response_of(&page);
    let assertion = response.child(NS_ASSERTION, "Assertion").unwrap();
    assert_eq!(
        attribute(
            assertion,
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
        ),
        vec!["Legacy.Admin"]
    );
    assert_eq!(
        attribute(
            assertion,
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
        ),
        vec![group]
    );
}

/// A key pair for the application's side of signed requests.
fn sp_key() -> (String, Vec<u8>, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let cert = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (key.serialize_pem(), cert.der().to_vec(), cert.pem())
}

async fn require_signed(w: &World, cert_pem: &str) {
    let add = AddSamlVerificationCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_pem: cert_pem.to_string(),
    };
    txn::run(&w.s.pool, &Actor::Cli, &add).await.into_result().unwrap();
    let set = SetSamlRequireSigned {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        required: true,
    };
    txn::run(&w.s.pool, &Actor::Cli, &set).await.into_result().unwrap();
}

/// A request as a signing application sends it: addressed here, issued now.
fn signed_request_xml(w: &World, id: &str) -> String {
    let destination = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let issued = protocol::instant(rust_oidc::util::now()).unwrap();
    authn_request(&format!(r#"Destination="{destination}""#), "")
        .replace("_req1", id)
        .replace("2026-11-23T00:00:00Z", &issued)
}

fn sp_signer<'a>(pem: &'a str, der: &'a [u8]) -> Signer<'a> {
    Signer {
        private_key_pem: pem,
        cert_der: der,
        algorithm: SigningAlgorithm::Sha256,
    }
}

fn encoded_param(xml: &str) -> String {
    url::form_urlencoded::byte_serialize(protocol::encode_redirect(xml).unwrap().as_bytes()).collect()
}

#[tokio::test]
async fn a_percent_encoded_or_repeated_parameter_cannot_smuggle_an_unsigned_message() {
    let w = world().await;
    let (pem, der, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let signed = signed_request_xml(&w, "_req1");
    let query = sp_signer(&pem, &der)
        .sign_redirect("SAMLRequest", &protocol::encode_redirect(&signed).unwrap(), None)
        .unwrap();
    let forged = encoded_param(&signed_request_xml(&w, "_attacker"));
    let b = Browser::new();
    for attack in [
        format!("SAML%52equest={forged}&{query}"),
        format!("SAMLRequest={forged}&{query}"),
        format!("{query}&SAMLRequest={forged}"),
        format!("{query}&Relay%53tate=evil"),
        format!("SAMLResponse={forged}&{query}"),
    ] {
        let page = b.get(&format!("{endpoint}?{attack}")).await;
        assert!(page.field("csrf").is_none(), "{attack}: {}", page.body);
        assert!(page.field("SAMLResponse").is_none(), "{attack}");
    }
}

#[tokio::test]
async fn a_signed_request_must_be_addressed_here_and_recent() {
    let w = world().await;
    let (pem, der, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let current = signed_request_xml(&w, "_req1");
    let destination = format!(r#"Destination="{endpoint}""#);
    let no_destination = current.replace(&destination, "");
    let elsewhere = current.replace(&destination, r#"Destination="https://other.example/saml2""#);
    let old = authn_request(&destination, "");
    let b = Browser::new();
    for xml in [no_destination, elsewhere, old] {
        let query = sp_signer(&pem, &der)
            .sign_redirect("SAMLRequest", &protocol::encode_redirect(&xml).unwrap(), None)
            .unwrap();
        let page = b.get(&format!("{endpoint}?{query}")).await;
        assert!(page.field("csrf").is_none(), "{xml}: {}", page.body);
        assert!(page.field("SAMLResponse").is_none(), "{xml}: {}", page.body);
    }

    // With no valid IssueInstant to judge, the request is schema-invalid: Requester.
    let issued = protocol::parse_xml(&current)
        .unwrap()
        .attr("IssueInstant")
        .unwrap()
        .to_string();
    let bad_time = current.replace(&issued, "not-a-saml-timestamp");
    assert_ne!(bad_time, current);
    let query = sp_signer(&pem, &der)
        .sign_redirect("SAMLRequest", &protocol::encode_redirect(&bad_time).unwrap(), None)
        .unwrap();
    let page = b.get(&format!("{endpoint}?{query}")).await;
    let response = response_of(&page);
    assert_eq!(status_codes(&response), vec![protocol::STATUS_REQUESTER]);
    assert!(response.child(NS_ASSERTION, "Assertion").is_none());
}

#[tokio::test]
async fn a_request_cannot_switch_the_name_id_to_another_property() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let xml = authn_request(
        "",
        r#"<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>"#,
    );
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    let response = response_of(&page);
    let name_id = &response
        .child(NS_ASSERTION, "Assertion")
        .and_then(|a| a.child(NS_ASSERTION, "Subject"))
        .and_then(|a| a.child(NS_ASSERTION, "NameID"))
        .unwrap()
        .text;
    assert_eq!(name_id, &w.f.upn, "the configured source, not the user's email");
}

#[tokio::test]
async fn the_login_form_cannot_start_an_idp_initiated_sign_in() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let forced = authn_request(r#"ForceAuthn="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &forced, None)).await;
    let csrf = page.field("csrf").unwrap();
    for value in [w.app_id.as_str(), "not-a-ticket"] {
        let request = format!("saml_launch={value}");
        let answer = b
            .post_form(
                &page.form_action(),
                &[
                    ("csrf", csrf.as_str()),
                    ("request", request.as_str()),
                    ("op", rust_oidc::html::LoginOp::Continue.as_str()),
                ],
            )
            .await;
        assert!(answer.field("SAMLResponse").is_none(), "{}", answer.body);
    }
}

#[tokio::test]
async fn a_consent_answer_cannot_skip_force_authn() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let forced = authn_request(r#"ForceAuthn="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &forced, None)).await;
    let (csrf, request) = (page.field("csrf").unwrap(), page.field("request").unwrap());
    for op in [
        rust_oidc::html::LoginOp::ConsentAccept,
        rust_oidc::html::LoginOp::ConsentDeny,
    ] {
        let answer = b
            .post_form(
                &page.form_action(),
                &[
                    ("csrf", csrf.as_str()),
                    ("request", request.as_str()),
                    ("op", op.as_str()),
                ],
            )
            .await;
        assert!(answer.field("SAMLResponse").is_none(), "{}", answer.body);
    }
}

#[tokio::test]
async fn a_server_set_claim_cannot_be_remapped() {
    let w = world().await;
    let save = rust_oidc::txn::ops::saml::SaveSamlClaims {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        name_id_format: protocol::NameIdFormat::EmailAddress,
        name_id_source: saml::NameIdSource::UserPrincipalName,
        claims: vec![saml::Claim {
            name: saml::CLAIM_ROLE.to_string(),
            source: saml::ClaimSource::DisplayName,
        }],
    };
    let outcome = txn::run(&w.s.pool, &Actor::Cli, &save).await;
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
}

#[tokio::test]
async fn a_required_signature_is_verified() {
    let w = world().await;
    let (pem, der, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let xml = signed_request_xml(&w, "_req1");
    let encoded = protocol::encode_redirect(&xml).unwrap();
    let signer = Signer {
        private_key_pem: &pem,
        cert_der: &der,
        algorithm: SigningAlgorithm::Sha256,
    };
    let query = signer.sign_redirect("SAMLRequest", &encoded, Some("keep")).unwrap();

    // Unsigned: refused.
    let b = Browser::new();
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None)).await;
    assert!(page.field("csrf").is_none(), "{}", page.body);

    // A signed request whose RelayState was changed: refused.
    let tampered = query.replace("RelayState=keep", "RelayState=evil");
    let page = b.get(&format!("{endpoint}?{tampered}")).await;
    assert!(page.field("csrf").is_none(), "{}", page.body);

    // Signed by someone else: refused.
    let (other_pem, other_der, _) = sp_key();
    let other = Signer {
        private_key_pem: &other_pem,
        cert_der: &other_der,
        algorithm: SigningAlgorithm::Sha256,
    };
    let forged = other.sign_redirect("SAMLRequest", &encoded, Some("keep")).unwrap();
    let page = b.get(&format!("{endpoint}?{forged}")).await;
    assert!(page.field("csrf").is_none(), "{}", page.body);

    // Properly signed: the sign-in continues, through the login form too.
    let page = b.get(&format!("{endpoint}?{query}")).await;
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    assert_eq!(page.field("RelayState").as_deref(), Some("keep"));
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);

    // The same signed request again, from another browser: a replay.
    let other_browser = Browser::new();
    let page = other_browser.get(&format!("{endpoint}?{query}")).await;
    let page = other_browser.login(&page, &w.f.upn, &w.f.password).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_REQUESTER]);
}

#[tokio::test]
async fn a_saml_request_is_not_served_by_the_oauth_endpoint() {
    let w = world().await;
    let b = Browser::new();
    let xml = authn_request("", "");
    let encoded = protocol::encode_redirect(&xml).unwrap();
    let page = b
        .authorize(
            &w.s,
            &w.f.tenant.id,
            &[("SAMLRequest", encoded.as_str()), ("client_id", w.app_id.as_str())],
        )
        .await;
    assert!(page.field("csrf").is_none(), "{}", page.body);
}

#[tokio::test]
async fn the_endpoint_does_not_accept_an_idp_initiated_sign_in() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let url = w.s.url(&format!("/{}/saml2?saml_launch={}", w.f.tenant.id, w.app_id));
    let page = b.get(&url).await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
}

#[tokio::test]
async fn an_identifier_belongs_to_one_application_in_the_tenant() {
    let w = world().await;
    let other = saml_app(&w.s, &w.f, "second", "https://other.example/").await;
    let clash = SaveSamlBasic {
        tenant_id: w.f.tenant.id.clone(),
        app_id: other,
        basic: basic(ENTITY),
    };
    let outcome = txn::run(&w.s.pool, &Actor::Cli, &clash).await;
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
}

#[tokio::test]
async fn certificate_rollover_follows_the_active_certificate() {
    let w = world().await;
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    let old = saml::certificates(&w.s.pool, &app).await.unwrap().remove(0);
    let add = AddSamlCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate: NewCertificate::generate(30).unwrap(),
    };
    txn::run(&w.s.pool, &Actor::Cli, &add).await.into_result().unwrap();
    let all = saml::certificates(&w.s.pool, &app).await.unwrap();
    let new = all.iter().find(|c| c.id != old.id).unwrap().clone();
    assert!(!new.active, "a new certificate starts inactive");

    let remove_active = RemoveSamlCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_id: old.id.clone(),
    };
    let outcome = txn::run(&w.s.pool, &Actor::Cli, &remove_active).await;
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");

    let activate = ActivateSamlCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_id: new.id.clone(),
    };
    txn::run(&w.s.pool, &Actor::Cli, &activate).await.into_result().unwrap();
    let all = saml::certificates(&w.s.pool, &app).await.unwrap();
    assert_eq!(all.iter().filter(|c| c.active).count(), 1);
    assert!(all.iter().find(|c| c.id == new.id).unwrap().active);

    let (_, page) = signed_in(&w).await;
    let encoded = page.field("SAMLResponse").unwrap();
    let xml = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    assert!(xml.contains(&STANDARD.encode(&new.cert_der)));
    txn::run(&w.s.pool, &Actor::Cli, &remove_active)
        .await
        .into_result()
        .unwrap();
}

#[tokio::test]
async fn stopping_saml_refuses_sign_in_and_keeps_the_configuration() {
    let w = world().await;
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    let certificates = saml::certificates(&w.s.pool, &app).await.unwrap();
    let (b, _) = signed_in(&w).await;
    let request = redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None);
    let metadata = w.s.url(&format!(
        "/{}/federationmetadata/2007-06/federationmetadata.xml?appid={}",
        w.f.tenant.id, w.app_id
    ));

    let stop = DisableSamlSso {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
    };
    txn::run(&w.s.pool, &Actor::Cli, &stop).await.into_result().unwrap();
    assert_eq!(audit_rows(&w.s, Event::AdminAppSamlDisable.as_str()).await.len(), 1);
    // A browser already signed in gets no assertion, and nobody is asked to sign in.
    let page = b.get(&request).await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
    let page = Browser::new().get(&request).await;
    assert!(page.field("csrf").is_none(), "{}", page.body);
    assert_eq!(Browser::new().get(&metadata).await.status, 404);

    // Choosing SAML again brings back what was there, certificate included.
    let again = EnableSamlSso {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate: NewCertificate::generate(saml::CERT_VALIDITY_DAYS).unwrap(),
    };
    txn::run(&w.s.pool, &Actor::Cli, &again).await.into_result().unwrap();
    let config = saml::config(&w.s.pool, &app).await.unwrap().unwrap();
    assert!(config.enabled);
    assert_eq!(config.identifiers, vec![ENTITY.to_string()]);
    assert_eq!(saml::certificates(&w.s.pool, &app).await.unwrap(), certificates);
    let page = b.get(&request).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);
}

#[tokio::test]
async fn the_signing_option_decides_what_is_signed() {
    const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let request = redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None);
    // (the response is signed, the assertion is signed), with the algorithm named.
    let cases = [
        (
            protocol::SigningOption::Assertion,
            SigningAlgorithm::Sha256,
            (false, true),
        ),
        (
            protocol::SigningOption::Response,
            SigningAlgorithm::Sha256,
            (true, false),
        ),
        (protocol::SigningOption::Both, SigningAlgorithm::Sha1, (true, true)),
    ];
    for (option, algorithm, expected) in cases {
        let save = SaveSamlSigning {
            tenant_id: w.f.tenant.id.clone(),
            app_id: w.app_id.clone(),
            option,
            algorithm,
        };
        txn::run(&w.s.pool, &Actor::Cli, &save).await.into_result().unwrap();
        let response = response_of(&b.get(&request).await);
        let assertion = response.child(NS_ASSERTION, "Assertion").unwrap();
        let signed = (
            response.child(NS_DS, "Signature").is_some(),
            assertion.child(NS_DS, "Signature").is_some(),
        );
        assert_eq!(signed, expected, "{option:?}");
        let method = [&response, assertion]
            .iter()
            .find_map(|n| n.child(NS_DS, "Signature"))
            .and_then(|s| s.child(NS_DS, "SignedInfo"))
            .and_then(|i| i.child(NS_DS, "SignatureMethod"))
            .and_then(|m| m.attr("Algorithm"))
            .unwrap();
        assert_eq!(method, algorithm.signature_uri(), "{option:?}");
    }
    assert_eq!(audit_rows(&w.s, Event::AdminAppSamlSigning.as_str()).await.len(), 3);
}

#[tokio::test]
async fn each_change_is_audited_without_key_material() {
    let w = world().await;
    let rows = audit_rows(&w.s, Event::AdminAppSamlEnable.as_str()).await;
    assert_eq!(rows.len(), 1);
    let all: Vec<(String,)> = sqlx::query_as(rust_oidc::db::q(&w.s.pool, "SELECT details FROM audit_log"))
        .fetch_all(&w.s.pool)
        .await
        .unwrap();
    assert!(all.iter().all(|(d,)| !d.contains("PRIVATE KEY")));
}

#[tokio::test]
async fn federation_metadata_describes_the_endpoint_and_certificate() {
    let w = world().await;
    let url = w.s.url(&format!(
        "/{}/federationmetadata/2007-06/federationmetadata.xml?appid={}",
        w.f.tenant.id, w.app_id
    ));
    let page = Browser::new().get(&url).await;
    assert_eq!(page.status, 200);
    let root = protocol::parse_xml(&page.body).unwrap();
    assert_eq!(root.local, "EntityDescriptor");
    assert!(page.body.contains("X509Certificate"));
    assert!(!page.body.contains("PRIVATE"));
}

async fn my_account(w: &World, b: &Browser) -> Page {
    b.get(&w.s.url(&format!("/{}/myaccount", w.f.tenant.id))).await
}

async fn assign(w: &World) {
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    apps::assign(&w.s.pool, &w.f.tenant, &app, &Principal::User(w.f.upn.clone()), &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn the_gallery_lists_only_assigned_visible_applications() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    assert!(!my_account(&w, &b).await.body.contains("legacy-app"));
    assign(&w).await;
    assert!(my_account(&w, &b).await.body.contains("legacy-app"));
    let hide = SetAppVisibility {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        visible: false,
    };
    txn::run(&w.s.pool, &Actor::Cli, &hide).await.into_result().unwrap();
    assert!(!my_account(&w, &b).await.body.contains("legacy-app"));
}

#[tokio::test]
async fn the_gallery_links_to_the_sign_on_url_when_there_is_one() {
    let w = world().await;
    assign(&w).await;
    let set = SetAppSignOnUrl {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        sign_on_url: Some("https://sp.example/login".to_string()),
    };
    txn::run(&w.s.pool, &Actor::Cli, &set).await.into_result().unwrap();
    let (b, _) = signed_in(&w).await;
    assert!(
        my_account(&w, &b)
            .await
            .body
            .contains(r#"href="https://sp.example/login""#)
    );
}

#[tokio::test]
async fn a_sign_on_url_must_be_https() {
    let w = world().await;
    let set = SetAppSignOnUrl {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        sign_on_url: Some("javascript:alert(1)".to_string()),
    };
    let outcome = txn::run(&w.s.pool, &Actor::Cli, &set).await;
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
}

#[tokio::test]
async fn plain_http_is_refused_for_a_sign_on_url_except_on_this_machine() {
    let w = world().await;
    let set = |url: &str| SetAppSignOnUrl {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        sign_on_url: Some(url.to_string()),
    };
    for refused in ["http://sp.example/login", "ftp://sp.example/login"] {
        let outcome = txn::run(&w.s.pool, &Actor::Cli, &set(refused)).await;
        assert!(matches!(outcome, Outcome::Refused(_)), "{refused}: {outcome:?}");
    }
    let local = txn::run(&w.s.pool, &Actor::Cli, &set("http://localhost:9000/login")).await;
    assert!(local.is_done(), "{local:?}");
}

#[tokio::test]
async fn launching_from_the_gallery_is_idp_initiated_and_needs_the_csrf_token() {
    let w = world().await;
    assign(&w).await;
    let (b, _) = signed_in(&w).await;
    let url = w.s.url(&format!("/{}/myaccount", w.f.tenant.id));
    let page = my_account(&w, &b).await;
    let csrf = page.field("csrf").unwrap();
    let launch = rust_oidc::html::AccountOp::LaunchApp.as_str();

    let wrong = b
        .post_form(&url, &[("csrf", "wrong"), ("op", launch), ("app", w.app_id.as_str())])
        .await;
    assert!(wrong.field("SAMLResponse").is_none());

    let page = my_account(&w, &b).await;
    let csrf_now = page.field("csrf").unwrap_or(csrf);
    let answer = b
        .post_form(
            &url,
            &[("csrf", csrf_now.as_str()), ("op", launch), ("app", w.app_id.as_str())],
        )
        .await;
    assert_eq!(answer.form_action(), ACS);
    let response = response_of(&answer);
    assert_eq!(response.attr("InResponseTo"), None);
    assert_eq!(status_codes(&response), vec![protocol::STATUS_SUCCESS]);
}

#[tokio::test]
async fn an_unassigned_application_cannot_be_launched() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let url = w.s.url(&format!("/{}/myaccount", w.f.tenant.id));
    let page = my_account(&w, &b).await;
    let csrf = page.field("csrf").unwrap();
    let launch = rust_oidc::html::AccountOp::LaunchApp.as_str();
    let answer = b
        .post_form(
            &url,
            &[("csrf", csrf.as_str()), ("op", launch), ("app", w.app_id.as_str())],
        )
        .await;
    assert!(answer.field("SAMLResponse").is_none(), "{}", answer.body);
}

fn logout_request(issuer: &str) -> String {
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_out1" Version="2.0" IssueInstant="2026-11-23T00:00:00Z"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID>x</saml:NameID></samlp:LogoutRequest>"#
    )
}

fn decoded_location(page: &Page, param: &str) -> Node {
    let encoded = page.redirect_params()[param].clone();
    protocol::parse_xml(&protocol::decode_message(&encoded).unwrap()).unwrap()
}

#[tokio::test]
async fn single_logout_tells_every_participant_then_answers_the_initiator() {
    let w = world().await;
    let second_entity = "https://second.example/";
    saml_app(&w.s, &w.f, "second", second_entity).await;
    let (b, _) = signed_in(&w).await;
    let to_second = authn_request("", "").replace(ENTITY, second_entity);
    let second = b.get(&redirect_url(&w.s, &w.f.tenant.id, &to_second, None)).await;
    assert!(second.field("SAMLResponse").is_some(), "{}", second.body);

    // The first application asks to log out: the second is told first.
    let url = {
        let mut u = url::Url::parse(&w.s.url(&format!("/{}/saml2", w.f.tenant.id))).unwrap();
        u.query_pairs_mut().append_pair(
            "SAMLRequest",
            &protocol::encode_redirect(&logout_request(ENTITY)).unwrap(),
        );
        u.query_pairs_mut().append_pair("RelayState", "after");
        u.to_string()
    };
    let told = b.get(&url).await;
    assert_eq!(told.status, 302);
    assert!(told.location.as_deref().unwrap().starts_with(LOGOUT));
    let request = decoded_location(&told, "SAMLRequest");
    assert_eq!(request.local, "LogoutRequest");
    let issued = request.attr("IssueInstant").unwrap();
    let not_after = request
        .attr("NotOnOrAfter")
        .expect("a LogoutRequest we issue says when it expires");
    assert!(
        not_after.ends_with('Z') && not_after > issued,
        "{issued} .. {not_after}"
    );
    assert!(told.redirect_params().contains_key("Signature"));
    let id = request.attr("ID").unwrap().to_string();

    // A response from the wrong application does not advance it.
    let answer = |issuer: &str| {
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_a1" InResponseTo="{id}" Version="2.0" IssueInstant="2026-11-23T00:00:00Z"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:LogoutResponse>"#,
            protocol::STATUS_SUCCESS
        )
    };
    let send = |xml: String| {
        let mut u = url::Url::parse(&w.s.url(&format!("/{}/saml2", w.f.tenant.id))).unwrap();
        u.query_pairs_mut()
            .append_pair("SAMLResponse", &protocol::encode_redirect(&xml).unwrap());
        u.to_string()
    };
    let wrong = b.get(&send(answer(ENTITY))).await;
    assert_ne!(wrong.status, 302, "{}", wrong.body);

    // The application it went to answers: the chain goes on to the initiator.
    let done = b.get(&send(answer(second_entity))).await;
    assert_eq!(done.status, 302, "{}", done.body);
    let response = decoded_location(&done, "SAMLResponse");
    assert_eq!(response.local, "LogoutResponse");
    assert_eq!(response.attr("InResponseTo"), Some("_out1"));
    assert_eq!(done.redirect_params()["RelayState"], "after");

    // An answer counts once.
    let replay = b.get(&send(answer(second_entity))).await;
    assert_ne!(replay.status, 302, "{}", replay.body);
}

#[tokio::test]
async fn single_logout_answers_the_initiator_and_ends_the_session() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let mut u = url::Url::parse(&w.s.url(&format!("/{}/saml2", w.f.tenant.id))).unwrap();
    u.query_pairs_mut().append_pair(
        "SAMLRequest",
        &protocol::encode_redirect(&logout_request(ENTITY)).unwrap(),
    );
    u.query_pairs_mut().append_pair("RelayState", "after");
    let done = b.get(u.as_str()).await;
    assert_eq!(done.status, 302);
    assert!(done.location.as_deref().unwrap().starts_with(LOGOUT));
    assert_eq!(done.redirect_params()["RelayState"], "after");
    let response = decoded_location(&done, "SAMLResponse");
    assert_eq!(response.local, "LogoutResponse");
    assert_eq!(response.attr("InResponseTo"), Some("_out1"));
    // Signed out: asking silently now gets NoPassive.
    let passive = authn_request(r#"IsPassive="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &passive, None)).await;
    assert_eq!(
        status_codes(&response_of(&page)),
        vec![protocol::STATUS_RESPONDER, protocol::STATUS_NO_PASSIVE]
    );
}

fn logout_url(w: &World, xml: &str) -> String {
    let mut u = url::Url::parse(&w.s.url(&format!("/{}/saml2", w.f.tenant.id))).unwrap();
    u.query_pairs_mut()
        .append_pair("SAMLRequest", &protocol::encode_redirect(xml).unwrap());
    u.to_string()
}

async fn still_signed_in(w: &World, b: &Browser) -> bool {
    let passive = authn_request(r#"IsPassive="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &passive, None)).await;
    status_codes(&response_of(&page)) == vec![protocol::STATUS_SUCCESS]
}

#[tokio::test]
async fn a_request_that_cannot_be_honored_gets_a_saml_error_at_the_registered_url() {
    let w = world().await;
    let subject = "<saml:Subject><saml:NameID>nobody@example.test</saml:NameID></saml:Subject>";
    let format = r#"<samlp:NameIDPolicy Format="urn:example:unknown"/>"#;
    let comparison = r#"<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:example</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>"#;
    let artifact = r#"ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact""#;
    let version = |v: &str| authn_request("", "").replace(r#"Version="2.0""#, &format!(r#"Version="{v}""#));
    let mut cases: Vec<(String, &str, &str)> = vec![
        (
            version("1.1"),
            protocol::STATUS_VERSION_MISMATCH,
            protocol::STATUS_VERSION_TOO_LOW,
        ),
        (
            version("3.0"),
            protocol::STATUS_VERSION_MISMATCH,
            protocol::STATUS_VERSION_TOO_HIGH,
        ),
        (
            authn_request(r#"ForceAuthn="true" IsPassive="true""#, ""),
            protocol::STATUS_RESPONDER,
            protocol::STATUS_NO_PASSIVE,
        ),
    ];
    for (attrs, body, top, sub) in [
        (
            "",
            subject,
            protocol::STATUS_REQUESTER,
            protocol::STATUS_REQUEST_UNSUPPORTED,
        ),
        (
            artifact,
            "",
            protocol::STATUS_REQUESTER,
            protocol::STATUS_REQUEST_UNSUPPORTED,
        ),
        (
            "",
            format,
            protocol::STATUS_REQUESTER,
            protocol::STATUS_INVALID_NAMEID_POLICY,
        ),
        (
            "",
            comparison,
            protocol::STATUS_RESPONDER,
            protocol::STATUS_NO_AUTHN_CONTEXT,
        ),
    ] {
        cases.push((authn_request(attrs, body), top, sub));
    }
    let certs = [idp_signing_cert(&w).await];
    for (xml, top, sub) in cases {
        let page = Browser::new()
            .get(&redirect_url(&w.s, &w.f.tenant.id, &xml, None))
            .await;
        let response = response_of(&page);
        assert_eq!(status_codes(&response), vec![top, sub], "{xml}");
        // Signed, so the application can trust the status.
        rust_oidc::saml_dsig::verify(&response_xml(&page), &certs, false).unwrap();
        assert_eq!(response.attr("Destination"), Some(ACS));
        assert_eq!(response.attr("InResponseTo"), Some("_req1"));
        assert!(response.child(NS_ASSERTION, "Assertion").is_none());
    }

    // A schema-invalid IssueInstant is the requester's fault, with no second-level code.
    let bad_time = authn_request("", "").replace("2026-11-23T00:00:00Z", "not-a-saml-timestamp");
    let page = Browser::new()
        .get(&redirect_url(&w.s, &w.f.tenant.id, &bad_time, None))
        .await;
    let response = response_of(&page);
    assert_eq!(status_codes(&response), vec![protocol::STATUS_REQUESTER]);
    assert!(response.child(NS_ASSERTION, "Assertion").is_none());

    // Never to a URL the application did not register.
    let elsewhere = r#"AssertionConsumerServiceURL="https://evil.example/acs""#;
    let page = Browser::new()
        .get(&redirect_url(
            &w.s,
            &w.f.tenant.id,
            &authn_request(elsewhere, subject),
            None,
        ))
        .await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);

    // And not for a request failing the application's signature requirement.
    let (_, _, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let page = Browser::new()
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", subject), None))
        .await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
}

#[tokio::test]
async fn an_unsigned_request_addressed_elsewhere_is_discarded() {
    let w = world().await;
    let here = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let (b, _) = signed_in(&w).await;

    // Control: the right Destination is accepted.
    let right = authn_request(&format!(r#"Destination="{here}""#), "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &right, None)).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);

    let wrong = r#"Destination="https://other.example/saml2""#;
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request(wrong, ""), None))
        .await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);

    // A misaddressed logout request ends nothing.
    let logout = logout_request(ENTITY).replace(r#"ID="_out1""#, &format!(r#"{wrong} ID="_out1""#));
    let page = b.get(&logout_url(&w, &logout)).await;
    assert_ne!(page.status, 302, "{}", page.body);
    assert!(still_signed_in(&w, &b).await);
}

#[tokio::test]
async fn a_request_addressed_by_the_tenants_domain_survives_the_sign_in_form() {
    let w = world().await;
    // The fixture tenant's verified domain: another name of the same endpoint.
    let domain = "contoso.com";
    let here = w.s.url(&format!("/{domain}/saml2"));
    let xml = authn_request(&format!(r#"Destination="{here}""#), "");
    let b = Browser::new();
    // The form posts back under the tenant's id, where the same request is
    // validated again.
    let page = b.get(&redirect_url(&w.s, domain, &xml, None)).await;
    assert!(at_sign_in(&page), "{}", page.body);
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);
}

#[tokio::test]
async fn a_destination_is_compared_exactly_and_names_this_tenant() {
    let w = world().await;
    let other = w.s.tenant("Fabrikam", "fabrikam.example").await;
    let (b, _) = signed_in(&w).await;
    let id = &w.f.tenant.id;
    let here = w.s.url(&format!("/{id}/saml2"));
    let send = async |destination: &str| {
        let xml = authn_request(&format!(r#"Destination="{destination}""#), "");
        b.get(&redirect_url(&w.s, id, &xml, None)).await
    };

    let page = send(&here).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);

    for wrong in [
        format!("{here}/"),
        format!("{here}?x=1"),
        format!("{here}#x"),
        here.replace("saml2", "SAML2"),
        here.replace("http://", "https://"),
        here.replace("http://", "http://user@"),
        here.replace(&format!("/{id}/"), &format!("//{id}/")),
        here.replace(&format!("/{id}/"), &format!("/x/{id}/")),
        // Another tenant's endpoint, though this server serves it too.
        w.s.url(&format!("/{}/saml2", other.id)),
        w.s.url("/fabrikam.example/saml2"),
        w.s.url("/saml2"),
        w.s.url("//saml2"),
        String::new(),
    ] {
        let page = send(&wrong).await;
        assert!(page.field("SAMLResponse").is_none(), "{wrong}: {}", page.body);
    }

    // The same on the POST binding, unsigned.
    let xml = authn_request(r#"Destination="https://other.example/saml2""#, "");
    let page = post_request(&w, &b, &xml).await;
    assert!(page.field("SAMLResponse").is_none(), "{}", page.body);
    let page = post_request(&w, &b, &authn_request(&format!(r#"Destination="{here}""#), "")).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);
}

#[tokio::test]
async fn an_application_the_session_never_reached_cannot_end_it() {
    let w = world().await;
    let other = "https://other.example/";
    saml_app(&w.s, &w.f, "other", other).await;
    let (b, _) = signed_in(&w).await;
    let done = b.get(&logout_url(&w, &logout_request(other))).await;
    let response = decoded_location(&done, "SAMLResponse");
    assert_eq!(
        status_codes(&response),
        vec![protocol::STATUS_RESPONDER, protocol::STATUS_UNKNOWN_PRINCIPAL]
    );
    assert!(still_signed_in(&w, &b).await);
}

#[tokio::test]
async fn a_wrong_session_index_ends_nothing() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let xml = logout_request(ENTITY).replace(
        "<saml:NameID>x</saml:NameID>",
        "<saml:NameID>x</saml:NameID><samlp:SessionIndex>_guess</samlp:SessionIndex>",
    );
    let done = b.get(&logout_url(&w, &xml)).await;
    assert_eq!(
        status_codes(&decoded_location(&done, "SAMLResponse")),
        vec![protocol::STATUS_RESPONDER, protocol::STATUS_UNKNOWN_PRINCIPAL]
    );
    assert!(still_signed_in(&w, &b).await);
}

#[tokio::test]
async fn single_logout_accepts_the_post_binding() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    assert!(page.field("SAMLResponse").is_some(), "{}", page.body);

    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let encoded = STANDARD.encode(logout_request(ENTITY));
    let answer = b
        .post_form(&endpoint, &[("SAMLRequest", encoded.as_str()), ("RelayState", "after")])
        .await;
    assert_eq!(answer.status, 302, "{}", answer.body);
    assert!(answer.location.as_deref().unwrap().starts_with(LOGOUT));
    let response = decoded_location(&answer, "SAMLResponse");
    assert_eq!(response.attr("InResponseTo"), Some("_out1"));
    assert_eq!(status_codes(&response), vec![protocol::STATUS_SUCCESS]);
    assert_eq!(answer.redirect_params()["RelayState"], "after");

    // The session really ended.
    let again = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    assert!(again.field("SAMLResponse").is_none(), "{}", again.body);
}

#[tokio::test]
async fn an_expired_logout_request_is_refused() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let xml = logout_request(ENTITY).replace(
        r#"Version="2.0""#,
        r#"NotOnOrAfter="2020-01-01T00:00:00Z" Version="2.0""#,
    );
    let page = b.get(&logout_url(&w, &xml)).await;
    assert_ne!(page.status, 302, "{}", page.body);
    assert!(still_signed_in(&w, &b).await);
}

#[tokio::test]
async fn logging_out_of_one_tenant_keeps_the_browser_signed_in_to_another() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    // A second tenant's session on the same browser, through its own app.
    let other = user_fixture_in(&w.s, w.s.tenant("Fabrikam", "fabrikam.com").await, "bob@fabrikam.com").await;
    let page = b
        .authorize(
            &w.s,
            &other.tenant.id,
            &[
                ("client_id", other.web.app_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", pkce().1.as_str()),
                ("code_challenge_method", "S256"),
                ("login_hint", other.upn.as_str()),
            ],
        )
        .await;
    assert_eq!(b.login(&page, &other.upn, &other.password).await.status, 302);
    let done = b.get(&logout_url(&w, &logout_request(ENTITY))).await;
    assert_eq!(done.status, 302);
    let cookies: Vec<&str> = done
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with(&format!("{}=", rust_oidc::session::SESSION_COOKIE))),
        "{cookies:?}"
    );
}

#[tokio::test]
async fn one_session_is_one_participant_per_application() {
    let w = world().await;
    let (b, first) = signed_in(&w).await;
    let index = |page: &Page| {
        response_of(page)
            .child(NS_ASSERTION, "Assertion")
            .and_then(|a| a.child(NS_ASSERTION, "AuthnStatement"))
            .and_then(|a| a.attr("SessionIndex"))
            .unwrap()
            .to_string()
    };
    let again = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    assert_eq!(index(&first), index(&again));
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &w.s.pool,
        "SELECT COUNT(*) FROM saml_session_participants",
    ))
    .fetch_one(&w.s.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_logout_answer_only_counts_in_the_browser_carrying_the_logout() {
    let w = world().await;
    let second = "https://second.example/";
    saml_app(&w.s, &w.f, "second", second).await;
    let (b, _) = signed_in(&w).await;
    let to_second = authn_request("", "").replace(ENTITY, second);
    b.get(&redirect_url(&w.s, &w.f.tenant.id, &to_second, None)).await;
    let told = b.get(&logout_url(&w, &logout_request(ENTITY))).await;
    let id = decoded_location(&told, "SAMLRequest").attr("ID").unwrap().to_string();
    let answer = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_a1" InResponseTo="{id}" Version="2.0" IssueInstant="2026-11-23T00:00:00Z"><saml:Issuer>{second}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:LogoutResponse>"#,
        protocol::STATUS_RESPONDER
    );
    let mut u = url::Url::parse(&w.s.url(&format!("/{}/saml2", w.f.tenant.id))).unwrap();
    u.query_pairs_mut()
        .append_pair("SAMLResponse", &protocol::encode_redirect(&answer).unwrap());
    // Another browser cannot use it up.
    let stranger = Browser::new().get(u.as_str()).await;
    assert_ne!(stranger.status, 302, "{}", stranger.body);
    // Nor can one holding a logout cookie of its own.
    let other_logout = Browser::new()
        .http
        .get(u.as_str())
        .header("cookie", "saml_logout=some-other-browser")
        .send()
        .await
        .unwrap();
    assert_ne!(other_logout.status().as_u16(), 302);
    // The right browser can, and a participant's failure is reported as partial.
    let done = b.get(u.as_str()).await;
    assert_eq!(done.status, 302, "{}", done.body);
    assert_eq!(
        status_codes(&decoded_location(&done, "SAMLResponse")),
        vec![protocol::STATUS_RESPONDER, protocol::STATUS_PARTIAL_LOGOUT]
    );
}

#[tokio::test]
async fn an_authentication_context_that_cannot_be_met_is_refused() {
    let w = world().await;
    for reference in [
        "<saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef>",
        "<saml:AuthnContextClassRef>urn:example:unavailable</saml:AuthnContextClassRef>",
    ] {
        let body =
            format!(r#"<samlp:RequestedAuthnContext Comparison="exact">{reference}</samlp:RequestedAuthnContext>"#);
        let b = Browser::new();
        let page = b
            .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", &body), None))
            .await;
        let page = b.login(&page, &w.f.upn, &w.f.password).await;
        let response = response_of(&page);
        assert_eq!(
            status_codes(&response),
            vec![protocol::STATUS_RESPONDER, protocol::STATUS_NO_AUTHN_CONTEXT],
            "{reference}"
        );
        assert!(response.child(NS_ASSERTION, "Assertion").is_none(), "{reference}");
    }
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// How a test's enveloped signature is put together. The message and SignedInfo
/// are written directly in canonical form, so these tests do not rely on the
/// canonicalizer under test to produce what they verify.
struct Enveloped<'a> {
    id: &'a str,
    destination: String,
    /// Canonical elements after the signature, covered by the digest.
    body: &'a str,
    uri: Option<&'a str>,
    /// Extra markup inside `Signature`, outside what is signed.
    after_value: &'a str,
}

fn enveloped(e: &Enveloped<'_>, pem: &str) -> String {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    let issued = protocol::instant(rust_oidc::util::now()).unwrap();
    let open = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{NS_PROTOCOL}" Destination="{}" ID="{}" IssueInstant="{issued}" Version="2.0"><saml:Issuer xmlns:saml="{NS_ASSERTION}">{ENTITY}</saml:Issuer>"#,
        e.destination, e.id
    );
    let close = "</samlp:AuthnRequest>";
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        format!("{open}{}{close}", e.body).as_bytes(),
    );
    let inner = format!(
        r##"<ds:CanonicalizationMethod Algorithm="{EXC}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{}"></ds:SignatureMethod><ds:Reference URI="{}"><ds:Transforms><ds:Transform Algorithm="{DS}enveloped-signature"></ds:Transform><ds:Transform Algorithm="{EXC}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference>"##,
        SigningAlgorithm::Sha256.signature_uri(),
        e.uri.map_or_else(|| format!("#{}", e.id), str::to_string),
        STANDARD.encode(digest.as_ref()),
    );
    let signed_info = format!(r#"<ds:SignedInfo xmlns:ds="{DS}">{inner}</ds:SignedInfo>"#);
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let key = RsaKeyPair::from_pkcs8(&STANDARD.decode(body).unwrap()).unwrap();
    let mut value = vec![0u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signed_info.as_bytes(),
        &mut value,
    )
    .unwrap();
    format!(
        r#"{open}<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo>{inner}</ds:SignedInfo><ds:SignatureValue>{}</ds:SignatureValue>{}</ds:Signature>{}{close}"#,
        STANDARD.encode(&value),
        e.after_value,
        e.body,
    )
}

fn plain<'a>(w: &World, id: &'a str) -> Enveloped<'a> {
    Enveloped {
        id,
        destination: w.s.url(&format!("/{}/saml2", w.f.tenant.id)),
        body: "",
        uri: None,
        after_value: "",
    }
}

/// The request was accepted and the browser is at the password page.
fn at_sign_in(page: &Page) -> bool {
    page.status == 200 && page.body.contains(r#"name="password""#)
}

async fn post_request(w: &World, b: &Browser, xml: &str) -> Page {
    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let encoded = STANDARD.encode(xml);
    b.post_form(&endpoint, &[("SAMLRequest", encoded.as_str())]).await
}

#[tokio::test]
async fn a_signed_post_request_signs_in_once() {
    let w = world().await;
    let (pem, _, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let xml = enveloped(&plain(&w, "_post1"), &pem);
    let b = Browser::new();
    let page = post_request(&w, &b, &xml).await;
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);
    let again = post_request(&w, &b, &xml).await;
    assert!(
        status_codes(&response_of(&again)) != vec![protocol::STATUS_SUCCESS],
        "a signed request is single-use"
    );
}

#[tokio::test]
async fn a_changed_or_misaddressed_signed_post_is_refused() {
    let w = world().await;
    let (pem, _, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let (other_pem, _, _) = sp_key();
    let good = enveloped(&plain(&w, "_post2"), &pem);
    let misaddressed = Enveloped {
        destination: "https://elsewhere.example/saml2".into(),
        ..plain(&w, "_post3")
    };
    for (what, xml) in [
        ("changed issuer", good.replace(ENTITY, "https://other.example/")),
        ("changed id", good.replace("_post2", "_post9")),
        ("another key", enveloped(&plain(&w, "_post4"), &other_pem)),
        ("wrong Destination", enveloped(&misaddressed, &pem)),
    ] {
        let page = post_request(&w, &Browser::new(), &xml).await;
        assert!(page.field("SAMLResponse").is_none(), "{what}: {}", page.body);
        assert!(!at_sign_in(&page), "{what}: reached sign-in");
    }
}

#[test]
fn only_one_signature_shape_is_accepted() {
    let (pem, der, _) = sp_key();
    let certs = [der];
    let base = || Enveloped {
        id: "_shape",
        destination: "https://idp.example/saml2".into(),
        body: "",
        uri: None,
        after_value: "",
    };
    assert!(rust_oidc::saml_dsig::verify(&enveloped(&base(), &pem), &certs, false).is_ok());

    let duplicate_id = r#"<samlp:Extensions ID="_shape"></samlp:Extensions>"#.to_string();
    let second_signature =
        format!(r#"<samlp:Extensions><ds:Signature xmlns:ds="{DS}"></ds:Signature></samlp:Extensions>"#);
    let object = format!(r#"<ds:Object xmlns:ds="{DS}"></ds:Object>"#);
    for (what, xml) in [
        (
            "a second element with the signed ID",
            enveloped(
                &Enveloped {
                    body: &duplicate_id,
                    ..base()
                },
                &pem,
            ),
        ),
        (
            "a second signature",
            enveloped(
                &Enveloped {
                    body: &second_signature,
                    ..base()
                },
                &pem,
            ),
        ),
        (
            "a reference to something else",
            enveloped(
                &Enveloped {
                    uri: Some("#_other"),
                    ..base()
                },
                &pem,
            ),
        ),
        (
            "an empty reference",
            enveloped(
                &Enveloped {
                    uri: Some(""),
                    ..base()
                },
                &pem,
            ),
        ),
        (
            "an Object in the signature",
            enveloped(
                &Enveloped {
                    after_value: &object,
                    ..base()
                },
                &pem,
            ),
        ),
        (
            "a changed message under a valid SignedInfo",
            enveloped(&base(), &pem).replace("https://idp.example/saml2", "https://evil.example/saml2"),
        ),
        (
            "a comment inside a signed value",
            enveloped(&base(), &pem).replace(ENTITY, &ENTITY.replacen("sp", "s<!-- x -->p", 1)),
        ),
    ] {
        assert!(rust_oidc::saml_dsig::verify(&xml, &certs, false).is_err(), "{what}");
    }
}

#[tokio::test]
async fn a_bad_signature_is_refused_when_a_certificate_is_registered() {
    let w = world().await;
    let (pem, _, cert_pem) = sp_key();
    let (other_pem, _, _) = sp_key();
    let forged = enveloped(&plain(&w, "_opt1"), &other_pem);
    // No certificate: the signature cannot be checked, and counts as absent.
    let page = post_request(&w, &Browser::new(), &forged).await;
    assert!(at_sign_in(&page), "{}", page.body);

    let add = AddSamlVerificationCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_pem: cert_pem,
    };
    txn::run(&w.s.pool, &Actor::Cli, &add).await.into_result().unwrap();
    let page = post_request(&w, &Browser::new(), &forged).await;
    assert!(!at_sign_in(&page), "a forged signature must not pass");
    let good = enveloped(&plain(&w, "_opt2"), &pem);
    let page = post_request(&w, &Browser::new(), &good).await;
    assert!(at_sign_in(&page), "{}", page.body);
    // Signatures are still optional here.
    let unsigned = authn_request("", "").replace("_req1", "_opt3");
    let page = post_request(&w, &Browser::new(), &unsigned).await;
    assert!(at_sign_in(&page), "{}", page.body);
}

#[tokio::test]
async fn a_logout_answer_must_be_addressed_to_this_endpoint() {
    let w = world().await;
    let second = "https://second.example/";
    saml_app(&w.s, &w.f, "second", second).await;
    let (b, _) = signed_in(&w).await;
    let to_second = authn_request("", "").replace(ENTITY, second);
    b.get(&redirect_url(&w.s, &w.f.tenant.id, &to_second, None)).await;
    // The first application signs what it sends from now on.
    let (pem, der, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    // The second asks to log out, so the first is told and must answer.
    let told = b.get(&logout_url(&w, &logout_request(second))).await;
    assert!(told.location.as_deref().unwrap().starts_with(LOGOUT), "{}", told.body);
    let id = decoded_location(&told, "SAMLRequest").attr("ID").unwrap().to_string();
    let endpoint = w.s.url(&format!("/{}/saml2", w.f.tenant.id));
    let answer = |destination: &str| {
        let xml = format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_a1" InResponseTo="{id}" Version="2.0" IssueInstant="2026-11-23T00:00:00Z"{destination}><saml:Issuer>{ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:LogoutResponse>"#,
            protocol::STATUS_SUCCESS
        );
        let query = sp_signer(&pem, &der)
            .sign_redirect("SAMLResponse", &protocol::encode_redirect(&xml).unwrap(), None)
            .unwrap();
        format!("{endpoint}?{query}")
    };
    // Signed for another identity provider's endpoint: discarded.
    let elsewhere = b
        .get(&answer(r#" Destination="https://other-idp.example/saml2""#))
        .await;
    assert_ne!(elsewhere.status, 302, "{}", elsewhere.body);
    // Signed, but saying nowhere: a signed message must say where it goes.
    let nowhere = b.get(&answer("")).await;
    assert_ne!(nowhere.status, 302, "{}", nowhere.body);
    // Neither used up the waiting logout: the answer addressed here carries on.
    let done = b.get(&answer(&format!(r#" Destination="{endpoint}""#))).await;
    assert_eq!(done.status, 302, "{}", done.body);
    assert_eq!(
        status_codes(&decoded_location(&done, "SAMLResponse")),
        vec![protocol::STATUS_SUCCESS]
    );
}

#[tokio::test]
async fn a_reply_url_is_used_exactly_as_registered() {
    let w = world().await;
    let registered = "https://sp.example:443/acs";
    let save = SaveSamlBasic {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        basic: BasicConfig {
            reply_urls: ReplyUrl::listed([registered.to_string()]),
            ..basic(ENTITY)
        },
    };
    txn::run(&w.s.pool, &Actor::Cli, &save).await.into_result().unwrap();
    let b = Browser::new();
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    let page = b.login(&page, &w.f.upn, &w.f.password).await;
    let response = response_of(&page);
    assert_eq!(response.attr("Destination"), Some(registered));
}

#[tokio::test]
async fn the_last_valid_verification_certificate_is_kept_while_signatures_are_required() {
    let w = world().await;
    let (_, _, cert_pem) = sp_key();
    require_signed(&w, &cert_pem).await;
    let (_, _, second_pem) = sp_key();
    let add = AddSamlVerificationCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_pem: second_pem,
    };
    txn::run(&w.s.pool, &Actor::Cli, &add).await.into_result().unwrap();
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    let certs = saml::verification_certificates(&w.s.pool, &app).await.unwrap();
    // One of the two has expired.
    sqlx::query(rust_oidc::db::q(
        &w.s.pool,
        "UPDATE app_saml_verification_certs SET not_after = 1 WHERE id = ?",
    ))
    .bind(&certs[0].id)
    .execute(&w.s.pool)
    .await
    .unwrap();
    let remove = rust_oidc::txn::ops::saml::RemoveSamlVerificationCertificate {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        certificate_id: certs[1].id.clone(),
    };
    let outcome = txn::run(&w.s.pool, &Actor::Cli, &remove).await;
    assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
}

#[tokio::test]
async fn a_launch_ticket_works_once_and_only_for_its_user() {
    let w = world().await;
    assign(&w).await;
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    let (b, _) = signed_in(&w).await;
    let forced = authn_request(r#"ForceAuthn="true""#, "");
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &forced, None)).await;
    let csrf = page.field("csrf").unwrap();
    let action = page.form_action();
    let send = |ticket: String| {
        let (b, csrf, action) = (&b, csrf.clone(), action.clone());
        async move {
            let request = format!("saml_launch={ticket}");
            b.post_form(
                &action,
                &[
                    ("csrf", csrf.as_str()),
                    ("request", request.as_str()),
                    ("op", rust_oidc::html::LoginOp::Continue.as_str()),
                ],
            )
            .await
        }
    };
    let someone_else = saml::create_launch_ticket(&w.s.pool, &w.f.tenant.id, &app, &w.f.api.sp_id)
        .await
        .unwrap();
    assert!(send(someone_else).await.field("SAMLResponse").is_none());
    let ticket = saml::create_launch_ticket(&w.s.pool, &w.f.tenant.id, &app, &w.f.user_id)
        .await
        .unwrap();
    assert!(send(ticket.clone()).await.field("SAMLResponse").is_some());
    assert!(
        send(ticket).await.field("SAMLResponse").is_none(),
        "a ticket is single-use"
    );
}

#[tokio::test]
async fn a_transient_request_does_not_replace_the_name_id_told_at_logout() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let transient = authn_request(
        "",
        r#"<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>"#,
    );
    b.get(&redirect_url(&w.s, &w.f.tenant.id, &transient, None)).await;
    let (names,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &w.s.pool,
        "SELECT COUNT(*) FROM saml_session_participants WHERE name_id = ?",
    ))
    .bind(&w.f.upn)
    .fetch_one(&w.s.pool)
    .await
    .unwrap();
    assert_eq!(names, 1, "the first assertion's subject is still recorded");
    let (both,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &w.s.pool,
        "SELECT COUNT(*) FROM saml_session_participants",
    ))
    .fetch_one(&w.s.pool)
    .await
    .unwrap();
    assert_eq!(both, 2, "the transient subject is recorded beside it");
    for _ in 0..12 {
        b.get(&redirect_url(&w.s, &w.f.tenant.id, &transient, None)).await;
    }
    let (n,): (i64,) = sqlx::query_as(rust_oidc::db::q(
        &w.s.pool,
        "SELECT COUNT(*) FROM saml_session_participants",
    ))
    .fetch_one(&w.s.pool)
    .await
    .unwrap();
    assert!(n <= 8, "{n} entries for one application");
}

#[tokio::test]
async fn logout_still_tells_an_application_the_previous_user_signed_in_to() {
    let w = world().await;
    let second = "https://second.example/";
    saml_app(&w.s, &w.f, "second", second).await;
    let (b, _) = signed_in(&w).await;
    rust_oidc::users::create(
        &w.s.pool,
        &w.f.tenant,
        rust_oidc::users::NewUser {
            upn: "bob@contoso.com",
            password: &w.f.password,
            display_name: Some("Bob"),
            given_name: None,
            family_name: None,
            email: None,
        },
    )
    .await
    .unwrap();
    let forced = authn_request(r#"ForceAuthn="true""#, "").replace(ENTITY, second);
    let page = b.get(&redirect_url(&w.s, &w.f.tenant.id, &forced, None)).await;
    let page = b.login(&page, "bob@contoso.com", &w.f.password).await;
    assert!(page.field("SAMLResponse").is_some(), "{}", page.body);
    let told = b.get(&logout_url(&w, &logout_request(second))).await;
    let request = decoded_location(&told, "SAMLRequest");
    assert_eq!(request.child(NS_ASSERTION, "NameID").unwrap().text, w.f.upn);
}

#[tokio::test]
async fn a_logout_keeps_the_browser_cookie_of_one_already_in_progress() {
    let w = world().await;
    let second = "https://second.example/";
    saml_app(&w.s, &w.f, "second", second).await;
    let to_second = authn_request("", "").replace(ENTITY, second);
    let binding = |page: &Page| {
        page.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .find_map(|c| c.strip_prefix("saml_logout="))
            .map(|c| c.split(';').next().unwrap().to_string())
            .expect("the logout sets its browser cookie")
    };
    let (b, _) = signed_in(&w).await;
    b.get(&redirect_url(&w.s, &w.f.tenant.id, &to_second, None)).await;
    let first = b.get(&logout_url(&w, &logout_request(ENTITY))).await;
    // A second logout starts before the first was answered.
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    b.login(&page, &w.f.upn, &w.f.password).await;
    b.get(&redirect_url(&w.s, &w.f.tenant.id, &to_second, None)).await;
    let again = b.get(&logout_url(&w, &logout_request(ENTITY))).await;
    assert_eq!(binding(&first), binding(&again));
}

#[tokio::test]
async fn an_application_that_cannot_be_told_makes_an_oidc_logout_partial() {
    let w = world().await;
    let (b, _) = signed_in(&w).await;
    let save = SaveSamlBasic {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        basic: BasicConfig {
            logout_url: None,
            ..basic(ENTITY)
        },
    };
    txn::run(&w.s.pool, &Actor::Cli, &save).await.into_result().unwrap();
    let page = b.get(&w.s.url(&format!("/{}/oauth2/v2.0/logout", w.f.tenant.id))).await;
    assert!(page.body.contains("may still be signed in"), "{}", page.body);
}

#[tokio::test]
async fn a_url_that_cannot_go_in_a_location_header_is_refused() {
    assert!(saml::url_problem("Logout URL", "https://sp.example/caf\u{e9}").is_some());
    assert!(saml::url_problem("Logout URL", "https://sp.example/caf%C3%A9").is_none());
}

// ---- accounts of another tenant ----

/// `w`'s application, and zed of Fabrikam.
async fn guest(w: &World) -> UserFixture {
    let fabrikam = w.s.tenant("Fabrikam", "fabrikam.test").await;
    user_fixture_in(&w.s, fabrikam, "zed@fabrikam.test").await
}

async fn accept_others(w: &World) {
    let sp = apps::service_principal(&w.s.pool, &w.f.tenant.id, &w.app_id)
        .await
        .unwrap()
        .unwrap();
    apps::set_accept_other_tenants(&w.s.pool, &sp, true).await.unwrap();
}

async fn home_allows(w: &World, zed: &UserFixture, on: bool) {
    let mut settings = rust_oidc::tenant::find_for_admin(&w.s.pool, &zed.tenant.id)
        .await
        .unwrap()
        .settings;
    settings.allow_cross_tenant_sign_in = on;
    rust_oidc::tenant::save_settings(&w.s.pool, &zed.tenant.id, &settings)
        .await
        .unwrap();
}

async fn assign_guest(w: &World, zed: &UserFixture) {
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    apps::assign(&w.s.pool, &w.f.tenant, &app, &Principal::User(zed.upn.clone()), &[])
        .await
        .unwrap();
}

async fn guest_signs_in(w: &World, zed: &UserFixture) -> Page {
    let b = Browser::new();
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    b.login(&page, &zed.upn, &zed.password).await
}

#[tokio::test]
async fn a_guest_needs_the_application_the_assignment_and_their_tenant() {
    let w = world().await;
    let zed = guest(&w).await;
    // The application does not accept other tenants.
    assert!(guest_signs_in(&w, &zed).await.field("SAMLResponse").is_none());
    accept_others(&w).await;
    // Accepted, but not assigned.
    assert!(guest_signs_in(&w, &zed).await.field("SAMLResponse").is_none());
    assign_guest(&w, &zed).await;
    // Assigned, but their own tenant does not let them.
    assert!(guest_signs_in(&w, &zed).await.field("SAMLResponse").is_none());
    home_allows(&w, &zed, true).await;
    let page = guest_signs_in(&w, &zed).await;
    assert_eq!(status_codes(&response_of(&page)), vec![protocol::STATUS_SUCCESS]);
}

#[tokio::test]
async fn a_guests_assertion_says_where_they_are_from_and_carries_no_home_groups() {
    let w = world().await;
    let zed = guest(&w).await;
    accept_others(&w).await;
    assign_guest(&w, &zed).await;
    home_allows(&w, &zed, true).await;
    rust_oidc::groups::create(&w.s.pool, &zed.tenant, "fabrikam-staff", None)
        .await
        .unwrap();
    rust_oidc::groups::add_member(&w.s.pool, &zed.tenant, "fabrikam-staff", &zed.upn)
        .await
        .unwrap();
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    apps::set_group_membership_claims(&w.s.pool, &app, apps::GroupMembershipClaims::All)
        .await
        .unwrap();
    let page = guest_signs_in(&w, &zed).await;
    let response = response_of(&page);
    let assertion = response.child(NS_ASSERTION, "Assertion").unwrap();
    assert_eq!(
        attribute(assertion, saml::CLAIM_IDENTITY_PROVIDER),
        vec![w.s.issuer(&zed.tenant.id)]
    );
    assert_eq!(attribute(assertion, saml::CLAIM_TENANT), vec![w.f.tenant.id.clone()]);
    assert!(attribute(assertion, saml::CLAIM_GROUPS).is_empty());
}

#[tokio::test]
async fn a_guests_unverified_email_never_identifies_them() {
    let w = world().await;
    let zed = guest(&w).await;
    accept_others(&w).await;
    assign_guest(&w, &zed).await;
    home_allows(&w, &zed, true).await;
    // The application identifies users by email, and zed's says they are alice.
    let save = rust_oidc::txn::ops::saml::SaveSamlClaims {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        name_id_format: protocol::NameIdFormat::EmailAddress,
        name_id_source: saml::NameIdSource::Mail,
        claims: vec![saml::Claim {
            name: saml::DEFAULT_CLAIMS[0].0.to_string(),
            source: saml::ClaimSource::Mail,
        }],
    };
    txn::run(&w.s.pool, &Actor::Cli, &save).await.into_result().unwrap();
    sqlx::query(rust_oidc::db::q(
        &w.s.pool,
        "UPDATE users SET email = ?, email_verified = ? WHERE id = ?",
    ))
    .bind(&w.f.upn)
    .bind(false)
    .bind(&zed.user_id)
    .execute(&w.s.pool)
    .await
    .unwrap();
    let page = guest_signs_in(&w, &zed).await;
    let response = response_of(&page);
    let assertion = response.child(NS_ASSERTION, "Assertion").unwrap();
    let name_id = &assertion
        .child(NS_ASSERTION, "Subject")
        .and_then(|s| s.child(NS_ASSERTION, "NameID"))
        .unwrap()
        .text;
    assert_eq!(name_id, &zed.upn);
    assert!(attribute(assertion, saml::DEFAULT_CLAIMS[0].0).is_empty());
}

#[tokio::test]
async fn a_guest_opens_the_application_from_their_own_gallery() {
    let w = world().await;
    let zed = guest(&w).await;
    accept_others(&w).await;
    assign_guest(&w, &zed).await;
    let b = Browser::new();
    let url = w.s.url(&format!("/{}/myaccount", zed.tenant.id));
    let page = b.get(&url).await;
    let page = b.login(&page, &zed.upn, &zed.password).await;
    let mine = if page.status == 303 || page.status == 302 {
        b.get(&url).await
    } else {
        page
    };
    assert!(!mine.body.contains("legacy-app"), "their tenant does not let them yet");
    home_allows(&w, &zed, true).await;
    let mine = b.get(&url).await;
    assert!(mine.body.contains("legacy-app"), "{}", mine.body);
    let csrf = mine.field("csrf").unwrap();
    let launch = rust_oidc::html::AccountOp::LaunchApp.as_str();
    let login = b
        .post_form(
            &url,
            &[("csrf", csrf.as_str()), ("op", launch), ("app", w.app_id.as_str())],
        )
        .await;
    assert!(
        login.body.contains(&format!(r#"value="{}""#, zed.upn)),
        "{}",
        login.body
    );
    let answer = b.login(&login, &zed.upn, &zed.password).await;
    assert_eq!(answer.form_action(), ACS);
    assert_eq!(status_codes(&response_of(&answer)), vec![protocol::STATUS_SUCCESS]);
}

// ---- Check sign-in ----

async fn check_page(w: &World, admin: &AdminBrowser, upn: &str) -> Page {
    admin
        .get(&w.s.url(&format!(
            "/admin/tenants/{}/apps/{}/check?upn={upn}",
            w.f.tenant.id, w.app_id
        )))
        .await
}

async fn check_admin(w: &World) -> AdminBrowser {
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::ApplicationAdministrator).await;
    signed_in_admin(&w.s, &w.f).await
}

#[tokio::test]
async fn check_sign_in_reports_saml_and_what_the_real_assertion_says() {
    let w = world().await;
    let admin = check_admin(&w).await;
    let page = check_page(&w, &admin, &w.f.upn).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("alice@contoso.com can sign in to"), "{}", page.body);
    assert!(
        page.body.contains("Sign-in started by the application"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Opening it from My apps"), "{}", page.body);
    assert!(page.body.contains("In the SAML assertion"), "{}", page.body);
    assert!(!page.body.contains("Password grant"), "OAuth rows do not apply");
    assert!(!page.body.contains("In the token"), "OAuth rows do not apply");

    // What it says is what a real sign-in sends.
    let (_, signed) = signed_in(&w).await;
    let response = response_of(&signed);
    let name_id = &response
        .child(NS_ASSERTION, "Assertion")
        .and_then(|a| a.child(NS_ASSERTION, "Subject"))
        .and_then(|s| s.child(NS_ASSERTION, "NameID"))
        .unwrap()
        .text;
    assert!(
        page.body.contains(&format!("Name ID (Email address): {name_id}")),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn check_sign_in_says_when_saml_setup_stops_a_sign_in() {
    let w = world().await;
    let admin = check_admin(&w).await;
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    let active = saml::certificates(&w.s.pool, &app).await.unwrap().remove(0);
    sqlx::query(rust_oidc::db::q(
        &w.s.pool,
        "UPDATE app_saml_certificates SET not_after = 1 WHERE id = ?",
    ))
    .bind(&active.id)
    .execute(&w.s.pool)
    .await
    .unwrap();
    let page = check_page(&w, &admin, &w.f.upn).await;
    assert!(
        page.body.contains("alice@contoso.com cannot sign in to"),
        "{}",
        page.body
    );
    assert!(page.body.contains("signing certificate has expired"), "{}", page.body);
}

#[tokio::test]
async fn check_sign_in_says_why_the_gallery_does_not_list_it() {
    let w = world().await;
    let admin = check_admin(&w).await;
    let page = check_page(&w, &admin, &w.f.upn).await;
    assert!(
        page.body.contains("only applications the user is assigned to"),
        "{}",
        page.body
    );
    assign(&w).await;
    let page = check_page(&w, &admin, &w.f.upn).await;
    assert!(page.body.contains("Listed: signs in here"), "{}", page.body);
    let hide = SetAppVisibility {
        tenant_id: w.f.tenant.id.clone(),
        app_id: w.app_id.clone(),
        visible: false,
    };
    txn::run(&w.s.pool, &Actor::Cli, &hide).await.into_result().unwrap();
    let page = check_page(&w, &admin, &w.f.upn).await;
    assert!(page.body.contains("not visible to users"), "{}", page.body);
}

#[tokio::test]
async fn check_sign_in_shows_a_guests_values_only_once_they_may_come_here() {
    let w = world().await;
    let admin = check_admin(&w).await;
    let zed = guest(&w).await;
    accept_others(&w).await;
    assign_guest(&w, &zed).await;
    sqlx::query(rust_oidc::db::q(
        &w.s.pool,
        "UPDATE users SET display_name = ? WHERE id = ?",
    ))
    .bind("Zed Private Name")
    .bind(&zed.user_id)
    .execute(&w.s.pool)
    .await
    .unwrap();
    let page = check_page(&w, &admin, &zed.upn).await;
    assert!(page.body.contains("cannot sign in"), "{}", page.body);
    assert!(!page.body.contains("Zed Private Name"), "{}", page.body);
    assert!(page.body.contains("Values are not shown"), "{}", page.body);
    home_allows(&w, &zed, true).await;
    let page = check_page(&w, &admin, &zed.upn).await;
    assert!(page.body.contains("can sign in"), "{}", page.body);
    assert!(page.body.contains("Zed Private Name"), "{}", page.body);
    assert!(page.body.contains("withheld"), "{}", page.body);
}

#[tokio::test]
async fn check_sign_in_is_unchanged_for_an_oidc_application() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind_in_own_tenant(&s, &f, rust_oidc::rbac::RoleId::ApplicationAdministrator).await;
    let admin = signed_in_admin(&s, &f).await;
    let page = admin
        .get(&s.url(&format!(
            "/admin/tenants/{}/apps/{}/check?upn={}",
            f.tenant.id, f.web.app_id, f.upn
        )))
        .await;
    assert!(page.body.contains("Password grant"), "{}", page.body);
    assert!(page.body.contains("In the token"), "{}", page.body);
    assert!(!page.body.contains("SAML setup"), "{}", page.body);
}

/// An SP metadata file: two POST endpoints, the second marked default, and an
/// Artifact one that cannot be used.
fn sp_metadata(entity: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://imported.example/slo"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://imported.example/art" index="0"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://imported.example/acs-1" index="1"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://imported.example/acs-2" index="2" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>"#
    )
}

async fn saved_config(w: &World) -> saml::SamlConfig {
    let app = apps::find(&w.s.pool, &w.app_id).await.unwrap().unwrap();
    saml::config(&w.s.pool, &app).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_metadata_file_fills_in_basic_saml_configuration_for_review() {
    let w = world().await;
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::TenantAdministrator).await;
    let a = signed_in_admin(&w.s, &w.f).await;
    let url = w.s.url(&format!("/admin/tenants/{}/apps/{}", w.f.tenant.id, w.app_id));
    let before = saved_config(&w).await;

    let entity = "https://imported.example/";
    let page = a
        .post_file(
            &url,
            &[("op", "saml_metadata_import")],
            ("metadata_file", "sp.xml", &sp_metadata(entity)),
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Review the values"), "{}", page.body);
    assert!(
        page.body.contains("https://imported.example/acs-1 index=1"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("https://imported.example/acs-2 index=2 default"),
        "{}",
        page.body
    );
    assert!(page.body.contains("https://imported.example/slo"), "{}", page.body);
    assert!(!page.body.contains("https://imported.example/art"), "{}", page.body);
    // Reading the file changes nothing.
    assert_eq!(saved_config(&w).await, before);

    // Saving the reviewed form keeps the indexes and the default.
    let saved = a
        .post(
            &url,
            &[
                ("op", "saml_basic"),
                ("identifiers", &format!("{entity}\n{ENTITY}")),
                (
                    "reply_urls",
                    "https://imported.example/acs-1 index=1\nhttps://imported.example/acs-2 index=2 default",
                ),
                ("logout_url", "https://imported.example/slo"),
            ],
        )
        .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let config = saved_config(&w).await;
    assert_eq!(config.default_reply_url(), Some("https://imported.example/acs-2"));
    assert_eq!(
        config.reply_url_for(None, Some(1)),
        Some("https://imported.example/acs-1")
    );
    assert_eq!(config.reply_url_for(None, Some(0)), None);
    assert_eq!(config.logout_url.as_deref(), Some("https://imported.example/slo"));

    // A file that is not one application's metadata is refused with the reason.
    let two = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">{}{}</md:EntitiesDescriptor>"#,
        sp_metadata("https://one.example/").replace(r#"<?xml version="1.0"?>"#, ""),
        sp_metadata("https://two.example/").replace(r#"<?xml version="1.0"?>"#, "")
    );
    let page = a
        .post_file(
            &url,
            &[("op", "saml_metadata_import")],
            ("metadata_file", "sp.xml", &two),
        )
        .await;
    assert_eq!(page.status, 400);
    assert!(page.body.contains("2 service providers"), "{}", page.body);
}

#[tokio::test]
async fn reply_urls_keep_their_index_and_default_through_the_form() {
    let w = world().await;
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::TenantAdministrator).await;
    let a = signed_in_admin(&w.s, &w.f).await;
    let url = w.s.url(&format!("/admin/tenants/{}/apps/{}", w.f.tenant.id, w.app_id));
    let save = |replies: &'static str| {
        let a = &a;
        let url = url.clone();
        async move {
            a.post(
                &url,
                &[("op", "saml_basic"), ("identifiers", ENTITY), ("reply_urls", replies)],
            )
            .await
        }
    };
    // Plain lines: indexed in order, the first the default.
    assert_eq!(save("https://a.example/acs\nhttps://b.example/acs").await.status, 303);
    let c = saved_config(&w).await;
    assert_eq!(c.default_reply_url(), Some("https://a.example/acs"));
    assert_eq!(c.reply_url_for(None, Some(1)), Some("https://b.example/acs"));
    // A line without an index takes the lowest unused one.
    assert_eq!(
        save("https://a.example/acs index=0\nhttps://b.example/acs default")
            .await
            .status,
        303
    );
    let c = saved_config(&w).await;
    assert_eq!(c.default_reply_url(), Some("https://b.example/acs"));
    assert_eq!(c.reply_url_for(None, Some(1)), Some("https://b.example/acs"));
    // Refused: two defaults, a repeated index, an unknown word.
    for bad in [
        "https://a.example/acs default\nhttps://b.example/acs default",
        "https://a.example/acs index=3\nhttps://b.example/acs index=3",
        "https://a.example/acs primary",
    ] {
        assert_eq!(save(bad).await.status, 400, "{bad}");
    }
    assert_eq!(
        saved_config(&w).await.default_reply_url(),
        Some("https://b.example/acs")
    );
}

#[tokio::test]
async fn the_encryption_method_can_change_without_the_certificate() {
    let w = world().await;
    bind_in_own_tenant(&w.s, &w.f, rust_oidc::rbac::RoleId::TenantAdministrator).await;
    let a = signed_in_admin(&w.s, &w.f).await;
    let url = w.s.url(&format!("/admin/tenants/{}/apps/{}", w.f.tenant.id, w.app_id));
    // A newly set up application starts with the recommended choice.
    assert_eq!(
        saved_config(&w).await.encryption_algorithms,
        protocol::EncryptionAlgorithms::RECOMMENDED
    );
    let (_, _, cert_pem) = sp_key();
    let choose = |content: &'static str, cert: String| {
        let a = &a;
        let url = url.clone();
        async move {
            a.post(
                &url,
                &[
                    ("op", "saml_encryption"),
                    ("encryption_method", content),
                    ("key_transport", "rsa-oaep-mgf1p"),
                    ("key_transport_digest", "sha256"),
                    ("certificate", &cert),
                ],
            )
            .await
        }
    };
    assert_eq!(choose("aes256-cbc", cert_pem.clone()).await.status, 303);
    let with_cert = saved_config(&w).await.encryption_cert.clone();
    assert!(with_cert.is_some());

    // Only the method changes; the certificate stays.
    assert_eq!(choose("aes128-gcm", String::new()).await.status, 303);
    let config = saved_config(&w).await;
    assert_eq!(config.encryption_cert, with_cert);
    assert_eq!(
        config.encryption_algorithms.content,
        protocol::ContentEncryption::Aes128Gcm
    );
    assert_eq!(
        config.encryption_algorithms.digest,
        protocol::KeyTransportDigest::Sha256
    );

    // A sign-in encrypts that way.
    let (b, _) = signed_in(&w).await;
    let page = b
        .get(&redirect_url(&w.s, &w.f.tenant.id, &authn_request("", ""), None))
        .await;
    let xml = response_xml(&page);
    assert!(xml.contains("http://www.w3.org/2009/xmlenc11#aes128-gcm"), "{xml}");
    assert!(xml.contains("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"), "{xml}");

    // An unknown method is refused and nothing changes.
    assert_eq!(choose("aes512-xyz", String::new()).await.status, 400);
    assert_eq!(saved_config(&w).await, config);

    // Stop encrypting.
    let stopped = a
        .post(
            &url,
            &[
                ("op", "saml_encryption"),
                ("encryption_method", "aes256-gcm"),
                ("key_transport", "rsa-oaep"),
                ("key_transport_digest", "sha256"),
                ("encryption_action", "stop"),
            ],
        )
        .await;
    assert_eq!(stopped.status, 303);
    assert!(saved_config(&w).await.encryption_cert.is_none());
}
