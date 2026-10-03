//! Changes to applications, run through the transaction engine without HTTP:
//! each kind completes with its audit row, and is refused with nothing changed.

mod common;

use common::*;
use rust_oidc::admin::bindings;
use rust_oidc::apps::{self, MemberType, PreparedSecret, Principal, RedirectPlatform, ScopeConsent, SecretCheck};
use rust_oidc::db::Event;
use rust_oidc::txn::ops::apps::{
    AddAppCertificate, AddAppRole, AddAppScope, AddAppSecret, AddIdentifierUri, AddRedirectUri, AssignApp, CreateApp,
    GrantAppRole, RemoveAppCertificate, RemoveAppSecret, RemoveIdentifierUri, RemoveRedirectUri, RevokeAppRole,
    SaveAppFlags, SetAssignmentRequired, UnassignApp,
};
use rust_oidc::txn::{self, Actor, Outcome, Refusal};
use serde_json::Value;

async fn admin(s: &TestServer, user_id: &str) -> Actor {
    Actor::Admin {
        user_id: user_id.to_string(),
        bindings: bindings::effective_for_user(&s.pool, user_id).await.unwrap(),
    }
}

/// (target, details) of every row of this event, oldest first.
async fn rows(s: &TestServer, event: Event) -> Vec<(Option<String>, Value)> {
    let raw: Vec<(Option<String>, String)> = sqlx::query_as(rust_oidc::db::q(
        &s.pool,
        "SELECT target, details FROM audit_log WHERE action = ? ORDER BY id",
    ))
    .bind(event.as_str())
    .fetch_all(&s.pool)
    .await
    .unwrap();
    raw.into_iter()
        .map(|(t, d)| (t, serde_json::from_str(&d).unwrap()))
        .collect()
}

fn refused<T: std::fmt::Debug>(outcome: &Outcome<T>) -> bool {
    matches!(outcome, Outcome::Refused(_))
}

/// A Global Administrator, the Contoso fixture and its web app.
struct World {
    s: TestServer,
    f: UserFixture,
    actor: Actor,
}

async fn world() -> World {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let actor = admin(&s, &f.user_id).await;
    World { s, f, actor }
}

impl World {
    fn tid(&self) -> String {
        self.f.tenant.id.clone()
    }
    fn web(&self) -> String {
        self.f.web.app_id.clone()
    }
    async fn app(&self) -> apps::Application {
        apps::find_in_tenant(&self.s.pool, &self.f.tenant, &self.f.web.app_id)
            .await
            .unwrap()
    }
    async fn sp(&self) -> apps::ServicePrincipal {
        apps::service_principal(&self.s.pool, &self.f.tenant.id, &self.f.web.app_id)
            .await
            .unwrap()
            .unwrap()
    }
    fn flags(&self, accept_other_tenants: bool, on: bool) -> SaveAppFlags {
        SaveAppFlags {
            tenant_id: self.tid(),
            app_id: self.web(),
            accept_other_tenants,
            mfa_required: on,
            allow_password_grant: on,
            allow_id_token_implicit: on,
            allow_access_token_implicit: on,
        }
    }
}

fn make_cert_pem() -> (String, String) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "txn-apps");
    params.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(30);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

// ---- create ----

#[tokio::test]
async fn an_application_is_created_with_its_audit_row() {
    let w = world().await;
    let create = CreateApp {
        tenant_id: w.tid(),
        display_name: "billing".into(),
    };
    let app = txn::run(&w.s.pool, &w.actor, &create).await.into_result().unwrap();
    assert!(apps::find(&w.s.pool, &app.app_id).await.unwrap().is_some());
    assert!(
        apps::service_principal(&w.s.pool, &w.tid(), &app.app_id)
            .await
            .unwrap()
            .is_some()
    );
    let audit = rows(&w.s, Event::AdminAppCreate).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(app.app_id.as_str()));
    assert_eq!(audit[0].1["displayName"], "billing");
}

#[tokio::test]
async fn an_application_needs_a_name_and_the_right_role() {
    let w = world().await;
    let before = apps::list(&w.s.pool, &w.tid()).await.unwrap().len();
    let nameless = CreateApp {
        tenant_id: w.tid(),
        display_name: "  ".into(),
    };
    let outcome = txn::run(&w.s.pool, &w.actor, &nameless).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");

    let s = TestServer::start().await;
    let r = reader_fixture(&s).await;
    let create = CreateApp {
        tenant_id: r.tenant.id.clone(),
        display_name: "billing".into(),
    };
    let outcome = txn::run(&s.pool, &admin(&s, &r.user_id).await, &create).await;
    assert_eq!(outcome.map_done(), Outcome::Refused(Refusal::NotPermitted));

    assert_eq!(apps::list(&w.s.pool, &w.tid()).await.unwrap().len(), before);
    assert!(rows(&w.s, Event::AdminAppCreate).await.is_empty());
}

// ---- sign-in and grants (TODO gaps 1 and 4) ----

#[tokio::test]
async fn the_flags_are_saved_together_with_one_audit_row() {
    let w = world().await;
    txn::run(&w.s.pool, &w.actor, &w.flags(true, true))
        .await
        .into_result()
        .unwrap();
    let app = w.app().await;
    let sp = w.sp().await;
    assert!(app.allow_password_grant && app.allow_id_token_implicit && app.allow_access_token_implicit);
    assert!(sp.mfa_required && sp.accept_other_tenants);
    let audit = rows(&w.s, Event::AdminAppFlags).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0.as_deref(), Some(w.web().as_str()));
    assert_eq!(audit[0].1["allowPasswordGrant"], true);
    assert_eq!(audit[0].1["acceptOtherTenants"], true);
}

/// Gaps 1 and 4: stopping accepting other tenants while one of theirs is
/// assigned is refused, and the other switches in the same save, written before
/// the refusal, are not saved either. No audit row.
#[tokio::test]
async fn a_refused_flags_save_changes_none_of_them() {
    let w = world().await;
    let fabrikam = w.s.tenant("Fabrikam", "fabrikam.test").await;
    let zed = user_fixture_in(&w.s, fabrikam, "zed@fabrikam.test").await;
    // Accept others (everything else off), and assign zed.
    txn::run(&w.s.pool, &w.actor, &w.flags(true, false))
        .await
        .into_result()
        .unwrap();
    let assign = AssignApp {
        tenant_id: w.tid(),
        app_id: w.web(),
        principal: Principal::User(zed.upn.clone()),
        roles: vec![],
    };
    let assignment = txn::run(&w.s.pool, &w.actor, &assign).await.into_result().unwrap();

    // Every other switch on, and accept-others off: refused.
    let outcome = txn::run(&w.s.pool, &w.actor, &w.flags(false, true)).await;
    match &outcome {
        Outcome::Refused(Refusal::Invalid(m)) => assert!(m.contains("other tenants"), "{m}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let app = w.app().await;
    let sp = w.sp().await;
    assert!(!app.allow_password_grant, "written before the refusal, rolled back");
    assert!(!app.allow_id_token_implicit && !app.allow_access_token_implicit);
    assert!(!sp.mfa_required);
    assert!(sp.accept_other_tenants, "unchanged");
    assert_eq!(rows(&w.s, Event::AdminAppFlags).await.len(), 1, "only the first save");

    // Withdrawn, the same save goes through.
    let unassign = UnassignApp {
        tenant_id: w.tid(),
        app_id: w.web(),
        assignment_id: assignment,
    };
    txn::run(&w.s.pool, &w.actor, &unassign).await.into_result().unwrap();
    txn::run(&w.s.pool, &w.actor, &w.flags(false, true))
        .await
        .into_result()
        .unwrap();
    assert!(!w.sp().await.accept_other_tenants);
    assert!(w.app().await.allow_password_grant);
}

#[tokio::test]
async fn the_flags_of_an_application_of_another_tenant_are_not_found() {
    let w = world().await;
    let other = w.s.tenant("Fabrikam", "fabrikam.test").await;
    let theirs = w.s.app(&other, "theirs").await;
    let mut save = w.flags(true, true);
    save.app_id = theirs.app_id.clone();
    let outcome = txn::run(&w.s.pool, &w.actor, &save).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(rows(&w.s, Event::AdminAppFlags).await.is_empty());
}

// ---- secrets ----

#[tokio::test]
async fn a_secret_is_added_and_its_value_never_audited() {
    let w = world().await;
    let add = AddAppSecret {
        tenant_id: w.tid(),
        app_id: w.web(),
        secret: PreparedSecret::generate(),
        valid_days: 30,
        display_name: Some("ci".into()),
    };
    let created = txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    assert_eq!(
        apps::verify_secret(&w.s.pool, &w.app().await, &created.secret)
            .await
            .unwrap(),
        SecretCheck::Valid
    );
    let audit = rows(&w.s, Event::AdminAppSecretAdd).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].1["keyId"], created.key_id.as_str());
    let raw = audit[0].1.to_string();
    assert!(!raw.contains(&created.secret), "the value is in the audit row");
    assert!(
        !format!("{created:?}").contains(&created.secret),
        "Debug shows the value"
    );

    let remove = RemoveAppSecret {
        tenant_id: w.tid(),
        app_id: w.web(),
        key_id: created.key_id.clone(),
    };
    txn::run(&w.s.pool, &w.actor, &remove).await.into_result().unwrap();
    assert_eq!(
        apps::verify_secret(&w.s.pool, &w.app().await, &created.secret)
            .await
            .unwrap(),
        SecretCheck::Invalid
    );
    assert_eq!(rows(&w.s, Event::AdminAppSecretRemove).await.len(), 1);
}

#[tokio::test]
async fn a_secret_out_of_range_or_unknown_is_refused() {
    let w = world().await;
    let before = apps::secrets(&w.s.pool, &w.app().await).await.unwrap().len();
    let add = AddAppSecret {
        tenant_id: w.tid(),
        app_id: w.web(),
        secret: PreparedSecret::generate(),
        valid_days: 731,
        display_name: None,
    };
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &add).await));
    assert_eq!(apps::secrets(&w.s.pool, &w.app().await).await.unwrap().len(), before);
    assert!(rows(&w.s, Event::AdminAppSecretAdd).await.is_empty());

    let remove = RemoveAppSecret {
        tenant_id: w.tid(),
        app_id: w.web(),
        key_id: "not-a-key".into(),
    };
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &remove).await));
    assert!(rows(&w.s, Event::AdminAppSecretRemove).await.is_empty());
}

/// Credentials are `App:Rotate`: a role without it cannot add one.
#[tokio::test]
async fn a_secret_needs_its_own_action() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    bind_in_own_tenant(&s, &f, rust_oidc::rbac::RoleId::ApplicationViewer).await;
    let add = AddAppSecret {
        tenant_id: f.tenant.id.clone(),
        app_id: f.web.app_id.clone(),
        secret: PreparedSecret::generate(),
        valid_days: 30,
        display_name: None,
    };
    let outcome = txn::run(&s.pool, &admin(&s, &f.user_id).await, &add).await;
    assert_eq!(outcome.map_done(), Outcome::Refused(Refusal::NotPermitted));
}

// ---- certificates ----

#[tokio::test]
async fn a_certificate_is_added_and_removed() {
    let w = world().await;
    let (pem, _) = make_cert_pem();
    let add = AddAppCertificate {
        tenant_id: w.tid(),
        app_id: w.web(),
        certificate_pem: pem,
        display_name: None,
    };
    let key_id = txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    assert_eq!(apps::key_credentials(&w.s.pool, &w.app().await).await.unwrap().len(), 1);
    let audit = rows(&w.s, Event::AdminAppKeyAdd).await;
    assert_eq!(audit[0].1["keyId"], key_id.as_str());

    let remove = RemoveAppCertificate {
        tenant_id: w.tid(),
        app_id: w.web(),
        key_id: key_id.clone(),
    };
    txn::run(&w.s.pool, &w.actor, &remove).await.into_result().unwrap();
    assert!(
        apps::key_credentials(&w.s.pool, &w.app().await)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(rows(&w.s, Event::AdminAppKeyRemove).await.len(), 1);

    // Gone, it cannot be removed again.
    assert!(matches!(
        txn::run(&w.s.pool, &w.actor, &remove).await,
        Outcome::Refused(Refusal::NotFound(_))
    ));
    assert_eq!(rows(&w.s, Event::AdminAppKeyRemove).await.len(), 1);
}

#[tokio::test]
async fn a_pasted_private_key_is_refused() {
    let w = world().await;
    let (pem, key) = make_cert_pem();
    let add = AddAppCertificate {
        tenant_id: w.tid(),
        app_id: w.web(),
        certificate_pem: format!("{pem}\n{key}"),
        display_name: None,
    };
    let outcome = txn::run(&w.s.pool, &w.actor, &add).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::Invalid(_))), "{outcome:?}");
    assert!(
        apps::key_credentials(&w.s.pool, &w.app().await)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(rows(&w.s, Event::AdminAppKeyAdd).await.is_empty());
}

// ---- redirect and identifier URIs ----

#[tokio::test]
async fn redirect_uris_are_added_and_removed() {
    let w = world().await;
    let uri = "https://app.example.com/other";
    let add = AddRedirectUri {
        tenant_id: w.tid(),
        app_id: w.web(),
        platform: RedirectPlatform::Web,
        uri: uri.into(),
    };
    txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    let registered = apps::redirect_uris(&w.s.pool, &w.app().await).await.unwrap();
    assert!(registered.contains(&(RedirectPlatform::Web, uri.to_string())));
    assert_eq!(rows(&w.s, Event::AdminAppRedirectUriAdd).await[0].1["uri"], uri);

    let remove = RemoveRedirectUri {
        tenant_id: w.tid(),
        app_id: w.web(),
        platform: RedirectPlatform::Web,
        uri: uri.into(),
    };
    txn::run(&w.s.pool, &w.actor, &remove).await.into_result().unwrap();
    assert_eq!(rows(&w.s, Event::AdminAppRedirectUriRemove).await.len(), 1);
    assert!(matches!(
        txn::run(&w.s.pool, &w.actor, &remove).await,
        Outcome::Refused(Refusal::NotFound(_))
    ));
    assert_eq!(rows(&w.s, Event::AdminAppRedirectUriRemove).await.len(), 1);
}

#[tokio::test]
async fn a_plain_http_web_redirect_uri_is_refused() {
    let w = world().await;
    let add = AddRedirectUri {
        tenant_id: w.tid(),
        app_id: w.web(),
        platform: RedirectPlatform::Web,
        uri: "http://app.example.com/cb".into(),
    };
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &add).await));
    assert!(rows(&w.s, Event::AdminAppRedirectUriAdd).await.is_empty());
}

#[tokio::test]
async fn identifier_uris_are_added_and_the_last_is_kept() {
    let w = world().await;
    let default = format!("api://{}", w.web());
    let add = AddIdentifierUri {
        tenant_id: w.tid(),
        app_id: w.web(),
        uri: "api://billing".into(),
    };
    txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    assert_eq!(rows(&w.s, Event::AdminAppIdentifierUriAdd).await.len(), 1);
    // Taken: refused by name, not failed on the constraint.
    let again = txn::run(&w.s.pool, &w.actor, &add).await;
    assert!(matches!(again, Outcome::Refused(Refusal::Invalid(_))), "{again:?}");
    assert_eq!(rows(&w.s, Event::AdminAppIdentifierUriAdd).await.len(), 1);
    let remove = |uri: &str| RemoveIdentifierUri {
        tenant_id: w.tid(),
        app_id: w.web(),
        uri: uri.into(),
    };
    txn::run(&w.s.pool, &w.actor, &remove(&default))
        .await
        .into_result()
        .unwrap();
    assert_eq!(rows(&w.s, Event::AdminAppIdentifierUriRemove).await.len(), 1);
    // The last one stays.
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &remove("api://billing")).await));
    assert_eq!(
        apps::identifier_uris(&w.s.pool, &w.app().await).await.unwrap(),
        vec!["api://billing".to_string()]
    );
    assert_eq!(rows(&w.s, Event::AdminAppIdentifierUriRemove).await.len(), 1);
}

// ---- scopes and roles ----

#[tokio::test]
async fn a_scope_is_added_once() {
    let w = world().await;
    let add = AddAppScope {
        tenant_id: w.tid(),
        app_id: w.web(),
        value: "Billing.Read".into(),
        consent: ScopeConsent::User,
        display_name: None,
    };
    let id = txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    let scopes = apps::scopes(&w.s.pool, &w.app().await).await.unwrap();
    let scope = scopes.iter().find(|s| s.id == id).unwrap();
    assert_eq!(
        scope.display_name, "Billing.Read",
        "the value stands in for a display name"
    );
    assert_eq!(rows(&w.s, Event::AdminAppScopeAdd).await[0].1["id"], id.as_str());

    assert!(refused(&txn::run(&w.s.pool, &w.actor, &add).await));
    assert_eq!(rows(&w.s, Event::AdminAppScopeAdd).await.len(), 1);
}

#[tokio::test]
async fn an_app_role_is_added_once() {
    let w = world().await;
    let add = AddAppRole {
        tenant_id: w.tid(),
        app_id: w.web(),
        value: "Billing.Admin".into(),
        member_types: vec![MemberType::User],
        display_name: Some("Billing admin".into()),
        description: None,
    };
    let id = txn::run(&w.s.pool, &w.actor, &add).await.into_result().unwrap();
    assert!(
        apps::roles(&w.s.pool, &w.app().await)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == id)
    );
    let audit = rows(&w.s, Event::AdminAppRoleAdd).await;
    assert_eq!(audit[0].1["allowedMemberTypes"][0], MemberType::User.as_str());

    assert!(refused(&txn::run(&w.s.pool, &w.actor, &add).await));
    assert_eq!(rows(&w.s, Event::AdminAppRoleAdd).await.len(), 1);
}

// ---- assignments ----

#[tokio::test]
async fn a_user_is_assigned_and_unassigned() {
    let w = world().await;
    let assign = AssignApp {
        tenant_id: w.tid(),
        app_id: w.f.api.app_id.clone(),
        principal: Principal::User(w.f.upn.clone()),
        roles: vec!["Orders.Approver".into()],
    };
    let id = txn::run(&w.s.pool, &w.actor, &assign).await.into_result().unwrap();
    let audit = rows(&w.s, Event::AdminAppAssign).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].1["assignmentId"], id.as_str());
    assert_eq!(audit[0].1["principalType"], "User");
    assert_eq!(audit[0].1["roles"][0], "Orders.Approver");

    let unassign = UnassignApp {
        tenant_id: w.tid(),
        app_id: w.f.api.app_id.clone(),
        assignment_id: id,
    };
    txn::run(&w.s.pool, &w.actor, &unassign).await.into_result().unwrap();
    assert_eq!(rows(&w.s, Event::AdminAppUnassign).await.len(), 1);
    assert!(matches!(
        txn::run(&w.s.pool, &w.actor, &unassign).await,
        Outcome::Refused(Refusal::NotFound(_))
    ));
    assert_eq!(rows(&w.s, Event::AdminAppUnassign).await.len(), 1);
}

#[tokio::test]
async fn an_unknown_or_outside_account_is_not_assigned() {
    let w = world().await;
    let assign = |name: &str| AssignApp {
        tenant_id: w.tid(),
        app_id: w.web(),
        principal: Principal::User(name.into()),
        roles: vec![],
    };
    assert!(refused(
        &txn::run(&w.s.pool, &w.actor, &assign("nobody@contoso.com")).await
    ));
    // Another tenant's, while the application accepts only its own.
    let fabrikam = w.s.tenant("Fabrikam", "fabrikam.test").await;
    let zed = user_fixture_in(&w.s, fabrikam, "zed@fabrikam.test").await;
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &assign(&zed.upn)).await));
    // An application is granted a role, not assigned.
    let as_app = AssignApp {
        principal: Principal::App(w.f.api.app_id.clone()),
        ..assign("x")
    };
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &as_app).await));
    assert!(
        apps::assignments(&w.s.pool, &w.tid(), &w.app().await)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(rows(&w.s, Event::AdminAppAssign).await.is_empty());
}

#[tokio::test]
async fn an_application_permission_is_granted_and_revoked() {
    let w = world().await;
    let api = apps::find(&w.s.pool, &w.f.api.app_id).await.unwrap().unwrap();
    apps::add_role(&w.s.pool, &api, "Orders.Sync", "Sync", None, &[MemberType::Application])
        .await
        .unwrap();
    let grant = |role: &str| GrantAppRole {
        tenant_id: w.tid(),
        app_id: w.f.api.app_id.clone(),
        role: role.into(),
        client_app_id: w.web(),
    };
    // A role only users may hold is refused to an application.
    assert!(refused(&txn::run(&w.s.pool, &w.actor, &grant("Orders.Approver")).await));
    assert!(rows(&w.s, Event::AdminAppRoleAssign).await.is_empty());

    txn::run(&w.s.pool, &w.actor, &grant("Orders.Sync"))
        .await
        .into_result()
        .unwrap();
    let audit = rows(&w.s, Event::AdminAppRoleAssign).await;
    assert_eq!(audit.len(), 1);
    // Granting it again changes nothing, and is not a failure.
    let again = txn::run(&w.s.pool, &w.actor, &grant("Orders.Sync")).await;
    assert!(again.is_done(), "{:?}", again.map_done());
    let held = apps::role_assignments(&w.s.pool, &w.tid(), &api).await.unwrap();
    assert_eq!(held.iter().filter(|g| g.role_value == "Orders.Sync").count(), 1);
    assert_eq!(audit[0].1["role"], "Orders.Sync");
    assert_eq!(audit[0].1["principalType"], "ServicePrincipal");

    let granted = apps::role_assignments(&w.s.pool, &w.tid(), &api).await.unwrap();
    let id = granted
        .iter()
        .find(|g| g.role_value == "Orders.Sync")
        .unwrap()
        .id
        .clone();
    let revoke = RevokeAppRole {
        tenant_id: w.tid(),
        app_id: w.f.api.app_id.clone(),
        assignment_id: id,
    };
    txn::run(&w.s.pool, &w.actor, &revoke).await.into_result().unwrap();
    assert_eq!(rows(&w.s, Event::AdminAppRoleUnassign).await.len(), 1);
    assert!(matches!(
        txn::run(&w.s.pool, &w.actor, &revoke).await,
        Outcome::Refused(Refusal::NotFound(_))
    ));
    assert_eq!(rows(&w.s, Event::AdminAppRoleUnassign).await.len(), 1);
}

#[tokio::test]
async fn assignment_required_is_set_with_its_audit_row_and_refused_for_an_unknown_app() {
    let w = world().await;
    let set = SetAssignmentRequired {
        tenant_id: w.tid(),
        app_id: w.web(),
        required: true,
    };
    txn::run(&w.s.pool, &w.actor, &set).await.into_result().unwrap();
    assert!(w.sp().await.app_role_assignment_required);
    let audited = rows(&w.s, Event::AdminAppAssignmentRequired).await;
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].0.as_deref(), Some(w.web().as_str()));
    assert_eq!(audited[0].1["required"], true);

    let unknown = SetAssignmentRequired {
        tenant_id: w.tid(),
        app_id: "00000000-0000-0000-0000-000000000000".into(),
        required: false,
    };
    let outcome = txn::run(&w.s.pool, &w.actor, &unknown).await;
    assert!(matches!(outcome, Outcome::Refused(Refusal::NotFound(_))), "{outcome:?}");
    assert!(w.sp().await.app_role_assignment_required, "nothing changed");
    assert_eq!(rows(&w.s, Event::AdminAppAssignmentRequired).await.len(), 1);
}
