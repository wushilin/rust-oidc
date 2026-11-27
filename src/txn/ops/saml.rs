//! Changes to an application's SAML single sign-on, one transaction per kind of
//! change on Entra's *Set up single sign-on with SAML* page.
//!
//! Key generation happens before a transaction begins, so a transaction that
//! needs a certificate takes a [`NewCertificate`]. The audit rows carry counts,
//! thumbprints and choices, never a private key.

use serde_json::json;

use super::tenant;
use crate::admin::{APP_ROTATE, APP_WRITE};
use crate::apps::{self, Application, ServicePrincipal};
use crate::db::Event;
use crate::saml::{self, BasicConfig, Claim, NameIdSource, NewCertificate};
use crate::saml_protocol::{EncryptionAlgorithms, NameIdFormat, SigningAlgorithm, SigningOption};
use crate::tenant::Tenant;
use crate::txn::{Audit, Cx, KindInfo, LockTarget, Need, Refusal, Scope, Step, Transaction};

const NO_SUCH_APP: &str = "There is no such application in this tenant.";
const SAML_NOT_CHOSEN: &str = "Choose SAML as this application's single sign-on method first.";

/// The tenant, one of its applications and its service principal, or abort.
async fn target(cx: &mut Cx<'_>, tenant_id: &str, app_id: &str) -> Step<(Tenant, Application, ServicePrincipal)> {
    let tenant = tenant(cx, tenant_id).await?;
    let found = apps::find_in(cx.conn(), app_id).await;
    let app = match cx.check(found)? {
        Some(app) if app.tenant_id == tenant.id => app,
        _ => return Err(cx.fail(Refusal::NotFound(NO_SUCH_APP.into()))),
    };
    let sp = apps::service_principal_in(cx.conn(), &tenant.id, &app.app_id).await;
    match cx.check(sp)? {
        Some(sp) => Ok((tenant, app, sp)),
        None => Err(cx.fail(Refusal::NotFound(NO_SUCH_APP.into()))),
    }
}

/// As [`target`], for a change to a SAML configuration that must already exist.
async fn configured(cx: &mut Cx<'_>, tenant_id: &str, app_id: &str) -> Step<(Tenant, Application, ServicePrincipal)> {
    let (tenant, app, sp) = target(cx, tenant_id, app_id).await?;
    let config = saml::config_in(cx.conn(), &app).await;
    let exists = cx.check(config)?.is_some();
    cx.ensure(exists, || Refusal::Invalid(SAML_NOT_CHOSEN.into()))?;
    Ok((tenant, app, sp))
}

fn on_app(tenant_id: &str, app_id: &str, details: serde_json::Value) -> Audit {
    Audit {
        tenant_id: Some(tenant_id.to_string()),
        target: Some(app_id.to_string()),
        details,
    }
}

macro_rules! on_application {
    () => {
        fn scope(&self) -> Scope {
            Scope::Tenant(self.tenant_id.clone())
        }

        fn locks(&self) -> Vec<LockTarget> {
            vec![LockTarget::App(self.app_id.clone())]
        }
    };
}

/// Choose SAML as the single sign-on method. The first time, this creates the
/// settings, default claims and an active signing certificate.
pub struct EnableSamlSso {
    pub tenant_id: String,
    pub app_id: String,
    /// Used only if the application has no SAML configuration yet.
    pub certificate: NewCertificate,
}

impl Transaction for EnableSamlSso {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Choose SAML single sign-on",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlEnable,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (tenant, app, sp) = target(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::enable_in(cx.conn(), &tenant, &app, &sp, &self.certificate).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "mode": saml::SSO_MODE_SAML }))
    }
}

/// Stop using SAML. Its configuration is kept.
pub struct DisableSamlSso {
    pub tenant_id: String,
    pub app_id: String,
}

impl Transaction for DisableSamlSso {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Stop SAML single sign-on",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppSamlDisable,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, _, sp) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::disable_in(cx.conn(), &sp).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "mode": null }))
    }
}

/// Save Basic SAML Configuration.
pub struct SaveSamlBasic {
    pub tenant_id: String,
    pub app_id: String,
    pub basic: BasicConfig,
}

impl Transaction for SaveSamlBasic {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Save Basic SAML Configuration",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppSamlBasic,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (tenant, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::save_basic_in(cx.conn(), &tenant.id, &app, &self.basic).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "identifiers": self.basic.identifiers.len(),
                "replyUrls": self.basic.reply_urls.len(),
                "signOnUrl": self.basic.sign_on_url.is_some(),
                "relayState": self.basic.relay_state.is_some(),
                "logoutUrl": self.basic.logout_url.is_some(),
            }),
        )
    }
}

/// Save Attributes & Claims.
pub struct SaveSamlClaims {
    pub tenant_id: String,
    pub app_id: String,
    pub name_id_format: NameIdFormat,
    pub name_id_source: NameIdSource,
    pub claims: Vec<Claim>,
}

impl Transaction for SaveSamlClaims {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Save SAML attributes and claims",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppSamlClaims,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::save_claims_in(cx.conn(), &app, self.name_id_format, self.name_id_source, &self.claims).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "nameIdFormat": self.name_id_format.as_str(),
                "nameIdSource": self.name_id_source.as_str(),
                "claims": self.claims.len(),
            }),
        )
    }
}

/// Save the signing option and algorithm.
pub struct SaveSamlSigning {
    pub tenant_id: String,
    pub app_id: String,
    pub option: SigningOption,
    pub algorithm: SigningAlgorithm,
}

impl Transaction for SaveSamlSigning {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Save SAML signing options",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlSigning,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::save_signing_in(cx.conn(), &app, self.option, self.algorithm).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "option": self.option.as_str(), "algorithm": self.algorithm.as_str() }),
        )
    }
}

/// Add a signing certificate, inactive until activated.
pub struct AddSamlCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate: NewCertificate,
}

impl Transaction for AddSamlCertificate {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Add SAML signing certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlCertificateAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::add_certificate_in(cx.conn(), &app, &self.certificate).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "thumbprint": self.certificate.thumbprint() }),
        )
    }
}

/// Make a certificate the one that signs.
pub struct ActivateSamlCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate_id: String,
}

impl Transaction for ActivateSamlCertificate {
    /// Its thumbprint.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Activate SAML signing certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlCertificateActivate,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::activate_certificate_in(cx.conn(), &app, &self.certificate_id).await;
        cx.check(done)
    }

    fn audit(&self, thumbprint: &String) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "thumbprint": thumbprint }))
    }
}

/// Remove an inactive signing certificate.
pub struct RemoveSamlCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate_id: String,
}

impl Transaction for RemoveSamlCertificate {
    /// Its thumbprint.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Remove SAML signing certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlCertificateRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::remove_certificate_in(cx.conn(), &app, &self.certificate_id).await;
        cx.check(done)
    }

    fn audit(&self, thumbprint: &String) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "thumbprint": thumbprint }))
    }
}

/// Require signed authentication requests, or stop.
pub struct SetSamlRequireSigned {
    pub tenant_id: String,
    pub app_id: String,
    pub required: bool,
}

impl Transaction for SetSamlRequireSigned {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set SAML request verification",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlVerification,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::set_require_signed_in(cx.conn(), &app, self.required).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "required": self.required }))
    }
}

/// Add a certificate that verifies the application's signed requests.
pub struct AddSamlVerificationCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate_pem: String,
}

impl Transaction for AddSamlVerificationCertificate {
    /// Its thumbprint.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Add SAML verification certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlVerificationCertAdd,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let pasted_key = self.certificate_pem.contains("PRIVATE KEY");
        cx.ensure(!pasted_key, || {
            Refusal::Invalid("that is a private key; paste only the certificate".into())
        })?;
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let parsed = saml::GivenCertificate::from_pem(&self.certificate_pem);
        let parsed = cx.check(parsed)?;
        let done = saml::add_verification_certificate_in(cx.conn(), &app, &parsed.der, parsed.not_after).await;
        cx.check(done)
    }

    fn audit(&self, thumbprint: &String) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "thumbprint": thumbprint }))
    }
}

/// Remove a verification certificate.
pub struct RemoveSamlVerificationCertificate {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate_id: String,
}

impl Transaction for RemoveSamlVerificationCertificate {
    /// Its thumbprint.
    type Output = String;
    const INFO: KindInfo = KindInfo {
        name: "Remove SAML verification certificate",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlVerificationCertRemove,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<String> {
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::remove_verification_certificate_in(cx.conn(), &app, &self.certificate_id).await;
        cx.check(done)
    }

    fn audit(&self, thumbprint: &String) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "thumbprint": thumbprint }))
    }
}

/// Encrypt assertions to a certificate, or stop (`None`).
pub struct SetSamlEncryption {
    pub tenant_id: String,
    pub app_id: String,
    pub certificate: EncryptionKey,
    pub algorithms: EncryptionAlgorithms,
}

/// What to encrypt to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionKey {
    /// The certificate already in use, or none.
    Keep,
    /// This certificate (PEM, public only).
    Use(String),
    /// Nothing: stop encrypting.
    Stop,
}

impl Transaction for SetSamlEncryption {
    /// The thumbprint of the certificate now in use.
    type Output = Option<String>;
    const INFO: KindInfo = KindInfo {
        name: "Set SAML token encryption",
        need: Need::Action(APP_ROTATE),
        event: Event::AdminAppSamlEncryption,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<Option<String>> {
        let pasted_key = matches!(&self.certificate, EncryptionKey::Use(pem) if pem.contains("PRIVATE KEY"));
        cx.ensure(!pasted_key, || {
            Refusal::Invalid("that is a private key; paste only the certificate".into())
        })?;
        let (_, app, _) = configured(cx, &self.tenant_id, &self.app_id).await?;
        let current = saml::config_in(cx.conn(), &app).await;
        let current = cx.check(current)?.and_then(|c| c.encryption_cert);
        let der = match &self.certificate {
            EncryptionKey::Use(pem) => {
                let parsed = apps::parse_certificate(pem);
                Some(cx.check(parsed)?.cert_der)
            }
            EncryptionKey::Keep | EncryptionKey::Stop => None,
        };
        let change = match (&self.certificate, der.as_deref()) {
            (EncryptionKey::Use(_), Some(der)) => saml::EncryptionCertificate::Use(der),
            (EncryptionKey::Stop, _) => saml::EncryptionCertificate::Stop,
            _ => saml::EncryptionCertificate::Keep,
        };
        let done = saml::set_encryption_in(cx.conn(), &app, change, self.algorithms).await;
        cx.check(done)?;
        let in_use = match &self.certificate {
            EncryptionKey::Use(_) => der,
            EncryptionKey::Stop => None,
            EncryptionKey::Keep => current,
        };
        Ok(in_use.as_deref().map(saml::thumbprint))
    }

    fn audit(&self, thumbprint: &Option<String>) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({
                "thumbprint": thumbprint,
                "encryptionMethod": self.algorithms.content.as_str(),
                "keyTransport": self.algorithms.transport.as_str(),
                "keyTransportDigest": self.algorithms.digest.as_str(),
            }),
        )
    }
}

/// Entra's *Visible to users*: whether the app gallery lists the application.
pub struct SetAppVisibility {
    pub tenant_id: String,
    pub app_id: String,
    pub visible: bool,
}

impl Transaction for SetAppVisibility {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set application visibility",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppVisibility,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, _, sp) = target(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::set_visible_in(cx.conn(), &sp, self.visible).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(&self.tenant_id, &self.app_id, json!({ "visible": self.visible }))
    }
}

/// Where the application's own sign-in starts, for an application of any kind:
/// the app gallery links there.
pub struct SetAppSignOnUrl {
    pub tenant_id: String,
    pub app_id: String,
    pub sign_on_url: Option<String>,
}

impl Transaction for SetAppSignOnUrl {
    type Output = ();
    const INFO: KindInfo = KindInfo {
        name: "Set application sign on URL",
        need: Need::Action(APP_WRITE),
        event: Event::AdminAppSignOnUrl,
    };

    on_application!();

    async fn run(&self, cx: &mut Cx<'_>) -> Step<()> {
        let (_, app, _) = target(cx, &self.tenant_id, &self.app_id).await?;
        let done = saml::set_sign_on_url_in(cx.conn(), &app, self.sign_on_url.as_deref()).await;
        cx.check(done)
    }

    fn audit(&self, _: &()) -> Audit {
        on_app(
            &self.tenant_id,
            &self.app_id,
            json!({ "signOnUrl": self.sign_on_url.is_some() }),
        )
    }
}
