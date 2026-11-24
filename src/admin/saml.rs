//! The console's *Single sign-on* page, laid out as Entra's: choose a method,
//! then for SAML: Basic SAML Configuration, Attributes & Claims, SAML
//! Certificates, and the values to set up in the application.
//!
//! Every form runs one transaction (`crate::txn::ops::saml`). The page is
//! script-free: values to copy are read-only inputs, and a certificate is a link.

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::APP_READ;
use super::apps::AppOp;
use super::context::{AdminContext, On};
use super::routes::{Params, checked, field, optional};
use super::view::{self, e};
use crate::AppState;
use crate::access::{Flow, FlowVerdict, Mark, Report, Section, line};
use crate::apps::{self, Application, ServicePrincipal};
use crate::claims::Amr;
use crate::routes::saml as endpoints;
use crate::saml::{self, BasicConfig, Claim, ClaimSource, NameIdSource, NewCertificate, ReplyUrl, SamlConfig};
use crate::saml_metadata::SpMetadata;
use crate::saml_protocol::{
    ContentEncryption, EncryptionAlgorithms, KeyTransport, KeyTransportDigest, NameIdFormat, SigningAlgorithm,
    SigningOption,
};
use crate::tenant::Tenant;
use crate::txn::ops::saml::{
    ActivateSamlCertificate, AddSamlCertificate, AddSamlVerificationCertificate, DisableSamlSso, EnableSamlSso,
    EncryptionKey, RemoveSamlCertificate, RemoveSamlVerificationCertificate, SaveSamlBasic, SaveSamlClaims,
    SaveSamlSigning, SetAppSignOnUrl, SetAppVisibility, SetSamlEncryption, SetSamlRequireSigned,
};
use crate::txn::{self, Actor, Outcome, Refusal, Transaction};
use crate::util::{b64, now};

const IDENTIFIERS: &str = "identifiers";
const REPLY_URLS: &str = "reply_urls";
const SIGN_ON_URL: &str = "sign_on_url";
const RELAY_STATE: &str = "relay_state";
const LOGOUT_URL: &str = "logout_url";
const NAME_ID_FORMAT: &str = "name_id_format";
const NAME_ID_SOURCE: &str = "name_id_source";
const CLAIM_NAME: &str = "claim_name";
const CLAIM_SOURCE: &str = "claim_source";
const SIGNING_OPTION: &str = "signing_option";
const SIGNING_ALGORITHM: &str = "signing_algorithm";
const CERTIFICATE: &str = "certificate";
const ENCRYPTION_METHOD: &str = "encryption_method";
const KEY_TRANSPORT: &str = "key_transport";
const KEY_TRANSPORT_DIGEST: &str = "key_transport_digest";
/// The encryption form's button: Save, or this one to stop encrypting.
const ENCRYPTION_ACTION: &str = "encryption_action";
const STOP_ENCRYPTING: &str = "stop";
const CERTIFICATE_ID: &str = "certificate_id";
const DAYS: &str = "days";
const REQUIRED: &str = "required";
const VISIBLE: &str = "visible";

/// How many empty claim rows the form offers for adding new ones.
const NEW_CLAIM_ROWS: usize = 2;
const PEM_CONTENT_TYPE: &str = "application/x-pem-file";

fn form_open(url: &str, csrf: &str, op: AppOp) -> String {
    format!(
        r#"<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{op}">"#,
        url = e(url),
        field = AppOp::FIELD,
        op = op.as_str(),
    )
}

fn copy_field(id: &str, label: &str, value: &str) -> String {
    format!(
        r#"<label for="{id}">{label}</label><input id="{id}" type="text" readonly value="{value}">"#,
        label = e(label),
        value = e(value),
    )
}

fn options<T: Copy + PartialEq>(
    all: &[T],
    selected: T,
    value: impl Fn(T) -> &'static str,
    label: impl Fn(T) -> String,
) -> String {
    all.iter()
        .map(|v| {
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                e(value(*v)),
                if *v == selected { " selected" } else { "" },
                e(&label(*v)),
            )
        })
        .collect()
}

fn format_label(format: NameIdFormat) -> String {
    match format {
        NameIdFormat::Persistent => "Persistent",
        NameIdFormat::EmailAddress => "Email address",
        NameIdFormat::Unspecified => "Unspecified",
        NameIdFormat::Transient => "Transient",
        NameIdFormat::WindowsDomain => "Windows domain qualified name",
    }
    .to_string()
}

fn option_label(option: SigningOption) -> String {
    match option {
        SigningOption::Assertion => "Sign SAML assertion",
        SigningOption::Response => "Sign SAML response",
        SigningOption::Both => "Sign SAML response and assertion",
    }
    .to_string()
}

fn algorithm_label(algorithm: SigningAlgorithm) -> String {
    match algorithm {
        SigningAlgorithm::Sha256 => "SHA-256",
        SigningAlgorithm::Sha1 => "SHA-1",
    }
    .to_string()
}

/// What the Single sign-on section may offer this administrator.
pub(super) struct May {
    pub write: bool,
    pub rotate: bool,
}

/// What the SAML page shows beyond the saved configuration.
struct Shown<'a> {
    may: &'a May,
    /// Values read from a metadata file, not yet saved.
    draft: Option<&'a SpMetadata>,
}

/// The uploaded SAML metadata file's field.
pub(super) const METADATA_FILE: &str = "metadata_file";

/// The Single sign-on section; with a draft, Basic SAML Configuration shows the
/// values read from a metadata file, for the administrator to review and save.
pub(super) async fn section(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    url: &str,
    csrf: &str,
    may: May,
    draft: Option<&SpMetadata>,
) -> String {
    let config = saml::config(&st.pool, app).await.ok().flatten();
    let sp = apps::service_principal(&st.pool, &tenant.id, &app.app_id)
        .await
        .ok()
        .flatten();
    let visible = match &sp {
        Some(sp) => saml::is_visible(&st.pool, sp).await.unwrap_or(true),
        None => true,
    };
    let properties = visibility_form(url, csrf, visible, may.write);
    match config.filter(|c| c.enabled) {
        Some(config) => {
            let body = saml_page(st, tenant, app, url, csrf, &config, Shown { may: &may, draft }).await;
            format!("{body}{properties}")
        }
        None => {
            let sign_on = saml::sign_on_url(&st.pool, app).await.unwrap_or(None);
            format!(
                "{}{}{}",
                method_choice(url, csrf, &may),
                sign_on_form(url, csrf, sign_on.as_deref(), may.write),
                properties
            )
        }
    }
}

fn method_choice(url: &str, csrf: &str, may: &May) -> String {
    let action = if may.rotate {
        format!(
            r#"{open}<div class="actions"><button type="submit">SAML</button></div>
<p class="muted">Rich and secure authentication to applications using the SAML protocol. Creates a signing
certificate for this application.</p></form>"#,
            open = form_open(url, csrf, AppOp::SamlEnable),
        )
    } else {
        r#"<p class="muted">Choosing SAML creates a certificate, which your role cannot do.</p>"#.to_string()
    };
    format!(r#"<h2>Select a single sign-on method</h2>{action}"#)
}

fn sign_on_form(url: &str, csrf: &str, value: Option<&str>, may_write: bool) -> String {
    if !may_write {
        return match value {
            Some(v) => format!(r#"<h2>Sign on URL</h2><p>{}</p>"#, e(v)),
            None => String::new(),
        };
    }
    format!(
        r#"<h2>Sign on URL</h2>{open}<label for="{SIGN_ON_URL}">Where the application's own sign-in starts</label>
<input id="{SIGN_ON_URL}" name="{SIGN_ON_URL}" type="text" inputmode="url" value="{value}">
<p class="muted">Assigned users see the application in their app gallery once this is set.</p>
<div class="actions"><button type="submit">Save</button></div></form>"#,
        open = form_open(url, csrf, AppOp::SignOnUrl),
        value = e(value.unwrap_or_default()),
    )
}

fn visibility_form(url: &str, csrf: &str, visible: bool, may_write: bool) -> String {
    let disabled = if may_write { "" } else { " disabled" };
    let button = if may_write {
        r#"<div class="actions"><button type="submit">Save</button></div>"#
    } else {
        ""
    };
    format!(
        r#"<h2>Properties</h2>{open}<label><input type="checkbox" name="{VISIBLE}"{checked}{disabled}> Visible to users</label>
<p class="muted">Whether assigned users see this application in their app gallery. It does not change who may sign in.</p>{button}</form>"#,
        open = form_open(url, csrf, AppOp::Visibility),
        checked = if visible { " checked" } else { "" },
    )
}

async fn saml_page(
    st: &AppState,
    tenant: &Tenant,
    app: &Application,
    url: &str,
    csrf: &str,
    config: &SamlConfig,
    shown: Shown<'_>,
) -> String {
    let Shown { may, draft } = shown;
    let certificates = saml::certificates(&st.pool, app).await.unwrap_or_default();
    let verification = saml::verification_certificates(&st.pool, app).await.unwrap_or_default();
    let metadata_url = format!(
        "{}?appid={}",
        st.public_url
            .tenant_url(&tenant.id, "federationmetadata/2007-06/federationmetadata.xml"),
        app.app_id
    );
    let sso = endpoints::sso_url(st, &tenant.id);
    let at = now();
    let active_expired = certificates.iter().any(|c| c.active && c.not_after <= at);
    let incomplete = if active_expired {
        r#"<p class="error" role="alert">The active signing certificate has expired. Add a new one, give it to the application, and make it active.</p>"#.to_string()
    } else if config.is_configured() {
        String::new()
    } else {
        r#"<p class="error" role="alert">Add an Identifier and a Reply URL below: nobody can sign in until both are set.</p>"#.to_string()
    };
    let mut out = format!(
        r#"<h2>Set up single sign-on with SAML</h2>{incomplete}<h3>Basic SAML Configuration</h3>{basic}
<h3>Attributes &amp; Claims</h3>{claims}
<h3>SAML Certificates</h3>{certs}{signing}{verify}{encrypt}
<h3>Set up {name}</h3>{login}{identifier}{logout}{metadata}"#,
        basic = basic_section(url, csrf, config, may.write, draft),
        claims = claims_form(url, csrf, config, may.write),
        certs = certificates_table(url, csrf, app, tenant, st.public_url.base(), &certificates, may.rotate),
        signing = signing_form(url, csrf, config, may.rotate),
        verify = verification_form(url, csrf, config, &verification, may.rotate),
        encrypt = encryption_form(url, csrf, config, may.rotate),
        name = e(&app.display_name),
        login = copy_field("saml_login_url", "Login URL", &sso),
        identifier = copy_field(
            "saml_idp_id",
            "Identity provider identifier",
            &endpoints::idp_entity_id(st, &tenant.id)
        ),
        logout = copy_field("saml_logout_url", "Logout URL", &sso),
        metadata = copy_field("saml_metadata_url", "App Federation Metadata URL", &metadata_url),
    );
    if may.write {
        out.push_str(&format!(
            r#"<h3>Change single sign-on mode</h3>{open}<p class="muted">Stops SAML sign-in. The configuration is kept and comes back if SAML is chosen again.</p>
<div class="actions"><button type="submit" class="secondary">Stop using SAML</button></div></form>"#,
            open = form_open(url, csrf, AppOp::SamlDisable),
        ));
    }
    out
}

/// The saved configuration with a metadata file's values in place: its entity ID
/// first among the Identifiers, its Reply URLs, and its Logout URL if it has one.
fn with_draft(c: &SamlConfig, draft: &SpMetadata) -> SamlConfig {
    let mut merged = c.clone();
    merged.identifiers = std::iter::once(draft.entity_id.clone())
        .chain(c.identifiers.iter().filter(|i| **i != draft.entity_id).cloned())
        .collect();
    merged.reply_urls = draft.reply_urls.clone();
    if draft.logout_url.is_some() {
        merged.logout_url = draft.logout_url.clone();
    }
    merged
}

/// Basic SAML Configuration, with the metadata file upload beside it.
fn basic_section(url: &str, csrf: &str, c: &SamlConfig, may_write: bool, draft: Option<&SpMetadata>) -> String {
    let (notice, shown) = match draft {
        Some(draft) => (
            r#"<p class="notice" role="status">Read from the metadata file. Review the values, then Save; nothing has changed yet.</p>"#,
            with_draft(c, draft),
        ),
        None => ("", c.clone()),
    };
    let upload = if may_write {
        format!(
            r#"<form method="post" action="{action}" enctype="multipart/form-data">{csrf}<input type="hidden" name="{field}" value="{op}">
<label for="{METADATA_FILE}">Upload metadata file</label><input id="{METADATA_FILE}" name="{METADATA_FILE}" type="file" accept=".xml,application/xml,text/xml,application/samlmetadata+xml" required>
<div class="actions"><button type="submit" class="secondary">Read file</button></div></form>"#,
            action = e(url),
            field = AppOp::FIELD,
            op = AppOp::SamlMetadataImport.as_str(),
        )
    } else {
        String::new()
    };
    format!("{upload}{notice}{}", basic_form(url, csrf, &shown, may_write))
}

fn basic_form(url: &str, csrf: &str, c: &SamlConfig, may_write: bool) -> String {
    let readonly = if may_write { "" } else { " readonly" };
    let button = if may_write {
        r#"<div class="actions"><button type="submit">Save</button></div>"#
    } else {
        ""
    };
    format!(
        r#"{open}<label for="{IDENTIFIERS}">Identifier (Entity ID), one per line; the first is the default</label>
<textarea id="{IDENTIFIERS}" name="{IDENTIFIERS}" rows="3"{readonly}>{identifiers}</textarea>
<label for="{REPLY_URLS}">Reply URL (Assertion Consumer Service URL), one per line; the first is the default. To set them yourself, add <code>index=N</code> and mark one <code>default</code>.</label>
<textarea id="{REPLY_URLS}" name="{REPLY_URLS}" rows="3"{readonly}>{replies}</textarea>
<label for="{SIGN_ON_URL}">Sign on URL (optional)</label><input id="{SIGN_ON_URL}" name="{SIGN_ON_URL}" type="text" inputmode="url" value="{sign_on}"{readonly}>
<label for="{RELAY_STATE}">Relay State (optional)</label><input id="{RELAY_STATE}" name="{RELAY_STATE}" type="text" value="{relay}"{readonly}>
<label for="{LOGOUT_URL}">Logout URL (optional)</label><input id="{LOGOUT_URL}" name="{LOGOUT_URL}" type="text" inputmode="url" value="{logout}"{readonly}>{button}</form>"#,
        open = form_open(url, csrf, AppOp::SamlBasic),
        identifiers = e(&c.identifiers.join("\n")),
        replies = e(&reply_lines(&c.reply_urls)),
        sign_on = e(c.sign_on_url.as_deref().unwrap_or_default()),
        relay = e(c.relay_state.as_deref().unwrap_or_default()),
        logout = e(c.logout_url.as_deref().unwrap_or_default()),
    )
}

fn claims_form(url: &str, csrf: &str, c: &SamlConfig, may_write: bool) -> String {
    let disabled = if may_write { "" } else { " disabled" };
    let readonly = if may_write { "" } else { " readonly" };
    let row = |name: &str, source: ClaimSource| {
        format!(
            r#"<tr><td><input aria-label="Claim name" name="{CLAIM_NAME}" type="text" value="{name}"{readonly}></td><td><select aria-label="Source attribute" name="{CLAIM_SOURCE}"{disabled}>{sources}</select></td></tr>"#,
            name = e(name),
            sources = options(ClaimSource::ALL, source, ClaimSource::as_str, |s| s.label().to_string()),
        )
    };
    let mut rows: String = c.claims.iter().map(|x| row(&x.name, x.source)).collect();
    if may_write {
        for _ in 0..NEW_CLAIM_ROWS {
            rows.push_str(&row("", ClaimSource::Mail));
        }
    }
    let button = if may_write {
        r#"<p class="muted">Clear a name to remove that claim. Tenant, object id, display name, authentication methods, roles and groups are added as Entra adds them.</p><div class="actions"><button type="submit">Save</button></div>"#
    } else {
        ""
    };
    format!(
        r#"{open}<label for="{NAME_ID_FORMAT}">Unique User Identifier (Name ID) format</label>
<select id="{NAME_ID_FORMAT}" name="{NAME_ID_FORMAT}"{disabled}>{formats}</select>
<label for="{NAME_ID_SOURCE}">Name ID source attribute</label>
<select id="{NAME_ID_SOURCE}" name="{NAME_ID_SOURCE}"{disabled}>{sources}</select>
<table><tr><th>Claim name</th><th>Source attribute</th></tr>{rows}</table>{button}</form>"#,
        open = form_open(url, csrf, AppOp::SamlClaims),
        formats = options(NameIdFormat::ALL, c.name_id_format, NameIdFormat::as_str, format_label),
        sources = options(NameIdSource::ALL, c.name_id_source, NameIdSource::as_str, |s| s
            .label()
            .to_string()),
    )
}

fn certificates_table(
    url: &str,
    csrf: &str,
    app: &Application,
    tenant: &Tenant,
    base: &str,
    certificates: &[saml::CertificateInfo],
    may_rotate: bool,
) -> String {
    let at = now();
    let rows: String = certificates
        .iter()
        .map(|c| {
            let status = if c.active {
                r#"<span class="pill good">Active</span>"#
            } else {
                r#"<span class="pill">Inactive</span>"#
            };
            let expired = if c.not_after <= at { " (expired)" } else { "" };
            let download = format!(
                "{base}/admin/tenants/{}/apps/{}/sso/certificate/{}",
                tenant.id, app.app_id, c.id
            );
            let actions = if may_rotate && !c.active {
                let activate = if c.not_after > at {
                    format!(
                        r#"{open}<input type="hidden" name="{CERTIFICATE_ID}" value="{id}"><button type="submit" class="secondary">Make certificate active</button></form>"#,
                        open = form_open(url, csrf, AppOp::SamlCertificateActivate),
                        id = e(&c.id),
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"{activate}{open}<input type="hidden" name="{CERTIFICATE_ID}" value="{id}"><button type="submit" class="secondary">Delete</button></form>"#,
                    open = form_open(url, csrf, AppOp::SamlCertificateRemove),
                    id = e(&c.id),
                )
            } else {
                String::new()
            };
            format!(
                r#"<tr><td>{status}</td><td class="muted">{thumbprint}</td><td>{expires}{expired}</td><td><a href="{download}">Certificate (Base64)</a></td><td>{actions}</td></tr>"#,
                thumbprint = e(&c.thumbprint),
                expires = e(&view::ts(c.not_after)),
                download = e(&download),
            )
        })
        .collect();
    let add = if may_rotate {
        view::expander(
            "New Certificate",
            &format!(
                r#"{open}<label for="{DAYS}">Valid for (days, up to {max})</label>
<input id="{DAYS}" name="{DAYS}" type="number" min="1" max="{max}" value="{max}" required>
<p class="muted">A new certificate is inactive. Give it to the application first, then make it active.</p>
<div class="actions"><button type="submit">Save</button></div></form>"#,
                open = form_open(url, csrf, AppOp::SamlCertificateAdd),
                max = saml::CERT_VALIDITY_DAYS,
            ),
            false,
        )
    } else {
        String::new()
    };
    format!(
        r#"<table><tr><th>Status</th><th>Thumbprint</th><th>Expires</th><th>Download</th><th></th></tr>{rows}</table>{add}"#
    )
}

fn signing_form(url: &str, csrf: &str, c: &SamlConfig, may_rotate: bool) -> String {
    let disabled = if may_rotate { "" } else { " disabled" };
    let button = if may_rotate {
        r#"<div class="actions"><button type="submit">Save</button></div>"#
    } else {
        ""
    };
    format!(
        r#"{open}<label for="{SIGNING_OPTION}">Signing Option</label><select id="{SIGNING_OPTION}" name="{SIGNING_OPTION}"{disabled}>{opts}</select>
<label for="{SIGNING_ALGORITHM}">Signing Algorithm</label><select id="{SIGNING_ALGORITHM}" name="{SIGNING_ALGORITHM}"{disabled}>{algs}</select>{button}</form>"#,
        open = form_open(url, csrf, AppOp::SamlSigning),
        opts = options(
            SigningOption::ALL,
            c.signing_option,
            SigningOption::as_str,
            option_label
        ),
        algs = options(
            SigningAlgorithm::ALL,
            c.signing_algorithm,
            SigningAlgorithm::as_str,
            algorithm_label
        ),
    )
}

fn verification_form(
    url: &str,
    csrf: &str,
    c: &SamlConfig,
    certificates: &[saml::VerificationCertificate],
    may_rotate: bool,
) -> String {
    let rows: String = certificates
        .iter()
        .map(|x| {
            let remove = if may_rotate {
                format!(
                    r#"{open}<input type="hidden" name="{CERTIFICATE_ID}" value="{id}"><button type="submit" class="secondary">Delete</button></form>"#,
                    open = form_open(url, csrf, AppOp::SamlVerificationRemove),
                    id = e(&x.id),
                )
            } else {
                String::new()
            };
            format!(
                r#"<tr><td class="muted">{}</td><td>{}</td><td>{remove}</td></tr>"#,
                e(&x.thumbprint),
                e(&view::ts(x.not_after))
            )
        })
        .collect();
    let table = if rows.is_empty() {
        r#"<p class="empty">No verification certificates.</p>"#.to_string()
    } else {
        format!(r#"<table><tr><th>Thumbprint</th><th>Expires</th><th></th></tr>{rows}</table>"#)
    };
    let controls = if may_rotate {
        format!(
            r#"{open}<label><input type="checkbox" name="{REQUIRED}"{checked}> Require verification certificates</label>
<p class="muted">Requests may be signed on the HTTP-Redirect or HTTP-POST binding, with RSA-SHA256.</p>
<div class="actions"><button type="submit">Save</button></div></form>{add}"#,
            open = form_open(url, csrf, AppOp::SamlRequireSigned),
            checked = if c.require_signed_requests { " checked" } else { "" },
            add = view::expander(
                "Add verification certificate",
                &format!(
                    r#"{open}<label for="verify_cert">Certificate (PEM, public key only)</label>
<textarea id="verify_cert" name="{CERTIFICATE}" rows="6" required></textarea>
<div class="actions"><button type="submit">Add</button></div></form>"#,
                    open = form_open(url, csrf, AppOp::SamlVerificationAdd),
                ),
                false,
            ),
        )
    } else {
        String::new()
    };
    format!(r#"<h4>Verification certificates</h4>{table}{controls}"#)
}

fn content_label(content: ContentEncryption) -> &'static str {
    match content {
        ContentEncryption::Aes256Gcm => "AES-256-GCM",
        ContentEncryption::Aes128Gcm => "AES-128-GCM",
        ContentEncryption::Aes256Cbc => "AES-256-CBC (as Entra)",
    }
}

fn transport_label(transport: KeyTransport) -> &'static str {
    match transport {
        KeyTransport::RsaOaep => "RSA-OAEP (XML Encryption 1.1)",
        KeyTransport::RsaOaepMgf1p => "RSA-OAEP-MGF1P (as Entra)",
    }
}

fn digest_label(digest: KeyTransportDigest) -> &'static str {
    match digest {
        KeyTransportDigest::Sha256 => "SHA-256",
        KeyTransportDigest::Sha1 => "SHA-1 (as Entra)",
    }
}

fn select<T: Copy + PartialEq>(
    id: &str,
    label: &str,
    all: &[T],
    current: T,
    wire: impl Fn(T) -> &'static str,
    shown: impl Fn(T) -> &'static str,
    disabled: &str,
) -> String {
    let options: String = all
        .iter()
        .map(|v| {
            let selected = if *v == current { " selected" } else { "" };
            format!(r#"<option value="{}"{selected}>{}</option>"#, wire(*v), e(shown(*v)))
        })
        .collect();
    format!(r#"<label for="{id}">{label}</label><select id="{id}" name="{id}"{disabled}>{options}</select>"#)
}

fn encryption_form(url: &str, csrf: &str, c: &SamlConfig, may_rotate: bool) -> String {
    let a = c.encryption_algorithms;
    let state = match &c.encryption_cert {
        Some(der) => format!(
            r#"<p>Assertions are encrypted ({}, key wrapped with {} over {}) to the certificate <code>{}</code>.</p>"#,
            e(content_label(a.content)),
            e(transport_label(a.transport)),
            e(digest_label(a.digest)),
            e(&saml::thumbprint(der))
        ),
        None => r#"<p class="empty">Assertions are not encrypted.</p>"#.to_string(),
    };
    let disabled = if may_rotate { "" } else { " disabled" };
    let choices = format!(
        "{}{}{}",
        select(
            ENCRYPTION_METHOD,
            "Encryption method",
            ContentEncryption::ALL,
            a.content,
            ContentEncryption::as_str,
            content_label,
            disabled
        ),
        select(
            KEY_TRANSPORT,
            "Key transport",
            KeyTransport::ALL,
            a.transport,
            KeyTransport::as_str,
            transport_label,
            disabled
        ),
        select(
            KEY_TRANSPORT_DIGEST,
            "Key transport digest",
            KeyTransportDigest::ALL,
            a.digest,
            KeyTransportDigest::as_str,
            digest_label,
            disabled
        ),
    );
    if !may_rotate {
        return format!("<h4>Token encryption</h4>{state}{choices}");
    }
    let stop = if c.encryption_cert.is_some() {
        format!(
            r#"<button type="submit" class="secondary" name="{ENCRYPTION_ACTION}" value="{STOP_ENCRYPTING}" formnovalidate>Stop encrypting</button>"#
        )
    } else {
        String::new()
    };
    format!(
        r#"<h4>Token encryption</h4>{state}{open}{choices}<label for="encrypt_cert">Certificate (PEM, public key only); leave empty to keep the current one</label>
<textarea id="encrypt_cert" name="{CERTIFICATE}" rows="6"></textarea>
<p class="muted">Pick what the application can decrypt. AES-GCM also protects the assertion's integrity; an encrypted assertion always comes in a signed response.</p>
<div class="actions"><button type="submit">Save</button>{stop}</div></form>"#,
        open = form_open(url, csrf, AppOp::SamlEncryption),
    )
}

// ---- Check sign-in ----

/// For an application whose method is SAML, replace the report's OAuth parts
/// with SAML's: its setup, how the user can get in, and what the assertion would
/// say, built by the same functions a real sign-in uses. Anything else is left
/// exactly as it is, and so is a report that says nothing about an account.
pub(super) async fn extend_check(
    st: &AppState,
    tenant: &Tenant,
    sp: &ServicePrincipal,
    app: &Application,
    report: &mut Report,
) -> anyhow::Result<()> {
    let Some(config) = saml::config(&st.pool, app).await?.filter(|c| c.enabled) else {
        return Ok(());
    };
    let Some(user) = report.user.clone() else {
        return Ok(());
    };
    let at = now();
    let certificates = saml::certificates(&st.pool, app).await?;
    let active = certificates.iter().find(|c| c.active);
    let verifiable = saml::verification_certificates(&st.pool, app)
        .await?
        .iter()
        .any(|c| c.not_after > at);

    // ---- the setup ----
    let mut problems: Vec<&str> = Vec::new();
    let mut setup = Vec::new();
    let mut require = |ok: bool, yes: String, no: &'static str, setup: &mut Vec<crate::access::Line>| {
        if ok {
            setup.push(line(Mark::Pass, yes));
        } else {
            setup.push(line(Mark::Fail, no));
            problems.push(no);
        }
    };
    require(
        !config.identifiers.is_empty(),
        format!("Identifier: {}", config.identifiers.join(", ")),
        "no Identifier (Entity ID) is set",
        &mut setup,
    );
    require(
        !config.reply_urls.is_empty(),
        format!(
            "Reply URL: {}",
            config
                .reply_urls
                .iter()
                .map(|r| r.url.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "no Reply URL is set",
        &mut setup,
    );
    require(
        active.is_some(),
        format!(
            "Active signing certificate: {}",
            active.map(|c| c.thumbprint.as_str()).unwrap_or_default()
        ),
        "there is no active signing certificate",
        &mut setup,
    );
    if active.is_some() {
        require(
            active.is_some_and(|c| c.not_after > at),
            format!("It is valid until {}", view::ts(active.map_or(0, |c| c.not_after))),
            "the active signing certificate has expired, so applications will reject its assertions",
            &mut setup,
        );
    }
    if config.require_signed_requests {
        require(
            verifiable,
            "Signed requests are required, and a valid verification certificate is set".to_string(),
            "signed requests are required, but no verification certificate is valid",
            &mut setup,
        );
    } else {
        setup.push(line(Mark::Note, "Signed requests are not required"));
    }
    setup.push(line(
        Mark::Note,
        format!(
            "{}, {}",
            option_label(config.signing_option),
            algorithm_label(config.signing_algorithm)
        ),
    ));
    setup.push(line(
        Mark::Note,
        if config.encryption_cert.is_some() {
            "Assertions are encrypted"
        } else {
            "Assertions are not encrypted"
        },
    ));
    setup.push(line(
        Mark::Note,
        match &config.logout_url {
            Some(url) => format!("Single Logout: {url}"),
            None => "Single Logout: no Logout URL, so a logout cannot reach this application".to_string(),
        },
    ));

    // ---- how the user can get in ----
    let access_works = report.works;
    let access_detail = report
        .flows
        .iter()
        .find(|f| matches!(f.flow, Flow::Browser))
        .map(|f| f.detail.clone())
        .unwrap_or_default();
    let request = match problems.first() {
        _ if !access_works => FlowVerdict {
            flow: Flow::SamlRequest,
            works: false,
            detail: access_detail.clone(),
        },
        Some(problem) => FlowVerdict {
            flow: Flow::SamlRequest,
            works: false,
            detail: format!("Refused: {problem}"),
        },
        None => FlowVerdict {
            flow: Flow::SamlRequest,
            works: true,
            detail: access_detail,
        },
    };
    let listed = saml::gallery(&st.pool, &user.tenant_id, &user.id)
        .await?
        .into_iter()
        .find(|a| a.app_id == app.app_id);
    let gallery = match &listed {
        Some(_) if !request.works => FlowVerdict {
            flow: Flow::SamlGallery,
            works: false,
            detail: format!("Listed, but opening it fails. {}", request.detail),
        },
        Some(a) => FlowVerdict {
            flow: Flow::SamlGallery,
            works: true,
            detail: if a.sign_on_url.is_some() {
                "Listed: opens the application's Sign on URL".to_string()
            } else {
                "Listed: signs in here and posts an assertion to the application".to_string()
            },
        },
        None => FlowVerdict {
            flow: Flow::SamlGallery,
            works: false,
            detail: format!(
                "Not listed: {}",
                if !saml::is_visible(&st.pool, sp).await? {
                    "the application is not visible to users"
                } else if !apps::user_is_assigned(&st.pool, &sp.id, &user.id).await? {
                    "the gallery shows only applications the user is assigned to"
                } else if config.require_signed_requests && config.sign_on_url.is_none() {
                    "it requires signed requests and has no Sign on URL to start from"
                } else if !config.is_configured() {
                    "Basic SAML Configuration is incomplete"
                } else {
                    "their tenant does not let them use it"
                }
            ),
        },
    };

    // ---- what the assertion would say ----
    // Another tenant's account: its values only once it may actually come here,
    // because until then they are not this tenant's to read.
    let guest = user.tenant_id != tenant.id;
    let mut assertion = Vec::new();
    if guest && !access_works {
        assertion.push(line(
            Mark::Note,
            "Values are not shown for an account of another tenant until it may sign in here",
        ));
    } else {
        let pairwise = st.secrets.pairwise_sub(&user.id, &app.app_id).await?;
        let (value, format) = saml::name_id_for(&config, None, &user, &pairwise)?;
        assertion.push(line(
            Mark::Note,
            if format == NameIdFormat::Transient {
                format!("Name ID ({}): generated at each sign-in", format_label(format))
            } else {
                format!("Name ID ({}): {value}", format_label(format))
            },
        ));
        if guest && user.email.is_some() && !user.email_verified {
            assertion.push(line(
                Mark::Note,
                "Their email is not verified, so it is withheld and never used as the Name ID",
            ));
        }
        let methods = [Amr::Pwd.as_str().to_string()];
        let attributes = endpoints::attributes(st, tenant, app, sp, &config, &user, &methods).await?;
        for attribute in attributes.iter().filter(|a| a.name != saml::CLAIM_AUTHN_METHODS) {
            assertion.push(line(
                Mark::Note,
                format!("{}: {}", attribute.name, attribute.values.join(", ")),
            ));
        }
        assertion.push(line(
            Mark::Note,
            format!("{}: how they actually signed in", saml::CLAIM_AUTHN_METHODS),
        ));
    }

    report.sections.retain(|s| s.title != "In the token");
    report.sections.push(Section {
        title: "SAML setup",
        lines: setup,
    });
    report.sections.push(Section {
        title: "In the SAML assertion",
        lines: assertion,
    });
    report.works = request.works;
    report.headline = format!(
        "{} {} sign in to {}",
        user.upn,
        if request.works { "can" } else { "cannot" },
        app.display_name
    );
    report.flows = vec![request, gallery];
    Ok(())
}

// ---- applying a form ----

async fn run<T: Transaction>(st: &AppState, actor: &Actor, t: &T) -> Outcome<()> {
    txn::run(&st.pool, actor, t).await.map_done()
}

fn invalid(message: &str) -> Outcome<()> {
    Outcome::Refused(Refusal::Invalid(message.to_string()))
}

/// Marks a Reply URL line's index.
const INDEX_PREFIX: &str = "index=";
/// Marks the default Reply URL's line.
const DEFAULT_MARK: &str = "default";

/// Reply URLs as the form shows them: plain lines when each is indexed by its
/// position and the first is the default, else every line with its index.
fn reply_lines(replies: &[ReplyUrl]) -> String {
    if ReplyUrl::is_plain_list(replies) {
        return replies.iter().map(|r| r.url.as_str()).collect::<Vec<_>>().join("\n");
    }
    replies
        .iter()
        .map(|r| {
            let mark = if r.default {
                format!(" {DEFAULT_MARK}")
            } else {
                String::new()
            };
            format!("{} {INDEX_PREFIX}{}{mark}", r.url, r.index)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reply URL lines: `URL`, optionally followed by `index=N` and `default`. A
/// line without an index takes the lowest one not yet used; with no line
/// marked default, the first is.
fn parse_reply_lines(lines: &[String]) -> Result<Vec<ReplyUrl>, String> {
    let mut parsed = Vec::with_capacity(lines.len());
    for line in lines {
        let mut words = line.split_whitespace();
        let Some(url) = words.next() else { continue };
        let (mut index, mut default) = (None, false);
        for word in words {
            if word == DEFAULT_MARK {
                default = true;
            } else if let Some(n) = word.strip_prefix(INDEX_PREFIX) {
                index = Some(
                    n.parse::<u16>()
                        .map_err(|_| format!("'{word}' is not an index from 0 to 65535."))?,
                );
            } else {
                return Err(format!(
                    "'{word}' is not understood after a Reply URL; use {INDEX_PREFIX}N or {DEFAULT_MARK}."
                ));
            }
        }
        parsed.push((url.to_string(), index, default));
    }
    let mut used: std::collections::BTreeSet<u16> = parsed.iter().filter_map(|(_, i, _)| *i).collect();
    let any_default = parsed.iter().any(|(_, _, d)| *d);
    let mut replies = Vec::with_capacity(parsed.len());
    for (position, (url, index, default)) in parsed.into_iter().enumerate() {
        let index = match index {
            Some(i) => i,
            None => {
                let free = (0..=u16::MAX)
                    .find(|i| !used.contains(i))
                    .ok_or("There are too many Reply URLs.")?;
                used.insert(free);
                free
            }
        };
        replies.push(ReplyUrl {
            url,
            index,
            default: default || (!any_default && position == 0),
        });
    }
    replies.sort_by_key(|r| r.index);
    Ok(replies)
}

fn lines(form: &Params, name: &str) -> Vec<String> {
    field(form, name)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// A signing certificate, made off the async workers before any transaction.
async fn generate(days: i64) -> anyhow::Result<NewCertificate> {
    tokio::task::spawn_blocking(move || NewCertificate::generate(days)).await?
}

/// Carry out one SAML operation: read the form, run one transaction.
pub(super) async fn apply(
    st: &AppState,
    actor: &Actor,
    tenant: &Tenant,
    app: &Application,
    op: AppOp,
    form: &Params,
    body: &[u8],
) -> Outcome<()> {
    let (tenant_id, app_id) = (tenant.id.clone(), app.app_id.clone());
    let maybe = |name: &str| optional(form, name).map(str::to_string);
    let certificate_id = field(form, CERTIFICATE_ID).to_string();
    match op {
        AppOp::SamlEnable => {
            let certificate = match generate(saml::CERT_VALIDITY_DAYS).await {
                Ok(c) => c,
                Err(err) => return Outcome::from_error(&err),
            };
            run(
                st,
                actor,
                &EnableSamlSso {
                    tenant_id,
                    app_id,
                    certificate,
                },
            )
            .await
        }
        AppOp::SamlDisable => run(st, actor, &DisableSamlSso { tenant_id, app_id }).await,
        AppOp::SamlBasic => {
            let reply_urls = match parse_reply_lines(&lines(form, REPLY_URLS)) {
                Ok(replies) => replies,
                Err(problem) => return invalid(&problem),
            };
            let basic = BasicConfig {
                identifiers: lines(form, IDENTIFIERS),
                reply_urls,
                sign_on_url: maybe(SIGN_ON_URL),
                relay_state: maybe(RELAY_STATE),
                logout_url: maybe(LOGOUT_URL),
            };
            run(
                st,
                actor,
                &SaveSamlBasic {
                    tenant_id,
                    app_id,
                    basic,
                },
            )
            .await
        }
        AppOp::SamlClaims => {
            let (Some(name_id_format), Some(name_id_source)) = (
                NameIdFormat::parse(field(form, NAME_ID_FORMAT)),
                NameIdSource::parse(field(form, NAME_ID_SOURCE)),
            ) else {
                return invalid("Choose a Name ID format and source.");
            };
            // The rows repeat their field names, so they are read in order.
            let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
            let names = pairs.iter().filter(|(k, _)| k == CLAIM_NAME).map(|(_, v)| v.trim());
            let sources = pairs.iter().filter(|(k, _)| k == CLAIM_SOURCE).map(|(_, v)| v.as_str());
            let mut claims = Vec::new();
            for (name, source) in names.zip(sources) {
                if name.is_empty() {
                    continue;
                }
                let Some(source) = ClaimSource::parse(source) else {
                    return invalid("Choose a source attribute for each claim.");
                };
                claims.push(Claim {
                    name: name.to_string(),
                    source,
                });
            }
            let t = SaveSamlClaims {
                tenant_id,
                app_id,
                name_id_format,
                name_id_source,
                claims,
            };
            run(st, actor, &t).await
        }
        AppOp::SamlSigning => {
            let (Some(option), Some(algorithm)) = (
                SigningOption::parse(field(form, SIGNING_OPTION)),
                SigningAlgorithm::parse(field(form, SIGNING_ALGORITHM)),
            ) else {
                return invalid("Choose a signing option and algorithm.");
            };
            run(
                st,
                actor,
                &SaveSamlSigning {
                    tenant_id,
                    app_id,
                    option,
                    algorithm,
                },
            )
            .await
        }
        AppOp::SamlCertificateAdd => {
            let Ok(days) = field(form, DAYS).parse::<i64>() else {
                return invalid("Enter how many days the certificate is valid for.");
            };
            let certificate = match generate(days).await {
                Ok(c) => c,
                Err(err) => return Outcome::from_error(&err),
            };
            run(
                st,
                actor,
                &AddSamlCertificate {
                    tenant_id,
                    app_id,
                    certificate,
                },
            )
            .await
        }
        AppOp::SamlCertificateActivate => {
            run(
                st,
                actor,
                &ActivateSamlCertificate {
                    tenant_id,
                    app_id,
                    certificate_id,
                },
            )
            .await
        }
        AppOp::SamlCertificateRemove => {
            run(
                st,
                actor,
                &RemoveSamlCertificate {
                    tenant_id,
                    app_id,
                    certificate_id,
                },
            )
            .await
        }
        AppOp::SamlRequireSigned => {
            let required = checked(form, REQUIRED);
            run(
                st,
                actor,
                &SetSamlRequireSigned {
                    tenant_id,
                    app_id,
                    required,
                },
            )
            .await
        }
        AppOp::SamlVerificationAdd => {
            let certificate_pem = field(form, CERTIFICATE).to_string();
            run(
                st,
                actor,
                &AddSamlVerificationCertificate {
                    tenant_id,
                    app_id,
                    certificate_pem,
                },
            )
            .await
        }
        AppOp::SamlVerificationRemove => {
            run(
                st,
                actor,
                &RemoveSamlVerificationCertificate {
                    tenant_id,
                    app_id,
                    certificate_id,
                },
            )
            .await
        }
        AppOp::SamlEncryption => {
            let (Some(content), Some(transport), Some(digest)) = (
                ContentEncryption::parse(field(form, ENCRYPTION_METHOD)),
                KeyTransport::parse(field(form, KEY_TRANSPORT)),
                KeyTransportDigest::parse(field(form, KEY_TRANSPORT_DIGEST)),
            ) else {
                return invalid("Choose how assertions are encrypted.");
            };
            let certificate = if field(form, ENCRYPTION_ACTION) == STOP_ENCRYPTING {
                EncryptionKey::Stop
            } else {
                match maybe(CERTIFICATE) {
                    Some(pem) => EncryptionKey::Use(pem),
                    None => EncryptionKey::Keep,
                }
            };
            run(
                st,
                actor,
                &SetSamlEncryption {
                    tenant_id,
                    app_id,
                    certificate,
                    algorithms: EncryptionAlgorithms {
                        content,
                        transport,
                        digest,
                    },
                },
            )
            .await
        }
        AppOp::SignOnUrl => {
            let sign_on_url = maybe(SIGN_ON_URL);
            run(
                st,
                actor,
                &SetAppSignOnUrl {
                    tenant_id,
                    app_id,
                    sign_on_url,
                },
            )
            .await
        }
        AppOp::Visibility => {
            let visible = checked(form, VISIBLE);
            run(
                st,
                actor,
                &SetAppVisibility {
                    tenant_id,
                    app_id,
                    visible,
                },
            )
            .await
        }
        _ => invalid("That is not an operation of this page."),
    }
}

/// Download one signing certificate as Base64 (PEM). Public material.
pub async fn certificate_download(
    ctx: AdminContext,
    State(st): State<AppState>,
    Path((key, app_key, id)): Path<(String, String, String)>,
) -> Response {
    if let Err(resp) = ctx.require(APP_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    let Ok(app) = apps::find_in_tenant(&st.pool, tenant, &app_key).await else {
        return view::not_found();
    };
    let Some(certificate) = saml::certificates(&st.pool, &app)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.id == id)
    else {
        return view::not_found();
    };
    let encoded = b64(&certificate.cert_der);
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        wrapped.join("\n")
    );
    let mut resp = (StatusCode::OK, pem).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(PEM_CONTENT_TYPE));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"saml-signing.cer\""),
    );
    resp
}
