//! SAML single sign-on configuration, following Entra's enterprise application
//! model: an application is created by name, SAML is then chosen as its
//! single sign-on method, and its Basic SAML Configuration, Attributes & Claims
//! and SAML Certificates are set on that page.
//!
//! The rules live here, where the data is written:
//!
//! - An account of another tenant signs in under the same three conditions as
//!   for OIDC ([`crate::access`]), and its unverified email never identifies it.
//! - An Identifier belongs to one application in the tenant.
//! - An application has at most one active signing certificate, and the active
//!   one cannot be removed.
//! - Requiring signed requests needs a verification certificate.

use anyhow::{anyhow, bail};
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use sha1::{Digest, Sha1};

use crate::apps::{Application, ServicePrincipal};
use crate::db::{Conn, Flag, Handle};
use crate::saml_protocol::{
    self as protocol, ContentEncryption, EncryptionAlgorithms, KeyTransport, KeyTransportDigest, NameIdFormat,
    SigningAlgorithm, SigningOption,
};
use crate::tenant::Tenant;
use crate::users::User;
use crate::util::{b64, new_guid, now};

/// Entra's `preferredSingleSignOnMode` value for SAML.
pub const SSO_MODE_SAML: &str = "saml";

/// How long a signing certificate is valid by default, and at most: three years.
pub const CERT_VALIDITY_DAYS: i64 = 3 * 365;

/// The longest URL or claim name accepted, matching the indexed column.
pub const MAX_URI_CHARS: usize = 512;
/// The longest Identifier (Entity ID) accepted: SAML Metadata 2.3.2 bounds
/// `entityIDType` at 1024 characters, and a 1024-character one must be taken.
pub const MAX_ENTITY_ID_CHARS: usize = 1024;
/// The old 512-character limit allowed up to 2048 UTF-8 bytes. Preserve that
/// range while keeping the full identifier within PostgreSQL's B-tree limit.
const MAX_ENTITY_ID_BYTES: usize = 2048;
/// The most Identifiers or Reply URLs an application may have.
pub const MAX_URIS: usize = 32;
/// The most custom claims an application may have.
pub const MAX_CLAIMS: usize = 64;
const MAX_RELAY_STATE_CHARS: usize = 512;

macro_rules! closed_set {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $wire:literal, $label:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [$name] = &[$(Self::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            pub fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
            pub fn parse(raw: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == raw)
            }
        }
    };
}

closed_set!(
    /// Entra's *Source attribute* for the Unique User Identifier (Name ID).
    NameIdSource {
        UserPrincipalName => "userPrincipalName", "user.userprincipalname",
        Mail => "mail", "user.mail",
        ObjectId => "objectId", "user.objectid",
        PairwiseId => "pairwiseId", "user.pairwiseid",
        PairwiseIdLowercase => "pairwiseIdLowercase", "user.pairwiseid (lowercase hex)",
    }
);

closed_set!(
    /// A user property a claim can carry.
    ClaimSource {
        UserPrincipalName => "userPrincipalName", "user.userprincipalname",
        Mail => "mail", "user.mail",
        GivenName => "givenName", "user.givenname",
        Surname => "surname", "user.surname",
        DisplayName => "displayName", "user.displayname",
        ObjectId => "objectId", "user.objectid",
    }
);

impl ClaimSource {
    /// This user's value, if they have one. An account of another tenant's email
    /// is released only when verified: that tenant's administrators set it, so
    /// unverified it could name someone in this one.
    pub fn of(self, user: &User, app_tenant_id: &str) -> Option<String> {
        match self {
            Self::UserPrincipalName => Some(user.upn.clone()),
            Self::Mail => trusted_email(user, app_tenant_id),
            Self::GivenName => user.given_name.clone(),
            Self::Surname => user.family_name.clone(),
            Self::DisplayName => user.display_name.clone(),
            Self::ObjectId => Some(user.id.clone()),
        }
    }
}

/// The user's email, if an application of this tenant may rely on it.
fn trusted_email(user: &User, app_tenant_id: &str) -> Option<String> {
    user.email
        .clone()
        .filter(|_| user.tenant_id == app_tenant_id || user.email_verified)
}

/// The claims a new SAML application starts with, as in Entra.
pub const DEFAULT_CLAIMS: &[(&str, ClaimSource)] = &[
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ClaimSource::Mail,
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        ClaimSource::GivenName,
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        ClaimSource::UserPrincipalName,
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        ClaimSource::Surname,
    ),
];

/// A signing key and certificate made before a transaction begins: generating
/// RSA is slow. Deliberately not `Debug`: it holds the private key.
pub struct NewCertificate {
    pub(crate) id: String,
    pub(crate) private_key_pem: String,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) thumbprint: String,
    pub(crate) not_after: i64,
}

impl NewCertificate {
    /// An RSA-2048 key in a self-signed certificate valid for `days`.
    pub fn generate(days: i64) -> anyhow::Result<Self> {
        if !(1..=CERT_VALIDITY_DAYS).contains(&days) {
            bail!("a signing certificate is valid for 1 to {CERT_VALIDITY_DAYS} days");
        }
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "rust-oidc SAML token signing");
        params.distinguished_name = dn;
        let start = time::OffsetDateTime::now_utc();
        params.not_before = start - time::Duration::days(1);
        params.not_after = start + time::Duration::days(days);
        let cert = params.self_signed(&key)?;
        let cert_der = cert.der().to_vec();
        Ok(Self {
            id: new_guid(),
            private_key_pem: key.serialize_pem(),
            thumbprint: thumbprint(&cert_der),
            cert_der,
            not_after: params.not_after.unix_timestamp(),
        })
    }

    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

/// A certificate's thumbprint, as Entra shows it: SHA-1, upper-case hex.
pub fn thumbprint(der: &[u8]) -> String {
    hex::encode_upper(Sha1::digest(der))
}

/// A service provider's certificate as given to us: its DER and validity. The
/// key may be RSA or EC; [`add_verification_certificate_in`] decides whether a
/// request can be verified with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenCertificate {
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

impl GivenCertificate {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        use x509_cert::der::{Decode, Encode};
        let cert = x509_cert::Certificate::from_der(der).map_err(|_| anyhow::anyhow!("not an X.509 certificate"))?;
        let validity = cert.tbs_certificate().validity();
        Ok(Self {
            der: cert.to_der()?,
            not_before: validity.not_before.to_unix_duration().as_secs() as i64,
            not_after: validity.not_after.to_unix_duration().as_secs() as i64,
        })
    }

    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        use x509_cert::der::{DecodePem, Encode};
        let cert = x509_cert::Certificate::from_pem(pem.as_bytes())
            .map_err(|_| anyhow::anyhow!("not a PEM X.509 certificate"))?;
        Self::from_der(&cert.to_der()?)
    }

    pub fn pem(&self) -> String {
        let body: Vec<String> = b64(&self.der)
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            body.join("\n")
        )
    }
}

/// One Reply URL (Assertion Consumer Service URL), with the index a request
/// may name it by and whether it is the one used when a request names none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyUrl {
    pub url: String,
    pub index: u16,
    pub default: bool,
}

impl ReplyUrl {
    /// URLs in order: each indexed by its position, the first the default.
    pub fn listed(urls: impl IntoIterator<Item = String>) -> Vec<ReplyUrl> {
        urls.into_iter()
            .enumerate()
            .map(|(i, url)| ReplyUrl {
                url,
                index: u16::try_from(i).unwrap_or(u16::MAX),
                default: i == 0,
            })
            .collect()
    }

    /// Whether these are exactly what `listed` would make of their URLs.
    pub fn is_plain_list(replies: &[ReplyUrl]) -> bool {
        replies
            .iter()
            .enumerate()
            .all(|(i, r)| usize::from(r.index) == i && r.default == (i == 0))
    }
}

/// Basic SAML Configuration, as read from a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicConfig {
    /// The first is the default.
    pub identifiers: Vec<String>,
    /// Exactly one is the default; indexes are distinct.
    pub reply_urls: Vec<ReplyUrl>,
    pub sign_on_url: Option<String>,
    pub relay_state: Option<String>,
    pub logout_url: Option<String>,
}

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Why this cannot be a Reply, Sign on or Logout URL: HTTPS (or plain HTTP to
/// this machine, for development), with no credentials or fragment.
pub fn url_problem(label: &str, raw: &str) -> Option<String> {
    if raw.chars().count() > MAX_URI_CHARS || has_control(raw) {
        return Some(format!("{label} is too long or holds a control character."));
    }
    // It is sent in a Location header, which carries ASCII only.
    if !raw.is_ascii() {
        return Some(format!(
            "{label} must be ASCII: percent-encode the path and use punycode for the host."
        ));
    }
    let Ok(url) = url::Url::parse(raw) else {
        return Some(format!("{label} '{raw}' is not a valid URL."));
    };
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && local)) {
        return Some(format!("{label} must use https (http is allowed for localhost only)."));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Some(format!("{label} must not contain credentials or a fragment."));
    }
    None
}

impl BasicConfig {
    /// Why this cannot be saved, or `None`.
    pub fn problem(&self) -> Option<String> {
        if self.identifiers.is_empty() {
            return Some("Identifier (Entity ID) is required.".into());
        }
        if self.reply_urls.is_empty() {
            return Some("Reply URL (Assertion Consumer Service URL) is required.".into());
        }
        if self.identifiers.len() > MAX_URIS || self.reply_urls.len() > MAX_URIS {
            return Some(format!("An application may have at most {MAX_URIS} of each."));
        }
        for id in &self.identifiers {
            if id.len() > MAX_ENTITY_ID_BYTES
                || id.chars().count() > MAX_ENTITY_ID_CHARS
                || has_control(id)
                || id.trim() != id
            {
                return Some(format!("Identifier '{id}' is not valid."));
            }
        }
        let distinct = |v: &[String]| v.iter().collect::<std::collections::BTreeSet<_>>().len() == v.len();
        let urls: Vec<String> = self.reply_urls.iter().map(|r| r.url.clone()).collect();
        if !distinct(&self.identifiers) || !distinct(&urls) {
            return Some("The same value is listed twice.".into());
        }
        let indexes: std::collections::BTreeSet<u16> = self.reply_urls.iter().map(|r| r.index).collect();
        if indexes.len() != self.reply_urls.len() {
            return Some("Two Reply URLs have the same index.".into());
        }
        if self.reply_urls.iter().filter(|r| r.default).count() != 1 {
            return Some("Exactly one Reply URL must be the default.".into());
        }
        for reply in &self.reply_urls {
            if let Some(problem) = url_problem("Reply URL", &reply.url) {
                return Some(problem);
            }
        }
        if let Some(problem) = self.sign_on_url.as_deref().and_then(|u| url_problem("Sign on URL", u)) {
            return Some(problem);
        }
        if let Some(problem) = self.logout_url.as_deref().and_then(|u| url_problem("Logout URL", u)) {
            return Some(problem);
        }
        if self
            .relay_state
            .as_deref()
            .is_some_and(|r| r.chars().count() > MAX_RELAY_STATE_CHARS || has_control(r))
        {
            return Some("Relay State is too long or holds a control character.".into());
        }
        None
    }
}

/// One claim of Attributes & Claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub name: String,
    pub source: ClaimSource,
}

/// Claims this server fills itself. They identify the user and what they may
/// do, so an administrator's mapping cannot replace them.
pub const CLAIM_TENANT: &str = "http://schemas.microsoft.com/identity/claims/tenantid";
pub const CLAIM_OBJECT_ID: &str = "http://schemas.microsoft.com/identity/claims/objectidentifier";
pub const CLAIM_DISPLAY_NAME: &str = "http://schemas.microsoft.com/identity/claims/displayname";
pub const CLAIM_AUTHN_METHODS: &str = "http://schemas.microsoft.com/claims/authnmethodsreferences";
pub const CLAIM_ROLE: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
pub const CLAIM_GROUPS: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
pub const CLAIM_IDENTITY_PROVIDER: &str = "http://schemas.microsoft.com/identity/claims/identityprovider";
const RESERVED_CLAIMS: [&str; 7] = [
    CLAIM_TENANT,
    CLAIM_OBJECT_ID,
    CLAIM_DISPLAY_NAME,
    CLAIM_AUTHN_METHODS,
    CLAIM_ROLE,
    CLAIM_GROUPS,
    CLAIM_IDENTITY_PROVIDER,
];

/// Why this cannot be a claim's name, or `None`.
pub fn claim_name_problem(name: &str) -> Option<String> {
    if RESERVED_CLAIMS.contains(&name) {
        return Some(format!("Claim '{name}' is set by the server and cannot be mapped."));
    }
    if name.is_empty() || name.chars().count() > MAX_URI_CHARS || has_control(name) || name.trim() != name {
        Some(format!("Claim name '{name}' is not valid."))
    } else {
        None
    }
}

/// An application's SAML configuration. Holds no private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlConfig {
    pub application_id: String,
    pub tenant_id: String,
    /// `Some` while SAML is the application's single sign-on method.
    pub enabled: bool,
    pub identifiers: Vec<String>,
    /// In index order.
    pub reply_urls: Vec<ReplyUrl>,
    pub sign_on_url: Option<String>,
    pub relay_state: Option<String>,
    pub logout_url: Option<String>,
    pub name_id_format: NameIdFormat,
    pub name_id_source: NameIdSource,
    pub signing_option: SigningOption,
    pub signing_algorithm: SigningAlgorithm,
    pub require_signed_requests: bool,
    pub encryption_cert: Option<Vec<u8>>,
    /// How assertions are encrypted when there is a certificate.
    pub encryption_algorithms: EncryptionAlgorithms,
    pub claims: Vec<Claim>,
}

impl SamlConfig {
    pub fn default_identifier(&self) -> Option<&str> {
        self.identifiers.first().map(String::as_str)
    }

    pub fn default_reply_url(&self) -> Option<&str> {
        self.reply_urls
            .iter()
            .find(|r| r.default)
            .or_else(|| self.reply_urls.first())
            .map(|r| r.url.as_str())
    }

    /// Basic SAML Configuration is complete enough to sign anyone in.
    pub fn is_configured(&self) -> bool {
        !self.identifiers.is_empty() && !self.reply_urls.is_empty()
    }

    /// The Reply URL for a request: the one it names, if registered, else the
    /// default. A URL that is not registered is never used.
    pub fn reply_url_for(&self, requested: Option<&str>, index: Option<i64>) -> Option<&str> {
        match (requested, index) {
            (Some(url), _) => self.reply_urls.iter().find(|r| r.url == url).map(|r| r.url.as_str()),
            (None, Some(i)) => self
                .reply_urls
                .iter()
                .find(|r| i64::from(r.index) == i)
                .map(|r| r.url.as_str()),
            (None, None) => self.default_reply_url(),
        }
    }
}

/// A signing certificate as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub id: String,
    pub cert_der: Vec<u8>,
    pub thumbprint: String,
    pub not_after: i64,
    pub active: bool,
    pub created_at: i64,
}

/// A verification certificate as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCertificate {
    pub id: String,
    pub cert_der: Vec<u8>,
    pub thumbprint: String,
    pub not_after: i64,
}

/// The active signing key. Deliberately not `Debug`.
pub struct ActiveKey {
    pub private_key_pem: String,
    pub cert_der: Vec<u8>,
}

fn unb64(raw: &str) -> anyhow::Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(raw)?)
}

// ---- reading ----

type SettingsRow = (
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    String,
    Flag,
    Option<String>,
    String,
    String,
    String,
);

/// The application's SAML configuration, or `None` if SAML was never chosen.
pub async fn config<'c>(db: impl Handle<'c>, app: &Application) -> anyhow::Result<Option<SamlConfig>> {
    let mut conn = db.acquire().await?;
    config_in(&mut conn, app).await
}

pub(crate) async fn config_in(conn: &mut Conn, app: &Application) -> anyhow::Result<Option<SamlConfig>> {
    let row: Option<SettingsRow> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT tenant_id, relay_state, logout_url, name_id_format, name_id_source, signing_option,
                signing_algorithm, require_signed_requests, encryption_cert_b64,
                encryption_method, key_transport, key_transport_digest
         FROM app_saml_settings WHERE application_id = ?",
    ))
    .bind(&app.id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((
        tenant_id,
        relay_state,
        logout_url,
        format,
        source,
        option,
        algorithm,
        require,
        encryption,
        content,
        transport,
        digest,
    )) = row
    else {
        return Ok(None);
    };
    let encryption_algorithms = EncryptionAlgorithms {
        content: ContentEncryption::parse(&content).ok_or_else(|| anyhow!("unknown encryption method '{content}'"))?,
        transport: KeyTransport::parse(&transport).ok_or_else(|| anyhow!("unknown key transport '{transport}'"))?,
        digest: KeyTransportDigest::parse(&digest).ok_or_else(|| anyhow!("unknown key transport digest '{digest}'"))?,
    };
    let (mode, sign_on_url): (Option<String>, Option<String>) = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT sp.preferred_sso_mode, a.sign_on_url FROM applications a
         JOIN service_principals sp ON sp.app_id = a.app_id AND sp.tenant_id = a.tenant_id
         WHERE a.id = ?",
    ))
    .bind(&app.id)
    .fetch_one(&mut *conn)
    .await?;
    let identifiers: Vec<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT entity_id FROM app_saml_identifiers WHERE application_id = ?
         ORDER BY is_default DESC, entity_id",
    ))
    .bind(&app.id)
    .fetch_all(&mut *conn)
    .await?;
    let replies: Vec<(String, i64, crate::db::Flag)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT url, url_index, is_default FROM app_saml_reply_urls WHERE application_id = ? ORDER BY url_index",
    ))
    .bind(&app.id)
    .fetch_all(&mut *conn)
    .await?;
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT name, source FROM app_saml_claims WHERE application_id = ? ORDER BY name",
    ))
    .bind(&app.id)
    .fetch_all(&mut *conn)
    .await?;
    let mut claims = Vec::with_capacity(rows.len());
    for (name, source) in rows {
        let source = ClaimSource::parse(&source).ok_or_else(|| anyhow!("unknown claim source '{source}'"))?;
        claims.push(Claim { name, source });
    }
    Ok(Some(SamlConfig {
        application_id: app.id.clone(),
        tenant_id,
        enabled: mode.as_deref() == Some(SSO_MODE_SAML),
        identifiers: identifiers.into_iter().map(|(v,)| v).collect(),
        reply_urls: replies
            .into_iter()
            .map(|(url, index, default)| {
                Ok(ReplyUrl {
                    url,
                    index: u16::try_from(index).map_err(|_| anyhow!("Reply URL index {index} is out of range"))?,
                    default: default.into(),
                })
            })
            .collect::<anyhow::Result<_>>()?,
        sign_on_url,
        relay_state,
        logout_url,
        name_id_format: NameIdFormat::parse(&format).ok_or_else(|| anyhow!("unknown NameID format"))?,
        name_id_source: NameIdSource::parse(&source).ok_or_else(|| anyhow!("unknown NameID source"))?,
        signing_option: SigningOption::parse(&option).ok_or_else(|| anyhow!("unknown signing option"))?,
        signing_algorithm: SigningAlgorithm::parse(&algorithm).ok_or_else(|| anyhow!("unknown signing algorithm"))?,
        require_signed_requests: require.into(),
        encryption_cert: encryption.as_deref().map(unb64).transpose()?,
        encryption_algorithms,
        claims,
    }))
}

/// The application in `tenant_id` that has this Identifier, among those whose
/// single sign-on method is SAML.
pub async fn find_by_identifier<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    entity_id: &str,
) -> anyhow::Result<Option<Application>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT a.app_id FROM app_saml_identifiers i
         JOIN applications a ON a.id = i.application_id AND a.deleted_at IS NULL
         JOIN service_principals sp ON sp.app_id = a.app_id AND sp.tenant_id = a.tenant_id
         WHERE i.tenant_id = ? AND i.entity_id = ? AND sp.preferred_sso_mode = ?",
    ))
    .bind(tenant_id)
    .bind(entity_id)
    .bind(SSO_MODE_SAML)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((app_id,)) => crate::apps::find_in(&mut conn, &app_id).await,
        None => Ok(None),
    }
}

/// As [`find_by_identifier`], whatever the application's current method: a
/// logout answer can arrive after SAML was turned off for it.
pub async fn find_by_identifier_any_mode<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    entity_id: &str,
) -> anyhow::Result<Option<Application>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT a.app_id FROM app_saml_identifiers i
         JOIN applications a ON a.id = i.application_id AND a.deleted_at IS NULL
         WHERE i.tenant_id = ? AND i.entity_id = ?",
    ))
    .bind(tenant_id)
    .bind(entity_id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((app_id,)) => crate::apps::find_in(&mut conn, &app_id).await,
        None => Ok(None),
    }
}

pub async fn certificates<'c>(db: impl Handle<'c>, app: &Application) -> anyhow::Result<Vec<CertificateInfo>> {
    let mut conn = db.acquire().await?;
    certificates_in(&mut conn, app).await
}

pub(crate) async fn certificates_in(conn: &mut Conn, app: &Application) -> anyhow::Result<Vec<CertificateInfo>> {
    let rows: Vec<(String, String, String, i64, Flag, i64)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id, cert_b64, thumbprint, not_after, active, created_at FROM app_saml_certificates
         WHERE application_id = ? ORDER BY created_at DESC, id",
    ))
    .bind(&app.id)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(id, cert, thumbprint, not_after, active, created_at)| {
            Ok(CertificateInfo {
                id,
                cert_der: unb64(&cert)?,
                thumbprint,
                not_after,
                active: active.into(),
                created_at,
            })
        })
        .collect()
}

/// The key that signs for this application now.
pub async fn active_key<'c>(db: impl Handle<'c>, app: &Application) -> anyhow::Result<Option<ActiveKey>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String, String)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT private_key_pem, cert_b64 FROM app_saml_certificates WHERE application_id = ? AND active = ?",
    ))
    .bind(&app.id)
    .bind(true)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(private_key_pem, cert)| {
        Ok(ActiveKey {
            private_key_pem,
            cert_der: unb64(&cert)?,
        })
    })
    .transpose()
}

pub async fn verification_certificates<'c>(
    db: impl Handle<'c>,
    app: &Application,
) -> anyhow::Result<Vec<VerificationCertificate>> {
    let mut conn = db.acquire().await?;
    verification_certificates_in(&mut conn, app).await
}

pub(crate) async fn verification_certificates_in(
    conn: &mut Conn,
    app: &Application,
) -> anyhow::Result<Vec<VerificationCertificate>> {
    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT id, cert_b64, thumbprint, not_after FROM app_saml_verification_certs
         WHERE application_id = ? ORDER BY created_at DESC, id",
    ))
    .bind(&app.id)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(id, cert, thumbprint, not_after)| {
            Ok(VerificationCertificate {
                id,
                cert_der: unb64(&cert)?,
                thumbprint,
                not_after,
            })
        })
        .collect()
}

// ---- writing ----

/// Choose SAML as the single sign-on method. The first time, this creates its
/// settings, default claims and active signing certificate (`certificate`).
pub(crate) async fn enable_in(
    conn: &mut Conn,
    tenant: &Tenant,
    app: &Application,
    sp: &ServicePrincipal,
    certificate: &NewCertificate,
) -> anyhow::Result<()> {
    if config_in(conn, app).await?.is_none() {
        let ts = now();
        sqlx::query(crate::db::qc(
            conn,
            "INSERT INTO app_saml_settings (application_id, tenant_id, name_id_format, name_id_source,
                                            signing_option, signing_algorithm, encryption_method,
                                            key_transport, key_transport_digest, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&app.id)
        .bind(&tenant.id)
        .bind(NameIdFormat::EmailAddress.as_str())
        .bind(NameIdSource::UserPrincipalName.as_str())
        .bind(SigningOption::Assertion.as_str())
        .bind(SigningAlgorithm::Sha256.as_str())
        .bind(EncryptionAlgorithms::RECOMMENDED.content.as_str())
        .bind(EncryptionAlgorithms::RECOMMENDED.transport.as_str())
        .bind(EncryptionAlgorithms::RECOMMENDED.digest.as_str())
        .bind(ts)
        .execute(&mut *conn)
        .await?;
        for (name, source) in DEFAULT_CLAIMS {
            insert_claim(conn, app, name, *source).await?;
        }
        insert_certificate(conn, app, certificate, true).await?;
    }
    set_mode(conn, sp, Some(SSO_MODE_SAML)).await
}

/// Stop using SAML. The configuration stays, so choosing it again restores it.
pub(crate) async fn disable_in(conn: &mut Conn, sp: &ServicePrincipal) -> anyhow::Result<()> {
    set_mode(conn, sp, None).await
}

async fn set_mode(conn: &mut Conn, sp: &ServicePrincipal, mode: Option<&str>) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE service_principals SET preferred_sso_mode = ? WHERE id = ?",
    ))
    .bind(mode)
    .bind(&sp.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert_claim(conn: &mut Conn, app: &Application, name: &str, source: ClaimSource) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO app_saml_claims (application_id, name, source) VALUES (?, ?, ?)",
    ))
    .bind(&app.id)
    .bind(name)
    .bind(source.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert_certificate(
    conn: &mut Conn,
    app: &Application,
    certificate: &NewCertificate,
    active: bool,
) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO app_saml_certificates (id, application_id, private_key_pem, cert_b64, thumbprint,
                                            not_after, active, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(&certificate.id)
    .bind(&app.id)
    .bind(&certificate.private_key_pem)
    .bind(b64(&certificate.cert_der))
    .bind(&certificate.thumbprint)
    .bind(certificate.not_after)
    .bind(active)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether another application of the tenant already has this Identifier.
pub(crate) async fn identifier_taken_in(
    conn: &mut Conn,
    tenant_id: &str,
    app: &Application,
    entity_id: &str,
) -> anyhow::Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT application_id FROM app_saml_identifiers
         WHERE tenant_id = ? AND entity_id = ? AND application_id <> ?",
    ))
    .bind(tenant_id)
    .bind(entity_id)
    .bind(&app.id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.is_some())
}

/// Save Basic SAML Configuration, replacing what was there.
pub(crate) async fn save_basic_in(
    conn: &mut Conn,
    tenant_id: &str,
    app: &Application,
    basic: &BasicConfig,
) -> anyhow::Result<()> {
    if let Some(problem) = basic.problem() {
        bail!(problem);
    }
    for id in &basic.identifiers {
        if identifier_taken_in(conn, tenant_id, app, id).await? {
            bail!("Identifier '{id}' is already used by another application in this tenant.");
        }
    }
    sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM app_saml_identifiers WHERE application_id = ?",
    ))
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    for (i, id) in basic.identifiers.iter().enumerate() {
        sqlx::query(crate::db::qc(
            conn,
            "INSERT INTO app_saml_identifiers (application_id, tenant_id, entity_id, is_default) VALUES (?, ?, ?, ?)",
        ))
        .bind(&app.id)
        .bind(tenant_id)
        .bind(id)
        .bind(i == 0)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM app_saml_reply_urls WHERE application_id = ?",
    ))
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    for reply in &basic.reply_urls {
        sqlx::query(crate::db::qc(
            conn,
            "INSERT INTO app_saml_reply_urls (application_id, url, url_index, is_default) VALUES (?, ?, ?, ?)",
        ))
        .bind(&app.id)
        .bind(&reply.url)
        .bind(i64::from(reply.index))
        .bind(reply.default)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET relay_state = ?, logout_url = ? WHERE application_id = ?",
    ))
    .bind(basic.relay_state.as_deref())
    .bind(basic.logout_url.as_deref())
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE applications SET sign_on_url = ? WHERE id = ?",
    ))
    .bind(basic.sign_on_url.as_deref())
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Save Attributes & Claims, replacing what was there.
pub(crate) async fn save_claims_in(
    conn: &mut Conn,
    app: &Application,
    format: NameIdFormat,
    source: NameIdSource,
    claims: &[Claim],
) -> anyhow::Result<()> {
    if claims.len() > MAX_CLAIMS {
        bail!("An application may have at most {MAX_CLAIMS} claims.");
    }
    let mut seen = std::collections::BTreeSet::new();
    for claim in claims {
        if let Some(problem) = claim_name_problem(&claim.name) {
            bail!(problem);
        }
        if !seen.insert(&claim.name) {
            bail!("Claim '{}' is listed twice.", claim.name);
        }
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET name_id_format = ?, name_id_source = ? WHERE application_id = ?",
    ))
    .bind(format.as_str())
    .bind(source.as_str())
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM app_saml_claims WHERE application_id = ?",
    ))
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    for claim in claims {
        insert_claim(conn, app, &claim.name, claim.source).await?;
    }
    Ok(())
}

pub(crate) async fn save_signing_in(
    conn: &mut Conn,
    app: &Application,
    option: SigningOption,
    algorithm: SigningAlgorithm,
) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET signing_option = ?, signing_algorithm = ? WHERE application_id = ?",
    ))
    .bind(option.as_str())
    .bind(algorithm.as_str())
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Add a signing certificate, inactive until an administrator activates it, so
/// the application can be given the new one first.
pub(crate) async fn add_certificate_in(
    conn: &mut Conn,
    app: &Application,
    certificate: &NewCertificate,
) -> anyhow::Result<()> {
    insert_certificate(conn, app, certificate, false).await
}

/// Make this certificate the one that signs; the previous one becomes inactive.
pub(crate) async fn activate_certificate_in(conn: &mut Conn, app: &Application, id: &str) -> anyhow::Result<String> {
    let found = certificates_in(conn, app).await?;
    let Some(certificate) = found.iter().find(|c| c.id == id) else {
        bail!("There is no such certificate on this application.");
    };
    if certificate.not_after <= now() {
        bail!("That certificate has expired.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_certificates SET active = ? WHERE application_id = ?",
    ))
    .bind(false)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_certificates SET active = ? WHERE id = ? AND application_id = ?",
    ))
    .bind(true)
    .bind(id)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(certificate.thumbprint.clone())
}

/// Remove an inactive certificate. The active one signs, so it stays.
pub(crate) async fn remove_certificate_in(conn: &mut Conn, app: &Application, id: &str) -> anyhow::Result<String> {
    let found = certificates_in(conn, app).await?;
    let Some(certificate) = found.iter().find(|c| c.id == id) else {
        bail!("There is no such certificate on this application.");
    };
    if certificate.active {
        bail!("The active certificate cannot be removed. Activate another one first.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM app_saml_certificates WHERE id = ? AND application_id = ?",
    ))
    .bind(id)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(certificate.thumbprint.clone())
}

/// Require signed requests, or stop. Requiring needs a verification certificate.
pub(crate) async fn set_require_signed_in(conn: &mut Conn, app: &Application, required: bool) -> anyhow::Result<()> {
    if required && verification_certificates_in(conn, app).await?.is_empty() {
        bail!("Add a verification certificate before requiring signed requests.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET require_signed_requests = ? WHERE application_id = ?",
    ))
    .bind(required)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Add a public certificate that verifies this application's signed requests.
///
/// Only its key is used. As the SAML V2.0 Metadata Interoperability Profile
/// requires, nothing else in it (validity dates, extensions, key usage, subject
/// or issuer) stops the key from verifying: an expired certificate's key works
/// until an administrator removes it. Its expiry is kept to show.
pub(crate) async fn add_verification_certificate_in(
    conn: &mut Conn,
    app: &Application,
    cert_der: &[u8],
    not_after: i64,
) -> anyhow::Result<String> {
    if !protocol::usable_verification_certificate(cert_der) {
        bail!("The certificate must hold an RSA public key, or an EC key on P-256 or P-384.");
    }
    let print = thumbprint(cert_der);
    if verification_certificates_in(conn, app)
        .await?
        .iter()
        .any(|c| c.thumbprint == print)
    {
        bail!("That certificate is already on this application.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO app_saml_verification_certs (id, application_id, cert_b64, thumbprint, not_after, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    ))
    .bind(new_guid())
    .bind(&app.id)
    .bind(b64(cert_der))
    .bind(&print)
    .bind(not_after)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(print)
}

/// Remove a verification certificate. The last one stays while signed requests
/// are required, or every sign-in to the application would fail.
pub(crate) async fn remove_verification_certificate_in(
    conn: &mut Conn,
    app: &Application,
    id: &str,
) -> anyhow::Result<String> {
    let found = verification_certificates_in(conn, app).await?;
    let Some(certificate) = found.iter().find(|c| c.id == id) else {
        bail!("There is no such certificate on this application.");
    };
    let required = config_in(conn, app).await?.is_some_and(|c| c.require_signed_requests);
    if required && !found.iter().any(|c| c.id != id) {
        bail!("Stop requiring signed requests before removing the last verification certificate.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "DELETE FROM app_saml_verification_certs WHERE id = ? AND application_id = ?",
    ))
    .bind(id)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(certificate.thumbprint.clone())
}

/// What a change to token encryption does to the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionCertificate<'a> {
    /// Keep the one in use (or none), changing only how it is used.
    Keep,
    /// Encrypt to this certificate's key from now on.
    Use(&'a [u8]),
    /// Stop encrypting.
    Stop,
}

/// Set how assertions are encrypted, and to which certificate.
pub(crate) async fn set_encryption_in(
    conn: &mut Conn,
    app: &Application,
    certificate: EncryptionCertificate<'_>,
    algorithms: EncryptionAlgorithms,
) -> anyhow::Result<()> {
    if let EncryptionCertificate::Use(der) = certificate
        && !protocol::usable_rsa_certificate(der)
    {
        bail!("The certificate must hold an RSA public key.");
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET encryption_method = ?, key_transport = ?, key_transport_digest = ?
         WHERE application_id = ?",
    ))
    .bind(algorithms.content.as_str())
    .bind(algorithms.transport.as_str())
    .bind(algorithms.digest.as_str())
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    let cert = match certificate {
        EncryptionCertificate::Keep => return Ok(()),
        EncryptionCertificate::Use(der) => Some(b64(der)),
        EncryptionCertificate::Stop => None,
    };
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE app_saml_settings SET encryption_cert_b64 = ? WHERE application_id = ?",
    ))
    .bind(cert)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The page the application's own sign-in starts from.
pub async fn sign_on_url<'c>(db: impl Handle<'c>, app: &Application) -> anyhow::Result<Option<String>> {
    let mut conn = db.acquire().await?;
    let (url,): (Option<String>,) = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT sign_on_url FROM applications WHERE id = ?",
    ))
    .bind(&app.id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(url)
}

pub(crate) async fn set_sign_on_url_in(conn: &mut Conn, app: &Application, url: Option<&str>) -> anyhow::Result<()> {
    if let Some(problem) = url.and_then(|u| url_problem("Sign on URL", u)) {
        bail!(problem);
    }
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE applications SET sign_on_url = ? WHERE id = ?",
    ))
    .bind(url)
    .bind(&app.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Entra's *Visible to users*: whether the app gallery lists the application.
pub(crate) async fn set_visible_in(conn: &mut Conn, sp: &ServicePrincipal, visible: bool) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(
        conn,
        "UPDATE service_principals SET visible_to_users = ? WHERE id = ?",
    ))
    .bind(visible)
    .bind(&sp.id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn is_visible<'c>(db: impl Handle<'c>, sp: &ServicePrincipal) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    let (visible,): (Flag,) = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT visible_to_users FROM service_principals WHERE id = ?",
    ))
    .bind(&sp.id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(visible.into())
}

// ---- session participants, for Single Logout ----

/// One application a browser session received an assertion for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub session_index: String,
    pub application_id: String,
    pub name_id: String,
    pub name_id_format: NameIdFormat,
}

/// The most distinct Name IDs recorded for one user at one application in one
/// session. Each is told at logout; a transient format makes a new one per
/// sign-in, and a cross-site page could otherwise grow the logout chain.
const MAX_NAME_IDS_PER_APP: i64 = 8;

/// This session's entry for this user, application and Name ID, created or
/// refreshed, and the SessionIndex its assertions carry. An entry is never
/// rewritten to another Name ID, and another user's on this browser stays, so a
/// logout names every subject the application was actually told about. Sign-in
/// state, like a session.
#[allow(clippy::too_many_arguments)]
pub async fn ensure_participant<'c>(
    db: impl Handle<'c>,
    session_hash: &str,
    tenant_id: &str,
    app: &Application,
    user_id: &str,
    name_id: &str,
    format: NameIdFormat,
    expires_at: i64,
) -> anyhow::Result<String> {
    let mut conn = db.acquire().await?;
    ensure_participant_in(
        &mut conn,
        session_hash,
        tenant_id,
        app,
        user_id,
        name_id,
        format,
        expires_at,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ensure_participant_in(
    conn: &mut Conn,
    session_hash: &str,
    tenant_id: &str,
    app: &Application,
    user_id: &str,
    name_id: &str,
    format: NameIdFormat,
    expires_at: i64,
) -> anyhow::Result<String> {
    let engine = crate::db::engine_of_conn(conn);
    let key = crate::util::sha256_hex(name_id.as_bytes());
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM saml_session_participants WHERE expires_at <= ?",
    ))
    .bind(now())
    .execute(&mut *tx)
    .await?;
    let existing: Option<(String,)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT session_index FROM saml_session_participants
         WHERE session_hash = ? AND application_id = ? AND user_id = ? AND name_id_key = ?",
    ))
    .bind(session_hash)
    .bind(&app.id)
    .bind(user_id)
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    let index = if let Some((index,)) = existing {
        sqlx::query(crate::db::sql_stmt(
            engine,
            "UPDATE saml_session_participants SET name_id_format = ?, expires_at = ? WHERE session_index = ?",
        ))
        .bind(format.as_str())
        .bind(expires_at)
        .bind(&index)
        .execute(&mut *tx)
        .await?;
        index
    } else {
        let recorded: Vec<(String,)> = sqlx::query_as(crate::db::sql_stmt(
            engine,
            "SELECT session_index FROM saml_session_participants
             WHERE session_hash = ? AND application_id = ? AND user_id = ?
             ORDER BY created_at DESC, session_index",
        ))
        .bind(session_hash)
        .bind(&app.id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        match recorded.first() {
            Some((latest,)) if recorded.len() as i64 >= MAX_NAME_IDS_PER_APP => latest.clone(),
            _ => {
                let index = protocol::new_id();
                sqlx::query(crate::db::sql_stmt(
                    engine,
                    "INSERT INTO saml_session_participants (session_index, session_hash, tenant_id, application_id,
                                                            user_id, name_id, name_id_key, name_id_format,
                                                            created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ))
                .bind(&index)
                .bind(session_hash)
                .bind(tenant_id)
                .bind(&app.id)
                .bind(user_id)
                .bind(name_id)
                .bind(&key)
                .bind(format.as_str())
                .bind(now())
                .bind(expires_at)
                .execute(&mut *tx)
                .await?;
                index
            }
        }
    };
    tx.commit().await?;
    Ok(index)
}

/// The SessionIndexes this user holds at this application in this browser.
pub async fn participant_indexes<'c>(
    db: impl Handle<'c>,
    session_hash: &str,
    tenant_id: &str,
    application_id: &str,
    user_id: &str,
) -> anyhow::Result<Vec<String>> {
    let mut conn = db.acquire().await?;
    let rows: Vec<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT session_index FROM saml_session_participants
         WHERE session_hash = ? AND tenant_id = ? AND application_id = ? AND user_id = ? AND expires_at > ?",
    ))
    .bind(session_hash)
    .bind(tenant_id)
    .bind(application_id)
    .bind(user_id)
    .bind(now())
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|(index,)| index).collect())
}

/// Take this session's participants in the tenant, in one transaction: each is
/// told about the logout once.
pub async fn take_participants<'c>(
    db: impl Handle<'c>,
    session_hash: &str,
    tenant_id: &str,
) -> anyhow::Result<Vec<Participant>> {
    let mut conn = db.acquire().await?;
    take_participants_in(&mut conn, session_hash, tenant_id).await
}

async fn take_participants_in(
    conn: &mut Conn,
    session_hash: &str,
    tenant_id: &str,
) -> anyhow::Result<Vec<Participant>> {
    let engine = crate::db::engine_of_conn(conn);
    let mut tx = crate::db::begin_write(&mut *conn).await?;
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(crate::db::sql_stmt(
        engine,
        "SELECT session_index, application_id, name_id, name_id_format FROM saml_session_participants
         WHERE session_hash = ? AND tenant_id = ? AND expires_at > ? ORDER BY created_at, session_index",
    ))
    .bind(session_hash)
    .bind(tenant_id)
    .bind(now())
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM saml_session_participants WHERE session_hash = ? AND tenant_id = ?",
    ))
    .bind(session_hash)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    rows.into_iter()
        .map(|(session_index, application_id, name_id, format)| {
            Ok(Participant {
                session_index,
                application_id,
                name_id,
                name_id_format: NameIdFormat::parse(&format).ok_or_else(|| anyhow!("unknown NameID format"))?,
            })
        })
        .collect()
}

// ---- gallery launches ----

/// How long a launch from the gallery may take, sign-in steps included.
const LAUNCH_TICKET_SECS: i64 = 600;

/// A launch from the gallery, still unused.
pub struct LaunchTicket {
    pub application_id: String,
    pub user_id: String,
}

/// Record a launch and return its ticket. Only the hash is stored.
pub async fn create_launch_ticket<'c>(
    db: impl Handle<'c>,
    tenant_id: &str,
    app: &Application,
    user_id: &str,
) -> anyhow::Result<String> {
    let ticket = crate::session::new_token();
    let mut conn = db.acquire().await?;
    sqlx::query(crate::db::qc(
        &conn,
        "DELETE FROM saml_launch_tickets WHERE expires_at <= ?",
    ))
    .bind(now())
    .execute(&mut *conn)
    .await?;
    sqlx::query(crate::db::qc(
        &conn,
        "INSERT INTO saml_launch_tickets (ticket_hash, tenant_id, application_id, user_id, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    ))
    .bind(crate::util::sha256_hex(ticket.as_bytes()))
    .bind(tenant_id)
    .bind(&app.id)
    .bind(user_id)
    .bind(now() + LAUNCH_TICKET_SECS)
    .execute(&mut *conn)
    .await?;
    Ok(ticket)
}

/// The launch this ticket stands for, without using it up.
pub async fn launch_ticket<'c>(
    db: impl Handle<'c>,
    ticket: &str,
    tenant_id: &str,
) -> anyhow::Result<Option<LaunchTicket>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String, String)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT application_id, user_id FROM saml_launch_tickets
         WHERE ticket_hash = ? AND tenant_id = ? AND expires_at > ?",
    ))
    .bind(crate::util::sha256_hex(ticket.as_bytes()))
    .bind(tenant_id)
    .bind(now())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(application_id, user_id)| LaunchTicket {
        application_id,
        user_id,
    }))
}

/// Use up a launch, for exactly this user and application. `false` if it was
/// already used, expired, or is someone else's.
pub async fn take_launch_ticket<'c>(
    db: impl Handle<'c>,
    ticket: &str,
    tenant_id: &str,
    application_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    let done = sqlx::query(crate::db::qc(
        &conn,
        "DELETE FROM saml_launch_tickets
         WHERE ticket_hash = ? AND tenant_id = ? AND application_id = ? AND user_id = ? AND expires_at > ?",
    ))
    .bind(crate::util::sha256_hex(ticket.as_bytes()))
    .bind(tenant_id)
    .bind(application_id)
    .bind(user_id)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Record a signed message as acted on. `false` if it already was: a replay.
pub async fn consume_message<'c>(db: impl Handle<'c>, application_id: &str, message_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    sqlx::query(crate::db::qc(
        &conn,
        "DELETE FROM saml_seen_messages WHERE expires_at <= ?",
    ))
    .bind(now())
    .execute(&mut *conn)
    .await?;
    let inserted = sqlx::query(crate::db::qc(
        &conn,
        "INSERT INTO saml_seen_messages (application_id, message_id, expires_at) VALUES (?, ?, ?)",
    ))
    .bind(application_id)
    .bind(message_id)
    // Kept for as long as the message itself could still be accepted.
    .bind(now() + protocol::SIGNED_MESSAGE_MAX_AGE_SECS + 2 * protocol::CLOCK_SKEW_SECS)
    .execute(&mut *conn)
    .await;
    Ok(crate::db::inserted(inserted)?)
}

/// A logout in progress, waiting for one participant's answer.
pub struct LogoutState {
    pub pending_app: String,
    pub remaining: Vec<Participant>,
    pub finish: crate::routes::saml::LogoutFinish,
}

/// How long a participant has to answer a logout request.
const LOGOUT_STATE_SECS: i64 = 600;

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredParticipant {
    session_index: String,
    application_id: String,
    name_id: String,
    name_id_format: String,
}

/// Remember where a logout is, keyed by the id of the request just sent.
pub async fn save_logout_state<'c>(
    db: impl Handle<'c>,
    request_id: &str,
    tenant_id: &str,
    pending_app: &str,
    browser_hash: &str,
    remaining: &[Participant],
    finish: &crate::routes::saml::LogoutFinish,
) -> anyhow::Result<()> {
    let stored: Vec<StoredParticipant> = remaining
        .iter()
        .map(|p| StoredParticipant {
            session_index: p.session_index.clone(),
            application_id: p.application_id.clone(),
            name_id: p.name_id.clone(),
            name_id_format: p.name_id_format.as_str().to_string(),
        })
        .collect();
    let mut conn = db.acquire().await?;
    sqlx::query(crate::db::qc(
        &conn,
        "DELETE FROM saml_logout_state WHERE expires_at <= ?",
    ))
    .bind(now())
    .execute(&mut *conn)
    .await?;
    sqlx::query(crate::db::qc(
        &conn,
        "INSERT INTO saml_logout_state (request_id, tenant_id, pending_app, browser_hash, remaining, finish, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    ))
    .bind(request_id)
    .bind(tenant_id)
    .bind(pending_app)
    .bind(browser_hash)
    .bind(serde_json::to_string(&stored)?)
    .bind(serde_json::to_string(finish)?)
    .bind(now() + LOGOUT_STATE_SECS)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether this browser still has a logout waiting for an answer.
pub async fn logout_in_progress<'c>(db: impl Handle<'c>, browser_hash: &str) -> anyhow::Result<bool> {
    let mut conn = db.acquire().await?;
    let (n,): (i64,) = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT COUNT(*) FROM saml_logout_state WHERE browser_hash = ? AND expires_at > ?",
    ))
    .bind(browser_hash)
    .bind(now())
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Take the logout waiting on this request: each answer counts once.
pub async fn take_logout_state<'c>(
    db: impl Handle<'c>,
    request_id: &str,
    tenant_id: &str,
    application_id: &str,
    browser_hash: &str,
) -> anyhow::Result<Option<LogoutState>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String, String)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT remaining, finish FROM saml_logout_state
         WHERE request_id = ? AND tenant_id = ? AND pending_app = ? AND browser_hash = ? AND expires_at > ?",
    ))
    .bind(request_id)
    .bind(tenant_id)
    .bind(application_id)
    .bind(browser_hash)
    .bind(now())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((remaining, finish)) = row else {
        return Ok(None);
    };
    let deleted = sqlx::query(crate::db::qc(
        &conn,
        "DELETE FROM saml_logout_state WHERE request_id = ? AND tenant_id = ? AND pending_app = ?",
    ))
    .bind(request_id)
    .bind(tenant_id)
    .bind(application_id)
    .execute(&mut *conn)
    .await?;
    if deleted.rows_affected() == 0 {
        return Ok(None);
    }
    let pending_app = application_id.to_string();
    let stored: Vec<StoredParticipant> = serde_json::from_str(&remaining)?;
    let remaining = stored
        .into_iter()
        .map(|p| {
            Ok(Participant {
                session_index: p.session_index,
                application_id: p.application_id,
                name_id: p.name_id,
                name_id_format: NameIdFormat::parse(&p.name_id_format)
                    .ok_or_else(|| anyhow!("unknown NameID format"))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Some(LogoutState {
        pending_app,
        remaining,
        finish: serde_json::from_str(&finish)?,
    }))
}

/// An application by its object id (`applications.id`).
pub async fn application_by_object_id<'c>(db: impl Handle<'c>, id: &str) -> anyhow::Result<Option<Application>> {
    let mut conn = db.acquire().await?;
    let row: Option<(String,)> = sqlx::query_as(crate::db::qc(
        &conn,
        "SELECT app_id FROM applications WHERE id = ? AND deleted_at IS NULL",
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((app_id,)) => crate::apps::find_in(&mut conn, &app_id).await,
        None => Ok(None),
    }
}

// ---- the app gallery ----

/// One tile of a user's app gallery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GalleryApp {
    pub app_id: String,
    /// The application's own tenant, which may not be the user's.
    pub tenant_id: String,
    pub display_name: String,
    pub sign_on_url: Option<String>,
    pub is_saml: bool,
    /// What its tile shows; `None` for its initials.
    pub logo: Option<crate::logos::Shown>,
}

/// app id, tenant, name, Sign on URL, single sign-on mode, accepts other
/// tenants; then its logo: library icon, image content type, updated at.
type GalleryRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Flag,
    Option<String>,
    Option<String>,
    Option<i64>,
);

/// The enabled, visible applications this user is assigned to, directly or
/// through a group, that can be launched: a Sign on URL, or SAML configured so
/// that sign-in can start here. `home_tenant_id` is the user's own tenant. An
/// application of another tenant is listed only when it accepts other tenants
/// and the user's own tenant lets them go there, as [`crate::access`] requires.
pub async fn gallery<'c>(db: impl Handle<'c>, home_tenant_id: &str, user_id: &str) -> anyhow::Result<Vec<GalleryApp>> {
    let mut acquired = db.acquire().await?;
    let conn: &mut Conn = &mut acquired;
    let rows: Vec<GalleryRow> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT DISTINCT a.app_id, sp.tenant_id, a.display_name, a.sign_on_url, sp.preferred_sso_mode,
                sp.accept_other_tenants, l.library_icon, l.content_type, l.updated_at
         FROM app_assignments x
         JOIN service_principals sp ON sp.id = x.resource_id
         JOIN applications a ON a.app_id = sp.app_id AND a.deleted_at IS NULL
         LEFT JOIN app_logos l ON l.application_id = a.id
         WHERE sp.enabled = ? AND sp.visible_to_users = ?
           AND ((x.principal_type = ? AND x.principal_id = ?)
             OR (x.principal_type = ? AND x.principal_id IN
                   (SELECT group_id FROM group_members WHERE user_id = ?)))
         ORDER BY a.display_name, a.app_id",
    ))
    .bind(true)
    .bind(true)
    .bind(crate::directory::PrincipalType::User.as_str())
    .bind(user_id)
    .bind(crate::directory::PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    let may_leave_home = match crate::tenant::resolve_in(&mut *conn, home_tenant_id).await? {
        Some(home) => crate::access::home_allows_in(&mut *conn, &home, user_id).await?.0,
        None => false,
    };
    let mut out = Vec::with_capacity(rows.len());
    for (app_id, tenant_id, display_name, sign_on_url, mode, accepts_others, icon, image_type, logo_at) in rows {
        if tenant_id != home_tenant_id {
            let accepts: bool = accepts_others.into();
            let live = crate::tenant::resolve_in(&mut *conn, &tenant_id).await?.is_some();
            if !(accepts && may_leave_home && live) {
                continue;
            }
        }
        let is_saml = mode.as_deref() == Some(SSO_MODE_SAML);
        let launchable = if is_saml {
            match crate::apps::find_in(&mut *conn, &app_id).await? {
                Some(app) => config_in(&mut *conn, &app)
                    .await?
                    .is_some_and(|c| c.is_configured() && (sign_on_url.is_some() || !c.require_signed_requests)),
                None => false,
            }
        } else {
            sign_on_url.is_some()
        };
        if launchable {
            out.push(GalleryApp {
                app_id,
                tenant_id,
                display_name,
                sign_on_url,
                is_saml,
                logo: logo_at.and_then(|at| crate::logos::Shown::from_row(icon.as_deref(), image_type.is_some(), at)),
            });
        }
    }
    Ok(out)
}

/// The pairwise identifier as lowercase hex, for an application that compares
/// Name IDs without regard to case.
fn lowercase_pairwise(pairwise: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pairwise)
        .map(hex::encode)
        .unwrap_or_else(|_| pairwise.to_ascii_lowercase())
}

/// What the assertion says the user's Name ID is. The value comes from the
/// configured source: a request may choose a compatible format, but never which
/// user property identifies the user. `persistent` is always this application's
/// own pairwise identifier (lowercase hex if that is the chosen source), so it is
/// never a name such as a UPN that other applications also see; `transient` is
/// generated; an empty source falls back to the user principal name.
pub fn name_id_for(
    config: &SamlConfig,
    requested: Option<NameIdFormat>,
    user: &User,
    pairwise: &str,
) -> Result<(String, NameIdFormat), protocol::SamlError> {
    let app_tenant_id = config.tenant_id.as_str();
    let format = requested.unwrap_or(config.name_id_format);
    let own_pairwise = match config.name_id_source {
        NameIdSource::PairwiseIdLowercase => lowercase_pairwise(pairwise),
        _ => pairwise.to_string(),
    };
    let configured = match config.name_id_source {
        NameIdSource::UserPrincipalName => user.upn.clone(),
        NameIdSource::Mail => trusted_email(user, app_tenant_id).unwrap_or_else(|| user.upn.clone()),
        NameIdSource::ObjectId => user.id.clone(),
        NameIdSource::PairwiseId | NameIdSource::PairwiseIdLowercase => own_pairwise.clone(),
    };
    let value = match (format, requested.is_some()) {
        (NameIdFormat::Transient, _) => protocol::new_id(),
        (NameIdFormat::Persistent, _) => own_pairwise,
        (NameIdFormat::EmailAddress, true)
            if matches!(
                config.name_id_source,
                NameIdSource::ObjectId | NameIdSource::PairwiseId | NameIdSource::PairwiseIdLowercase
            ) =>
        {
            return Err(protocol::SamlError {
                status: protocol::STATUS_REQUESTER,
                sub_status: Some(protocol::STATUS_INVALID_NAMEID_POLICY),
                message: "This application's Name ID is not an email address.".into(),
            });
        }
        _ => configured,
    };
    Ok((value, format))
}
