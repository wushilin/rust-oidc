//! SAML 2.0 messages, with no database and no HTTP: reading what a service
//! provider sends, and building and signing what we send back.
//!
//! **What is read** goes through one small strict parser ([`parse_xml`]): no
//! DOCTYPE (so no entity expansion), bounded size, depth and element count.
//!
//! **What is signed is generated, never re-serialized.** Every element we sign
//! is written directly in Exclusive XML Canonicalization form (sorted attributes,
//! no self-closed tags, namespaces declared where first used), so the bytes we
//! digest are the bytes we send and no general canonicalizer is needed.
//!
//! **Signed requests** are verified over the query octets as received on the
//! HTTP-Redirect binding, and by [`crate::saml_dsig`] on the POST binding.

use aws_lc_rs::cipher::{AES_256, PaddedBlockEncryptingKey, UnboundCipherKey};
use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey};
use aws_lc_rs::signature::{self, RsaKeyPair, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::io::{Read, Write};

use crate::util::{b64, random_bytes};

pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// The HTTP parameters of the SAML bindings, spelled once.
pub const PARAM_REQUEST: &str = "SAMLRequest";
pub const PARAM_RESPONSE: &str = "SAMLResponse";
pub const PARAM_RELAY_STATE: &str = "RelayState";
const PARAM_SIG_ALG: &str = "SigAlg";
const PARAM_SIGNATURE: &str = "Signature";
const SIGNED_PARAMS: [&str; 5] = [
    PARAM_REQUEST,
    PARAM_RESPONSE,
    PARAM_RELAY_STATE,
    PARAM_SIG_ALG,
    PARAM_SIGNATURE,
];

pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ENC_AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const ENC_RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const TYPE_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
pub const STATUS_NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
pub const STATUS_AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
pub const STATUS_NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
pub const STATUS_INVALID_NAMEID_POLICY: &str = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
pub const STATUS_REQUEST_UNSUPPORTED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";

pub const STATUS_PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
pub const STATUS_UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

pub const AC_PASSWORD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
pub const AC_PASSWORD_PROTECTED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
pub const AC_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
pub const AC_MFA: &str = "http://schemas.microsoft.com/claims/multipleauthn";

/// The largest message accepted, encoded or inflated.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_DEPTH: usize = 16;
pub(crate) const MAX_ELEMENTS: usize = 256;
const MAX_ID_CHARS: usize = 256;

/// How long a bearer assertion may be delivered. Entra's `Conditions` window is
/// 70 minutes; the subject confirmation uses the same.
pub const ASSERTION_LIFETIME_SECS: i64 = 70 * 60;
/// How old a signed message may be: long enough to finish signing in on the
/// page it opened, whose form lasts an hour.
pub const SIGNED_MESSAGE_MAX_AGE_SECS: i64 = 3600;
/// How far ahead of this server's clock a signed message may claim to be.
pub const CLOCK_SKEW_SECS: i64 = 300;
/// The longest RelayState accepted from a request.
pub const MAX_RELAY_STATE_BYTES: usize = 1024;

macro_rules! closed_set {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [$name] = &[$(Self::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            pub fn parse(raw: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == raw)
            }
        }
    };
}

closed_set!(
    /// The `Format` of a NameID, as Entra's name identifier format list offers.
    NameIdFormat {
        Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        WindowsDomain => "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    }
);

closed_set!(
    /// Entra's *Signing Option*.
    SigningOption {
        Assertion => "assertion",
        Response => "response",
        Both => "both",
    }
);

closed_set!(
    /// Entra's *Signing Algorithm*: SHA-256 by default, SHA-1 only when chosen.
    SigningAlgorithm {
        Sha256 => "sha256",
        Sha1 => "sha1",
    }
);

impl SigningAlgorithm {
    pub fn signature_uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        }
    }

    fn digest_uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha1 => DIGEST_SHA1,
        }
    }

    fn digest(self, data: &[u8]) -> String {
        let algorithm = match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        };
        b64(digest::digest(algorithm, data).as_ref())
    }
}

/// A protocol problem, reported to the service provider with this status when
/// the request got far enough to know where to send it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlError {
    pub status: &'static str,
    pub sub_status: Option<&'static str>,
    pub message: String,
}

impl SamlError {
    pub(crate) fn requester(message: impl Into<String>) -> Self {
        Self {
            status: STATUS_REQUESTER,
            sub_status: None,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            status: STATUS_REQUESTER,
            sub_status: Some(STATUS_REQUEST_UNSUPPORTED),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SamlError {}

// ---- reading ----

/// One parsed element: namespace, local name, unprefixed attributes, children
/// and direct text.
#[derive(Debug, Default)]
pub struct Node {
    pub ns: String,
    pub local: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub text: String,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn child(&self, ns: &str, local: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.ns == ns && c.local == local)
    }

    fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }
}

fn node_from(ns: ResolveResult<'_>, e: &BytesStart<'_>) -> Result<Node, SamlError> {
    let bad = || SamlError::requester("The SAML message is not well-formed XML.");
    let namespace = match ns {
        ResolveResult::Bound(n) => AsRef::<str>::as_ref(&n).to_string(),
        ResolveResult::Unbound => String::new(),
        ResolveResult::Unknown(_) => return Err(bad()),
    };
    let local = AsRef::<str>::as_ref(&e.local_name()).to_string();
    let mut attrs = Vec::new();
    for attribute in e.attributes() {
        let attribute = attribute.map_err(|_| bad())?;
        // Namespace declarations and qualified attributes carry nothing we read.
        let key: &str = attribute.key.as_ref();
        if attribute.key.prefix().is_some() || key == "xmlns" {
            continue;
        }
        let name = key.to_string();
        let value = attribute
            .normalized_value(XmlVersion::Explicit1_0)
            .map_err(|_| bad())?
            .into_owned();
        attrs.push((name, value));
    }
    Ok(Node {
        ns: namespace,
        local,
        attrs,
        ..Node::default()
    })
}

fn predefined_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// Parse a message into a tree, refusing anything a SAML message has no use for.
pub fn parse_xml(xml: &str) -> Result<Node, SamlError> {
    let bad = || SamlError::requester("The SAML message is not well-formed XML.");
    if xml.len() > MAX_MESSAGE_BYTES {
        return Err(SamlError::requester("The SAML message is too large."));
    }
    let mut reader = NsReader::from_str(xml);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut elements = 0usize;
    loop {
        let (ns, event) = reader.read_resolved_event().map_err(|_| bad())?;
        match event {
            Event::DocType(_) => return Err(SamlError::requester("A DOCTYPE is not allowed in a SAML message.")),
            // A second root element.
            Event::Start(_) | Event::Empty(_) if root.is_some() => return Err(bad()),
            Event::Start(e) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    return Err(SamlError::requester("The SAML message is too complex."));
                }
                stack.push(node_from(ns, &e)?);
            }
            Event::Empty(e) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    return Err(SamlError::requester("The SAML message is too complex."));
                }
                let node = node_from(ns, &e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(bad)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }
            Event::Text(t) => {
                let content = t.xml10_content();
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&content);
                } else if !content.chars().all(|c| c.is_ascii_whitespace()) {
                    return Err(bad());
                }
            }
            Event::CData(t) => {
                let top = stack.last_mut().ok_or_else(bad)?;
                top.text.push_str(&t.xml10_content());
            }
            Event::GeneralRef(r) => {
                let top = stack.last_mut().ok_or_else(bad)?;
                let c = match r.resolve_char_ref().map_err(|_| bad())? {
                    Some(c) => c,
                    None => predefined_entity(&r.xml10_content()).ok_or_else(bad)?,
                };
                top.text.push(c);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(bad());
    }
    root.ok_or_else(bad)
}

/// A message parameter as text: base64, then inflated if it was deflated (the
/// Redirect binding) or used as it is (the POST binding).
pub fn decode_message(raw: &str) -> Result<String, SamlError> {
    let bad = || SamlError::requester("The SAML message could not be decoded.");
    if raw.len() > MAX_MESSAGE_BYTES * 2 {
        return Err(SamlError::requester("The SAML message is too large."));
    }
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = STANDARD.decode(compact).map_err(|_| bad())?;
    if bytes.first() == Some(&b'<') || bytes.starts_with(b"\xef\xbb\xbf<") {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(SamlError::requester("The SAML message is too large."));
        }
        return String::from_utf8(bytes).map_err(|_| bad());
    }
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(bytes.as_slice())
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| bad())?;
    if out.len() > MAX_MESSAGE_BYTES {
        return Err(SamlError::requester("The SAML message is too large."));
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// Deflate and base64 a message for the Redirect binding.
pub fn encode_redirect(xml: &str) -> anyhow::Result<String> {
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml.as_bytes())?;
    Ok(b64(&encoder.finish()?))
}

/// An `xs:dateTime` with a time zone, as seconds since the epoch.
pub fn parse_instant(raw: &str) -> Option<i64> {
    time::OffsetDateTime::parse(raw.trim(), &time::format_description::well_known::Rfc3339)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp)
}

/// Whether a signed message was issued recently enough to act on.
pub fn is_fresh(issue_instant: Option<i64>, now: i64) -> bool {
    issue_instant.is_some_and(|at| at <= now + CLOCK_SKEW_SECS && at >= now - SIGNED_MESSAGE_MAX_AGE_SECS)
}

fn check_id(id: Option<&str>) -> Result<String, SamlError> {
    let id = id.ok_or_else(|| SamlError::requester("The SAML message has no ID."))?;
    let first_ok = id.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_');
    let rest_ok = id.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !first_ok || !rest_ok || id.chars().count() > MAX_ID_CHARS {
        return Err(SamlError::requester("The ID of the SAML message is not valid."));
    }
    Ok(id.to_string())
}

fn check_version(root: &Node) -> Result<(), SamlError> {
    if root.attr("Version") != Some("2.0") {
        return Err(SamlError {
            status: STATUS_REQUESTER,
            sub_status: Some("urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"),
            message: "The SAML message must have Version 2.0.".into(),
        });
    }
    if root.attr("IssueInstant").is_none() {
        return Err(SamlError::requester("The SAML message has no IssueInstant."));
    }
    Ok(())
}

fn issuer_of(root: &Node) -> Result<String, SamlError> {
    root.child(NS_ASSERTION, "Issuer")
        .map(|i| i.text.trim().to_string())
        .filter(|i| !i.is_empty())
        .ok_or_else(|| SamlError::requester("The SAML message has no Issuer."))
}

fn xs_bool(raw: Option<&str>) -> bool {
    matches!(raw.map(str::trim), Some("true" | "1"))
}

/// A parsed `<samlp:AuthnRequest>`, following Entra's treatment of each field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnRequest {
    pub id: String,
    pub issuer: String,
    /// Checked only on a signed request; Entra otherwise ignores it.
    pub issue_instant: Option<i64>,
    /// When present it must be where the request was received. A signed
    /// request must have one.
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub acs_index: Option<i64>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub name_id_format: Option<NameIdFormat>,
    pub sp_name_qualifier: Option<String>,
    /// The authentication context classes asked for, with `exact` comparison.
    pub authn_contexts: Vec<String>,
    /// The request names an authentication context declaration. None is
    /// supported, so such a request can never be satisfied.
    pub requests_declaration: bool,
    /// Why this well-formed request cannot be honored. It is answered with this
    /// SAML status at the registered Reply URL, once the requester is known.
    pub refusal: Option<SamlError>,
}

impl AuthnRequest {
    pub fn parse(xml: &str) -> Result<Self, SamlError> {
        let root = parse_xml(xml)?;
        if !root.is(NS_PROTOCOL, "AuthnRequest") {
            return Err(SamlError::requester("The message is not a SAML AuthnRequest."));
        }
        let id = check_id(root.attr("ID"))?;
        check_version(&root)?;
        let issuer = issuer_of(&root)?;
        let mut refusal = root
            .child(NS_ASSERTION, "Subject")
            .map(|_| SamlError::unsupported("An AuthnRequest must not contain a Subject."));
        if let Some(binding) = root.attr("ProtocolBinding")
            && binding != BINDING_POST
        {
            refusal.get_or_insert_with(|| {
                SamlError::unsupported("Only the HTTP-POST binding is supported for the SAML response.")
            });
        }
        let acs_index = match root.attr("AssertionConsumerServiceIndex") {
            Some(raw) => Some(
                raw.trim()
                    .parse::<i64>()
                    .ok()
                    .filter(|i| (0..=65_535).contains(i))
                    .ok_or_else(|| SamlError::requester("AssertionConsumerServiceIndex is not valid."))?,
            ),
            None => None,
        };
        let acs_url = root.attr("AssertionConsumerServiceURL").map(str::to_string);
        if acs_url.is_some() && acs_index.is_some() {
            return Err(SamlError::requester(
                "An AuthnRequest may not give both an AssertionConsumerServiceURL and an index.",
            ));
        }
        let force_authn = xs_bool(root.attr("ForceAuthn"));
        let is_passive = xs_bool(root.attr("IsPassive"));
        if force_authn && is_passive {
            return Err(SamlError::requester("ForceAuthn and IsPassive cannot both be true."));
        }
        let (name_id_format, sp_name_qualifier) = match root.child(NS_PROTOCOL, "NameIDPolicy") {
            Some(policy) => {
                let format = match policy.attr("Format") {
                    None => None,
                    Some(raw) if raw == NameIdFormat::Unspecified.as_str() => None,
                    Some(raw) => {
                        let format = NameIdFormat::parse(raw).filter(|f| *f != NameIdFormat::WindowsDomain);
                        if format.is_none() {
                            refusal.get_or_insert_with(|| SamlError {
                                status: STATUS_REQUESTER,
                                sub_status: Some(STATUS_INVALID_NAMEID_POLICY),
                                message: "The requested NameID format is not supported.".into(),
                            });
                        }
                        format
                    }
                };
                (format, policy.attr("SPNameQualifier").map(str::to_string))
            }
            None => (None, None),
        };
        let mut authn_contexts = Vec::new();
        let mut requests_declaration = false;
        if let Some(context) = root.child(NS_PROTOCOL, "RequestedAuthnContext") {
            if !matches!(context.attr("Comparison"), None | Some("exact")) {
                refusal.get_or_insert_with(|| SamlError {
                    status: STATUS_RESPONDER,
                    sub_status: Some(STATUS_NO_AUTHN_CONTEXT),
                    message: "RequestedAuthnContext Comparison must be 'exact'.".into(),
                });
            }
            requests_declaration = context
                .children
                .iter()
                .any(|c| c.is(NS_ASSERTION, "AuthnContextDeclRef"));
            authn_contexts = context
                .children
                .iter()
                .filter(|c| c.is(NS_ASSERTION, "AuthnContextClassRef"))
                .map(|c| c.text.trim().to_string())
                .collect();
        }
        Ok(Self {
            id,
            issuer,
            issue_instant: root.attr("IssueInstant").and_then(parse_instant),
            destination: root.attr("Destination").map(str::to_string),
            acs_url,
            acs_index,
            force_authn,
            is_passive,
            name_id_format,
            sp_name_qualifier,
            authn_contexts,
            requests_declaration,
            refusal,
        })
    }
}

/// A parsed `<samlp:LogoutRequest>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: Option<i64>,
    pub not_on_or_after: Option<i64>,
    pub destination: Option<String>,
    pub session_indexes: Vec<String>,
}

impl LogoutRequest {
    pub fn parse(xml: &str) -> Result<Self, SamlError> {
        let root = parse_xml(xml)?;
        if !root.is(NS_PROTOCOL, "LogoutRequest") {
            return Err(SamlError::requester("The message is not a SAML LogoutRequest."));
        }
        let id = check_id(root.attr("ID"))?;
        check_version(&root)?;
        let issuer = issuer_of(&root)?;
        let not_on_or_after = match root.attr("NotOnOrAfter") {
            Some(raw) => {
                Some(parse_instant(raw).ok_or_else(|| SamlError::requester("NotOnOrAfter is not a valid time."))?)
            }
            None => None,
        };
        let session_indexes = root
            .children
            .iter()
            .filter(|c| c.is(NS_PROTOCOL, "SessionIndex"))
            .map(|c| c.text.trim().to_string())
            .collect();
        Ok(Self {
            id,
            issuer,
            issue_instant: root.attr("IssueInstant").and_then(parse_instant),
            not_on_or_after,
            destination: root.attr("Destination").map(str::to_string),
            session_indexes,
        })
    }
}

/// A parsed `<samlp:LogoutResponse>`: which of our requests it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResponse {
    pub in_response_to: Option<String>,
    pub issuer: String,
    /// Where its sender addressed it, if it says.
    pub destination: Option<String>,
    pub success: bool,
}

impl LogoutResponse {
    pub fn parse(xml: &str) -> Result<Self, SamlError> {
        let root = parse_xml(xml)?;
        if !root.is(NS_PROTOCOL, "LogoutResponse") {
            return Err(SamlError::requester("The message is not a SAML LogoutResponse."));
        }
        check_id(root.attr("ID"))?;
        check_version(&root)?;
        let success = root
            .child(NS_PROTOCOL, "Status")
            .and_then(|s| s.child(NS_PROTOCOL, "StatusCode"))
            .and_then(|c| c.attr("Value"))
            == Some(STATUS_SUCCESS);
        Ok(Self {
            in_response_to: root.attr("InResponseTo").map(str::to_string),
            issuer: issuer_of(&root)?,
            destination: root.attr("Destination").map(str::to_string),
            success,
        })
    }
}

// ---- certificates ----

/// The DER of the certificate's SubjectPublicKeyInfo, and of the RSA key in it.
pub(crate) fn public_key_of(cert_der: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    let rsa = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("the certificate's key is not byte-aligned"))?
        .to_vec();
    Ok((spki.to_der()?, rsa))
}

/// Whether `cert_der` holds an RSA key this server can verify and encrypt with.
pub fn usable_rsa_certificate(cert_der: &[u8]) -> bool {
    public_key_of(cert_der)
        .ok()
        .and_then(|(spki, _)| PublicEncryptingKey::from_der(&spki).ok())
        .is_some()
}

/// The SAML parameters of one request, read once from the raw query.
///
/// A Redirect signature covers the parameters' encoded octets, so what is
/// verified and what is acted on must be the same parameters. A SAML parameter
/// that is repeated, or whose *name* is percent-encoded, could make those two
/// differ, so it is refused here, before anything reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlQuery {
    /// [`PARAM_REQUEST`] or [`PARAM_RESPONSE`].
    pub param: &'static str,
    /// The message, URL-decoded.
    pub message: String,
    pub relay_state: Option<String>,
    raw_message: String,
    raw_relay_state: Option<String>,
    raw_sig_alg: Option<String>,
    raw_signature: Option<String>,
}

impl SamlQuery {
    pub fn parse(raw: &str) -> Result<Self, SamlError> {
        let refused = || SamlError::requester("The SAML parameters are malformed or repeated.");
        let mut found: std::collections::HashMap<&'static str, (String, String)> = std::collections::HashMap::new();
        for pair in raw.split('&').filter(|p| !p.is_empty()) {
            let raw_key = pair.split_once('=').map_or(pair, |(k, _)| k);
            let raw_value = pair.split_once('=').map_or("", |(_, v)| v);
            let Some((key, value)) = url::form_urlencoded::parse(pair.as_bytes()).next() else {
                continue;
            };
            let Some(name) = SIGNED_PARAMS.iter().copied().find(|n| *n == key) else {
                continue;
            };
            if raw_key != name
                || found
                    .insert(name, (raw_value.to_string(), value.into_owned()))
                    .is_some()
            {
                return Err(refused());
            }
        }
        let (param, message) = match (found.remove(PARAM_REQUEST), found.remove(PARAM_RESPONSE)) {
            (Some(m), None) => (PARAM_REQUEST, m),
            (None, Some(m)) => (PARAM_RESPONSE, m),
            _ => return Err(refused()),
        };
        let relay = found.remove(PARAM_RELAY_STATE);
        if relay.as_ref().is_some_and(|(_, v)| v.len() > MAX_RELAY_STATE_BYTES) {
            return Err(SamlError::requester("RelayState is too long."));
        }
        Ok(Self {
            param,
            message: message.1,
            relay_state: relay.as_ref().map(|(_, v)| v.clone()).filter(|v| !v.is_empty()),
            raw_message: message.0,
            raw_relay_state: relay.map(|(r, _)| r),
            raw_sig_alg: found.remove(PARAM_SIG_ALG).map(|(r, _)| r),
            raw_signature: found.remove(PARAM_SIGNATURE).map(|(_, v)| v),
        })
    }

    /// Whether the query carries a Redirect-binding signature (or part of one).
    pub fn is_signed(&self) -> bool {
        self.raw_sig_alg.is_some() || self.raw_signature.is_some()
    }

    /// The same message with no Redirect-binding signature: what a POST carries,
    /// because its signature, if it has one, is inside the message.
    pub fn without_signature(&self) -> String {
        let mut out = format!("{}={}", self.param, self.raw_message);
        if let Some(relay) = &self.raw_relay_state {
            out.push_str(&format!("&{PARAM_RELAY_STATE}={relay}"));
        }
        out
    }

    /// Verify the Redirect signature over exactly these parameters' octets:
    /// message, RelayState if present, then SigAlg.
    pub fn verify(&self, certificates: &[Vec<u8>], allow_sha1: bool) -> Result<(), SamlError> {
        let refused = |m: &str| SamlError::requester(m);
        let (Some(sig_alg), Some(signature)) = (&self.raw_sig_alg, &self.raw_signature) else {
            return Err(refused("The request is not signed."));
        };
        let decoded_alg: String = url::form_urlencoded::parse(format!("a={sig_alg}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let algorithm: &'static dyn signature::VerificationAlgorithm =
            if decoded_alg == SigningAlgorithm::Sha256.signature_uri() {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else if decoded_alg == SigningAlgorithm::Sha1.signature_uri() && allow_sha1 {
                &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
            } else {
                return Err(refused(
                    "Signature algorithm not allowed. Only RSA-SHA256 is supported.",
                ));
            };
        let signature = STANDARD
            .decode(signature)
            .map_err(|_| refused("The request's signature could not be read."))?;
        let mut signed = format!("{}={}", self.param, self.raw_message);
        if let Some(relay) = &self.raw_relay_state {
            signed.push_str(&format!("&{PARAM_RELAY_STATE}={relay}"));
        }
        signed.push_str(&format!("&{PARAM_SIG_ALG}={sig_alg}"));
        let verified = certificates.iter().any(|cert| {
            public_key_of(cert)
                .map(|(_, rsa)| {
                    UnparsedPublicKey::new(algorithm, rsa)
                        .verify(signed.as_bytes(), &signature)
                        .is_ok()
                })
                .unwrap_or(false)
        });
        if verified {
            Ok(())
        } else {
            Err(refused("The request's signature did not verify."))
        }
    }
}

// ---- writing ----

/// Text content in canonical form. A character XML cannot carry is an error:
/// dropping it would silently change an identity.
fn text(value: &str) -> anyhow::Result<String> {
    check_chars(value)?;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// An attribute value in canonical form.
fn attr(value: &str) -> anyhow::Result<String> {
    check_chars(value)?;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    Ok(out)
}

fn check_chars(value: &str) -> anyhow::Result<()> {
    let valid = |c: char| matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}');
    anyhow::ensure!(value.chars().all(valid), "a value holds a character XML cannot carry");
    Ok(())
}

pub fn instant(unix: i64) -> anyhow::Result<String> {
    use time::macros::format_description;
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    Ok(time::OffsetDateTime::from_unix_timestamp(unix)?.format(&format)?)
}

/// A new message id: never starts with a digit, as SAML's `xs:ID` requires.
pub fn new_id() -> String {
    format!("_{}", hex::encode(random_bytes(16)))
}

/// The key that signs for one application.
pub struct Signer<'a> {
    pub private_key_pem: &'a str,
    pub cert_der: &'a [u8],
    pub algorithm: SigningAlgorithm,
}

const SHA1_LEN: usize = 20;
/// The DER `DigestInfo` prefix of a SHA-1 hash (RFC 8017, section 9.2).
const SHA1_DIGEST_INFO: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

fn pkcs8_of(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(STANDARD.decode(body)?)
}

impl Signer<'_> {
    fn sign(&self, data: &[u8]) -> anyhow::Result<String> {
        let der = pkcs8_of(self.private_key_pem)?;
        match self.algorithm {
            SigningAlgorithm::Sha256 => {
                let key =
                    RsaKeyPair::from_pkcs8(&der).map_err(|e| anyhow::anyhow!("the signing key cannot be read: {e}"))?;
                let mut out = vec![0u8; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut out)
                    .map_err(|_| anyhow::anyhow!("signing failed"))?;
                Ok(b64(&out))
            }
            // aws-lc-rs verifies RSA-SHA1 but will not create it, so this one
            // opt-in legacy choice is signed by the `rsa` crate, with blinding.
            SigningAlgorithm::Sha1 => {
                use rsa::pkcs8::DecodePrivateKey;
                let key = rsa::RsaPrivateKey::from_pkcs8_der(&der)?;
                let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
                let padding = rsa::Pkcs1v15Sign {
                    hash_len: Some(SHA1_LEN),
                    prefix: SHA1_DIGEST_INFO.to_vec().into_boxed_slice(),
                };
                let out = key.sign_with_rng(&mut rsa::rand_core::OsRng, padding, hash.as_ref())?;
                Ok(b64(&out))
            }
        }
    }

    /// The `<ds:Signature>` for an element with this id and canonical form.
    fn enveloped(&self, id: &str, canonical: &str) -> anyhow::Result<String> {
        let digest = self.algorithm.digest(canonical.as_bytes());
        let inner = format!(
            r##"<ds:CanonicalizationMethod Algorithm="{C14N_EXCLUSIVE}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{sig}"></ds:SignatureMethod><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{TRANSFORM_ENVELOPED}"></ds:Transform><ds:Transform Algorithm="{C14N_EXCLUSIVE}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{dig}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##,
            sig = self.algorithm.signature_uri(),
            dig = self.algorithm.digest_uri(),
        );
        // Signed on its own, where exclusive canonicalization puts the namespace
        // on it; inside the Signature it inherits the same declaration.
        let standalone = format!(r#"<ds:SignedInfo xmlns:ds="{NS_DS}">{inner}</ds:SignedInfo>"#);
        let value = self.sign(standalone.as_bytes())?;
        Ok(format!(
            r#"<ds:Signature xmlns:ds="{NS_DS}"><ds:SignedInfo>{inner}</ds:SignedInfo><ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
            cert = b64(self.cert_der),
        ))
    }

    /// Sign a Redirect-binding message: the query string, with `SigAlg` and
    /// `Signature` appended, over the exact octets sent.
    pub fn sign_redirect(&self, param: &str, encoded: &str, relay_state: Option<&str>) -> anyhow::Result<String> {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair(param, encoded);
        if let Some(relay) = relay_state {
            query.append_pair("RelayState", relay);
        }
        query.append_pair("SigAlg", self.algorithm.signature_uri());
        let unsigned = query.finish();
        let signature = self.sign(unsigned.as_bytes())?;
        let tail = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("Signature", &signature)
            .finish();
        Ok(format!("{unsigned}&{tail}"))
    }
}

/// One attribute of an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionAttribute {
    pub name: String,
    pub values: Vec<String>,
}

/// Everything an assertion says.
pub struct AssertionInput<'a> {
    pub idp_entity_id: &'a str,
    pub audience: &'a str,
    pub recipient: &'a str,
    pub in_response_to: Option<&'a str>,
    pub name_id: &'a str,
    pub name_id_format: NameIdFormat,
    pub sp_name_qualifier: Option<&'a str>,
    pub session_index: &'a str,
    pub authn_instant: i64,
    pub authn_context: &'a str,
    pub attributes: &'a [AssertionAttribute],
    pub now: i64,
}

fn issuer_element(entity: &str) -> anyhow::Result<String> {
    Ok(format!(
        r#"<saml:Issuer xmlns:saml="{NS_ASSERTION}">{}</saml:Issuer>"#,
        text(entity)?
    ))
}

/// A `<saml:Assertion>`, signed when `signer` is given.
fn assertion(a: &AssertionInput<'_>, signer: Option<&Signer<'_>>) -> anyhow::Result<String> {
    let id = new_id();
    let issued = instant(a.now)?;
    let not_after = instant(a.now + ASSERTION_LIFETIME_SECS)?;
    let in_response_to = match a.in_response_to {
        Some(r) => format!(r#" InResponseTo="{}""#, attr(r)?),
        None => String::new(),
    };
    let qualifier = match a.sp_name_qualifier {
        Some(q) => format!(r#" SPNameQualifier="{}""#, attr(q)?),
        None => String::new(),
    };
    let head = format!(
        r#"<saml:Assertion xmlns:saml="{NS_ASSERTION}" ID="{id}" IssueInstant="{issued}" Version="2.0"><saml:Issuer>{issuer}</saml:Issuer>"#,
        issuer = text(a.idp_entity_id)?,
    );
    let mut attributes = String::new();
    for attribute in a.attributes.iter().filter(|x| !x.values.is_empty()) {
        attributes.push_str(&format!(r#"<saml:Attribute Name="{}">"#, attr(&attribute.name)?));
        for value in &attribute.values {
            attributes.push_str(&format!("<saml:AttributeValue>{}</saml:AttributeValue>", text(value)?));
        }
        attributes.push_str("</saml:Attribute>");
    }
    let attribute_statement = if attributes.is_empty() {
        String::new()
    } else {
        format!("<saml:AttributeStatement>{attributes}</saml:AttributeStatement>")
    };
    let tail = format!(
        r#"<saml:Subject><saml:NameID Format="{format}"{qualifier}>{name_id}</saml:NameID><saml:SubjectConfirmation Method="{CM_BEARER}"><saml:SubjectConfirmationData{in_response_to} NotOnOrAfter="{not_after}" Recipient="{recipient}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{issued}" NotOnOrAfter="{not_after}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{attribute_statement}<saml:AuthnStatement AuthnInstant="{authn}" SessionIndex="{session}"><saml:AuthnContext><saml:AuthnContextClassRef>{context}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>"#,
        format = a.name_id_format.as_str(),
        name_id = text(a.name_id)?,
        recipient = attr(a.recipient)?,
        audience = text(a.audience)?,
        authn = instant(a.authn_instant)?,
        session = attr(a.session_index)?,
        context = text(a.authn_context)?,
    );
    Ok(match signer {
        Some(signer) => {
            let signature = signer.enveloped(&id, &format!("{head}{tail}"))?;
            format!("{head}{signature}{tail}")
        }
        None => format!("{head}{tail}"),
    })
}

/// Encrypt an assertion for the application: AES-256-CBC, its key wrapped with
/// RSA-OAEP to the application's certificate. The assertion is signed first.
fn encrypt_assertion(assertion: &str, cert_der: &[u8]) -> anyhow::Result<String> {
    let (spki, _) = public_key_of(cert_der)?;
    let public = PublicEncryptingKey::from_der(&spki).map_err(|_| anyhow::anyhow!("the encryption key is not RSA"))?;
    let oaep = OaepPublicEncryptingKey::new(public).map_err(|_| anyhow::anyhow!("the encryption key is unusable"))?;
    let key = random_bytes(32);
    let cipher = PaddedBlockEncryptingKey::cbc_pkcs7(
        UnboundCipherKey::new(&AES_256, &key).map_err(|_| anyhow::anyhow!("cipher key"))?,
    )
    .map_err(|_| anyhow::anyhow!("cipher"))?;
    let mut data = assertion.as_bytes().to_vec();
    let context = cipher
        .encrypt(&mut data)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let iv: &[u8] = (&context)
        .try_into()
        .map_err(|_| anyhow::anyhow!("cipher returned no IV"))?;
    let mut sealed = iv.to_vec();
    sealed.extend_from_slice(&data);
    let mut wrapped = vec![0u8; oaep.ciphertext_size()];
    let wrapped_len = oaep
        .encrypt(&OAEP_SHA1_MGF1SHA1, &key, &mut wrapped, None)
        .map_err(|_| anyhow::anyhow!("key wrapping failed"))?
        .len();
    wrapped.truncate(wrapped_len);
    Ok(format!(
        r#"<saml:EncryptedAssertion xmlns:saml="{NS_ASSERTION}"><xenc:EncryptedData xmlns:xenc="{NS_XENC}" Type="{TYPE_ELEMENT}"><xenc:EncryptionMethod Algorithm="{ENC_AES256_CBC}"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds="{NS_DS}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{ENC_RSA_OAEP}"><ds:DigestMethod Algorithm="{DIGEST_SHA1}"></ds:DigestMethod></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{key}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{value}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#,
        cert = b64(cert_der),
        key = b64(&wrapped),
        value = b64(&sealed),
    ))
}

fn status_element(status: &str, sub_status: Option<&str>, message: Option<&str>) -> anyhow::Result<String> {
    let code = match sub_status {
        Some(sub) => format!(
            r#"<samlp:StatusCode Value="{}"><samlp:StatusCode Value="{}"></samlp:StatusCode></samlp:StatusCode>"#,
            attr(status)?,
            attr(sub)?
        ),
        None => format!(r#"<samlp:StatusCode Value="{}"></samlp:StatusCode>"#, attr(status)?),
    };
    let message = match message {
        Some(m) => format!("<samlp:StatusMessage>{}</samlp:StatusMessage>", text(m)?),
        None => String::new(),
    };
    Ok(format!("<samlp:Status>{code}{message}</samlp:Status>"))
}

/// A successful `<samlp:Response>`, signed and encrypted as the application is
/// configured, base64-encoded for the POST binding.
pub fn success_response(
    a: &AssertionInput<'_>,
    signer: &Signer<'_>,
    option: SigningOption,
    encrypt_to: Option<&[u8]>,
) -> anyhow::Result<String> {
    let sign_assertion = matches!(option, SigningOption::Assertion | SigningOption::Both);
    let sign_response = matches!(option, SigningOption::Response | SigningOption::Both);
    let inner = assertion(a, sign_assertion.then_some(signer))?;
    let inner = match encrypt_to {
        Some(cert) => encrypt_assertion(&inner, cert)?,
        None => inner,
    };
    let id = new_id();
    let in_response_to = match a.in_response_to {
        Some(r) => format!(r#" InResponseTo="{}""#, attr(r)?),
        None => String::new(),
    };
    let head = format!(
        r#"<samlp:Response xmlns:samlp="{NS_PROTOCOL}" Destination="{destination}" ID="{id}"{in_response_to} IssueInstant="{issued}" Version="2.0">{issuer}"#,
        destination = attr(a.recipient)?,
        issued = instant(a.now)?,
        issuer = issuer_element(a.idp_entity_id)?,
    );
    let tail = format!(
        "{}{inner}</samlp:Response>",
        status_element(STATUS_SUCCESS, None, None)?
    );
    let xml = if sign_response {
        let signature = signer.enveloped(&id, &format!("{head}{tail}"))?;
        format!("{head}{signature}{tail}")
    } else {
        format!("{head}{tail}")
    };
    Ok(b64(xml.as_bytes()))
}

/// A failed `<samlp:Response>`, base64-encoded for the POST binding.
pub fn error_response(
    idp_entity_id: &str,
    destination: &str,
    in_response_to: Option<&str>,
    error: &SamlError,
    now: i64,
) -> anyhow::Result<String> {
    let in_response_to = match in_response_to {
        Some(r) => format!(r#" InResponseTo="{}""#, attr(r)?),
        None => String::new(),
    };
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{NS_PROTOCOL}" Destination="{destination}" ID="{id}"{in_response_to} IssueInstant="{issued}" Version="2.0">{issuer}{status}</samlp:Response>"#,
        destination = attr(destination)?,
        id = new_id(),
        issued = instant(now)?,
        issuer = issuer_element(idp_entity_id)?,
        status = status_element(error.status, error.sub_status, Some(&error.message))?,
    );
    Ok(b64(xml.as_bytes()))
}

/// A `<samlp:LogoutResponse>`, as XML for the Redirect binding.
pub fn logout_response(
    idp_entity_id: &str,
    destination: &str,
    in_response_to: &str,
    status: &str,
    sub_status: Option<&str>,
    now: i64,
) -> anyhow::Result<String> {
    Ok(format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{NS_PROTOCOL}" Destination="{destination}" ID="{id}" InResponseTo="{reply}" IssueInstant="{issued}" Version="2.0">{issuer}{status}</samlp:LogoutResponse>"#,
        destination = attr(destination)?,
        id = new_id(),
        reply = attr(in_response_to)?,
        issued = instant(now)?,
        issuer = issuer_element(idp_entity_id)?,
        status = status_element(status, sub_status, None)?,
    ))
}

/// A `<samlp:LogoutRequest>` to one session participant, as XML, and its id.
pub fn logout_request(
    idp_entity_id: &str,
    destination: &str,
    name_id: &str,
    name_id_format: NameIdFormat,
    session_index: &str,
    now: i64,
) -> anyhow::Result<(String, String)> {
    let id = new_id();
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{NS_PROTOCOL}" Destination="{destination}" ID="{id}" IssueInstant="{issued}" NotOnOrAfter="{not_after}" Version="2.0">{issuer}<saml:NameID xmlns:saml="{NS_ASSERTION}" Format="{format}">{name}</saml:NameID><samlp:SessionIndex>{session}</samlp:SessionIndex></samlp:LogoutRequest>"#,
        destination = attr(destination)?,
        issued = instant(now)?,
        // No earlier than any assertion already issued for the session can
        // expire: each of those was issued by now, with this same lifetime.
        not_after = instant(now + ASSERTION_LIFETIME_SECS)?,
        issuer = issuer_element(idp_entity_id)?,
        format = name_id_format.as_str(),
        name = text(name_id)?,
        session = text(session_index)?,
    );
    Ok((xml, id))
}

/// The application's federation metadata (`IDPSSODescriptor`).
pub fn idp_metadata(
    idp_entity_id: &str,
    sso_url: &str,
    certificates: &[Vec<u8>],
    want_signed_requests: bool,
) -> anyhow::Result<String> {
    let keys: String = certificates
        .iter()
        .map(|c| {
            format!(
                r#"<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{NS_DS}"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"#,
                b64(c)
            )
        })
        .collect();
    let formats: String = NameIdFormat::ALL
        .iter()
        .filter(|f| **f != NameIdFormat::WindowsDomain)
        .map(|f| format!("<NameIDFormat>{}</NameIDFormat>", f.as_str()))
        .collect();
    let url = attr(sso_url)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="utf-8"?><EntityDescriptor xmlns="{NS_METADATA}" entityID="{entity}"><IDPSSODescriptor WantAuthnRequestsSigned="{want_signed_requests}" protocolSupportEnumeration="{NS_PROTOCOL}">{keys}<SingleLogoutService Binding="{BINDING_REDIRECT}" Location="{url}"/>{formats}<SingleSignOnService Binding="{BINDING_REDIRECT}" Location="{url}"/><SingleSignOnService Binding="{BINDING_POST}" Location="{url}"/></IDPSSODescriptor></EntityDescriptor>"#,
        entity = attr(idp_entity_id)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(extra: &str, body: &str) -> String {
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{NS_PROTOCOL}" xmlns:saml="{NS_ASSERTION}" ID="_abc" Version="2.0" IssueInstant="2026-11-23T00:00:00Z" {extra}><saml:Issuer>https://sp.example/</saml:Issuer>{body}</samlp:AuthnRequest>"#
        )
    }

    #[test]
    fn reads_a_request() {
        let r = AuthnRequest::parse(&request(
            r#"ForceAuthn="true" AssertionConsumerServiceURL="https://sp.example/acs""#,
            "",
        ))
        .unwrap();
        assert_eq!(r.id, "_abc");
        assert_eq!(r.issuer, "https://sp.example/");
        assert!(r.force_authn);
        assert_eq!(r.acs_url.as_deref(), Some("https://sp.example/acs"));
    }

    #[test]
    fn refuses_a_doctype() {
        let xml = format!(r#"<!DOCTYPE x [<!ENTITY a "b">]>{}"#, request("", ""));
        assert!(AuthnRequest::parse(&xml).is_err());
    }

    #[test]
    fn refuses_a_subject_as_entra_does() {
        let xml = request("", "<saml:Subject></saml:Subject>");
        let refusal = AuthnRequest::parse(&xml).unwrap().refusal.unwrap();
        assert_eq!(refusal.sub_status, Some(STATUS_REQUEST_UNSUPPORTED));
    }

    #[test]
    fn refuses_an_id_starting_with_a_digit() {
        let xml = request("", "").replace("_abc", "1abc");
        assert!(AuthnRequest::parse(&xml).is_err());
    }

    #[test]
    fn refuses_a_comparison_other_than_exact() {
        let xml = request(
            "",
            r#"<samlp:RequestedAuthnContext Comparison="minimum"></samlp:RequestedAuthnContext>"#,
        );
        assert_eq!(
            AuthnRequest::parse(&xml).unwrap().refusal.unwrap().sub_status,
            Some(STATUS_NO_AUTHN_CONTEXT)
        );
    }

    #[test]
    fn a_saml_parameter_name_must_not_be_encoded() {
        assert!(SamlQuery::parse("SAMLRequest=x").is_ok());
        assert!(SamlQuery::parse("SAML%52equest=x").is_err());
        assert!(SamlQuery::parse("SAMLRequest=x&Relay%53tate=y").is_err());
    }

    #[test]
    fn a_deflate_bomb_is_refused() {
        let huge = "a".repeat(MAX_MESSAGE_BYTES * 4);
        let encoded = encode_redirect(&huge).unwrap();
        assert!(decode_message(&encoded).is_err());
    }

    #[test]
    fn deflated_messages_round_trip() {
        let xml = request("", "");
        assert_eq!(decode_message(&encode_redirect(&xml).unwrap()).unwrap(), xml);
    }

    #[test]
    fn escapes_text_and_refuses_control_characters() {
        assert_eq!(text("a<b>&c").unwrap(), "a&lt;b&gt;&amp;c");
        assert_eq!(attr("a\"b").unwrap(), "a&quot;b");
        assert!(text("a\u{1}b").is_err());
    }
}
