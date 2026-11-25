//! Reading a service provider's SAML metadata file, as Entra's "Upload metadata
//! file" does: the entity ID, the Assertion Consumer Service URLs on the
//! HTTP-POST binding (the only one we answer on) with their indexes and default,
//! and a Single Logout URL. Nothing is fetched and nothing in the file is
//! trusted: the values go through the same checks as typed ones, and the
//! administrator saves them like any other Basic SAML Configuration. Its signing
//! certificates are offered the same way: each is added only when the
//! administrator chooses to verify requests with it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::saml::{GivenCertificate, ReplyUrl};
use crate::saml_protocol::{
    BINDING_POST, BINDING_REDIRECT, NS_ASSERTION, NS_DS, NS_METADATA, NS_PROTOCOL, Node, XmlLimits, parse_instant,
    parse_xml_within, usable_verification_certificate,
};

/// `KeyDescriptor/@use` for a signing key; a descriptor without `use` serves both.
const USE_SIGNING: &str = "signing";

/// An uploaded metadata file, from a signed-in administrator: room for a group
/// of entities, still bounded.
const METADATA_LIMITS: XmlLimits = XmlLimits {
    bytes: 2 * 1024 * 1024,
    elements: 50_000,
    depth: 32,
};

/// What a metadata file says about one service provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadata {
    pub entity_id: String,
    /// In index order; exactly one is the default.
    pub reply_urls: Vec<ReplyUrl>,
    pub logout_url: Option<String>,
    /// The service provider's signing certificates a request could be verified
    /// with, in document order, each once.
    pub signing_certificates: Vec<GivenCertificate>,
}

fn is(node: &Node, local: &str) -> bool {
    node.ns == NS_METADATA && node.local == local
}

fn children<'a>(node: &'a Node, local: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
    node.children.iter().filter(move |c| is(c, local))
}

/// `xs:boolean`: `true`, `false`, `1` or `0`.
fn xs_bool(raw: &str) -> Option<bool> {
    match raw.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Every `EntityDescriptor`, however deeply grouped, with whether it or a group
/// holding it has a `validUntil` already past.
fn entities<'a>(node: &'a Node, now: i64, expired: bool, out: &mut Vec<(&'a Node, bool)>) {
    let expired = expired
        || node
            .attr("validUntil")
            .and_then(parse_instant)
            .is_some_and(|t| t <= now);
    if is(node, "EntityDescriptor") {
        out.push((node, expired));
    } else if is(node, "EntitiesDescriptor") {
        for child in &node.children {
            entities(child, now, expired, out);
        }
    }
}

/// A SAML-defined element directly inside an `Extensions`, which the schema
/// reserves for other namespaces.
fn saml_element_in_extensions(node: &Node) -> bool {
    let reserved = |n: &Node| [NS_METADATA, NS_ASSERTION, NS_PROTOCOL].contains(&n.ns.as_str());
    (is(node, "Extensions") && node.children.iter().any(reserved))
        || node.children.iter().any(saml_element_in_extensions)
}

/// Read a metadata file describing exactly one service provider.
pub fn parse_sp_metadata(xml: &str) -> Result<SpMetadata, String> {
    read_sp_metadata(xml, &[], crate::util::now())
}

/// Read a metadata file for an application already known by these
/// identifiers. A file grouping several service providers is accepted when
/// exactly one of them is this application.
pub fn read_sp_metadata(xml: &str, known: &[String], now: i64) -> Result<SpMetadata, String> {
    if xml.len() > METADATA_LIMITS.bytes {
        return Err("The file is larger than 2 MB.".into());
    }
    let root = parse_xml_within(xml, METADATA_LIMITS)
        .map_err(|_| "The file is not a readable SAML metadata document.".to_string())?;
    if !is(&root, "EntityDescriptor") && !is(&root, "EntitiesDescriptor") {
        return Err("The file is not SAML metadata: it has no EntityDescriptor.".into());
    }
    if saml_element_in_extensions(&root) {
        return Err("The file is not valid SAML metadata: an Extensions element holds a SAML element.".into());
    }
    let mut all = Vec::new();
    entities(&root, now, false, &mut all);
    let mut ids = std::collections::BTreeSet::new();
    for (entity, _) in &all {
        if let Some(id) = entity.attr("entityID")
            && !ids.insert(id)
        {
            return Err(format!("The file lists the entity '{id}' twice."));
        }
    }
    let providers: Vec<(&Node, bool)> = all
        .into_iter()
        .filter(|(e, _)| children(e, "SPSSODescriptor").next().is_some())
        .collect();
    let chosen: Vec<&(&Node, bool)> = match providers.len() {
        0 => return Err("The file describes no service provider (SPSSODescriptor).".into()),
        1 => providers.iter().collect(),
        _ => providers
            .iter()
            .filter(|(e, _)| e.attr("entityID").is_some_and(|id| known.iter().any(|k| k == id)))
            .collect(),
    };
    let (entity, expired) = match chosen.as_slice() {
        [one] => **one,
        _ => {
            return Err(format!(
                "The file describes {} service providers and none is clearly this application; upload its own metadata.",
                providers.len()
            ));
        }
    };
    if expired {
        return Err("The metadata has expired: its validUntil has passed.".into());
    }
    let entity_id = entity
        .attr("entityID")
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or("The EntityDescriptor has no entityID.")?
        .to_string();
    let sp = children(entity, "SPSSODescriptor")
        .next()
        .ok_or("The file has no SPSSODescriptor.")?;

    // (index, explicit isDefault, URL), in document order.
    let mut endpoints = Vec::new();
    for acs in children(sp, "AssertionConsumerService") {
        if acs.attr("Binding") != Some(BINDING_POST) {
            continue;
        }
        let url = acs.attr("Location").map(str::trim).filter(|l| !l.is_empty());
        let url = url.ok_or("An AssertionConsumerService has no Location.")?;
        let index = acs
            .attr("index")
            .and_then(|i| i.trim().parse::<u16>().ok())
            .ok_or_else(|| format!("The AssertionConsumerService '{url}' has no valid index."))?;
        let default = match acs.attr("isDefault") {
            None => None,
            Some(raw) => Some(xs_bool(raw).ok_or_else(|| format!("isDefault '{raw}' is not true or false."))?),
        };
        if endpoints.iter().any(|(i, _, _)| *i == index) {
            return Err(format!("Two AssertionConsumerService endpoints have index {index}."));
        }
        endpoints.push((index, default, url.to_string()));
    }
    if endpoints.is_empty() {
        return Err("The file has no AssertionConsumerService on the HTTP-POST binding.".into());
    }
    // SAML metadata 2.2.3: the first marked true, else the first left unmarked,
    // else the first.
    let chosen = endpoints
        .iter()
        .position(|(_, d, _)| *d == Some(true))
        .or_else(|| endpoints.iter().position(|(_, d, _)| d.is_none()))
        .unwrap_or(0);
    let mut reply_urls: Vec<ReplyUrl> = endpoints
        .into_iter()
        .enumerate()
        .map(|(i, (index, _, url))| ReplyUrl {
            url,
            index,
            default: i == chosen,
        })
        .collect();
    reply_urls.sort_by_key(|r| r.index);

    // We answer logout over HTTP-Redirect, so that endpoint first.
    let logout_url = [BINDING_REDIRECT, BINDING_POST].iter().find_map(|binding| {
        children(sp, "SingleLogoutService")
            .find(|s| s.attr("Binding") == Some(binding))
            .and_then(|s| s.attr("Location"))
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
    });
    Ok(SpMetadata {
        entity_id,
        reply_urls,
        logout_url,
        signing_certificates: signing_certificates(sp),
    })
}

fn in_ds<'a>(node: &'a Node, local: &'static str) -> impl Iterator<Item = &'a Node> + 'a {
    node.children.iter().filter(move |c| c.ns == NS_DS && c.local == local)
}

/// The certificates in the descriptor's signing `KeyDescriptor`s. One this
/// server cannot verify with, or cannot read, is left out: the file is only a
/// source of candidates.
fn signing_certificates(sp: &Node) -> Vec<GivenCertificate> {
    let mut out: Vec<GivenCertificate> = Vec::new();
    for key in children(sp, "KeyDescriptor").filter(|k| k.attr("use").is_none_or(|u| u.trim() == USE_SIGNING)) {
        for info in in_ds(key, "KeyInfo") {
            for data in in_ds(info, "X509Data") {
                for cert in in_ds(data, "X509Certificate") {
                    let text: String = cert.text.chars().filter(|c| !c.is_whitespace()).collect();
                    let Some(given) = STANDARD
                        .decode(text)
                        .ok()
                        .and_then(|der| GivenCertificate::from_der(&der).ok())
                    else {
                        continue;
                    };
                    if usable_verification_certificate(&given.der) && !out.iter().any(|c| c.der == given.der) {
                        out.push(given);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(body: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="{NS_METADATA}" entityID="https://sp.example/"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{body}</md:SPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    fn acs(index: u16, default: Option<&str>, binding: &str) -> String {
        let default = default.map(|d| format!(r#" isDefault="{d}""#)).unwrap_or_default();
        format!(
            r#"<md:AssertionConsumerService Binding="{binding}" Location="https://sp.example/acs/{index}" index="{index}"{default}/>"#
        )
    }

    fn default_index(m: &SpMetadata) -> u16 {
        m.reply_urls.iter().find(|r| r.default).unwrap().index
    }

    #[test]
    fn reads_the_entity_reply_urls_and_logout_url() {
        let slo = format!(
            r#"<md:SingleLogoutService Binding="{BINDING_POST}" Location="https://sp.example/slo-post"/><md:SingleLogoutService Binding="{BINDING_REDIRECT}" Location="https://sp.example/slo"/>"#
        );
        let m = parse_sp_metadata(&sp(&format!(
            "{slo}{}{}",
            acs(3, None, BINDING_POST),
            acs(1, None, BINDING_POST)
        )))
        .unwrap();
        assert_eq!(m.entity_id, "https://sp.example/");
        assert_eq!(m.logout_url.as_deref(), Some("https://sp.example/slo"));
        let indexes: Vec<u16> = m.reply_urls.iter().map(|r| r.index).collect();
        assert_eq!(indexes, vec![1, 3]);
        // The first in the document, not the lowest index.
        assert_eq!(default_index(&m), 3);
    }

    #[test]
    fn picks_the_default_as_saml_metadata_says() {
        let pick = |body: String| default_index(&parse_sp_metadata(&sp(&body)).unwrap());
        let a = |i, d| acs(i, d, BINDING_POST);
        assert_eq!(pick(format!("{}{}", a(0, None), a(1, Some("true")))), 1);
        assert_eq!(pick(format!("{}{}", a(0, Some("false")), a(1, None))), 1);
        assert_eq!(pick(format!("{}{}", a(0, Some("0")), a(1, Some("false")))), 0);
        assert_eq!(
            pick(format!("{}{}{}", a(0, None), a(1, Some("1")), a(2, Some("true")))),
            1
        );
    }

    #[test]
    fn keeps_only_the_post_binding() {
        let artifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
        let m = parse_sp_metadata(&sp(&format!(
            "{}{}",
            acs(0, Some("true"), artifact),
            acs(1, None, BINDING_POST)
        )))
        .unwrap();
        assert_eq!(m.reply_urls.len(), 1);
        assert!(m.reply_urls[0].default);
        assert!(parse_sp_metadata(&sp(&acs(0, None, artifact))).is_err());
    }

    #[test]
    fn reads_one_provider_from_a_group() {
        let group = |n: usize| {
            let one = sp(&acs(0, None, BINDING_POST));
            format!(
                r#"<md:EntitiesDescriptor xmlns:md="{NS_METADATA}">{}</md:EntitiesDescriptor>"#,
                one.repeat(n)
            )
        };
        assert!(parse_sp_metadata(&group(1)).is_ok());
        assert!(parse_sp_metadata(&group(2)).is_err());
        assert!(parse_sp_metadata(&group(0)).is_err());
    }

    #[test]
    fn picks_this_application_from_a_group() {
        let other = sp(&acs(0, None, BINDING_POST)).replace("https://sp.example/", "https://other.example/");
        let group = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{NS_METADATA}">{}{other}</md:EntitiesDescriptor>"#,
            sp(&acs(0, None, BINDING_POST))
        );
        let known = ["https://sp.example/".to_string()];
        assert_eq!(
            read_sp_metadata(&group, &known, 0).unwrap().entity_id,
            "https://sp.example/"
        );
        assert!(read_sp_metadata(&group, &[], 0).is_err());
        // The same entity twice is refused, whatever is known.
        let twice = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{NS_METADATA}">{0}{0}</md:EntitiesDescriptor>"#,
            sp(&acs(0, None, BINDING_POST))
        );
        assert!(read_sp_metadata(&twice, &known, 0).unwrap_err().contains("twice"));
    }

    #[test]
    fn reads_a_large_group() {
        let many: String = (0..100)
            .map(|i| sp(&acs(0, None, BINDING_POST)).replace("https://sp.example/", &format!("https://sp{i}.example/")))
            .collect();
        let group = format!(r#"<md:EntitiesDescriptor xmlns:md="{NS_METADATA}">{many}</md:EntitiesDescriptor>"#);
        // Beyond what a SAML message may hold.
        assert!(crate::saml_protocol::parse_xml(&group).is_err());
        let known = ["https://sp42.example/".to_string()];
        assert_eq!(
            read_sp_metadata(&group, &known, 0).unwrap().entity_id,
            "https://sp42.example/"
        );
    }

    #[test]
    fn refuses_expired_metadata_at_any_level() {
        let now = 1_900_000_000;
        let entity = sp(&acs(0, None, BINDING_POST));
        let dated = |when: &str| {
            entity.replace(
                "<md:EntityDescriptor ",
                &format!(r#"<md:EntityDescriptor validUntil="{when}" "#),
            )
        };
        assert!(
            read_sp_metadata(&dated("2020-01-01T00:00:00Z"), &[], now)
                .unwrap_err()
                .contains("expired")
        );
        assert!(read_sp_metadata(&dated("2040-01-01T00:00:00Z"), &[], now).is_ok());
        let group = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{NS_METADATA}" validUntil="2020-01-01T00:00:00Z">{entity}</md:EntitiesDescriptor>"#
        );
        assert!(read_sp_metadata(&group, &[], now).is_err());
    }

    #[test]
    fn refuses_a_saml_element_in_extensions() {
        let bad = sp(&format!(
            r#"<md:Extensions><md:Organization/></md:Extensions>{}"#,
            acs(0, None, BINDING_POST)
        ));
        assert!(read_sp_metadata(&bad, &[], 0).is_err());
        let fine = sp(&format!(
            r#"<md:Extensions><x:Thing xmlns:x="urn:example:ext"/></md:Extensions>{}"#,
            acs(0, None, BINDING_POST)
        ));
        assert!(read_sp_metadata(&fine, &[], 0).is_ok());
    }

    #[test]
    fn refuses_what_it_cannot_use() {
        assert!(parse_sp_metadata("<html/>").is_err());
        let doctype = format!(r#"<!DOCTYPE x [<!ENTITY a "b">]>{}"#, sp(&acs(0, None, BINDING_POST)));
        assert!(parse_sp_metadata(&doctype).is_err());
        let twice = format!("{}{}", acs(0, None, BINDING_POST), acs(0, None, BINDING_POST));
        assert!(parse_sp_metadata(&sp(&twice)).is_err());
        let no_index = sp(&acs(0, None, BINDING_POST).replace(r#" index="0""#, ""));
        assert!(parse_sp_metadata(&no_index).is_err());
        let no_entity = sp(&acs(0, None, BINDING_POST)).replace(r#" entityID="https://sp.example/""#, "");
        assert!(parse_sp_metadata(&no_entity).is_err());
    }

    fn cert(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .der()
            .to_vec()
    }

    fn key_descriptor(usage: Option<&str>, der: &[u8]) -> String {
        let usage = usage.map(|u| format!(r#" use="{u}""#)).unwrap_or_default();
        // Wrapped, as files usually are.
        let body: Vec<String> = STANDARD
            .encode(der)
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        format!(
            r#"<md:KeyDescriptor{usage}><ds:KeyInfo xmlns:ds="{NS_DS}"><ds:X509Data><ds:X509Certificate>
{}
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
            body.join("\n")
        )
    }

    #[test]
    fn offers_the_signing_certificates_it_can_verify_with() {
        let rsa = {
            let key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
            rcgen::CertificateParams::new(Vec::<String>::new())
                .unwrap()
                .self_signed(&key)
                .unwrap()
                .der()
                .to_vec()
        };
        let p256 = cert(&rcgen::PKCS_ECDSA_P256_SHA256);
        let encryption = cert(&rcgen::PKCS_ECDSA_P384_SHA384);
        let ed25519 = cert(&rcgen::PKCS_ED25519);
        let body = [
            key_descriptor(Some("signing"), &rsa),
            key_descriptor(None, &p256),
            key_descriptor(Some("encryption"), &encryption),
            key_descriptor(Some("signing"), &ed25519),
            key_descriptor(Some("signing"), &rsa),
            r#"<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>not base64!</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#.to_string(),
            acs(0, None, BINDING_POST),
        ]
        .concat();
        let m = parse_sp_metadata(&sp(&body)).unwrap();
        let found: Vec<&[u8]> = m.signing_certificates.iter().map(|c| c.der.as_slice()).collect();
        // Signing and unmarked keys, once each; not the encryption key, nor a
        // key or text this server cannot verify with.
        assert_eq!(found, vec![rsa.as_slice(), p256.as_slice()]);
        assert!(m.signing_certificates.iter().all(|c| c.not_after > c.not_before));
    }
}
