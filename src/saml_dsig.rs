//! Verifying the enveloped XML signature on a POSTed SAML message.
//!
//! XML signatures are easy to accept wrongly, so this accepts one shape only:
//!
//! - exactly one `Signature` in the document, a direct child of the root;
//! - exactly one `Reference`, to the root's `ID`, which no other element shares;
//! - the enveloped-signature transform, then Exclusive Canonicalization;
//! - RSA with SHA-256 (SHA-1 only where the application opted in);
//! - the key is one of the application's registered certificates. `KeyInfo` in
//!   the message is never read.
//!
//! Comments, processing instructions and CDATA are refused rather than
//! canonicalized away: a comment inside a value is how a signed `user@a.example`
//! comes to be read as something else. The verifier and [`parse_xml`] read the
//! same bytes, and what is signed is always the whole message.
//!
//! [`parse_xml`]: crate::saml_protocol::parse_xml

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::saml_protocol::{MAX_DEPTH, MAX_ELEMENTS, MAX_MESSAGE_BYTES, SamlError, SigningAlgorithm, public_key_of};

const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
const C14N_EXCLUSIVE: &str = NS_EXC_C14N;
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const DEFAULT_PREFIX_TOKEN: &str = "#default";
/// The attributes that can name an element as a signature's target.
const ID_ATTRIBUTES: [&str; 3] = ["ID", "Id", "id"];

type Scope = Rc<BTreeMap<String, String>>;

struct Attribute {
    prefix: String,
    local: String,
    ns: String,
    value: String,
}

enum Item {
    Element(Element),
    Text(String),
}

struct Element {
    prefix: String,
    local: String,
    ns: String,
    attrs: Vec<Attribute>,
    items: Vec<Item>,
    /// Every namespace binding in scope here.
    scope: Scope,
}

impl Element {
    fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }

    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.prefix.is_empty() && a.local == name)
            .map(|a| a.value.as_str())
    }

    fn elements(&self) -> impl Iterator<Item = &Element> {
        self.items.iter().filter_map(|i| match i {
            Item::Element(e) => Some(e),
            Item::Text(_) => None,
        })
    }

    fn text(&self) -> String {
        self.items
            .iter()
            .filter_map(|i| match i {
                Item::Text(t) => Some(t.as_str()),
                Item::Element(_) => None,
            })
            .collect()
    }

    /// The only child with this name; two of them is an error.
    fn only(&self, ns: &str, local: &str) -> Result<&Element, SamlError> {
        let mut found = self.elements().filter(|e| e.is(ns, local));
        match (found.next(), found.next()) {
            (Some(e), None) => Ok(e),
            _ => Err(refused()),
        }
    }

    /// Children, in order, must be exactly these names (the last may be optional).
    fn has_only_children(&self, names: &[&str], optional_last: bool) -> bool {
        let got: Vec<&str> = self
            .elements()
            .map(|e| if e.ns == NS_DS { e.local.as_str() } else { "" })
            .collect();
        got == names || (optional_last && got == names[..names.len() - 1])
    }

    fn walk<'a>(&'a self, visit: &mut impl FnMut(&'a Element)) {
        visit(self);
        for child in self.elements() {
            child.walk(visit);
        }
    }
}

fn refused() -> SamlError {
    SamlError::requester("The request's signature did not verify.")
}

fn split(name: &str) -> (&str, &str) {
    name.split_once(':').unwrap_or(("", name))
}

/// Read a start tag, with its namespace declarations applied to `parent`'s scope.
fn open(e: &BytesStart<'_>, parent: &Scope) -> Result<Element, SamlError> {
    let mut declared = BTreeMap::new();
    let mut raw = Vec::new();
    for attribute in e.attributes() {
        let attribute = attribute.map_err(|_| refused())?;
        let key: &str = attribute.key.as_ref();
        let value = attribute
            .normalized_value(XmlVersion::Explicit1_0)
            .map_err(|_| refused())?
            .into_owned();
        if key == "xmlns" {
            declared.insert(String::new(), value);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            if prefix == "xml" || prefix == "xmlns" || value.is_empty() {
                return Err(refused());
            }
            declared.insert(prefix.to_string(), value);
        } else {
            raw.push((key.to_string(), value));
        }
    }
    let scope = if declared.is_empty() {
        parent.clone()
    } else {
        let mut merged = (**parent).clone();
        for (prefix, uri) in declared {
            if uri.is_empty() {
                merged.remove(&prefix);
            } else {
                merged.insert(prefix, uri);
            }
        }
        Rc::new(merged)
    };
    let qualified = e.name();
    let name: &str = qualified.as_ref();
    let (prefix, local) = split(name);
    let ns = match scope.get(prefix) {
        Some(uri) => uri.clone(),
        None if prefix.is_empty() => String::new(),
        None => return Err(refused()),
    };
    let mut attrs = Vec::with_capacity(raw.len());
    let mut seen = BTreeSet::new();
    for (key, value) in raw {
        let (attr_prefix, attr_local) = split(&key);
        let attr_ns = match attr_prefix {
            "" => String::new(),
            "xml" => NS_XML.to_string(),
            p => scope.get(p).cloned().ok_or_else(refused)?,
        };
        // The same expanded name twice, through two prefixes.
        if !seen.insert((attr_ns.clone(), attr_local.to_string())) {
            return Err(refused());
        }
        attrs.push(Attribute {
            prefix: attr_prefix.to_string(),
            local: attr_local.to_string(),
            ns: attr_ns,
            value,
        });
    }
    Ok(Element {
        prefix: prefix.to_string(),
        local: local.to_string(),
        ns,
        attrs,
        items: Vec::new(),
        scope,
    })
}

fn push_text(stack: &mut [Element], text: &str) -> Result<(), SamlError> {
    match stack.last_mut() {
        Some(top) => {
            if let Some(Item::Text(last)) = top.items.last_mut() {
                last.push_str(text);
            } else {
                top.items.push(Item::Text(text.to_string()));
            }
            Ok(())
        }
        None if text.chars().all(|c| c.is_ascii_whitespace()) => Ok(()),
        None => Err(refused()),
    }
}

fn parse(xml: &str) -> Result<Element, SamlError> {
    if xml.len() > MAX_MESSAGE_BYTES {
        return Err(refused());
    }
    let mut reader = Reader::from_str(xml);
    let empty: Scope = Rc::new(BTreeMap::new());
    let mut stack: Vec<Element> = Vec::new();
    let mut root = None;
    let mut elements = 0usize;
    let close = |stack: &mut Vec<Element>, root: &mut Option<Element>, node: Element| match stack.last_mut() {
        Some(parent) => parent.items.push(Item::Element(node)),
        None => *root = Some(node),
    };
    loop {
        let event = reader.read_event().map_err(|_| refused())?;
        match event {
            Event::Start(_) | Event::Empty(_) if root.is_some() => return Err(refused()),
            Event::Start(e) | Event::Empty(e) if elements >= MAX_ELEMENTS || stack.len() >= MAX_DEPTH => {
                let _ = e;
                return Err(refused());
            }
            Event::Start(e) => {
                elements += 1;
                let parent = stack.last().map_or(&empty, |p| &p.scope);
                let node = open(&e, parent)?;
                stack.push(node);
            }
            Event::Empty(e) => {
                elements += 1;
                let parent = stack.last().map_or(&empty, |p| &p.scope);
                let node = open(&e, parent)?;
                close(&mut stack, &mut root, node);
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(refused)?;
                close(&mut stack, &mut root, node);
            }
            Event::Text(t) => push_text(&mut stack, &t.xml10_content())?,
            Event::GeneralRef(r) => {
                let c = match r.resolve_char_ref().map_err(|_| refused())? {
                    Some(c) => c,
                    None => match r.xml10_content().as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return Err(refused()),
                    },
                };
                push_text(&mut stack, c.encode_utf8(&mut [0; 4]))?;
            }
            Event::Decl(_) if stack.is_empty() && root.is_none() => {}
            Event::Eof => break,
            // Comments, processing instructions, CDATA and a DOCTYPE.
            _ => return Err(refused()),
        }
    }
    if !stack.is_empty() {
        return Err(refused());
    }
    root.ok_or_else(refused)
}

fn escape_text(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(value: &str, out: &mut String) {
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
}

/// Exclusive XML Canonicalization (without comments) of `element`.
fn canonicalize(
    element: &Element,
    rendered: &BTreeMap<String, String>,
    inclusive: &BTreeSet<String>,
    skip: Option<*const Element>,
    out: &mut String,
) {
    // The prefixes this element visibly uses, plus any the signer listed.
    let mut prefixes: BTreeSet<&str> = BTreeSet::new();
    prefixes.insert(&element.prefix);
    for attr in &element.attrs {
        if !attr.prefix.is_empty() && attr.prefix != "xml" {
            prefixes.insert(&attr.prefix);
        }
    }
    for prefix in inclusive {
        if prefix.is_empty() || element.scope.contains_key(prefix) {
            prefixes.insert(prefix);
        }
    }
    let mut now_rendered = rendered.clone();
    let name = if element.prefix.is_empty() {
        element.local.clone()
    } else {
        format!("{}:{}", element.prefix, element.local)
    };
    out.push('<');
    out.push_str(&name);
    for prefix in prefixes {
        let uri = element.scope.get(prefix).map_or("", String::as_str);
        let previous = rendered.get(prefix).map_or("", String::as_str);
        if uri == previous {
            continue;
        }
        if prefix.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(prefix);
            out.push_str("=\"");
        }
        escape_attr(uri, out);
        out.push('"');
        now_rendered.insert(prefix.to_string(), uri.to_string());
    }
    let mut attrs: Vec<&Attribute> = element.attrs.iter().collect();
    attrs.sort_by(|a, b| (&a.ns, &a.local).cmp(&(&b.ns, &b.local)));
    for attr in attrs {
        out.push(' ');
        if !attr.prefix.is_empty() {
            out.push_str(&attr.prefix);
            out.push(':');
        }
        out.push_str(&attr.local);
        out.push_str("=\"");
        escape_attr(&attr.value, out);
        out.push('"');
    }
    out.push('>');
    for item in &element.items {
        match item {
            Item::Text(t) => escape_text(t, out),
            Item::Element(child) => {
                if skip != Some(child as *const Element) {
                    canonicalize(child, &now_rendered, inclusive, skip, out);
                }
            }
        }
    }
    out.push_str("</");
    out.push_str(&name);
    out.push('>');
}

/// The `PrefixList` of an `InclusiveNamespaces` under a method element.
fn inclusive_prefixes(method: &Element) -> Result<BTreeSet<String>, SamlError> {
    let mut children = method.elements();
    let Some(list) = children.next() else {
        return Ok(BTreeSet::new());
    };
    if children.next().is_some() || !list.is(NS_EXC_C14N, "InclusiveNamespaces") {
        return Err(refused());
    }
    Ok(list
        .attr("PrefixList")
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(|p| {
            if p == DEFAULT_PREFIX_TOKEN {
                String::new()
            } else {
                p.to_string()
            }
        })
        .collect())
}

fn decode(value: &str) -> Result<Vec<u8>, SamlError> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(compact).map_err(|_| refused())
}

/// Whether the message carries an enveloped signature at all.
pub fn carries_signature(xml: &str) -> bool {
    crate::saml_protocol::parse_xml(xml).is_ok_and(|root| root.child(NS_DS, "Signature").is_some())
}

/// Verify the message's enveloped signature against the registered certificates.
pub fn verify(xml: &str, certificates: &[Vec<u8>], allow_sha1: bool) -> Result<(), SamlError> {
    let root = parse(xml)?;
    let id = root.attr("ID").filter(|id| !id.is_empty()).ok_or_else(refused)?;

    // One signature in the whole document, and one element with the signed ID.
    let mut signatures = 0usize;
    let mut holders = 0usize;
    root.walk(&mut |e| {
        signatures += usize::from(e.is(NS_DS, "Signature"));
        holders += usize::from(
            e.attrs
                .iter()
                .any(|a| a.value == id && (ID_ATTRIBUTES.contains(&a.local.as_str()))),
        );
    });
    if signatures != 1 || holders != 1 {
        return Err(refused());
    }
    let sig = root.only(NS_DS, "Signature")?;
    if !sig.has_only_children(&["SignedInfo", "SignatureValue", "KeyInfo"], true) {
        return Err(refused());
    }
    let info = sig.only(NS_DS, "SignedInfo")?;
    if !info.has_only_children(&["CanonicalizationMethod", "SignatureMethod", "Reference"], false) {
        return Err(refused());
    }
    let c14n = info.only(NS_DS, "CanonicalizationMethod")?;
    if c14n.attr("Algorithm") != Some(C14N_EXCLUSIVE) {
        return Err(refused());
    }
    let method = info
        .only(NS_DS, "SignatureMethod")?
        .attr("Algorithm")
        .unwrap_or_default();
    let algorithm: &'static dyn signature::VerificationAlgorithm = if method == SigningAlgorithm::Sha256.signature_uri()
    {
        &signature::RSA_PKCS1_2048_8192_SHA256
    } else if allow_sha1 && method == SigningAlgorithm::Sha1.signature_uri() {
        &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
    } else {
        return Err(refused());
    };

    let reference = info.only(NS_DS, "Reference")?;
    if reference.attr("URI") != Some(format!("#{id}").as_str())
        || !reference.has_only_children(&["Transforms", "DigestMethod", "DigestValue"], false)
    {
        return Err(refused());
    }
    let transforms: Vec<&Element> = reference.only(NS_DS, "Transforms")?.elements().collect();
    let [enveloped, exclusive] = transforms.as_slice() else {
        return Err(refused());
    };
    if !enveloped.is(NS_DS, "Transform")
        || !exclusive.is(NS_DS, "Transform")
        || enveloped.attr("Algorithm") != Some(TRANSFORM_ENVELOPED)
        || exclusive.attr("Algorithm") != Some(C14N_EXCLUSIVE)
        || enveloped.elements().next().is_some()
    {
        return Err(refused());
    }
    let digest_algorithm = match reference.only(NS_DS, "DigestMethod")?.attr("Algorithm") {
        Some(DIGEST_SHA256) => &digest::SHA256,
        Some(DIGEST_SHA1) if allow_sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        _ => return Err(refused()),
    };

    let mut message = String::with_capacity(xml.len());
    canonicalize(
        &root,
        &BTreeMap::new(),
        &inclusive_prefixes(exclusive)?,
        Some(sig as *const Element),
        &mut message,
    );
    let expected = decode(&reference.only(NS_DS, "DigestValue")?.text())?;
    if digest::digest(digest_algorithm, message.as_bytes()).as_ref() != expected.as_slice() {
        return Err(refused());
    }

    let mut signed = String::new();
    canonicalize(info, &BTreeMap::new(), &inclusive_prefixes(c14n)?, None, &mut signed);
    let value = decode(&sig.only(NS_DS, "SignatureValue")?.text())?;
    let verified = certificates.iter().any(|cert| {
        public_key_of(cert).is_ok_and(|(_, rsa)| {
            UnparsedPublicKey::new(algorithm, rsa)
                .verify(signed.as_bytes(), &value)
                .is_ok()
        })
    });
    if verified { Ok(()) } else { Err(refused()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(xml: &str, inclusive: &[&str]) -> String {
        let root = parse(xml).unwrap();
        let list = inclusive.iter().map(|p| p.to_string()).collect();
        let mut out = String::new();
        canonicalize(&root, &BTreeMap::new(), &list, None, &mut out);
        out
    }

    #[test]
    fn canonical_form_sorts_and_declares_only_what_is_used() {
        let xml = "<a:r xmlns:z=\"urn:z\" xmlns:a=\"urn:a\" b=\"2\" a=\"1\" z:c=\"3\"><a:k/><n xmlns=\"urn:d\">x &amp; y</n></a:r>";
        assert_eq!(
            canonical(xml, &[]),
            "<a:r xmlns:a=\"urn:a\" xmlns:z=\"urn:z\" a=\"1\" b=\"2\" z:c=\"3\"><a:k></a:k><n xmlns=\"urn:d\">x &amp; y</n></a:r>"
        );
    }

    #[test]
    fn canonical_form_drops_an_unused_namespace_unless_listed() {
        let xml = "<r xmlns:u=\"urn:u\"><c></c></r>";
        assert_eq!(canonical(xml, &[]), "<r><c></c></r>");
        assert_eq!(canonical(xml, &["u"]), "<r xmlns:u=\"urn:u\"><c></c></r>");
    }

    #[test]
    fn canonical_form_escapes_values() {
        let xml = "<r a=\"&lt;&quot;&#9;\">&#13;&gt;</r>";
        assert_eq!(canonical(xml, &[]), "<r a=\"&lt;&quot;&#x9;\">&#xD;&gt;</r>");
    }

    #[test]
    fn markup_that_hides_content_is_refused() {
        for xml in [
            "<r>a<!-- c -->b</r>",
            "<r><![CDATA[a]]></r>",
            "<r><?pi x?></r>",
            "<!DOCTYPE r><r></r>",
            "<p:r></p:r>",
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
    }

    /// The DER `DigestInfo` prefix of a SHA-1 hash (RFC 8017, section 9.2).
    const SHA1_DIGEST_INFO: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// A service provider's key, as PKCS#8, and its certificate.
    fn sp_key() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let cert = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (key.serialize_der(), cert.der().to_vec())
    }

    /// What a test's signature says about itself. Each is the accepted shape
    /// with one thing changed, and every one is correctly signed: only the
    /// checks on its shape stand between it and acceptance.
    struct Shape {
        /// The root's start tag; the reference is always to `_m`.
        open: &'static str,
        /// Canonical elements after the signature, covered by the digest.
        body: &'static str,
        c14n: &'static str,
        sha1_signature: bool,
        sha1_digest: bool,
        /// The `Transform` elements, in canonical form.
        transforms: String,
    }

    fn transform(algorithm: &str) -> String {
        format!(r#"<ds:Transform Algorithm="{algorithm}"></ds:Transform>"#)
    }

    fn accepted() -> Shape {
        Shape {
            open: r#"<r ID="_m">"#,
            body: "",
            c14n: C14N_EXCLUSIVE,
            sha1_signature: false,
            sha1_digest: false,
            transforms: transform(TRANSFORM_ENVELOPED) + &transform(C14N_EXCLUSIVE),
        }
    }

    /// The message, written directly in canonical form, so that these tests do
    /// not rely on the canonicalizer to produce what they verify.
    fn signed(shape: &Shape, pkcs8: &[u8]) -> String {
        let message = format!("{}{}</r>", shape.open, shape.body);
        let (digest_uri, digest_algorithm) = if shape.sha1_digest {
            (DIGEST_SHA1, &digest::SHA1_FOR_LEGACY_USE_ONLY)
        } else {
            (DIGEST_SHA256, &digest::SHA256)
        };
        let inner = format!(
            r##"<ds:CanonicalizationMethod Algorithm="{}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{}"></ds:SignatureMethod><ds:Reference URI="#_m"><ds:Transforms>{}</ds:Transforms><ds:DigestMethod Algorithm="{digest_uri}"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference>"##,
            shape.c14n,
            if shape.sha1_signature { RSA_SHA1 } else { RSA_SHA256 },
            shape.transforms,
            STANDARD.encode(digest::digest(digest_algorithm, message.as_bytes())),
        );
        let signed_info = format!(r#"<ds:SignedInfo xmlns:ds="{NS_DS}">{inner}</ds:SignedInfo>"#);
        let value = if shape.sha1_signature {
            // aws-lc-rs verifies RSA-SHA1 but will not create it.
            use rsa::pkcs8::DecodePrivateKey;
            let key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).unwrap();
            let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, signed_info.as_bytes());
            let padding = rsa::Pkcs1v15Sign {
                hash_len: Some(hash.as_ref().len()),
                prefix: SHA1_DIGEST_INFO.to_vec().into_boxed_slice(),
            };
            key.sign(padding, hash.as_ref()).unwrap()
        } else {
            use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
            let key = RsaKeyPair::from_pkcs8(pkcs8).unwrap();
            let mut value = vec![0u8; key.public_modulus_len()];
            key.sign(
                &RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                signed_info.as_bytes(),
                &mut value,
            )
            .unwrap();
            value
        };
        format!(
            r#"{}<ds:Signature xmlns:ds="{NS_DS}"><ds:SignedInfo>{inner}</ds:SignedInfo><ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>{}</r>"#,
            shape.open,
            STANDARD.encode(value),
            shape.body,
        )
    }

    #[test]
    fn sha1_is_accepted_only_where_it_is_allowed() {
        let (key, cert) = sp_key();
        let certs = [cert];
        for (what, shape) in [
            (
                "an RSA-SHA1 signature",
                Shape {
                    sha1_signature: true,
                    ..accepted()
                },
            ),
            (
                "a SHA-1 digest",
                Shape {
                    sha1_digest: true,
                    ..accepted()
                },
            ),
        ] {
            let xml = signed(&shape, &key);
            assert!(verify(&xml, &certs, true).is_ok(), "{what}, allowed");
            assert!(verify(&xml, &certs, false).is_err(), "{what}, not allowed");
        }
    }

    #[test]
    fn only_the_two_saml_transforms_and_exclusive_canonicalization_are_accepted() {
        const C14N_INCLUSIVE: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        const C14N_EXCLUSIVE_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
        const TRANSFORM_XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        let (key, cert) = sp_key();
        let certs = [cert];
        assert!(verify(&signed(&accepted(), &key), &certs, false).is_ok());

        let enveloped = transform(TRANSFORM_ENVELOPED);
        let exclusive = transform(C14N_EXCLUSIVE);
        let xpath =
            format!(r#"<ds:Transform Algorithm="{TRANSFORM_XPATH}"><ds:XPath>self::r</ds:XPath></ds:Transform>"#);
        // Every one of these is signed over the octets this verifier computes:
        // the signature is good, and only its shape is not.
        for (what, shape) in [
            (
                "inclusive canonicalization of SignedInfo",
                Shape {
                    c14n: C14N_INCLUSIVE,
                    ..accepted()
                },
            ),
            (
                "canonicalization with comments of SignedInfo",
                Shape {
                    c14n: C14N_EXCLUSIVE_WITH_COMMENTS,
                    ..accepted()
                },
            ),
            (
                "no canonicalization transform",
                Shape {
                    transforms: enveloped.clone(),
                    ..accepted()
                },
            ),
            (
                "no enveloped-signature transform",
                Shape {
                    transforms: exclusive.clone(),
                    ..accepted()
                },
            ),
            (
                "canonicalization in place of the enveloped-signature transform",
                Shape {
                    transforms: format!("{exclusive}{exclusive}"),
                    ..accepted()
                },
            ),
            (
                "the transforms in the other order",
                Shape {
                    transforms: format!("{exclusive}{enveloped}"),
                    ..accepted()
                },
            ),
            (
                "inclusive canonicalization as a transform",
                Shape {
                    transforms: format!("{enveloped}{}", transform(C14N_INCLUSIVE)),
                    ..accepted()
                },
            ),
            (
                "canonicalization with comments as a transform",
                Shape {
                    transforms: format!("{enveloped}{}", transform(C14N_EXCLUSIVE_WITH_COMMENTS)),
                    ..accepted()
                },
            ),
            (
                "an XPath transform",
                Shape {
                    transforms: format!("{enveloped}{xpath}{exclusive}"),
                    ..accepted()
                },
            ),
            (
                "an XPath filter inside the enveloped-signature transform",
                Shape {
                    transforms: format!(
                        r#"<ds:Transform Algorithm="{TRANSFORM_ENVELOPED}"><ds:XPath>self::r</ds:XPath></ds:Transform>{exclusive}"#
                    ),
                    ..accepted()
                },
            ),
        ] {
            assert!(verify(&signed(&shape, &key), &certs, true).is_err(), "{what}");
        }
    }

    #[test]
    fn the_signed_id_may_be_claimed_by_one_element_only() {
        let (key, cert) = sp_key();
        let certs = [cert];
        let other = Shape {
            body: r#"<e ID="_n"></e><e Id="_o"></e>"#,
            ..accepted()
        };
        assert!(verify(&signed(&other, &key), &certs, false).is_ok());
        // However the second element spells its ID attribute, a reader looking
        // the reference up could land on it instead of the root.
        for body in [
            r#"<e ID="_m"></e>"#,
            r#"<e Id="_m"></e>"#,
            r#"<e id="_m"></e>"#,
            r#"<e xml:id="_m"></e>"#,
            r#"<e xmlns:w="urn:w" w:Id="_m"></e>"#,
        ] {
            let shape = Shape { body, ..accepted() };
            assert!(verify(&signed(&shape, &key), &certs, false).is_err(), "{body}");
        }
        // The root's own ID is the unprefixed attribute, and must be there.
        for open in [r#"<r>"#, r#"<r xmlns:w="urn:w" w:ID="_m">"#] {
            let shape = Shape { open, ..accepted() };
            assert!(verify(&signed(&shape, &key), &certs, false).is_err(), "{open}");
        }
    }

    #[test]
    fn a_message_too_large_or_too_complex_is_refused() {
        assert!(parse(&format!("<r>{}</r>", "<e></e>".repeat(MAX_ELEMENTS - 1))).is_ok());
        assert!(parse(&format!("<r>{}</r>", "<e></e>".repeat(MAX_ELEMENTS))).is_err());
        assert!(parse(&format!("<r>{}</r>", "<e/>".repeat(MAX_ELEMENTS))).is_err());
        let nested = |depth: usize| format!("{}{}", "<e>".repeat(depth), "</e>".repeat(depth));
        assert!(parse(&nested(MAX_DEPTH)).is_ok());
        assert!(parse(&nested(MAX_DEPTH + 1)).is_err());
        let sized = |bytes: usize| format!("<r>{}</r>", "x".repeat(bytes - "<r></r>".len()));
        assert!(parse(&sized(MAX_MESSAGE_BYTES)).is_ok());
        assert!(parse(&sized(MAX_MESSAGE_BYTES + 1)).is_err());
    }
}
