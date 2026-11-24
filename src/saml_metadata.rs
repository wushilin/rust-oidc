//! Reading a service provider's SAML metadata file, as Entra's "Upload metadata
//! file" does: the entity ID, the Assertion Consumer Service URLs on the
//! HTTP-POST binding (the only one we answer on) with their indexes and default,
//! and a Single Logout URL. Nothing is fetched and nothing in the file is
//! trusted: the values go through the same checks as typed ones, and the
//! administrator saves them like any other Basic SAML Configuration.

use crate::saml::ReplyUrl;
use crate::saml_protocol::{BINDING_POST, BINDING_REDIRECT, NS_METADATA, Node, parse_xml};

/// What a metadata file says about one service provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadata {
    pub entity_id: String,
    /// In index order; exactly one is the default.
    pub reply_urls: Vec<ReplyUrl>,
    pub logout_url: Option<String>,
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

/// Every `EntityDescriptor` with an `SPSSODescriptor`, however deeply grouped.
fn service_providers<'a>(node: &'a Node, out: &mut Vec<&'a Node>) {
    if is(node, "EntityDescriptor") {
        if children(node, "SPSSODescriptor").next().is_some() {
            out.push(node);
        }
    } else if is(node, "EntitiesDescriptor") {
        for child in &node.children {
            service_providers(child, out);
        }
    }
}

/// Read a metadata file describing exactly one service provider.
pub fn parse_sp_metadata(xml: &str) -> Result<SpMetadata, String> {
    let root = parse_xml(xml).map_err(|_| "The file is not a readable SAML metadata document.".to_string())?;
    if !is(&root, "EntityDescriptor") && !is(&root, "EntitiesDescriptor") {
        return Err("The file is not SAML metadata: it has no EntityDescriptor.".into());
    }
    let mut found = Vec::new();
    service_providers(&root, &mut found);
    let entity = match found.as_slice() {
        [one] => *one,
        [] => return Err("The file describes no service provider (SPSSODescriptor).".into()),
        many => {
            return Err(format!(
                "The file describes {} service providers; upload one application's metadata.",
                many.len()
            ));
        }
    };
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
    })
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
}
