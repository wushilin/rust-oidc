use anyhow::{Context, bail};
use url::Url;

/// The externally visible base URL, e.g. `https://auth.example.com/rust-oidc`.
/// Every URL we hand out (issuer, endpoints) is built from this, never from the
/// request's Host header.
#[derive(Clone, Debug)]
pub struct PublicUrl {
    base: String,
    path: String,
    host: String,
}

impl PublicUrl {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let url = Url::parse(raw).with_context(|| format!("invalid public URL '{raw}'"))?;
        if url.scheme() != "https" && url.scheme() != "http" {
            bail!("public URL must be http(s): {raw}");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("public URL must not have a query or fragment: {raw}");
        }
        let base = url.as_str().trim_end_matches('/').to_string();
        let path = url.path().trim_end_matches('/').to_string();
        let host = url.host_str().unwrap_or_default().to_string();
        Ok(Self { base, path, host })
    }

    /// `https://host/rust-oidc`, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `/rust-oidc`, or empty when served at the root.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// v2.0 issuer for a tenant: `{base}/{tid}/v2.0`, as in Entra.
    pub fn issuer(&self, tid: &str) -> String {
        format!("{}/{tid}/v2.0", self.base)
    }

    pub fn tenant_url(&self, tid: &str, rest: &str) -> String {
        format!("{}/{tid}/{rest}", self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefix() {
        let u = PublicUrl::parse("https://auth.example.com/rust-oidc/").unwrap();
        assert_eq!(u.base(), "https://auth.example.com/rust-oidc");
        assert_eq!(u.path(), "/rust-oidc");
        assert_eq!(u.issuer("t1"), "https://auth.example.com/rust-oidc/t1/v2.0");
    }

    #[test]
    fn parses_root() {
        let u = PublicUrl::parse("https://auth.example.com").unwrap();
        assert_eq!(u.base(), "https://auth.example.com");
        assert_eq!(u.path(), "");
    }
}
