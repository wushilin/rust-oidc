//! The configuration file: `rust-oidc -c config.toml serve`.
//!
//! Every setting the server takes on the command line or from a `RUST_OIDC_*`
//! environment variable can be written here instead. With `-c`, the file is the
//! source of truth: a value given **on the command line** still wins (so one run
//! can override one setting), but the file beats environment variables and the
//! built-in defaults. Without `-c`, nothing changes: flags, environment and
//! defaults, as before.
//!
//! `rust-oidc --generate-config-file config.toml` writes a commented file holding
//! the settings in effect now (the environment's where set, else the defaults),
//! so an existing env-file deployment converts in one step.
//!
//! Unknown keys are refused: a misspelt setting must fail at start-up rather than
//! be silently ignored.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

use crate::server::{TlsArgs, TlsMode};

/// The log filter when neither the file nor `RUST_LOG` sets one.
pub const DEFAULT_LOG_FILTER: &str = "info,tower_http=info,sqlx=warn";

/// The file, as written: every setting optional, so a file may hold only the
/// ones it changes.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub database: DatabaseSection,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub log: LogSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSection {
    pub url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub bind: Option<SocketAddr>,
    pub public_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub mode: Option<TlsMode>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub acme: AcmeSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSection {
    pub domains: Option<Vec<String>>,
    pub email: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub production: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// A `tracing` filter, as `RUST_LOG` takes it.
    pub filter: Option<String>,
}

/// Read and check a configuration file.
pub fn load(path: &Path) -> anyhow::Result<ConfigFile> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("{} is not a valid configuration file", path.display()))
}

/// Every setting, resolved: what the server runs with, and what
/// [`render`] writes out.
#[derive(Debug, Clone)]
pub struct Settings {
    pub database: String,
    pub bind: SocketAddr,
    pub public_url: String,
    pub tls: TlsArgs,
    pub log_filter: String,
}

/// A TOML string literal.
fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn quoted_path(p: &Path) -> String {
    quoted(&p.to_string_lossy())
}

/// An optional setting: written when set, commented out with an example when not.
fn optional(key: &str, value: Option<String>, example: &str) -> String {
    match value {
        Some(v) => format!("{key} = {v}\n"),
        None => format!("# {key} = {example}\n"),
    }
}

/// The settings as a commented configuration file.
pub fn render(s: &Settings) -> String {
    let modes: Vec<&str> = TlsMode::ALL.iter().map(|m| m.as_str()).collect();
    let domains: Vec<String> = s.tls.acme_domains.iter().map(|d| quoted(d)).collect();
    format!(
        r#"# rust-oidc configuration. Run with: rust-oidc -c <this file> serve
#
# A flag given on the command line overrides the value here; this file overrides
# RUST_OIDC_* environment variables and the built-in defaults. Unknown keys are
# an error.

[database]
# SQLite, PostgreSQL or MySQL, e.g. "sqlite://data/rust-oidc.db",
# "postgres://user:password@host/db", "mysql://user:password@host/db".
url = {database}

[server]
# The address to listen on.
bind = {bind}
# The externally visible base URL, including the path prefix. It is part of
# every token's issuer: changing it invalidates refresh tokens already issued.
public_url = {public_url}

[tls]
# One of: {modes}. "none" serves plain HTTP (behind a TLS-terminating proxy).
mode = {mode}
# For mode = "files": PEM certificate chain and private key.
{cert}{key}
[tls.acme]
# For mode = "acme": automatic Let's Encrypt certificates on this listener.
domains = [{domains}]
{email}cache_dir = {cache_dir}
# The production Let's Encrypt directory; false uses staging.
production = {production}

[log]
# A tracing filter, as RUST_LOG takes it.
filter = {filter}
"#,
        database = quoted(&s.database),
        bind = quoted(&s.bind.to_string()),
        public_url = quoted(&s.public_url),
        modes = modes.join(", "),
        mode = quoted(s.tls.tls_mode.as_str()),
        cert = optional(
            "cert",
            s.tls.tls_cert.as_deref().map(quoted_path),
            "\"tls/fullchain.pem\""
        ),
        key = optional("key", s.tls.tls_key.as_deref().map(quoted_path), "\"tls/key.pem\""),
        domains = domains.join(", "),
        email = optional(
            "email",
            s.tls.acme_email.as_deref().map(quoted),
            "\"admin@example.com\""
        ),
        cache_dir = quoted_path(&s.tls.acme_cache_dir),
        production = s.tls.acme_production,
        filter = quoted(&s.log_filter),
    )
}

/// Write a new configuration file, readable by its owner only (a database URL
/// can hold a password). An existing file is never overwritten.
pub fn write_new(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        if path.exists() {
            format!("{} already exists; it is not overwritten", path.display())
        } else {
            format!("creating {}", path.display())
        }
    })?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            database: "sqlite://data/rust-oidc.db".into(),
            bind: "0.0.0.0:8080".parse().unwrap(),
            public_url: "https://login.example.com/rust-oidc".into(),
            tls: TlsArgs {
                tls_mode: TlsMode::Files,
                tls_cert: Some("tls/fullchain.pem".into()),
                tls_key: Some("tls/key.pem".into()),
                acme_domains: vec!["login.example.com".into()],
                acme_email: None,
                acme_cache_dir: "data/acme".into(),
                acme_production: false,
            },
            log_filter: DEFAULT_LOG_FILTER.into(),
        }
    }

    /// What `render` writes, `load` reads back to the same settings.
    #[test]
    fn a_rendered_file_reads_back_to_the_same_settings() {
        let s = settings();
        let file: ConfigFile = toml::from_str(&render(&s)).unwrap();
        assert_eq!(file.database.url.as_deref(), Some(s.database.as_str()));
        assert_eq!(file.server.bind, Some(s.bind));
        assert_eq!(file.server.public_url.as_deref(), Some(s.public_url.as_str()));
        assert_eq!(file.tls.mode, Some(TlsMode::Files));
        assert_eq!(file.tls.cert, s.tls.tls_cert);
        assert_eq!(file.tls.key, s.tls.tls_key);
        assert_eq!(file.tls.acme.domains, Some(s.tls.acme_domains.clone()));
        assert_eq!(file.tls.acme.email, None, "unset stays unset (commented out)");
        assert_eq!(file.tls.acme.cache_dir, Some(s.tls.acme_cache_dir.clone()));
        assert_eq!(file.tls.acme.production, Some(false));
        assert_eq!(file.log.filter.as_deref(), Some(DEFAULT_LOG_FILTER));
    }

    #[test]
    fn values_that_need_quoting_survive() {
        let mut s = settings();
        s.database = r#"postgres://u:p"w\d@h/db"#.into();
        let file: ConfigFile = toml::from_str(&render(&s)).unwrap();
        assert_eq!(file.database.url.as_deref(), Some(s.database.as_str()));
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(toml::from_str::<ConfigFile>("[server]\nbnd = \"0.0.0.0:1\"").is_err());
        assert!(toml::from_str::<ConfigFile>("[nonsense]\n").is_err());
        assert!(toml::from_str::<ConfigFile>("[tls]\nmode = \"sometimes\"").is_err());
        assert!(toml::from_str::<ConfigFile>("[server]\nbind = \"not an address\"").is_err());
        // A file may hold only what it changes.
        let partial: ConfigFile = toml::from_str("[server]\nbind = \"127.0.0.1:9000\"").unwrap();
        assert!(partial.database.url.is_none());
    }
}
