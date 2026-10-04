use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::{Args, ValueEnum};
use futures::StreamExt;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Plain HTTP (behind a TLS-terminating proxy, or local development).
    None,
    /// Certificate and key from PEM files.
    Files,
    /// Automatic certificates from Let's Encrypt (TLS-ALPN-01 on this listener).
    Acme,
}

impl TlsMode {
    pub const ALL: &'static [TlsMode] = &[Self::None, Self::Files, Self::Acme];

    /// The value on the command line and in the configuration file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Files => "files",
            Self::Acme => "acme",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct TlsArgs {
    #[arg(long, env = "RUST_OIDC_TLS_MODE", value_enum, default_value = "none")]
    pub tls_mode: TlsMode,
    #[arg(long, env = "RUST_OIDC_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,
    #[arg(long, env = "RUST_OIDC_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
    /// Domains to request certificates for (comma separated).
    #[arg(long, env = "RUST_OIDC_ACME_DOMAINS", value_delimiter = ',')]
    pub acme_domains: Vec<String>,
    #[arg(long, env = "RUST_OIDC_ACME_EMAIL")]
    pub acme_email: Option<String>,
    #[arg(long, env = "RUST_OIDC_ACME_CACHE_DIR", default_value = "data/acme")]
    pub acme_cache_dir: PathBuf,
    /// Use the Let's Encrypt production directory (default: staging).
    #[arg(long, env = "RUST_OIDC_ACME_PRODUCTION")]
    pub acme_production: bool,
}

pub async fn serve(app: Router, bind: SocketAddr, tls: &TlsArgs) -> anyhow::Result<()> {
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown_signal().await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });
    let service = app.into_make_service();

    match tls.tls_mode {
        TlsMode::None => {
            tracing::info!(%bind, "listening (plain HTTP)");
            axum_server::bind(bind).handle(handle).serve(service).await?;
        }
        TlsMode::Files => {
            let (Some(cert), Some(key)) = (&tls.tls_cert, &tls.tls_key) else {
                bail!("--tls-cert and --tls-key are required with --tls-mode files");
            };
            let config = RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| format!("loading {} / {}", cert.display(), key.display()))?;
            tracing::info!(%bind, "listening (TLS, certificate files)");
            axum_server::bind_rustls(bind, config)
                .handle(handle)
                .serve(service)
                .await?;
        }
        TlsMode::Acme => {
            if tls.acme_domains.is_empty() {
                bail!("--acme-domains is required with --tls-mode acme");
            }
            std::fs::create_dir_all(&tls.acme_cache_dir)?;
            let mut state = AcmeConfig::new(&tls.acme_domains)
                .contact(tls.acme_email.iter().map(|e| format!("mailto:{e}")))
                .cache(DirCache::new(tls.acme_cache_dir.clone()))
                .directory_lets_encrypt(tls.acme_production)
                .state();
            let acceptor = state.axum_acceptor(state.default_rustls_config());
            tokio::spawn(async move {
                while let Some(event) = state.next().await {
                    match event {
                        Ok(ok) => tracing::info!("acme: {ok:?}"),
                        Err(err) => tracing::error!("acme: {err:?}"),
                    }
                }
            });
            tracing::info!(%bind, domains = ?tls.acme_domains, production = tls.acme_production, "listening (TLS, ACME)");
            axum_server::bind(bind)
                .acceptor(acceptor)
                .handle(handle)
                .serve(service)
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

/// Self-signed certificate for local development and the compatibility tests.
pub fn write_dev_cert(dir: &std::path::Path, names: Vec<String>) -> anyhow::Result<(PathBuf, PathBuf)> {
    let certified = rcgen::generate_simple_self_signed(names)?;
    std::fs::create_dir_all(dir)?;
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, certified.cert.pem())?;
    std::fs::write(&key, certified.signing_key.serialize_pem())?;
    Ok((cert, key))
}
