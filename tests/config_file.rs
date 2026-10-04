//! The configuration file, run through the binary: `--generate-config-file`
//! writes what is in effect, `-c` reads it, a command-line flag beats the file,
//! and the file beats the environment.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rust-oidc"));
    // Start from a clean slate: no RUST_OIDC_* from the developer's shell.
    for (key, _) in std::env::vars() {
        if key.starts_with("RUST_OIDC_") || key == "RUST_LOG" {
            c.env_remove(key);
        }
    }
    c
}

fn ok(out: Output) -> String {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn sqlite(dir: &Path, name: &str) -> String {
    format!("sqlite://{}?mode=rwc", dir.join(name).display())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The issuer template the running server publishes, which is built from its
/// public URL.
async fn issuer_of(port: u16) -> String {
    let url = format!("http://127.0.0.1:{port}/rust-oidc/common/discovery/v2.0/keys");
    for _ in 0..100 {
        if let Ok(resp) = reqwest::get(&url).await
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            return body["keys"][0]["issuer"].as_str().unwrap_or_default().to_string();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the server did not answer on {port}");
}

#[test]
fn generate_writes_the_settings_in_effect_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let out = bin()
        .env("RUST_OIDC_BIND", "127.0.0.1:9999")
        .env("RUST_OIDC_PUBLIC_URL", "https://login.example.com/rust-oidc")
        .arg("--generate-config-file")
        .arg(&path)
        .output()
        .unwrap();
    ok(out);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"bind = "127.0.0.1:9999""#), "{text}");
    assert!(
        text.contains(r#"public_url = "https://login.example.com/rust-oidc""#),
        "{text}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a database URL can hold a password");
    }

    let again = bin().arg("--generate-config-file").arg(&path).output().unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "untouched");
}

/// The database in the file is the one every command uses, whatever the
/// environment says; `--database` on the command line still wins.
#[test]
fn commands_use_the_files_database_unless_the_command_line_says_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!("[database]\nurl = \"{}\"\n", sqlite(dir.path(), "from-file.db")),
    )
    .unwrap();

    ok(bin()
        .env("RUST_OIDC_DATABASE", sqlite(dir.path(), "from-env.db"))
        .arg("-c")
        .arg(&config)
        .args(["tenant", "list"])
        .output()
        .unwrap());
    assert!(dir.path().join("from-file.db").exists());
    assert!(
        !dir.path().join("from-env.db").exists(),
        "the file beats the environment"
    );

    ok(bin()
        .arg("--config")
        .arg(&config)
        .args(["--database", &sqlite(dir.path(), "from-flag.db"), "tenant", "list"])
        .output()
        .unwrap());
    assert!(
        dir.path().join("from-flag.db").exists(),
        "the command line beats the file"
    );
}

#[test]
fn a_misspelt_setting_is_an_error_naming_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[server]\nbnd = \"0.0.0.0:8080\"\n").unwrap();
    let out = bin().arg("-c").arg(&config).args(["tenant", "list"]).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("config.toml") && err.contains("bnd"), "{err}");
}

/// `serve` takes its address and public URL from the file, over the
/// environment; a flag on the command line beats the file.
#[tokio::test]
async fn serve_runs_from_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[database]\nurl = \"{db}\"\n[server]\nbind = \"127.0.0.1:{port}\"\n\
             public_url = \"http://from-file.example/rust-oidc\"\n[log]\nfilter = \"warn\"\n",
            db = sqlite(dir.path(), "serve.db"),
        ),
    )
    .unwrap();

    let server = Server(
        bin()
            .env("RUST_OIDC_PUBLIC_URL", "http://from-env.example/rust-oidc")
            .env("RUST_OIDC_BIND", "127.0.0.1:1")
            .arg("-c")
            .arg(&config)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        issuer_of(port).await.starts_with("http://from-file.example/rust-oidc/"),
        "the file's public URL, not the environment's"
    );
    drop(server);

    let port = free_port();
    let _server = Server(
        bin()
            .arg("-c")
            .arg(&config)
            .args([
                "serve",
                "--bind",
                &format!("127.0.0.1:{port}"),
                "--public-url",
                "http://from-flag.example/rust-oidc",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        issuer_of(port).await.starts_with("http://from-flag.example/rust-oidc/"),
        "the command line beats the file"
    );
}
