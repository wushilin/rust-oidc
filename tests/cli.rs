//! The command line, run as a process against a fresh SQLite database: every
//! change it makes is a transaction, recorded with actor `cli` under the
//! console's event names.

use std::process::{Command, Output};

const PASSWORD: &str = "Correct-Horse-9";

struct Cli {
    _dir: tempfile::TempDir,
    database: String,
}

impl Cli {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = format!("sqlite://{}?mode=rwc", dir.path().join("cli.db").display());
        Self { _dir: dir, database }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rust-oidc"))
            .arg("--database")
            .arg(&self.database)
            .args(args)
            .env("RUST_OIDC_PASSWORD", PASSWORD)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    async fn audit(&self) -> Vec<(String, String)> {
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(&self.database).await.unwrap();
        sqlx::query_as("SELECT actor, action FROM audit_log ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn every_command_line_change_is_a_recorded_transaction() {
    let cli = Cli::new();
    cli.ok(&[
        "bootstrap",
        "--domain",
        "contoso.com",
        "--name",
        "Contoso",
        "--admin-upn",
        "admin@contoso.com",
    ]);
    // A second bootstrap is refused, and changes nothing.
    let again = cli.run(&[
        "bootstrap",
        "--domain",
        "fabrikam.com",
        "--admin-upn",
        "admin@fabrikam.com",
    ]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("Already bootstrapped"));

    let t = ["--tenant", "contoso.com"];
    // An account with a directory role: one batch, both or neither. An unknown
    // role is refused before anything is written (the audit rows below show it).
    cli.ok(&[
        &["user", "create"][..],
        &t,
        &["--upn", "bea@contoso.com", "--directory-role", "User Administrator"],
    ]
    .concat());
    let refused = cli.run(
        &[
            &["user", "create"][..],
            &t,
            &["--upn", "cal@contoso.com", "--directory-role", "No Such Role"],
        ]
        .concat(),
    );
    assert!(!refused.status.success());
    cli.ok(&[&["group", "create"][..], &t, &["--name", "Engineering"]].concat());
    cli.ok(&[
        &["group", "add-member"][..],
        &t,
        &["--group", "Engineering", "--user", "bea@contoso.com"],
    ]
    .concat());
    cli.ok(&[
        &["user", "set-password"][..],
        &t,
        &["--upn", "bea@contoso.com", "--require-change"],
    ]
    .concat());
    cli.ok(&["key", "rotate"]);

    let rows = cli.audit().await;
    assert!(rows.iter().all(|(actor, _)| actor == "cli"), "{rows:?}");
    let actions: Vec<&str> = rows.iter().map(|(_, a)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "bootstrap",
            "admin.user.create",
            "admin.role.grant",
            "admin.group.create",
            "admin.group.member.add",
            "admin.user.reset",
            "admin.key.rotate",
        ]
    );
}
