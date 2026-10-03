use std::io::BufRead;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use rust_oidc::db::DbPool;
use serde_json::json;

use rust_oidc::apps::{self, MemberType, Principal, RedirectPlatform, ScopeConsent};
use rust_oidc::config::PublicUrl;
use rust_oidc::rbac::RoleId;
use rust_oidc::server::{self, TlsArgs};
use rust_oidc::txn::{self, Actor as TxnActor};
use rust_oidc::{AppState, db, directory, groups, keys, routes, tenant, users};

/// Who every command-line change is made by: an operator with access to the
/// database, recorded as `cli`.
const CLI: TxnActor = TxnActor::Cli;

#[derive(Parser)]
#[command(
    name = "rust-oidc",
    version,
    about = "OIDC / OAuth 2.0 provider compatible with Microsoft Entra ID v2.0"
)]
struct Cli {
    /// Database URL (SQLite, PostgreSQL or MySQL).
    #[arg(long, global = true, env = "RUST_OIDC_DATABASE", default_value = db::DEFAULT_DATABASE_URL)]
    database: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve {
        #[arg(long, env = "RUST_OIDC_BIND", default_value = "0.0.0.0:8080")]
        bind: SocketAddr,
        /// Externally visible base URL, including the path prefix.
        #[arg(
            long,
            env = "RUST_OIDC_PUBLIC_URL",
            default_value = "http://localhost:8080/rust-oidc"
        )]
        public_url: String,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Create the root tenant, its first Global Administrator and the signing keys.
    Bootstrap {
        /// Verified domain of the root tenant.
        #[arg(long)]
        domain: String,
        #[arg(long, default_value = "System")]
        name: String,
        /// UPN of the first admin, e.g. admin@example.com.
        #[arg(long)]
        admin_upn: String,
        /// Admin password (read from stdin if omitted).
        #[arg(long, env = "RUST_OIDC_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },
    #[command(subcommand)]
    Tenant(TenantCmd),
    #[command(subcommand)]
    User(UserCmd),
    #[command(subcommand)]
    Group(GroupCmd),
    #[command(subcommand)]
    App(AppCmd),
    #[command(subcommand)]
    Key(KeyCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Write a self-signed TLS certificate for local development.
    DevCert {
        #[arg(long, default_value = "data/dev-cert")]
        out: PathBuf,
        #[arg(long, value_delimiter = ',', default_value = "localhost,127.0.0.1")]
        names: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TenantCmd {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        domain: String,
    },
    List,
    /// Replace the tenant's domain and rename every account in it to match.
    ChangeDomain {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    Create {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        upn: String,
        #[arg(long, env = "RUST_OIDC_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        given_name: Option<String>,
        #[arg(long)]
        family_name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        /// Directory role to assign, e.g. "Global Administrator".
        #[arg(long)]
        directory_role: Option<String>,
    },
    /// Reset a password. Revokes the user's refresh tokens and sessions.
    SetPassword {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        upn: String,
        #[arg(long, env = "RUST_OIDC_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// The user must choose their own password at their next sign-in.
        #[arg(long)]
        require_change: bool,
    },
    /// Bring back a deleted account, enabled, with the password and roles it had.
    /// The way back in when the console can no longer be signed in to.
    Restore {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        upn: String,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    Create {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    AddMember {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        group: String,
        /// UPN of the user.
        #[arg(long)]
        user: String,
    },
}

#[derive(Subcommand)]
enum AppCmd {
    /// Register an application (creates its service principal and api://{appId}).
    Create {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        name: String,
    },
    List {
        #[arg(long)]
        tenant: String,
    },
    Show {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
    },
    /// Add an Application ID URI.
    AddIdentifierUri {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        uri: String,
    },
    /// Register a redirect URI on a platform (web, spa, publicClient).
    AddRedirectUri {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long, value_enum)]
        platform: RedirectPlatform,
        #[arg(long)]
        uri: String,
    },
    /// Expose a delegated permission (scope), e.g. Orders.Read.
    AddScope {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        value: String,
        #[arg(long)]
        display_name: Option<String>,
        /// Who may consent: User or Admin.
        #[arg(long, value_enum, default_value = "User")]
        r#type: ScopeConsent,
    },
    /// Allow front-channel tokens for this app: Entra's "ID tokens" and "access
    /// tokens" toggles under Implicit grant and hybrid flows. Both off by default,
    /// so response_type must be `code`.
    Implicit {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        /// Permit response_type values containing `id_token`.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        id_tokens: bool,
        /// Permit response_type values containing `token`.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        access_tokens: bool,
    },
    /// Allow the resource owner password grant (ROPC) for this app. Off by
    /// default: the client sees the user's password and MFA cannot apply.
    PasswordGrant {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long, action = clap::ArgAction::Set)]
        allowed: bool,
    },
    /// Require users to be assigned (directly or via a group) before signing in.
    AssignmentRequired {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long, action = clap::ArgAction::Set)]
        required: bool,
    },
    #[command(subcommand)]
    Secret(SecretCmd),
    #[command(subcommand)]
    Key(AppKeyCmd),
    #[command(subcommand)]
    Role(RoleCmd),
}

#[derive(Subcommand)]
enum AppKeyCmd {
    /// Register a certificate the app may sign client assertions with
    /// (private_key_jwt). Takes the PEM certificate, never the private key.
    Add {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        /// Path to the PEM certificate, or `-` to read it from stdin.
        #[arg(long)]
        cert: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// List the certificates registered on the app.
    List {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
    },
    Remove {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        /// The certificate thumbprint, as shown by `app key list`.
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Add a client secret. The value is shown once.
    Add {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 180)]
        days: i64,
    },
    Remove {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Subcommand)]
enum RoleCmd {
    /// Define an app role on an application.
    Add {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        value: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        /// Allowed member types: User, Application.
        #[arg(long, value_enum, value_delimiter = ',', default_value = "User,Application")]
        member_types: Vec<MemberType>,
    },
    /// Assign an app role of --resource to an app, user or group.
    Assign {
        #[arg(long)]
        tenant: String,
        /// appId of the application that defines the role.
        #[arg(long)]
        resource: String,
        #[arg(long)]
        role: String,
        /// appId of a client application.
        #[arg(long, group = "principal")]
        app: Option<String>,
        /// UPN of a user.
        #[arg(long, group = "principal")]
        user: Option<String>,
        /// Name of a group.
        #[arg(long, group = "principal")]
        group: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Delete audit rows older than --older-than-days.
    ///
    /// The table is append-only and unauthenticated requests can append to it,
    /// so an operator or cron must run this. There is no scheduler in the
    /// server process.
    Prune {
        #[arg(long, default_value_t = 90)]
        older_than_days: i64,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    List,
    /// Promote the pre-published next key to active and publish a new next key.
    Rotate,
    /// Delete keys retired more than --older-than-days ago.
    Prune {
        #[arg(long, default_value_t = 2)]
        older_than_days: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info,sqlx=warn".into()),
        )
        .init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    if let Command::DevCert { out, names } = cli.command {
        let (cert, key) = server::write_dev_cert(&out, names)?;
        println!("wrote {} and {}", cert.display(), key.display());
        return Ok(());
    }
    ensure_db_dir(&cli.database)?;
    let policy = if matches!(cli.command, Command::Serve { .. }) {
        db::FoldPolicy::FailClosed
    } else {
        db::FoldPolicy::ReportOnly
    };
    let pool = db::connect_with(&cli.database, policy).await?;

    match cli.command {
        Command::Serve { bind, public_url, tls } => {
            let public_url = PublicUrl::parse(&public_url)?;
            keys::ensure(&pool).await?;
            if tenant::root(&pool).await?.is_none() {
                tracing::warn!("no root tenant yet; run `rust-oidc bootstrap`");
            }
            tracing::info!(base = public_url.base(), "public URL");
            let app = routes::router(AppState::new(pool, public_url));
            server::serve(app, bind, &tls).await?;
        }
        Command::Bootstrap {
            domain,
            name,
            admin_upn,
            password,
        } => {
            let password = users::NewPassword::for_new_account(&password_or_stdin(password)?)?;
            let bootstrap = txn::ops::bootstrap::Bootstrap {
                name,
                domain,
                admin_upn,
                password,
            };
            let done = txn::run(&pool, &CLI, &bootstrap).await.into_result()?;
            keys::ensure(&pool).await?;
            let (t, user_id) = (tenant::find_for_admin(&pool, &done.tenant_id).await?, done.user_id);
            print_json(json!({ "tenantId": t.id, "adminObjectId": user_id }));
        }
        Command::Tenant(cmd) => tenant_cmd(&pool, cmd).await?,
        Command::User(cmd) => user_cmd(&pool, cmd).await?,
        Command::Group(cmd) => group_cmd(&pool, cmd).await?,
        Command::App(cmd) => app_cmd(&pool, cmd).await?,
        Command::Key(cmd) => key_cmd(&pool, cmd).await?,
        Command::Audit(AuditCmd::Prune { older_than_days }) => {
            let n = db::prune_audit(&pool, older_than_days * 86_400).await?;
            println!("deleted {n} audit row(s)");
        }
        Command::DevCert { .. } => unreachable!(),
    }
    Ok(())
}

async fn tenant_cmd(pool: &DbPool, cmd: TenantCmd) -> anyhow::Result<()> {
    match cmd {
        TenantCmd::Create { name, domain } => {
            let create = txn::ops::tenants::CreateTenant { name, domain };
            let t = txn::run(pool, &CLI, &create).await.into_result()?;
            print_json(json!({ "tenantId": t.id, "name": t.name }));
        }
        TenantCmd::List => {
            let list: Vec<_> = tenant::list(pool)
                .await?
                .into_iter()
                .map(|(t, domains)| {
                    json!({ "tenantId": t.id, "name": t.name, "isRoot": t.is_root, "enabled": t.enabled, "domains": domains })
                })
                .collect();
            print_json(json!(list));
        }
        TenantCmd::ChangeDomain { tenant: key, domain } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let change = txn::ops::tenants::ChangeTenantDomain {
                tenant_id: t.id.clone(),
                domain,
            };
            txn::run(pool, &CLI, &change).await.into_result()?;
            print_json(json!({ "tenantId": t.id, "domains": tenant::domains(pool, &t.id).await? }));
        }
    }
    Ok(())
}

async fn user_cmd(pool: &DbPool, cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Create {
            tenant: key,
            upn,
            password,
            display_name,
            given_name,
            family_name,
            email,
            directory_role,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let password = users::NewPassword::for_new_account(&password_or_stdin(password)?)?;
            let create = txn::ops::users::CreateUser {
                tenant_id: t.id.clone(),
                upn: upn.clone(),
                password,
                display_name,
                given_name,
                family_name,
                email,
            };
            // With a directory role, the account and its role are one batch:
            // both or neither. The role names the account by user name, which
            // resolves to the one the batch just created.
            let mut batch: Vec<txn::Txn> = vec![create.into()];
            if let Some(role) = directory_role {
                let Some(found) = directory::find(&role) else {
                    bail!("unknown directory role '{role}'");
                };
                let Some(role_id) = RoleId::for_template_in_tenant(found.template_id) else {
                    bail!("directory role '{role}' has no RBAC role");
                };
                let grant = txn::ops::roles::GrantRole {
                    page: txn::ops::roles::RolePage::Tenant(t.id.clone()),
                    principal: txn::ops::roles::Principal::User(upn.clone()),
                    role: role_id,
                };
                batch.push(grant.into());
            }
            let id = match txn::run_batch(pool, &CLI, &batch).await {
                txn::BatchOutcome::Done(outputs) => match outputs.into_iter().next() {
                    Some(txn::TxnOutput::CreateUser(created)) => created.id,
                    _ => bail!("the batch did not create the account"),
                },
                txn::BatchOutcome::Aborted { outcome, .. } => return outcome.into_result(),
            };
            print_json(json!({ "id": id, "userPrincipalName": upn }));
        }
        UserCmd::SetPassword {
            tenant: key,
            upn,
            password,
            require_change,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let password = password_or_stdin(password)?;
            let by = if require_change {
                users::PasswordSetBy::AdminTemporary
            } else {
                users::PasswordSetBy::Admin
            };
            let Some(user) = users::find_by_upn(pool, &t.id, &upn).await? else {
                bail!("user '{upn}' not found");
            };
            // Checked against the history and hashed before the transaction.
            let password = users::prepare_password(pool, &t, &user.id, &password, by).await?;
            let reset = txn::ops::users::ResetPassword {
                tenant_id: t.id.clone(),
                account: txn::ops::Account::Id(user.id),
                password,
            };
            txn::run(pool, &CLI, &reset).await.into_result()?;
        }
        UserCmd::Restore { tenant: key, upn } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let restore = txn::ops::users::RestoreUser {
                tenant_id: t.id.clone(),
                account: txn::ops::Account::Upn(upn.clone()),
            };
            txn::run(pool, &CLI, &restore).await.into_result()?;
            print_json(json!({ "userPrincipalName": upn, "restored": true }));
        }
    }
    Ok(())
}

async fn group_cmd(pool: &DbPool, cmd: GroupCmd) -> anyhow::Result<()> {
    match cmd {
        GroupCmd::Create {
            tenant: key,
            name,
            description,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let create = txn::ops::groups::CreateGroup {
                tenant_id: t.id.clone(),
                name: name.clone(),
                description,
            };
            let id = txn::run(pool, &CLI, &create).await.into_result()?;
            print_json(json!({ "id": id, "displayName": name }));
        }
        GroupCmd::AddMember {
            tenant: key,
            group,
            user,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            // The command line names the group, the console its id.
            let Some(group_id) = groups::find(pool, &t.id, &group).await? else {
                bail!("group '{group}' not found");
            };
            let add = txn::ops::groups::AddGroupMember {
                tenant_id: t.id.clone(),
                group_id,
                account: txn::ops::Account::Upn(user),
            };
            txn::run(pool, &CLI, &add).await.into_result()?;
        }
    }
    Ok(())
}

async fn app_cmd(pool: &DbPool, cmd: AppCmd) -> anyhow::Result<()> {
    match cmd {
        AppCmd::Create { tenant: key, name } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let create = txn::ops::apps::CreateApp {
                tenant_id: t.id.clone(),
                display_name: name,
            };
            let application = txn::run(pool, &CLI, &create).await.into_result()?;
            let sp = apps::service_principal(pool, &t.id, &application.app_id)
                .await?
                .context("no service principal")?;
            let identifier_uri = apps::identifier_uris(pool, &application).await?.into_iter().next();
            let created = apps::CreatedApp {
                service_principal_id: sp.id,
                identifier_uri: identifier_uri.unwrap_or_default(),
                application,
            };
            print_json(json!({
                "appId": created.application.app_id,
                "id": created.application.id,
                "servicePrincipalId": created.service_principal_id,
                "identifierUris": [created.identifier_uri],
                "tenantId": t.id,
            }));
        }
        AppCmd::List { tenant: key } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let list: Vec<_> = apps::list(pool, &t.id)
                .await?
                .into_iter()
                .map(|a| json!({ "appId": a.app_id, "id": a.id, "displayName": a.display_name }))
                .collect();
            print_json(json!(list));
        }
        AppCmd::Show { tenant: key, app } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let roles: Vec<_> = apps::roles(pool, &a)
                .await?
                .into_iter()
                .map(|r| json!({
                    "id": r.id, "value": r.value, "displayName": r.display_name, "isEnabled": r.enabled,
                    "allowedMemberTypes": serde_json::from_str::<serde_json::Value>(&r.allowed_member_types).unwrap_or_default(),
                }))
                .collect();
            let sp = apps::service_principal(pool, &t.id, &a.app_id).await?;
            print_json(json!({
                "appId": a.app_id, "id": a.id, "displayName": a.display_name,
                "identifierUris": apps::identifier_uris(pool, &a).await?,
                "redirectUris": apps::redirect_uris(pool, &a).await?.into_iter()
                    .map(|(platform, uri)| json!({ "platform": platform.as_str(), "uri": uri })).collect::<Vec<_>>(),
                "scopes": apps::enabled_scopes(pool, &a).await?,
                "appRoles": roles,
                "servicePrincipalId": sp.map(|s| s.id),
            }));
        }
        AppCmd::AddIdentifierUri { tenant: key, app, uri } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let add = txn::ops::apps::AddIdentifierUri {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                uri,
            };
            txn::run(pool, &CLI, &add).await.into_result()?;
            print_json(json!({ "appId": a.app_id, "identifierUris": apps::identifier_uris(pool, &a).await? }));
        }
        AppCmd::AddRedirectUri {
            tenant: key,
            app,
            platform,
            uri,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let add = txn::ops::apps::AddRedirectUri {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                platform,
                uri,
            };
            txn::run(pool, &CLI, &add).await.into_result()?;
        }
        AppCmd::AddScope {
            tenant: key,
            app,
            value,
            display_name,
            r#type,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let add = txn::ops::apps::AddAppScope {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                value: value.clone(),
                consent: r#type,
                display_name,
            };
            let id = txn::run(pool, &CLI, &add).await.into_result()?;
            print_json(json!({ "id": id, "value": value }));
        }
        AppCmd::AssignmentRequired {
            tenant: key,
            app,
            required,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let set = txn::ops::apps::SetAssignmentRequired {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                required,
            };
            txn::run(pool, &CLI, &set).await.into_result()?;
        }
        AppCmd::Secret(SecretCmd::Add {
            tenant: key,
            app,
            name,
            days,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let add = txn::ops::apps::AddAppSecret {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                secret: apps::PreparedSecret::generate(),
                valid_days: days,
                display_name: name,
            };
            let s = txn::run(pool, &CLI, &add).await.into_result()?;
            let end = time::OffsetDateTime::from_unix_timestamp(s.end_at)?
                .format(&time::format_description::well_known::Rfc3339)?;
            print_json(
                json!({ "keyId": s.key_id, "secretText": s.secret, "hint": &s.secret[..3], "endDateTime": end }),
            );
        }
        AppCmd::Implicit {
            tenant: key,
            app,
            id_tokens,
            access_tokens,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let flags = AppFlags::read(pool, &t, &a).await?;
            let save = txn::ops::apps::SaveAppFlags {
                allow_id_token_implicit: id_tokens,
                allow_access_token_implicit: access_tokens,
                ..flags.save(&t, &a)
            };
            txn::run(pool, &CLI, &save).await.into_result()?;
            println!("id_tokens={id_tokens} access_tokens={access_tokens} for {}", a.app_id);
        }
        AppCmd::PasswordGrant {
            tenant: key,
            app,
            allowed,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let flags = AppFlags::read(pool, &t, &a).await?;
            let save = txn::ops::apps::SaveAppFlags {
                allow_password_grant: allowed,
                ..flags.save(&t, &a)
            };
            txn::run(pool, &CLI, &save).await.into_result()?;
            print_json(json!({ "appId": a.app_id, "allowPasswordGrant": allowed }));
        }
        AppCmd::Key(AppKeyCmd::Add {
            tenant: key,
            app,
            cert,
            name,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let pem = if cert == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&cert).with_context(|| format!("reading {cert}"))?
            };
            // The transaction refuses a private key.
            let add = txn::ops::apps::AddAppCertificate {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                certificate_pem: pem,
                display_name: name,
            };
            let key_id = txn::run(pool, &CLI, &add).await.into_result()?;
            print_json(json!({ "keyId": key_id }));
        }
        AppCmd::Key(AppKeyCmd::List { tenant: key, app }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let rfc3339 = |ts: i64| -> anyhow::Result<String> {
                Ok(time::OffsetDateTime::from_unix_timestamp(ts)?
                    .format(&time::format_description::well_known::Rfc3339)?)
            };
            let mut out = Vec::new();
            for c in apps::key_credentials(pool, &a).await? {
                out.push(json!({
                    "keyId": c.key_id,
                    "displayName": c.display_name,
                    "startDateTime": rfc3339(c.not_before)?,
                    "endDateTime": rfc3339(c.not_after)?,
                }));
            }
            print_json(json!(out));
        }
        AppCmd::Key(AppKeyCmd::Remove {
            tenant: key,
            app,
            key_id,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let remove = txn::ops::apps::RemoveAppCertificate {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                key_id: key_id.clone(),
            };
            txn::run(pool, &CLI, &remove).await.into_result()?;
            print_json(json!({ "removed": key_id }));
        }
        AppCmd::Secret(SecretCmd::Remove {
            tenant: key,
            app,
            key_id,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let remove = txn::ops::apps::RemoveAppSecret {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                key_id,
            };
            txn::run(pool, &CLI, &remove).await.into_result()?;
        }
        AppCmd::Role(RoleCmd::Add {
            tenant: key,
            app,
            value,
            display_name,
            description,
            member_types,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let add = txn::ops::apps::AddAppRole {
                tenant_id: t.id.clone(),
                app_id: a.app_id.clone(),
                value: value.clone(),
                member_types: member_types.clone(),
                display_name,
                description,
            };
            let id = txn::run(pool, &CLI, &add).await.into_result()?;
            let types: Vec<&str> = member_types.iter().map(|m| m.as_str()).collect();
            print_json(json!({ "id": id, "value": value, "allowedMemberTypes": types }));
        }
        AppCmd::Role(RoleCmd::Assign {
            tenant: key,
            resource,
            role,
            app,
            user,
            group,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let resource_app = apps::find_in_tenant(pool, &t, &resource).await?;
            // An application is granted the role as an application permission;
            // a user or group is assigned to the application with it.
            let outcome = match (app, user, group) {
                (Some(client_app_id), None, None) => {
                    let grant = txn::ops::apps::GrantAppRole {
                        tenant_id: t.id.clone(),
                        app_id: resource_app.app_id.clone(),
                        role,
                        client_app_id,
                    };
                    txn::run(pool, &CLI, &grant).await.map_done()
                }
                (None, Some(u), None) => assign(pool, &t, &resource_app, Principal::User(u), role).await,
                (None, None, Some(g)) => assign(pool, &t, &resource_app, Principal::Group(g), role).await,
                _ => bail!("give exactly one of --app, --user, --group"),
            };
            outcome.into_result()?;
        }
    }
    Ok(())
}

/// Assign a user or group to an application with one of its roles.
async fn assign(
    pool: &DbPool,
    t: &tenant::Tenant,
    resource: &apps::Application,
    principal: Principal,
    role: String,
) -> txn::Outcome<()> {
    let assign = txn::ops::apps::AssignApp {
        tenant_id: t.id.clone(),
        app_id: resource.app_id.clone(),
        principal,
        roles: vec![role],
    };
    txn::run(pool, &CLI, &assign).await.map_done()
}

/// An application's sign-in switches as they are, so the command line can change
/// one of them through the transaction that saves them all.
struct AppFlags {
    accept_other_tenants: bool,
    mfa_required: bool,
}

impl AppFlags {
    async fn read(pool: &DbPool, t: &tenant::Tenant, a: &apps::Application) -> anyhow::Result<Self> {
        let sp = apps::service_principal(pool, &t.id, &a.app_id)
            .await?
            .context("no service principal")?;
        Ok(Self {
            accept_other_tenants: sp.accept_other_tenants,
            mfa_required: sp.mfa_required,
        })
    }

    fn save(&self, t: &tenant::Tenant, a: &apps::Application) -> txn::ops::apps::SaveAppFlags {
        txn::ops::apps::SaveAppFlags {
            tenant_id: t.id.clone(),
            app_id: a.app_id.clone(),
            accept_other_tenants: self.accept_other_tenants,
            mfa_required: self.mfa_required,
            allow_password_grant: a.allow_password_grant,
            allow_id_token_implicit: a.allow_id_token_implicit,
            allow_access_token_implicit: a.allow_access_token_implicit,
        }
    }
}

async fn key_cmd(pool: &DbPool, cmd: KeyCmd) -> anyhow::Result<()> {
    match cmd {
        KeyCmd::List => {
            let rows: Vec<(String, String, i64, Option<i64>, i64)> = sqlx::query_as(
                "SELECT kid, status, created_at, retired_at, not_after FROM signing_keys ORDER BY created_at",
            )
            .fetch_all(pool)
            .await?;
            let list: Vec<_> = rows
                .into_iter()
                .map(|(kid, status, created, retired, not_after)| {
                    json!({ "kid": kid, "status": status, "createdAt": created, "retiredAt": retired, "notAfter": not_after })
                })
                .collect();
            print_json(json!(list));
        }
        KeyCmd::Rotate => {
            // Generated before the transaction: RSA key generation is slow.
            let rotate = txn::ops::keys::RotateKeys {
                fresh: keys::NewKey::generate()?,
            };
            txn::run(pool, &CLI, &rotate).await.into_result()?;
            println!("rotated; running servers pick up the change within 30 seconds");
        }
        KeyCmd::Prune { older_than_days } => {
            let prune = txn::ops::keys::PruneKeys { older_than_days };
            let n = txn::run(pool, &CLI, &prune).await.into_result()?.deleted;
            println!("deleted {n} retired key(s)");
        }
    }
    Ok(())
}

fn password_or_stdin(password: Option<String>) -> anyhow::Result<String> {
    if let Some(p) = password {
        return Ok(p);
    }
    eprint!("password: ");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading password from stdin")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn ensure_db_dir(url: &str) -> anyhow::Result<()> {
    if let Some(path) = db::database_file_path(url)
        && let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn print_json(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
}
