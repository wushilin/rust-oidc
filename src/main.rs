use std::io::BufRead;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use sqlx::SqlitePool;

use rust_oidc::apps::{self, Principal};
use rust_oidc::config::PublicUrl;
use rust_oidc::server::{self, TlsArgs};
use rust_oidc::{AppState, db, directory, groups, keys, routes, tenant, users};

#[derive(Parser)]
#[command(
    name = "rust-oidc",
    version,
    about = "OIDC / OAuth 2.0 provider compatible with Microsoft Entra ID v2.0"
)]
struct Cli {
    /// SQLite database URL.
    #[arg(
        long,
        global = true,
        env = "RUST_OIDC_DATABASE",
        default_value = "sqlite://data/rust-oidc.db"
    )]
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
    AddDomain {
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
        #[arg(long)]
        platform: String,
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
        /// User or Admin.
        #[arg(long, default_value = "User")]
        r#type: String,
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
    Role(RoleCmd),
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
        #[arg(long, value_delimiter = ',', default_value = "User,Application")]
        member_types: Vec<String>,
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
    let pool = db::connect(&cli.database).await?;

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
            if tenant::root(&pool).await?.is_some() {
                bail!("already bootstrapped: a root tenant exists");
            }
            let password = password_or_stdin(password)?;
            let t = tenant::create(&pool, &name, &domain, true).await?;
            let user_id = users::create(
                &pool,
                &t,
                users::NewUser {
                    upn: &admin_upn,
                    password: &password,
                    display_name: Some("Administrator"),
                    given_name: None,
                    family_name: None,
                    email: None,
                },
            )
            .await?;
            directory::assign(&pool, &t.id, directory::GLOBAL_ADMINISTRATOR, &user_id, "User").await?;
            keys::ensure(&pool).await?;
            db::audit(
                &pool,
                Some(&t.id),
                "cli",
                "bootstrap",
                Some(&user_id),
                json!({ "upn": admin_upn }),
            )
            .await?;
            print_json(json!({ "tenantId": t.id, "adminObjectId": user_id }));
        }
        Command::Tenant(cmd) => tenant_cmd(&pool, cmd).await?,
        Command::User(cmd) => user_cmd(&pool, cmd).await?,
        Command::Group(cmd) => group_cmd(&pool, cmd).await?,
        Command::App(cmd) => app_cmd(&pool, cmd).await?,
        Command::Key(cmd) => key_cmd(&pool, cmd).await?,
        Command::DevCert { .. } => unreachable!(),
    }
    Ok(())
}

async fn tenant_cmd(pool: &SqlitePool, cmd: TenantCmd) -> anyhow::Result<()> {
    match cmd {
        TenantCmd::Create { name, domain } => {
            let t = tenant::create(pool, &name, &domain, false).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "tenant.create",
                Some(&t.id),
                json!({ "name": name, "domain": domain }),
            )
            .await?;
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
        TenantCmd::AddDomain { tenant: key, domain } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            tenant::add_domain(pool, &t.id, &domain).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "tenant.add_domain",
                Some(&t.id),
                json!({ "domain": domain }),
            )
            .await?;
            print_json(json!({ "tenantId": t.id, "domains": tenant::domains(pool, &t.id).await? }));
        }
    }
    Ok(())
}

async fn user_cmd(pool: &SqlitePool, cmd: UserCmd) -> anyhow::Result<()> {
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
            let password = password_or_stdin(password)?;
            let id = users::create(
                pool,
                &t,
                users::NewUser {
                    upn: &upn,
                    password: &password,
                    display_name: display_name.as_deref(),
                    given_name: given_name.as_deref(),
                    family_name: family_name.as_deref(),
                    email: email.as_deref(),
                },
            )
            .await?;
            if let Some(role) = directory_role {
                directory::assign(pool, &t.id, &role, &id, "User").await?;
            }
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "user.create",
                Some(&id),
                json!({ "upn": upn }),
            )
            .await?;
            print_json(json!({ "id": id, "userPrincipalName": upn }));
        }
        UserCmd::SetPassword {
            tenant: key,
            upn,
            password,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let password = password_or_stdin(password)?;
            users::set_password(pool, &t, &upn, &password).await?;
            db::audit(pool, Some(&t.id), "cli", "user.set_password", Some(&upn), json!({})).await?;
        }
    }
    Ok(())
}

async fn group_cmd(pool: &SqlitePool, cmd: GroupCmd) -> anyhow::Result<()> {
    match cmd {
        GroupCmd::Create {
            tenant: key,
            name,
            description,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let id = groups::create(pool, &t, &name, description.as_deref()).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "group.create",
                Some(&id),
                json!({ "name": name }),
            )
            .await?;
            print_json(json!({ "id": id, "displayName": name }));
        }
        GroupCmd::AddMember {
            tenant: key,
            group,
            user,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            groups::add_member(pool, &t, &group, &user).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "group.add_member",
                Some(&group),
                json!({ "upn": user }),
            )
            .await?;
        }
    }
    Ok(())
}

async fn app_cmd(pool: &SqlitePool, cmd: AppCmd) -> anyhow::Result<()> {
    match cmd {
        AppCmd::Create { tenant: key, name } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let created = apps::create(pool, &t, &name).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.create",
                Some(&created.application.app_id),
                json!({ "name": name }),
            )
            .await?;
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
                    .map(|(platform, uri)| json!({ "platform": platform, "uri": uri })).collect::<Vec<_>>(),
                "scopes": apps::enabled_scopes(pool, &a).await?,
                "appRoles": roles,
                "servicePrincipalId": sp.map(|s| s.id),
            }));
        }
        AppCmd::AddIdentifierUri { tenant: key, app, uri } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            apps::add_identifier_uri(pool, &a, &uri).await?;
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
            apps::add_redirect_uri(pool, &a, &platform, &uri).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.redirect_uri.add",
                Some(&a.app_id),
                json!({ "platform": platform, "uri": uri }),
            )
            .await?;
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
            let display = display_name.unwrap_or_else(|| value.clone());
            let id = apps::add_scope(pool, &a, &value, &display, &r#type).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.scope.add",
                Some(&a.app_id),
                json!({ "value": value }),
            )
            .await?;
            print_json(json!({ "id": id, "value": value }));
        }
        AppCmd::AssignmentRequired {
            tenant: key,
            app,
            required,
        } => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let sp = apps::service_principal(pool, &t.id, &a.app_id)
                .await?
                .context("no service principal")?;
            apps::set_assignment_required(pool, &sp.id, required).await?;
        }
        AppCmd::Secret(SecretCmd::Add {
            tenant: key,
            app,
            name,
            days,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            let s = apps::add_secret(pool, &a, name.as_deref(), days).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.secret.add",
                Some(&a.app_id),
                json!({ "keyId": s.key_id }),
            )
            .await?;
            let end = time::OffsetDateTime::from_unix_timestamp(s.end_at)?
                .format(&time::format_description::well_known::Rfc3339)?;
            print_json(
                json!({ "keyId": s.key_id, "secretText": s.secret, "hint": &s.secret[..3], "endDateTime": end }),
            );
        }
        AppCmd::Secret(SecretCmd::Remove {
            tenant: key,
            app,
            key_id,
        }) => {
            let t = tenant::find_for_admin(pool, &key).await?;
            let a = apps::find_in_tenant(pool, &t, &app).await?;
            apps::remove_secret(pool, &a, &key_id).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.secret.remove",
                Some(&a.app_id),
                json!({ "keyId": key_id }),
            )
            .await?;
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
            let types: Vec<&str> = member_types.iter().map(String::as_str).collect();
            let display = display_name.unwrap_or_else(|| value.clone());
            let id = apps::add_role(pool, &a, &value, &display, description.as_deref(), &types).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.role.add",
                Some(&a.app_id),
                json!({ "value": value }),
            )
            .await?;
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
            let principal = match (app, user, group) {
                (Some(a), None, None) => Principal::App(a),
                (None, Some(u), None) => Principal::User(u),
                (None, None, Some(g)) => Principal::Group(g),
                _ => bail!("give exactly one of --app, --user, --group"),
            };
            apps::assign_role(pool, &t, &resource_app, &role, &principal).await?;
            db::audit(
                pool,
                Some(&t.id),
                "cli",
                "app.role.assign",
                Some(&resource_app.app_id),
                json!({ "role": role }),
            )
            .await?;
        }
    }
    Ok(())
}

async fn key_cmd(pool: &SqlitePool, cmd: KeyCmd) -> anyhow::Result<()> {
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
            keys::rotate(pool).await?;
            db::audit(pool, None, "cli", "key.rotate", None, json!({})).await?;
            println!("rotated; running servers pick up the change within 30 seconds");
        }
        KeyCmd::Prune { older_than_days } => {
            let n = keys::prune(pool, older_than_days * 86_400).await?;
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
    let path = url.trim_start_matches("sqlite://").trim_start_matches("sqlite:");
    let path = path.split('?').next().unwrap_or_default();
    if path.is_empty() || path == ":memory:" {
        return Ok(());
    }
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn print_json(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
}
