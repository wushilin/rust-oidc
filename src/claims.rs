//! User token contents, following Entra ID's v2.0 ID and access tokens.

use serde_json::{Map, Value, json};

use crate::AppState;
use crate::apps::{self, Application};
use crate::scopes::{Grant, Resource};
use crate::tenant::Tenant;
use crate::users::User;
use crate::util::{b64url, half_hash, now, random_bytes};
use crate::{directory, groups};

pub const ID_TOKEN_LIFETIME: i64 = 3600;

/// Who signed in, to which client, and how.
pub struct SignIn {
    pub tenant: Tenant,
    pub user: User,
    pub client: Application,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

/// What is delivered alongside the ID token in the same front-channel response.
///
/// OpenID Connect Core 3.3.2.11 requires the ID token to bind these, so that a
/// response's ID token cannot be paired with a code or access token taken from a
/// different response.
#[derive(Default, Clone, Copy)]
pub struct FrontChannel<'a> {
    /// The authorization code in this response, hashed into `c_hash`.
    pub code: Option<&'a str>,
    /// Whether this response also carries the access token, hashed into `at_hash`.
    pub with_access_token: bool,
}

pub struct Issued {
    pub access_token: String,
    pub expires_in: i64,
    pub id_token: Option<String>,
}

/// Whether a token represents a signed-in user or an app itself, emitted as
/// the `idtyp` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdType {
    User,
    App,
}

impl IdType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::App => "app",
        }
    }
}

/// How the client authenticated, emitted as the `azpacr` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Azpacr {
    /// Public client: no credential.
    None,
    ClientSecret,
    Certificate,
}

impl Azpacr {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "0",
            Self::ClientSecret => "1",
            Self::Certificate => "2",
        }
    }
}

/// Authentication methods, emitted in the `amr` claim.
///
/// Only a password exists today. TOTP adds `Otp` and `Mfa`; see
/// `docs/superpowers/specs/2026-09-30-totp-mfa-design.md`.
///
/// `amr` is *stored* as a list of strings (in `sessions.amr`, and carried
/// forward by refresh tokens and OBO assertions) rather than as this enum, so a
/// token minted by an older build cannot be dropped or rejected for naming a
/// method this build does not know. The enum is for producing values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amr {
    /// Password.
    Pwd,
    /// A second factor: here, an authenticator app code or a recovery code.
    /// Entra writes `["pwd","mfa"]` after a multi-factor sign-in.
    Mfa,
}

impl Amr {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pwd => "pwd",
            Self::Mfa => "mfa",
        }
    }
}

pub async fn issue(
    st: &AppState,
    sign_in: &SignIn,
    grant: &Grant,
    nonce: Option<&str>,
    azpacr: Azpacr,
    front: FrontChannel<'_>,
) -> anyhow::Result<Issued> {
    let pool = &st.pool;
    let user = &sign_in.user;
    let tid = &sign_in.tenant.id;
    let iat = now();
    let sub = st.secrets.pairwise_sub(&user.id, &sign_in.client.app_id).await?;
    let user_groups = groups::for_user(pool, &user.id).await?;
    let wids = directory::wids_for_user(pool, tid, &user.id).await?;
    let name = user.display_name.clone().unwrap_or_else(|| user.upn.clone());

    // ---- access token ----
    let lifetime = sign_in.tenant.settings.access_token_lifetime_secs;
    let resource_roles = match &grant.resource {
        Resource::App { sp, .. } => apps::app_roles_for_user(pool, &sp.id, &user.id).await?,
        Resource::Graph => Vec::new(),
    };
    let mut at = Map::new();
    at.insert("aud".into(), json!(grant.resource.audience()));
    at.insert("iss".into(), json!(st.public_url.issuer(tid)));
    at.insert("iat".into(), json!(iat));
    at.insert("nbf".into(), json!(iat));
    at.insert("exp".into(), json!(iat + lifetime));
    at.insert("amr".into(), json!(sign_in.amr));
    at.insert("azp".into(), json!(sign_in.client.app_id));
    at.insert("azpacr".into(), json!(azpacr.as_str()));
    insert_groups(&mut at, &user_groups);
    at.insert("idtyp".into(), json!(IdType::User.as_str()));
    at.insert("name".into(), json!(name));
    at.insert("oid".into(), json!(user.id));
    at.insert("preferred_username".into(), json!(user.upn));
    insert_roles(&mut at, &resource_roles);
    at.insert("scp".into(), json!(grant.scp.join(" ")));
    at.insert("sub".into(), json!(sub));
    at.insert("tid".into(), json!(tid));
    at.insert("upn".into(), json!(user.upn));
    at.insert("uti".into(), json!(uti()));
    at.insert("ver".into(), json!("2.0"));
    insert_nonempty(&mut at, "wids", &wids);
    let access_token = st.keys.sign(&Value::Object(at)).await?;

    // ---- ID token ----
    let id_token = if grant.has("openid") {
        let sp = apps::service_principal(pool, tid, &sign_in.client.app_id).await?;
        let client_roles = match sp {
            Some(sp) => apps::app_roles_for_user(pool, &sp.id, &user.id).await?,
            None => Vec::new(),
        };
        let mut id = Map::new();
        id.insert("aud".into(), json!(sign_in.client.app_id));
        id.insert("iss".into(), json!(st.public_url.issuer(tid)));
        id.insert("iat".into(), json!(iat));
        id.insert("nbf".into(), json!(iat));
        id.insert("exp".into(), json!(iat + ID_TOKEN_LIFETIME));
        id.insert("amr".into(), json!(sign_in.amr));
        id.insert("auth_time".into(), json!(sign_in.auth_time));
        if let Some(code) = front.code {
            id.insert("c_hash".into(), json!(half_hash(code)));
        }
        if front.with_access_token {
            id.insert("at_hash".into(), json!(half_hash(&access_token)));
        }
        if grant.has("email")
            && let Some(email) = &user.email
        {
            id.insert("email".into(), json!(email));
            id.insert("email_verified".into(), json!(user.email_verified));
        }
        insert_groups(&mut id, &user_groups);
        if let Some(nonce) = nonce {
            id.insert("nonce".into(), json!(nonce));
        }
        id.insert("oid".into(), json!(user.id));
        if grant.has("profile") {
            id.insert("name".into(), json!(name));
            id.insert("preferred_username".into(), json!(user.upn));
            id.insert("upn".into(), json!(user.upn));
            if let Some(v) = &user.given_name {
                id.insert("given_name".into(), json!(v));
            }
            if let Some(v) = &user.family_name {
                id.insert("family_name".into(), json!(v));
            }
        }
        insert_roles(&mut id, &client_roles);
        id.insert("sub".into(), json!(sub));
        id.insert("tid".into(), json!(tid));
        id.insert("uti".into(), json!(uti()));
        id.insert("ver".into(), json!("2.0"));
        insert_nonempty(&mut id, "wids", &wids);
        Some(st.keys.sign(&Value::Object(id)).await?)
    } else {
        None
    };

    Ok(Issued {
        access_token,
        expires_in: lifetime,
        id_token,
    })
}

fn insert_nonempty(map: &mut Map<String, Value>, key: &str, values: &[String]) {
    if !values.is_empty() {
        map.insert(key.into(), json!(values));
    }
}

/// `groups` (names, as before) and `group_ids`, the same groups in the same order.
///
/// Names are what this server has always emitted; Entra emits ids. An application
/// that keys on something stable reads `group_ids[i]` for `groups[i]`. Both come
/// from one ordered list, so they cannot fall out of step.
fn insert_groups(claims: &mut Map<String, Value>, groups: &[groups::GroupRef]) {
    if groups.is_empty() {
        return;
    }
    claims.insert(
        "groups".into(),
        json!(groups.iter().map(|g| &g.name).collect::<Vec<_>>()),
    );
    claims.insert(
        "group_ids".into(),
        json!(groups.iter().map(|g| &g.id).collect::<Vec<_>>()),
    );
}

/// `roles` (app role values) and `role_ids`, the same roles in the same order.
pub fn insert_roles(claims: &mut Map<String, Value>, roles: &[apps::RoleRef]) {
    if roles.is_empty() {
        return;
    }
    claims.insert(
        "roles".into(),
        json!(roles.iter().map(|r| &r.value).collect::<Vec<_>>()),
    );
    claims.insert(
        "role_ids".into(),
        json!(roles.iter().map(|r| &r.id).collect::<Vec<_>>()),
    );
}

fn uti() -> String {
    b64url(&random_bytes(16))
}

/// MSAL's `client_info`: base64url JSON with the user's object id and tenant id,
/// which MSAL uses to build the home account id.
pub fn client_info(user: &User) -> String {
    b64url(json!({ "uid": user.id, "utid": user.tenant_id }).to_string().as_bytes())
}
