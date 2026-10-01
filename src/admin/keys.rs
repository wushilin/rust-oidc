//! The token signing keys: what is published, and the two consequential buttons.
//!
//! The keys are shared by every tenant, as in Entra, so this is a platform page:
//! `Key:Read` and `Key:Rotate` are both required at `On::Platform`, an
//! `all`-scope binding and nothing less. A tenant administrator has no business
//! rotating the key every other tenant's tokens are signed with.
//!
//! **There is no `Key:Prune` action**, so pruning is authorized by `Key:Rotate`.
//! Adding a verb would mean widening a role to hold it, which is not a change to
//! make quietly; rotation and pruning are two halves of the same lifecycle.
//! Recorded in `docs/decisions-log.md`.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{Params, audited, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{KEY_READ, KEY_ROTATE};
use crate::db::Event;
use crate::keys::{self, KeyStatus, StoredKey};

/// What a post to the keys page asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    Rotate,
    Prune,
}

impl KeyOp {
    pub const ALL: &'static [KeyOp] = &[Self::Rotate, Self::Prune];
    pub const FIELD: &'static str = "op";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::Prune => "prune",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == raw)
    }

    fn event(self) -> Event {
        match self {
            Self::Rotate => Event::AdminKeyRotate,
            Self::Prune => Event::AdminKeyPrune,
        }
    }
}

const DAYS: &str = "days";

/// How long a retired key must have been retired before pruning may delete it.
/// The same default `key prune --older-than-days` has: two days, comfortably
/// longer than any access token this server will issue under the lifetime bounds
/// in [`crate::tenant::TenantSettings`].
const DEFAULT_PRUNE_DAYS: i64 = 2;

fn keys_url(base: &str) -> String {
    format!("{base}/admin/keys")
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>) -> Response {
    if let Err(resp) = ctx.require(KEY_READ, On::Platform) {
        return resp;
    }
    render(&st, &ctx, None, StatusCode::OK).await
}

async fn render(st: &AppState, ctx: &AdminContext, error: Option<&str>, status: StatusCode) -> Response {
    let listed = match keys::list(&st.pool).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("signing key list failed: {err}");
            return view::server_error();
        }
    };
    let url = keys_url(st.public_url.base());
    let csrf = view::csrf_input(&ctx.csrf);
    let rows: String = listed.iter().map(row).collect();
    let may_rotate = ctx.can(KEY_ROTATE, On::Platform);

    let actions = if may_rotate {
        let retired = listed.iter().filter(|k| k.status == KeyStatus::Retired).count();
        format!(
            r#"<h2>Rotate</h2>
<p>Rotating does three things, in one step: the <strong>active</strong> key becomes
<strong>retired</strong>, the pre-published <strong>next</strong> key becomes the one that signs,
and a fresh <strong>next</strong> key is published. Tokens already issued stay verifiable, because a
retired key is still published in JWKS. Running servers pick the change up within 30 seconds.</p>
<p class="muted">This affects every tenant: the keys are shared, as in Entra.</p>
<form method="post" action="{url}" class="inline">{csrf}
<button class="danger" type="submit" name="{field}" value="{rotate}">Rotate the signing key</button></form>
<h2>Prune retired keys</h2>
<p>Deletes keys that have been retired for longer than the age below, which must exceed the
longest access token lifetime any tenant issues, or a token signed by a deleted key can no
longer be verified. {retired} key(s) are retired now.</p>
<form method="post" action="{url}">{csrf}<input type="hidden" name="{field}" value="{prune}">
<label for="days">Retired for at least (days)</label>
<input id="days" name="{DAYS}" type="text" value="{DEFAULT_PRUNE_DAYS}">
<div class="actions"><button class="danger" type="submit">Prune</button></div></form>"#,
            url = e(&url),
            field = KeyOp::FIELD,
            rotate = KeyOp::Rotate.as_str(),
            prune = KeyOp::Prune.as_str(),
        )
    } else {
        r#"<p class="muted">Your roles allow seeing the keys but not rotating them.</p>"#.to_string()
    };

    let body = format!(
        r#"<h1>Signing keys</h1><p class="sub">RS256, shared by every tenant. <code>kid</code> is the
certificate thumbprint, so <code>kid</code> = <code>x5t</code>.</p>{error}
<table><tr><th>Key id</th><th>Status</th><th>Created</th><th>Retired</th><th>Certificate expires</th></tr>{rows}</table>
{actions}"#,
        error = view::error_block(error),
    );
    view::page(&chrome(st, ctx), status, "Signing keys", &body)
}

fn row(k: &StoredKey) -> String {
    format!(
        "<tr><td class=\"muted\">{kid}</td><td>{status}</td><td>{created}</td><td>{retired}</td><td>{expires}</td></tr>",
        kid = e(&k.kid),
        status = status_cell(k.status),
        created = e(&view::ts(k.created_at)),
        retired = match k.retired_at {
            Some(at) => e(&view::ts(at)),
            None => String::new(),
        },
        expires = e(&view::ts(k.not_after)),
    )
}

/// The lifecycle in words, so "next" and "retired" do not have to be guessed at.
fn status_cell(status: KeyStatus) -> String {
    let note = match status {
        KeyStatus::Active => "signs new tokens",
        KeyStatus::Next => "published, not yet signing",
        KeyStatus::Retired => "published so old tokens still verify",
    };
    format!(
        r#"<strong>{status}</strong> <span class="muted">{note}</span>"#,
        status = e(status.as_str()),
        note = e(note),
    )
}

pub async fn post(ctx: AdminContext, State(st): State<AppState>, body: Bytes) -> Response {
    let form = parse_form(&body);
    let Some(op) = KeyOp::parse(field(&form, KeyOp::FIELD)) else {
        return view::bad_request("That is not an operation this page offers.");
    };
    if let Err(resp) = ctx.require(KEY_ROTATE, On::Platform) {
        return resp;
    }
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    match apply(&st, op, &form).await {
        Ok(details) => {
            // The keys belong to no tenant, so the row is attributed to the
            // administrator's own: `audit_log.tenant_id` is how a tenant admin's
            // page is filtered, and a row with none would be invisible to
            // everyone. The actor is the person either way.
            audited(&st, &ctx, &ctx.home_tenant.id, op.event(), None, details).await;
            view::see_other(&keys_url(st.public_url.base()))
        }
        Err(err) => render(&st, &ctx, Some(&err.to_string()), StatusCode::BAD_REQUEST).await,
    }
}

async fn apply(st: &AppState, op: KeyOp, form: &Params) -> anyhow::Result<serde_json::Value> {
    match op {
        KeyOp::Rotate => {
            keys::rotate(&st.pool).await?;
            Ok(json!({}))
        }
        KeyOp::Prune => {
            let days = field(form, DAYS)
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("the age must be a whole number of days"))?;
            // Zero or negative would delete a key retired moments ago, whose
            // tokens are certainly still alive.
            if days < 1 {
                anyhow::bail!("the age must be at least one day");
            }
            let deleted = keys::prune(&st.pool, days * 86_400).await?;
            Ok(json!({ "olderThanDays": days, "deleted": deleted }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip_and_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for op in KeyOp::ALL {
            assert!(seen.insert(op.as_str()), "two operations are both {}", op.as_str());
            assert_eq!(KeyOp::parse(op.as_str()), Some(*op));
            assert!(seen.insert(op.event().as_str()), "{op:?} shares an event");
        }
        assert_eq!(KeyOp::parse("delete"), None);
    }

    /// The prune default must outlive the longest access token any tenant can be
    /// configured to issue, or pruning could delete the key a live token was
    /// signed with.
    #[test]
    fn the_prune_default_outlives_the_longest_possible_access_token() {
        let longest = crate::tenant::TenantSettings::MAX_ACCESS_TOKEN_SECS;
        assert!(
            DEFAULT_PRUNE_DAYS * 86_400 > longest,
            "{DEFAULT_PRUNE_DAYS} days does not exceed {longest} seconds"
        );
    }
}
