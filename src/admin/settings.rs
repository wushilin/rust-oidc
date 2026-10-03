//! A tenant's token, session and refresh-token lifetimes.
//!
//! [`crate::tenant::TenantSettings`] has been read since the first commit and
//! written by nothing: every tenant has carried whatever `TenantSettings::default`
//! produced when it was created, and there is no CLI command either. This is the
//! first write path, so the bounds it enforces are new and are invented; they
//! live on the type, next to the values, and are recorded in
//! `docs/decisions-log.md`.
//!
//! Authorized by `Tenant:Write` **against the tenant in the URL**, the design
//! spec's own reading of that action ("change tenant settings and domains"). So a
//! tenant's own Global Administrator can tune their lifetimes, and a platform
//! administrator can do it for any tenant because an `all`-scope binding covers
//! every one.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, TenantTab, audited, checked, chrome, field, parse_form};
use crate::admin::view::{self, e};
use crate::admin::{TENANT_READ, TENANT_WRITE};
use crate::db::Event;
use crate::tenant::{self, Tenant, TenantSettings};

/// Form field names, spelled once. They match the struct's field names, which is
/// what makes the form and the type obviously the same three values.
const REQUIRE_MFA: &str = "require_mfa";
const PASSWORD_HISTORY: &str = "password_history";
const REQUIRE_CONSOLE_MFA: &str = "require_console_mfa";
const ACCESS_TOKEN: &str = "access_token_lifetime_secs";
const SESSION: &str = "session_lifetime_secs";
const REFRESH: &str = "refresh_token_lifetime_secs";

fn settings_url(base: &str, tenant: &Tenant) -> String {
    format!("{base}/admin/tenants/{}/settings", tenant.id)
}

pub async fn page(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>) -> Response {
    // Reading the settings is reading the tenant.
    if let Err(resp) = ctx.require(TENANT_READ, On::Tenant(&key)) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };
    render(&st, &ctx, tenant, &tenant.settings, None, StatusCode::OK).await
}

async fn render(
    st: &AppState,
    ctx: &AdminContext,
    tenant: &Tenant,
    settings: &TenantSettings,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let may_write = ctx.can_in(TENANT_WRITE, tenant);
    let disabled = if may_write { "" } else { " disabled" };
    // Renaming, domains and disabling are platform operations: they need an
    // every-tenant binding, which a tenant's own administrator does not hold.
    let domains = crate::tenant::domains(&st.pool, &tenant.id).await.unwrap_or_default();
    let manage = crate::admin::tenants::manage(
        st.public_url.base(),
        &view::csrf_input(&ctx.csrf),
        tenant,
        &domains,
        ctx.can(TENANT_WRITE, On::Platform),
    );
    let row = |id: &str, label: &str, value: i64, lo: i64, hi: i64| {
        format!(
            r#"<label for="{id}">{label}</label><input id="{id}" name="{id}" type="text" value="{value}"{disabled}>
<p class="muted">Between {lo} and {hi} seconds. Currently {human}.</p>"#,
            id = e(id),
            label = e(label),
            human = e(&humanise(value)),
        )
    };
    let body = format!(
        r#"<h1>Settings</h1><p class="sub">How long what this tenant issues lasts, who must use MFA, and the tenant itself.</p>{error}
<h2>Lifetimes</h2>
<form method="post" action="{url}">{csrf}
{access}{session}{refresh}
<h2>Passwords</h2>
<label for="{PASSWORD_HISTORY}">Remembered passwords</label><input id="{PASSWORD_HISTORY}" name="{PASSWORD_HISTORY}" type="text" value="{history}"{disabled}>
<p class="muted">A new password may not be one of the account's last this many. Between 0 (off) and {max_history}.
A temporary password set by an administrator is exempt; the one the user then chooses is not.</p>
<h2>Multi-factor authentication</h2>
<label><input type="checkbox" name="{REQUIRE_MFA}"{mfa}{disabled}> Require MFA of everyone signing in to this tenant's applications</label>
<p class="muted">A user's own setting, on their page, can make an exception either way. Whoever has not set
up an authenticator does so at their next sign-in, and then signs in again with it.</p>
<label><input type="checkbox" name="{REQUIRE_CONSOLE_MFA}"{console_mfa}{disabled}> Require MFA of this tenant's administrators signing in to the console</label>
<p class="muted">Applies whatever their own setting says.{root_note}</p>
{save}</form>
<p class="muted">A change applies to tokens and sessions issued from now on. Those already
issued are self-contained and cannot be shortened after the fact.</p>{manage}"#,
        error = view::error_block(error),
        manage = manage,
        url = e(&settings_url(st.public_url.base(), tenant)),
        csrf = view::csrf_input(&ctx.csrf),
        mfa = if settings.require_mfa { " checked" } else { "" },
        history = settings.password_history,
        max_history = TenantSettings::MAX_PASSWORD_HISTORY,
        console_mfa = if settings.require_console_mfa { " checked" } else { "" },
        root_note = if tenant.is_root {
            " This is the root tenant, so it covers the Global Administrators."
        } else {
            ""
        },
        access = row(
            ACCESS_TOKEN,
            "Access token lifetime (seconds)",
            settings.access_token_lifetime_secs,
            TenantSettings::MIN_ACCESS_TOKEN_SECS,
            TenantSettings::MAX_ACCESS_TOKEN_SECS,
        ),
        session = row(
            SESSION,
            "Browser session lifetime (seconds)",
            settings.session_lifetime_secs,
            TenantSettings::MIN_SESSION_SECS,
            TenantSettings::MAX_SESSION_SECS,
        ),
        refresh = row(
            REFRESH,
            "Refresh token lifetime (seconds)",
            settings.refresh_token_lifetime_secs,
            TenantSettings::MIN_REFRESH_SECS,
            TenantSettings::MAX_REFRESH_SECS,
        ),
        save = if may_write {
            r#"<div class="actions"><button type="submit">Save settings</button></div>"#
        } else {
            r#"<p class="muted">Your roles allow reading these settings but not changing them.</p>"#
        },
    );
    view::page(
        &chrome(st, ctx, At::Tenant(tenant, TenantTab::Settings)),
        status,
        "Tenant settings",
        &body,
    )
}

/// A number of seconds in words, so a text box full of digits is readable.
fn humanise(secs: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;
    let (n, unit) = match secs {
        s if s >= DAY => (s / DAY, "day"),
        s if s >= HOUR => (s / HOUR, "hour"),
        s if s >= MINUTE => (s / MINUTE, "minute"),
        s => (s, "second"),
    };
    format!("about {n} {unit}{}", if n == 1 { "" } else { "s" })
}

pub async fn post(ctx: AdminContext, State(st): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    if let Err(resp) = ctx.require(TENANT_WRITE, On::Tenant(&key)) {
        return resp;
    }
    let form = parse_form(&body);
    if let Err(resp) = ctx.check_csrf(&form) {
        return resp;
    }
    let Some(tenant) = ctx.tenant(&key) else {
        return view::not_found();
    };

    // Each field is parsed on its own so a typo in one does not silently reset
    // the other two to a default.
    let seconds = |name: &str, label: &str| -> Result<i64, String> {
        field(&form, name)
            .parse::<i64>()
            .map_err(|_| format!("the {label} must be a whole number of seconds"))
    };
    let proposed = match (
        seconds(ACCESS_TOKEN, "access token lifetime"),
        seconds(SESSION, "session lifetime"),
        seconds(REFRESH, "refresh token lifetime"),
    ) {
        (Ok(access), Ok(session), Ok(refresh)) => TenantSettings {
            access_token_lifetime_secs: access,
            session_lifetime_secs: session,
            refresh_token_lifetime_secs: refresh,
            // Left out of the form, it keeps what the tenant has.
            password_history: match field(&form, PASSWORD_HISTORY).trim() {
                "" => tenant.settings.password_history,
                raw => match raw.parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => {
                        return render(
                            &st,
                            &ctx,
                            tenant,
                            &tenant.settings,
                            Some("the number of remembered passwords must be a whole number"),
                            StatusCode::BAD_REQUEST,
                        )
                        .await;
                    }
                },
            },
            require_mfa: checked(&form, REQUIRE_MFA),
            require_console_mfa: checked(&form, REQUIRE_CONSOLE_MFA),
        },
        (access, session, refresh) => {
            let message = [access.err(), session.err(), refresh.err()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("; ");
            // The tenant's stored settings are shown again, not the rejected
            // numbers: the form must not look as though the change took.
            return render(
                &st,
                &ctx,
                tenant,
                &tenant.settings,
                Some(&message),
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
    };

    // `save_settings` validates before it stores, so the bounds are enforced in
    // one place whatever calls it.
    if let Err(err) = tenant::save_settings(&st.pool, &tenant.id, &proposed).await {
        return render(
            &st,
            &ctx,
            tenant,
            &tenant.settings,
            Some(&err.to_string()),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    // Lifetimes are configuration, not anyone's personal data, so the values
    // themselves are safe to record and are what makes the row useful.
    audited(
        &st,
        &ctx,
        &tenant.id,
        Event::AdminTenantSettings,
        Some(&tenant.id),
        json!({
            "accessTokenLifetimeSecs": proposed.access_token_lifetime_secs,
            "sessionLifetimeSecs": proposed.session_lifetime_secs,
            "refreshTokenLifetimeSecs": proposed.refresh_token_lifetime_secs,
        }),
    )
    .await;
    view::see_other(&settings_url(st.public_url.base(), tenant))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_are_described_in_the_largest_whole_unit() {
        assert_eq!(humanise(3_599), "about 59 minutes");
        assert_eq!(humanise(3_600), "about 1 hour");
        assert_eq!(humanise(86_400), "about 1 day");
        assert_eq!(humanise(90 * 86_400), "about 90 days");
        assert_eq!(humanise(45), "about 45 seconds");
    }
}
