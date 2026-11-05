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

use crate::AppState;
use crate::admin::context::{AdminContext, On};
use crate::admin::routes::{At, Settled, TenantTab, checked, chrome, field, parse_form, settle};
use crate::admin::view::{self, e};
use crate::admin::{TENANT_READ, TENANT_WRITE};
use crate::tenant::{MfaMode, Tenant, TenantSettings};
use crate::txn::{self, ops::tenants::SaveTenantSettings};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

/// Form field names, spelled once. They match the struct's field names, which is
/// what makes the form and the type obviously the same three values.
const REQUIRE_MFA: &str = "require_mfa";
const MFA_MODE: &str = "mfa_mode";
const SUGGEST_MFA_SETUP: &str = "suggest_mfa_setup";
const PASSWORD_HISTORY: &str = "password_history";
const ALLOW_CROSS_TENANT: &str = "allow_cross_tenant_sign_in";
const REQUIRE_CONSOLE_MFA: &str = "require_console_mfa";
const ALLOW_KEEP_SIGNED_IN: &str = "allow_keep_signed_in";
const ALLOW_REMEMBER_MFA: &str = "allow_remember_mfa";
const AUDIT_RETENTION: &str = "audit_retention_days";
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
A password an administrator sets is exempt (refusing it would tell them one the account recently had), but it is
remembered, so the user cannot choose it again.</p>
<h2>Other organizations</h2>
<label><input type="checkbox" name="{ALLOW_CROSS_TENANT}"{cross}{disabled}> Allow this tenant's accounts to sign in to applications of other tenants</label>
<p class="muted">Only to applications that accept other tenants and have assigned the account, directly or
through one of this tenant's groups. A user's own setting, on their page, can make an exception either way.</p>
<h2>Multi-factor authentication</h2>
<fieldset class="ticks mfa-mode"><legend>Mode</legend>
<label><input type="radio" name="{MFA_MODE}" value="{permissive}"{is_permissive}{disabled}> <strong>Permissive</strong>: the user's own setting and each application's switch decide</label>
<label><input type="radio" name="{MFA_MODE}" value="{enforced}"{is_enforced}{disabled}> <strong>Enforced</strong>: every sign-in needs MFA, for everyone</label>
</fieldset>
<p class="muted">Enforced covers sign-in to this tenant's applications (by its own accounts and by other tenants'),
this tenant's accounts signing in anywhere, My Account, the console and the Auth API. Nobody is exempt, each
user's and application's own MFA setting no longer matters, and a code is asked at every new sign-in:
"Don't ask again on this device" is not offered, and browsers already remembered are forgotten. Whoever has not
set up an authenticator does so at their next sign-in. Either way, an account with an authenticator is always
asked for a code.</p>
<div class="when-permissive">
<label><input type="checkbox" name="{REQUIRE_MFA}"{mfa}{disabled}> Permissive: require MFA of everyone by default</label>
<p class="muted">A user's own setting, on their page, can make an exception either way. Whoever has not set
up an authenticator does so at their next sign-in, and then signs in again with it.</p>
<label><input type="checkbox" name="{SUGGEST_MFA_SETUP}"{suggest}{disabled}> Permissive: offer to set up an authenticator at sign-in</label>
<p class="muted">Someone without an authenticator signing in to an application is asked, after their password,
whether to set one up now. "Not now" carries on with the sign-in and asks again after {snooze_days} days. They
can also set one up on their My Account page at any time.</p>
</div>
<label><input type="checkbox" name="{REQUIRE_CONSOLE_MFA}"{console_mfa}{disabled}> Require MFA of this tenant's administrators signing in to the console</label>
<p class="muted">Applies whatever their own setting says, and in either mode.{root_note}</p>
<h2>Staying signed in</h2>
<label><input type="checkbox" name="{ALLOW_KEEP_SIGNED_IN}"{keep}{disabled}> Offer "Keep me signed in" on the sign-in page</label>
<p class="muted">A session the user keeps lasts {keep_days} days on that browser instead of the session lifetime above.
Applications that need a fresh sign-in can still ask for one (<code>prompt=login</code>, <code>max_age</code>).</p>
<div class="when-permissive">
<label><input type="checkbox" name="{ALLOW_REMEMBER_MFA}"{remember}{disabled}> Offer "Don't ask again on this device" when a code is entered</label>
<p class="muted">For this tenant's accounts: a browser they remember skips the code for {remember_days} days, but
never the password. A fresh sign-in an application asks for always asks for the code too. Signing out
everywhere, a new password or a new authenticator forgets every remembered browser. Not in the console,
which always asks administrators for their code. Not offered or trusted while MFA is enforced.</p>
</div>
<h2>Audit log</h2>
<label for="{AUDIT_RETENTION}">Keep audit entries for (days)</label><input id="{AUDIT_RETENTION}" name="{AUDIT_RETENTION}" type="text" value="{retention}"{disabled}>
<p class="muted">Between {min_retention} and {max_retention} days. Older entries for this tenant are deleted every hour.</p>
{save}</form>
<p class="muted">A change applies to tokens and sessions issued from now on. Those already
issued are self-contained and cannot be shortened after the fact, with one exception: turning
either "Staying signed in" option off takes effect at once, for what was already remembered too.</p>{manage}"#,
        error = view::error_block(error),
        manage = manage,
        url = e(&settings_url(st.public_url.base(), tenant)),
        csrf = view::csrf_input(&ctx.csrf),
        mfa = if settings.require_mfa { " checked" } else { "" },
        suggest = if settings.suggest_mfa_setup { " checked" } else { "" },
        snooze_days = TenantSettings::MFA_SETUP_SNOOZE_SECS / SECS_PER_DAY,
        permissive = MfaMode::Permissive.as_str(),
        enforced = MfaMode::Enforced.as_str(),
        is_permissive = if settings.mfa_mode == MfaMode::Permissive {
            " checked"
        } else {
            ""
        },
        is_enforced = if settings.mfa_mode == MfaMode::Enforced {
            " checked"
        } else {
            ""
        },
        history = settings.password_history,
        retention = settings.audit_retention_days,
        min_retention = TenantSettings::MIN_AUDIT_RETENTION_DAYS,
        max_retention = TenantSettings::MAX_AUDIT_RETENTION_DAYS,
        cross = if settings.allow_cross_tenant_sign_in {
            " checked"
        } else {
            ""
        },
        max_history = TenantSettings::MAX_PASSWORD_HISTORY,
        console_mfa = if settings.require_console_mfa { " checked" } else { "" },
        keep = if settings.allow_keep_signed_in { " checked" } else { "" },
        remember = if settings.allow_remember_mfa { " checked" } else { "" },
        keep_days = TenantSettings::KEEP_SIGNED_IN_SECS / SECS_PER_DAY,
        remember_days = TenantSettings::REMEMBER_MFA_SECS / SECS_PER_DAY,
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

const SECS_PER_DAY: i64 = 86_400;

/// A number of seconds in words, so a text box full of digits is readable.
fn humanise(secs: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 3_600;
    const DAY: i64 = SECS_PER_DAY;
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
            allow_cross_tenant_sign_in: checked(&form, ALLOW_CROSS_TENANT),
            require_mfa: checked(&form, REQUIRE_MFA),
            require_console_mfa: checked(&form, REQUIRE_CONSOLE_MFA),
            // Left out of the form, or not one of the modes, it keeps what the tenant has.
            mfa_mode: MfaMode::parse(field(&form, MFA_MODE)).unwrap_or(tenant.settings.mfa_mode),
            suggest_mfa_setup: checked(&form, SUGGEST_MFA_SETUP),
            allow_keep_signed_in: checked(&form, ALLOW_KEEP_SIGNED_IN),
            allow_remember_mfa: checked(&form, ALLOW_REMEMBER_MFA),
            // Left out of the form, it keeps what the tenant has.
            audit_retention_days: match field(&form, AUDIT_RETENTION).trim() {
                "" => tenant.settings.audit_retention_days,
                raw => match raw.parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => {
                        return render(
                            &st,
                            &ctx,
                            tenant,
                            &tenant.settings,
                            Some("the audit retention must be a whole number of days"),
                            StatusCode::BAD_REQUEST,
                        )
                        .await;
                    }
                },
            },
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

    // The storage layer validates before it stores, so the bounds are enforced
    // in one place whatever calls it.
    let save = SaveTenantSettings {
        tenant_id: tenant.id.clone(),
        settings: proposed,
    };
    match settle(txn::run(&st.pool, &ctx.actor(), &save).await) {
        Settled::Done(()) => view::see_other(&settings_url(st.public_url.base(), tenant)),
        Settled::Refused(message) => {
            render(
                &st,
                &ctx,
                tenant,
                &tenant.settings,
                Some(&message),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Settled::Respond(resp) => resp,
    }
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
