//! Whether a user may sign in to an application, and why not.
//!
//! An account belongs to one tenant. It signs in to that tenant's applications
//! as always; it may sign in to an application of **another** tenant only when
//! all three hold (the user's design, 2026-10-03):
//!
//! 1. the application accepts accounts of other tenants;
//! 2. the account is assigned to it, directly or through an assigned group of
//!    its own tenant;
//! 3. its own tenant lets it: the user's own setting (Allow / Disallow), or the
//!    tenant's default when theirs is Default. Off by default.
//!
//! [`decide`] is the one place that is answered. Every sign-in (browser, device
//! code, password grant) and every token issued for a user goes through it, and
//! so does the console's Check sign-in tool, so the tool cannot say something
//! the sign-in would not do.

use crate::apps::{self, ServicePrincipal};
use crate::db::DbPool;
use crate::directory::PrincipalType;
use crate::error::{AadError, Aadsts};
use crate::tenant::{self, Tenant};
use crate::users::{self, AuthResult, AuthTrace, User};
use crate::util::now;

/// A user's own say over signing in to other tenants' applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossTenantPolicy {
    /// Follow the tenant's default.
    Default,
    Allow,
    Disallow,
}

impl CrossTenantPolicy {
    pub const ALL: &'static [CrossTenantPolicy] = &[Self::Default, Self::Allow, Self::Disallow];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Allow => "Allow",
            Self::Disallow => "Disallow",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Default (as the tenant)",
            Self::Allow => "Allowed",
            Self::Disallow => "Not allowed",
        }
    }
}

pub async fn policy(pool: &DbPool, user_id: &str) -> anyhow::Result<CrossTenantPolicy> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as(crate::db::q(pool, "SELECT cross_tenant_policy FROM users WHERE id = ?"))
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .and_then(|(p,)| p)
        .and_then(|p| CrossTenantPolicy::parse(&p))
        .unwrap_or(CrossTenantPolicy::Default))
}

pub async fn set_policy(
    pool: &DbPool,
    tenant_id: &str,
    user_id: &str,
    policy: CrossTenantPolicy,
) -> anyhow::Result<bool> {
    let stored = (policy != CrossTenantPolicy::Default).then_some(policy.as_str());
    let done = sqlx::query(crate::db::q(
        pool,
        "UPDATE users SET cross_tenant_policy = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(stored)
    .bind(now())
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Whether the account's own tenant lets it sign in to other tenants'
/// applications, and what decided it.
pub async fn home_allows(pool: &DbPool, home: &Tenant, user_id: &str) -> anyhow::Result<(bool, CrossTenantPolicy)> {
    let own = policy(pool, user_id).await?;
    let allowed = match own {
        CrossTenantPolicy::Allow => true,
        CrossTenantPolicy::Disallow => false,
        CrossTenantPolicy::Default => home.settings.allow_cross_tenant_sign_in,
    };
    Ok((allowed, own))
}

/// The account's own tenant, if it is live: a disabled tenant's accounts sign in
/// nowhere.
pub async fn home_of(pool: &DbPool, user: &User) -> anyhow::Result<Option<Tenant>> {
    tenant::resolve(pool, &user.tenant_id).await
}

/// Why a user may not sign in to an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The account's own tenant is disabled.
    HomeTenantUnavailable,
    /// The account is of another tenant, and the application accepts only its own.
    OtherTenantsNotAccepted,
    /// Not assigned, where assignment is needed: always for an account of another
    /// tenant, and when the application requires it.
    NotAssigned,
    /// The account's own tenant (or their own setting) does not let it sign in
    /// to other tenants' applications.
    HomeDisallows,
}

impl Refusal {
    /// The AADSTS number. 50020 is Entra's "user account from identity provider
    /// does not exist in tenant"; 500213 is its "outbound cross-tenant access
    /// policy" block, **our guess** at the closest pairing.
    pub fn aadsts(self) -> Aadsts {
        match self {
            Self::HomeTenantUnavailable => Aadsts::AccountDisabled,
            Self::OtherTenantsNotAccepted => Aadsts::ExternalUserNotInTenant,
            Self::NotAssigned => Aadsts::NotAssigned,
            Self::HomeDisallows => Aadsts::OutboundAccessBlocked,
        }
    }

    pub fn message(self, app_name: &str, app_tenant: &str, home_tenant: &str) -> String {
        match self {
            Self::HomeTenantUnavailable => format!("The organization {home_tenant} is disabled."),
            Self::OtherTenantsNotAccepted => format!(
                "{app_name} accepts only accounts of {app_tenant}. Sign in with one of its accounts, or ask its \
                 administrator to accept accounts of other organizations."
            ),
            Self::NotAssigned => format!(
                "Your administrator has configured the application {app_name} to block users unless they are \
                 specifically granted ('assigned') access to the application."
            ),
            Self::HomeDisallows => format!(
                "{home_tenant} does not allow its accounts to sign in to applications of other organizations, \
                 such as {app_name} of {app_tenant}. Ask an administrator of {home_tenant}."
            ),
        }
    }
}

/// What [`decide`] found.
pub struct Decision {
    /// The account's own tenant: whose MFA and password rules apply.
    pub home: Tenant,
    /// The account is of another tenant than the application.
    pub outsider: bool,
    pub refusal: Option<Refusal>,
}

impl Decision {
    /// The refusal as an OAuth error for the token endpoint.
    pub fn grant_error(&self, app_name: &str, app_tenant: &Tenant) -> Option<AadError> {
        self.refusal
            .map(|r| AadError::invalid_grant(r.aadsts(), r.message(app_name, &app_tenant.name, &self.home.name)))
    }
}

/// Whether `user` may sign in to the application `sp` of `app_tenant`. The user
/// is already known to be live and enabled; this is about the application.
pub async fn decide(
    pool: &DbPool,
    app_tenant: &Tenant,
    sp: &ServicePrincipal,
    user: &User,
) -> anyhow::Result<Decision> {
    let outsider = user.tenant_id != app_tenant.id;
    let Some(home) = home_of(pool, user).await? else {
        // Their tenant is disabled: refuse, naming it as best we can.
        let named = tenant::find_for_admin(pool, &user.tenant_id).await?;
        return Ok(Decision {
            home: named,
            outsider,
            refusal: Some(Refusal::HomeTenantUnavailable),
        });
    };
    let refusal = if outsider {
        if !sp.accept_other_tenants {
            Some(Refusal::OtherTenantsNotAccepted)
        } else if !apps::user_is_assigned(pool, &sp.id, &user.id).await? {
            Some(Refusal::NotAssigned)
        } else if !home_allows(pool, &home, &user.id).await?.0 {
            Some(Refusal::HomeDisallows)
        } else {
            None
        }
    } else if sp.app_role_assignment_required && !apps::user_is_assigned(pool, &sp.id, &user.id).await? {
        Some(Refusal::NotAssigned)
    } else {
        None
    };
    Ok(Decision {
        home,
        outsider,
        refusal,
    })
}

/// What a sign-in form's name and password come to, at an application of
/// `app_tenant`: checked in the account's own tenant when the name is of
/// another tenant and the application accepts other tenants, and in
/// `app_tenant` otherwise (where a name of another tenant is simply unknown).
pub async fn authenticate(
    pool: &DbPool,
    app_tenant: &Tenant,
    sp: Option<&ServicePrincipal>,
    upn: &str,
    password: &str,
) -> anyhow::Result<(AuthResult, AuthTrace)> {
    let home = match upn.trim().rsplit_once('@') {
        Some((_, domain)) if sp.is_some_and(|sp| sp.accept_other_tenants) => {
            tenant::resolve(pool, domain).await?.filter(|t| t.id != app_tenant.id)
        }
        _ => None,
    };
    users::authenticate_traced(pool, home.as_ref().unwrap_or(app_tenant), upn, password).await
}

/// For an assignment's principal: its tenant's name if it is not `tenant_id`'s,
/// and for a user whether their tenant lets them sign in elsewhere now.
pub async fn outside_principal(
    pool: &DbPool,
    tenant_id: &str,
    kind: PrincipalType,
    principal_id: &str,
) -> anyhow::Result<Option<apps::Outside>> {
    let sql = match kind {
        PrincipalType::User => "SELECT tenant_id FROM users WHERE id = ?",
        PrincipalType::Group => "SELECT tenant_id FROM user_groups WHERE id = ?",
        PrincipalType::ServicePrincipal => return Ok(None),
    };
    let row: Option<(String,)> = sqlx::query_as(crate::db::q(pool, sql))
        .bind(principal_id)
        .fetch_optional(pool)
        .await?;
    let Some((home_id,)) = row.filter(|(t,)| t != tenant_id) else {
        return Ok(None);
    };
    let home = tenant::find_for_admin(pool, &home_id).await?;
    let may_sign_in = match kind {
        PrincipalType::User => home.enabled && home_allows(pool, &home, principal_id).await?.0,
        _ => home.enabled,
    };
    let domain = tenant::domains(pool, &home.id)
        .await?
        .into_iter()
        .next()
        .unwrap_or_default();
    Ok(Some(apps::Outside {
        tenant_name: home.name,
        domain,
        may_sign_in,
    }))
}

// ---- the console's Check sign-in ----

/// How a line of the report reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Pass,
    Fail,
    Note,
}

pub struct Line {
    pub mark: Mark,
    pub text: String,
}

pub struct Section {
    pub title: &'static str,
    pub lines: Vec<Line>,
}

/// A way of signing in, and whether it would work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Browser,
    PasswordGrant,
    Refresh,
}

impl Flow {
    pub fn label(self) -> &'static str {
        match self {
            Self::Browser => "Browser sign-in (and device code)",
            Self::PasswordGrant => "Password grant",
            Self::Refresh => "Refreshing a token",
        }
    }
}

pub struct FlowVerdict {
    pub flow: Flow,
    pub works: bool,
    pub detail: String,
}

pub struct Report {
    pub works: bool,
    pub headline: String,
    pub sections: Vec<Section>,
    pub flows: Vec<FlowVerdict>,
}

fn line(mark: Mark, text: impl Into<String>) -> Line {
    Line {
        mark,
        text: text.into(),
    }
}

fn pass_or_fail(ok: bool, yes: impl Into<String>, no: impl Into<String>) -> Line {
    if ok {
        line(Mark::Pass, yes)
    } else {
        line(Mark::Fail, no)
    }
}

fn only(headline: String) -> Report {
    Report {
        works: false,
        headline,
        sections: Vec::new(),
        flows: Vec::new(),
    }
}

/// Everything that decides whether `upn` can sign in to `app` of `app_tenant`,
/// with the real group memberships and every setting involved, for the console.
/// Nothing is changed and no password is asked for.
///
/// About an account of another tenant that this application has not assigned,
/// it says only that: whether such an account exists is not this tenant's to
/// learn.
pub async fn explain(
    pool: &DbPool,
    app_tenant: &Tenant,
    sp: &ServicePrincipal,
    app: &apps::Application,
    upn: &str,
) -> anyhow::Result<Report> {
    let upn = upn.trim();
    let Some((_, domain)) = upn.rsplit_once('@') else {
        return Ok(only("Enter a full user name, with the @ part.".into()));
    };
    let ours = tenant::domains(pool, &app_tenant.id).await?;
    let local = ours.iter().any(|d| crate::util::fold(d) == crate::util::fold(domain));
    // The account's tenant, disabled ones included: its state is reported.
    let home = if local {
        Some(app_tenant.clone())
    } else {
        tenant::find_for_admin(pool, domain).await.ok()
    };
    let user = match &home {
        Some(t) => users::find_by_upn(pool, &t.id, upn).await?,
        None => None,
    };
    let assigned = match &user {
        Some(u) => apps::user_is_assigned(pool, &sp.id, &u.id).await?,
        None => false,
    };
    if !local && !assigned {
        return Ok(only(format!(
            "{upn} is not assigned to {}. An account of another tenant can sign in only once it is \
             assigned, directly or through an assigned group of its tenant.",
            app.display_name
        )));
    }
    let (Some(user), Some(home)) = (user, home) else {
        return Ok(only(format!("{} has no account named {upn}.", app_tenant.name)));
    };
    let outsider = !local;

    // ---- the account ----
    let (locked_until,): (Option<i64>,) =
        sqlx::query_as(crate::db::q(pool, "SELECT locked_until FROM users WHERE id = ?"))
            .bind(&user.id)
            .fetch_one(pool)
            .await?;
    let locked = locked_until.is_some_and(|t| t > now());
    let account = vec![
        line(Mark::Pass, format!("{} is an account of {}", user.upn, home.name)),
        pass_or_fail(user.enabled, "Enabled", "Disabled: it cannot sign in anywhere"),
        pass_or_fail(!locked, "Not locked out", "Locked out after wrong passwords, for now"),
        pass_or_fail(
            home.enabled,
            format!("{} is enabled", home.name),
            format!("{} is disabled", home.name),
        ),
    ];

    // ---- the application, and assignment ----
    let mut application = vec![pass_or_fail(
        sp.enabled,
        format!("{} is enabled in {}", app.display_name, app_tenant.name),
        format!("{} is disabled in {}", app.display_name, app_tenant.name),
    )];
    if outsider {
        application.push(pass_or_fail(
            sp.accept_other_tenants,
            format!("{} accepts accounts of other tenants", app.display_name),
            format!("{} accepts only accounts of {}", app.display_name, app_tenant.name),
        ));
    }
    let via = assignment_paths(pool, sp, &user.id).await?;
    let mut assignment = Vec::new();
    if outsider {
        assignment.push(line(Mark::Note, "An account of another tenant must be assigned"));
    } else if sp.app_role_assignment_required {
        assignment.push(line(Mark::Note, format!("{} requires assignment", app.display_name)));
    } else {
        assignment.push(line(
            Mark::Note,
            format!("{} does not require assignment", app.display_name),
        ));
    }
    if via.is_empty() {
        let needed = outsider || sp.app_role_assignment_required;
        assignment.push(line(
            if needed { Mark::Fail } else { Mark::Note },
            "Not assigned, directly or through any group",
        ));
    }
    for (how, roles) in &via {
        let roles = if roles.is_empty() {
            "no role".to_string()
        } else {
            roles.join(", ")
        };
        assignment.push(line(Mark::Pass, format!("Assigned {how} ({roles})")));
    }

    let mut sections = vec![
        Section {
            title: "Account",
            lines: account,
        },
        Section {
            title: "Application",
            lines: application,
        },
        Section {
            title: "Assignment",
            lines: assignment,
        },
    ];

    // ---- other tenants ----
    if outsider {
        let (allowed, own) = home_allows(pool, &home, &user.id).await?;
        sections.push(Section {
            title: "Signing in from another tenant",
            lines: vec![
                line(
                    Mark::Note,
                    format!(
                        "{}'s default: {}",
                        home.name,
                        if home.settings.allow_cross_tenant_sign_in {
                            "allowed"
                        } else {
                            "not allowed"
                        }
                    ),
                ),
                line(Mark::Note, format!("{}'s own setting: {}", user.upn, own.label())),
                pass_or_fail(
                    allowed,
                    format!("{} lets it sign in here", home.name),
                    format!("{} does not let it sign in to other tenants' applications", home.name),
                ),
            ],
        });
    }

    // ---- what sign-in will ask for ----
    let mfa_policy = crate::mfa::policy(pool, &user.id).await?;
    let enrolled = crate::mfa::enrolled_at(pool, &user.id).await?.is_some();
    let step = crate::mfa::step(pool, &home, &user.id, crate::mfa::At::App(sp)).await?;
    let must_change = users::must_change_password(pool, &user.id).await?;
    let mfa_outcome = match step {
        crate::mfa::Step::Done => line(Mark::Pass, "No second step is asked for"),
        crate::mfa::Step::Verify => line(Mark::Note, "A code from their authenticator is asked for"),
        crate::mfa::Step::Enroll => line(
            Mark::Note,
            "They set up an authenticator at sign-in, are signed out, and sign in again",
        ),
    };
    sections.push(Section {
        title: "Multi-factor authentication",
        lines: vec![
            line(Mark::Note, format!("Their own setting: {}", mfa_policy.label())),
            line(
                Mark::Note,
                format!(
                    "{} requires it of everyone: {}",
                    home.name,
                    if home.settings.require_mfa { "yes" } else { "no" }
                ),
            ),
            line(
                Mark::Note,
                format!(
                    "{} requires it: {}",
                    app.display_name,
                    if sp.mfa_required { "yes" } else { "no" }
                ),
            ),
            line(
                Mark::Note,
                if enrolled {
                    "Authenticator set up"
                } else {
                    "No authenticator set up"
                },
            ),
            mfa_outcome,
        ],
    });
    sections.push(Section {
        title: "Password",
        lines: vec![if must_change {
            line(Mark::Note, "They must choose a new password at their next sign-in")
        } else {
            line(Mark::Pass, "No password change pending")
        }],
    });

    // ---- the token ----
    let roles: Vec<String> = apps::app_roles_for_user(pool, &sp.id, &user.id)
        .await?
        .into_iter()
        .map(|r| r.value)
        .collect();
    let mut token = vec![line(
        Mark::Note,
        if roles.is_empty() {
            "roles: none".to_string()
        } else {
            format!("roles: {}", roles.join(", "))
        },
    )];
    if outsider {
        token.push(line(
            Mark::Note,
            format!(
                "Issued by {}; marked as an account of {} (idp, acct); no groups",
                app_tenant.name, home.name
            ),
        ));
    } else {
        let names = crate::groups::names_for_user(pool, &user.id).await?;
        token.push(line(
            Mark::Note,
            if names.is_empty() {
                "groups: none".to_string()
            } else {
                format!("groups: {}", names.join(", "))
            },
        ));
    }
    sections.push(Section {
        title: "In the token",
        lines: token,
    });

    // ---- the verdicts ----
    let decision = decide(pool, app_tenant, sp, &user).await?;
    let blocked: Option<String> = if !user.enabled {
        Some("the account is disabled".into())
    } else if locked {
        Some("the account is locked out for now".into())
    } else if !sp.enabled {
        Some(format!("{} is disabled", app.display_name))
    } else {
        decision
            .refusal
            .map(|r| r.message(&app.display_name, &app_tenant.name, &decision.home.name))
    };
    let mut steps = Vec::new();
    match step {
        crate::mfa::Step::Verify => steps.push("a code from their authenticator"),
        crate::mfa::Step::Enroll => steps.push("setting up an authenticator first"),
        crate::mfa::Step::Done => {}
    }
    if must_change {
        steps.push("choosing a new password");
    }
    let browser = FlowVerdict {
        flow: Flow::Browser,
        works: blocked.is_none(),
        detail: match &blocked {
            Some(why) => format!("Refused: {why}"),
            None if steps.is_empty() => "Works with their password".into(),
            None => format!("Works after their password and {}", steps.join(", then ")),
        },
    };
    let password_grant = {
        let why = if let Some(why) = &blocked {
            Some(why.clone())
        } else if !app.allow_password_grant {
            Some(format!("{} does not allow the password grant", app.display_name))
        } else if step != crate::mfa::Step::Done {
            Some("MFA is needed, and the password grant cannot ask for it".into())
        } else if must_change {
            Some("a new password must be chosen first, in a browser".into())
        } else {
            None
        };
        FlowVerdict {
            flow: Flow::PasswordGrant,
            works: why.is_none(),
            detail: why.map(|w| format!("Refused: {w}")).unwrap_or_else(|| "Works".into()),
        }
    };
    let refresh = FlowVerdict {
        flow: Flow::Refresh,
        works: blocked.is_none(),
        detail: match &blocked {
            Some(why) => format!("Refused: {why}"),
            None if step != crate::mfa::Step::Done => {
                "Works for a token from a sign-in that included MFA; refused for one that did not".into()
            }
            None => "Works".into(),
        },
    };
    let works = browser.works;
    Ok(Report {
        works,
        headline: if works {
            format!("{} can sign in to {}", user.upn, app.display_name)
        } else {
            format!("{} cannot sign in to {}", user.upn, app.display_name)
        },
        sections,
        flows: vec![browser, password_grant, refresh],
    })
}

/// How a user is assigned to `sp`: "directly", or "through group X", each with
/// the roles that assignment carries.
async fn assignment_paths(
    pool: &DbPool,
    sp: &ServicePrincipal,
    user_id: &str,
) -> anyhow::Result<Vec<(String, Vec<String>)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT principal_type, principal_id FROM app_assignments
         WHERE resource_id = ? AND ((principal_type = ? AND principal_id = ?)
            OR (principal_type = ? AND principal_id IN (SELECT group_id FROM group_members WHERE user_id = ?)))",
    ))
    .bind(&sp.id)
    .bind(PrincipalType::User.as_str())
    .bind(user_id)
    .bind(PrincipalType::Group.as_str())
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for (kind, principal_id) in rows {
        let how = if kind == PrincipalType::Group.as_str() {
            let name: Option<(String,)> =
                sqlx::query_as(crate::db::q(pool, "SELECT name FROM user_groups WHERE id = ?"))
                    .bind(&principal_id)
                    .fetch_optional(pool)
                    .await?;
            format!("through group {}", name.map(|(n,)| n).unwrap_or(principal_id.clone()))
        } else {
            "directly".to_string()
        };
        let roles: Vec<(String,)> = sqlx::query_as(crate::db::q(
            pool,
            "SELECT r.value FROM app_role_assignments a JOIN app_roles r ON r.id = a.app_role_id
             WHERE a.resource_id = ? AND a.principal_id = ? ORDER BY r.value",
        ))
        .bind(&sp.id)
        .bind(&principal_id)
        .fetch_all(pool)
        .await?;
        out.push((how, roles.into_iter().map(|(v,)| v).collect()));
    }
    Ok(out)
}
