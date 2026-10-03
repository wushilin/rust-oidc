//! Multi-factor authentication with an authenticator app (TOTP, RFC 6238), and
//! one-time recovery codes. Also the pending-step tickets every sign-in step
//! after the password uses, a forced password change included.
//!
//! **Who needs it.** A user's own setting decides when it says Required or Not
//! required; set to Default it follows the tenant's "everyone" switch. On top of
//! that an application can require it of everyone signing in to it, and a tenant
//! can require it of its administrators signing in to the console. Whoever has an
//! authenticator is asked for a code at every sign-in, required or not.
//!
//! **Not enrolled but required.** They set an authenticator up at that sign-in,
//! and are then signed out and sign in again with it -- the user's rule.
//!
//! **Storage.** The TOTP secret is stored as is: it has to be read to check a
//! code, and the decision (2026-10-03) is that the database is the thing to
//! protect. Recovery codes are hashed, since they are only ever compared.

use anyhow::bail;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::apps::ServicePrincipal;
use crate::db::DbPool;
use crate::tenant::Tenant;
use crate::util::{new_guid, now, random_bytes, random_string, sha256_hex};

/// RFC 6238's defaults, which every authenticator app uses.
pub const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
/// Codes one step either side of now are accepted, for clocks that drift.
const WINDOW: i64 = 1;
/// 160 bits, RFC 4226's recommendation for HMAC-SHA1.
const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Without the ambiguous characters, in two groups of five.
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const RECOVERY_GROUP: usize = 5;
/// How long a sign-in may wait at its second step. Ten minutes, as the other
/// sign-in pages.
pub const TICKET_LIFETIME_SECS: i64 = 600;
/// Wrong codes allowed at one second step before the sign-in starts again.
pub const MAX_ATTEMPTS: i64 = 5;

/// A user's own MFA setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaPolicy {
    /// Follow the tenant.
    Default,
    Required,
    NotRequired,
}

impl MfaPolicy {
    pub const ALL: &'static [MfaPolicy] = &[Self::Default, Self::Required, Self::NotRequired];

    /// As stored; `Default` is stored as NULL.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Required => "Required",
            Self::NotRequired => "NotRequired",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == raw)
    }

    fn stored(self) -> Option<&'static str> {
        (self != Self::Default).then_some(self.as_str())
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Default (as the tenant)",
            Self::Required => "Required",
            Self::NotRequired => "Not required",
        }
    }
}

/// Where a sign-in is happening, which decides what else may require MFA.
pub enum At<'a> {
    /// Signing in to an application: its own "require MFA" switch applies.
    App(&'a ServicePrincipal),
    /// Signing in to the admin console: the tenant's console switch applies.
    Console,
    /// Signing in to My Account: only the user's and the tenant's own setting.
    MyAccount,
}

/// What a sign-in needs after the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing more.
    Done,
    /// A code from the authenticator, or a recovery code.
    Verify,
    /// Set an authenticator up first.
    Enroll,
}

/// What a pending second step is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Verify,
    Enroll,
    /// Choosing a new password, after a password alone.
    ChangePassword,
    /// Choosing a new password, after a password and a second factor: the
    /// session that follows carries both.
    ChangePasswordAfterMfa,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Enroll => "enroll",
            Self::ChangePassword => "change_password",
            Self::ChangePasswordAfterMfa => "change_password_mfa",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        [
            Self::Verify,
            Self::Enroll,
            Self::ChangePassword,
            Self::ChangePasswordAfterMfa,
        ]
        .into_iter()
        .find(|p| p.as_str() == raw)
    }

    /// The pending step that changes the password, given what was done so far.
    pub fn change_password(after_mfa: bool) -> Self {
        if after_mfa {
            Self::ChangePasswordAfterMfa
        } else {
            Self::ChangePassword
        }
    }
}

pub async fn policy(pool: &DbPool, user_id: &str) -> anyhow::Result<MfaPolicy> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as(crate::db::q(pool, "SELECT mfa_policy FROM users WHERE id = ?"))
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .and_then(|(p,)| p)
        .and_then(|p| MfaPolicy::parse(&p))
        .unwrap_or(MfaPolicy::Default))
}

pub async fn set_policy(pool: &DbPool, tenant_id: &str, user_id: &str, policy: MfaPolicy) -> anyhow::Result<bool> {
    let done = sqlx::query(crate::db::q(
        pool,
        "UPDATE users SET mfa_policy = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL",
    ))
    .bind(policy.stored())
    .bind(now())
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// When the user set their authenticator up, if they have.
pub async fn enrolled_at(pool: &DbPool, user_id: &str) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT enrolled_at FROM user_totp WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(at,)| at))
}

/// Whether MFA is required of this user here. `tenant` is the user's own.
pub async fn required(pool: &DbPool, tenant: &Tenant, user_id: &str, at: At<'_>) -> anyhow::Result<bool> {
    let base = match policy(pool, user_id).await? {
        MfaPolicy::Required => true,
        MfaPolicy::NotRequired => false,
        MfaPolicy::Default => tenant.settings.require_mfa,
    };
    let here = match at {
        At::App(sp) => sp.mfa_required,
        At::Console => tenant.settings.require_console_mfa,
        At::MyAccount => false,
    };
    Ok(base || here)
}

/// What this user's sign-in needs after the password, here.
pub async fn step(pool: &DbPool, tenant: &Tenant, user_id: &str, at: At<'_>) -> anyhow::Result<Step> {
    if enrolled_at(pool, user_id).await?.is_some() {
        return Ok(Step::Verify);
    }
    Ok(if required(pool, tenant, user_id, at).await? {
        Step::Enroll
    } else {
        Step::Done
    })
}

// ---- TOTP ----

const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding: how authenticator apps take a secret.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = BASE32.iter().position(|&b| b as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// RFC 4226's HOTP value for one counter, as the six digits a person types.
fn code_at(secret: &[u8], counter: i64) -> u32 {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    value % 10u32.pow(DIGITS)
}

/// The code an authenticator shows for `secret` at `unix` time. For tests and
/// for nothing else.
pub fn code_for(secret: &str, unix: i64) -> String {
    let key = base32_decode(secret).unwrap_or_default();
    format!(
        "{:0width$}",
        code_at(&key, unix.div_euclid(STEP_SECS)),
        width = DIGITS as usize
    )
}

/// The step a code matches, within the window around now, if any.
fn matching_step(secret: &str, code: &str, unix: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let key = base32_decode(secret)?;
    let now_step = unix.div_euclid(STEP_SECS);
    (now_step - WINDOW..=now_step + WINDOW).find(|step| code_at(&key, *step) == wanted)
}

/// A new secret, as the base32 text an authenticator app is given.
pub fn new_secret() -> String {
    base32(&random_bytes(SECRET_BYTES))
}

/// The `otpauth://` address an authenticator app reads from the QR code.
pub fn otpauth_uri(secret: &str, issuer: &str, account: &str) -> String {
    let enc = |v: &str| {
        url::form_urlencoded::byte_serialize(v.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
    };
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        issuer = enc(issuer),
        account = enc(account),
    )
}

/// The QR code for an address, as inline SVG: no image file, no script.
pub fn qr_svg(uri: &str) -> String {
    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

/// Whether `code` is right for a secret being set up. Nothing is recorded: the
/// secret is not anyone's yet.
pub fn verify_new(secret: &str, code: &str) -> bool {
    matching_step(secret, code, now()).is_some()
}

/// Check an authenticator code for an enrolled user. A code is accepted once:
/// the step it matched is recorded, and a code for that step or an earlier one
/// is refused afterwards, so a code seen over someone's shoulder is spent.
async fn verify_totp(pool: &DbPool, user_id: &str, code: &str) -> anyhow::Result<bool> {
    let row: Option<(String, i64)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT secret, last_step FROM user_totp WHERE user_id = ?",
    ))
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    let Some((secret, last_step)) = row else {
        return Ok(false);
    };
    let Some(step) = matching_step(&secret, code, now()) else {
        return Ok(false);
    };
    if step <= last_step {
        return Ok(false);
    }
    // Conditional, so two posts of the same code race to one success.
    let done = sqlx::query(crate::db::q(
        pool,
        "UPDATE user_totp SET last_step = ? WHERE user_id = ? AND last_step < ?",
    ))
    .bind(step)
    .bind(user_id)
    .bind(step)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

// ---- recovery codes ----

fn normalise_recovery(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn recovery_hash(code: &str) -> String {
    sha256_hex(normalise_recovery(code).as_bytes())
}

fn new_recovery_code() -> String {
    let raw = random_string(RECOVERY_ALPHABET, RECOVERY_GROUP * 2);
    format!("{}-{}", &raw[..RECOVERY_GROUP], &raw[RECOVERY_GROUP..])
}

async fn insert_recovery_codes(
    conn: &mut sqlx::AnyConnection,
    engine: crate::db::Engine,
    user_id: &str,
) -> anyhow::Result<Vec<String>> {
    sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM user_recovery_codes WHERE user_id = ?",
    ))
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT).map(|_| new_recovery_code()).collect();
    for code in &codes {
        sqlx::query(crate::db::sql_stmt(
            engine,
            "INSERT INTO user_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
        ))
        .bind(new_guid())
        .bind(user_id)
        .bind(recovery_hash(code))
        .bind(now())
        .execute(&mut *conn)
        .await?;
    }
    Ok(codes)
}

/// Spend a recovery code. Each works once.
async fn use_recovery_code(pool: &DbPool, user_id: &str, code: &str) -> anyhow::Result<bool> {
    if normalise_recovery(code).len() != RECOVERY_GROUP * 2 {
        return Ok(false);
    }
    let done = sqlx::query(crate::db::q(
        pool,
        "UPDATE user_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
    ))
    .bind(now())
    .bind(user_id)
    .bind(recovery_hash(code))
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// How many unused recovery codes a user has left.
pub async fn recovery_codes_left(pool: &DbPool, user_id: &str) -> anyhow::Result<i64> {
    let (n,): (i64,) = sqlx::query_as(crate::db::q(
        pool,
        "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL",
    ))
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// A new set of recovery codes, replacing all the old ones. Shown once.
pub async fn replace_recovery_codes(pool: &DbPool, user_id: &str) -> anyhow::Result<Vec<String>> {
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let codes = insert_recovery_codes(&mut tx, engine, user_id).await?;
    tx.commit().await?;
    Ok(codes)
}

/// Which kind of second factor was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    Authenticator,
    RecoveryCode,
}

impl Factor {
    /// How it is named in the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticator => "authenticator",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

/// Check what someone typed at the second step: six digits are an authenticator
/// code, anything else is tried as a recovery code.
pub async fn check(pool: &DbPool, user_id: &str, typed: &str) -> anyhow::Result<Option<Factor>> {
    let digits = typed.trim().replace(' ', "");
    if digits.len() == DIGITS as usize && digits.chars().all(|c| c.is_ascii_digit()) {
        return Ok(verify_totp(pool, user_id, &digits)
            .await?
            .then_some(Factor::Authenticator));
    }
    Ok(use_recovery_code(pool, user_id, typed)
        .await?
        .then_some(Factor::RecoveryCode))
}

// ---- enrolment and reset ----

/// Make `secret` the user's authenticator, replacing any other, with a new set
/// of recovery codes, which are returned to be shown once.
pub async fn enroll(pool: &DbPool, user_id: &str, secret: &str) -> anyhow::Result<Vec<String>> {
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM user_totp WHERE user_id = ?"))
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    // The step it was confirmed with counts as used.
    sqlx::query(crate::db::sql_stmt(
        engine,
        "INSERT INTO user_totp (user_id, secret, enrolled_at, last_step) VALUES (?, ?, ?, ?)",
    ))
    .bind(user_id)
    .bind(secret)
    .bind(now())
    .bind(matching_step(secret, &code_for(secret, now()), now()).unwrap_or(0))
    .execute(&mut *tx)
    .await?;
    let codes = insert_recovery_codes(&mut tx, engine, user_id).await?;
    tx.commit().await?;
    Ok(codes)
}

/// An administrator's reset: the authenticator and every recovery code go, and
/// so do the user's sessions and refresh tokens, so nothing signed in with the
/// old authenticator keeps working. `false` when there was nothing to reset.
pub async fn reset(pool: &DbPool, tenant_id: &str, user_id: &str) -> anyhow::Result<bool> {
    let in_tenant: Option<(String,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT id FROM users WHERE id = ? AND tenant_id = ?",
    ))
    .bind(user_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    if in_tenant.is_none() {
        bail!("no such account in this tenant");
    }
    let engine = crate::db::engine_of(pool);
    let mut tx = pool.begin().await?;
    let removed = sqlx::query(crate::db::sql_stmt(engine, "DELETE FROM user_totp WHERE user_id = ?"))
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(crate::db::sql_stmt(
        engine,
        "DELETE FROM user_recovery_codes WHERE user_id = ?",
    ))
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    crate::users::end_sessions(pool, user_id).await?;
    Ok(removed > 0)
}

// ---- the pending second step ----

/// A sign-in waiting at its second step.
pub struct Pending {
    pub user_id: String,
    pub tenant_id: String,
    pub purpose: Purpose,
    /// For an enrolment: the secret being set up.
    pub enroll_secret: Option<String>,
}

/// Start a second step for a user whose password was right (or whose session
/// already stands). Returns the ticket for the page's form.
pub async fn begin(pool: &DbPool, tenant_id: &str, user_id: &str, purpose: Purpose) -> anyhow::Result<String> {
    let ticket = crate::util::b64url(&random_bytes(32));
    let ts = now();
    sqlx::query(crate::db::q(pool, "DELETE FROM mfa_pending WHERE expires_at < ?"))
        .bind(ts)
        .execute(pool)
        .await?;
    let secret = (purpose == Purpose::Enroll).then(new_secret);
    sqlx::query(crate::db::q(
        pool,
        "INSERT INTO mfa_pending (ticket_hash, user_id, tenant_id, purpose, enroll_secret, attempts, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
    ))
    .bind(sha256_hex(ticket.as_bytes()))
    .bind(user_id)
    .bind(tenant_id)
    .bind(purpose.as_str())
    .bind(secret)
    .bind(ts)
    .bind(ts + TICKET_LIFETIME_SECS)
    .execute(pool)
    .await?;
    Ok(ticket)
}

/// The live second step a ticket names, in this tenant.
pub async fn pending(pool: &DbPool, ticket: &str, tenant_id: &str) -> anyhow::Result<Option<Pending>> {
    let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT user_id, tenant_id, purpose, enroll_secret FROM mfa_pending
         WHERE ticket_hash = ? AND tenant_id = ? AND expires_at > ? AND attempts < ?",
    ))
    .bind(sha256_hex(ticket.as_bytes()))
    .bind(tenant_id)
    .bind(now())
    .bind(MAX_ATTEMPTS)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(user_id, tenant_id, purpose, enroll_secret)| {
        Some(Pending {
            user_id,
            tenant_id,
            purpose: Purpose::parse(&purpose)?,
            enroll_secret,
        })
    }))
}

/// Count a wrong code. `false` once the ticket has had its last attempt.
pub async fn failed_attempt(pool: &DbPool, ticket: &str) -> anyhow::Result<bool> {
    let hash = sha256_hex(ticket.as_bytes());
    sqlx::query(crate::db::q(
        pool,
        "UPDATE mfa_pending SET attempts = attempts + 1 WHERE ticket_hash = ?",
    ))
    .bind(&hash)
    .execute(pool)
    .await?;
    let row: Option<(i64,)> = sqlx::query_as(crate::db::q(
        pool,
        "SELECT attempts FROM mfa_pending WHERE ticket_hash = ?",
    ))
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some_and(|(n,)| n < MAX_ATTEMPTS))
}

/// The second step is over, one way or the other.
pub async fn finish(pool: &DbPool, ticket: &str) -> anyhow::Result<()> {
    sqlx::query(crate::db::q(pool, "DELETE FROM mfa_pending WHERE ticket_hash = ?"))
        .bind(sha256_hex(ticket.as_bytes()))
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1 column, truncated to the six digits apps show.
    #[test]
    fn matches_the_rfc_test_vectors() {
        let secret = base32(b"12345678901234567890");
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(code_for(&secret, time), code, "{time}");
        }
    }

    #[test]
    fn base32_round_trips() {
        for len in 0..25 {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            assert_eq!(base32_decode(&base32(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_no_further() {
        let secret = new_secret();
        let t = 1_700_000_000;
        for (offset, ok) in [(-60, false), (-30, true), (0, true), (30, true), (60, false)] {
            let code = code_for(&secret, t + offset);
            assert_eq!(matching_step(&secret, &code, t).is_some(), ok, "{offset}");
        }
        assert!(matching_step(&secret, "12345", t).is_none());
        assert!(matching_step(&secret, "abcdef", t).is_none());
    }

    #[test]
    fn recovery_codes_compare_without_case_or_punctuation() {
        let code = new_recovery_code();
        assert_eq!(code.len(), RECOVERY_GROUP * 2 + 1);
        assert_eq!(
            recovery_hash(&code),
            recovery_hash(&code.to_uppercase().replace('-', " "))
        );
    }

    #[test]
    fn policies_round_trip_and_default_is_stored_as_nothing() {
        for p in MfaPolicy::ALL {
            assert_eq!(MfaPolicy::parse(p.as_str()), Some(*p));
        }
        assert_eq!(MfaPolicy::Default.stored(), None);
    }
}
