//! In-process rate limiting for the endpoints an unauthenticated caller can reach.
//!
//! # What this defends
//!
//! Every limited event also writes an `audit_log` row, so before this existed an
//! unauthenticated caller could append rows indefinitely — which both grows the
//! table without bound and pushes the evidence of a real attack out of whatever
//! retention window the operator keeps ([`crate::db`], `audit prune`). Bounding
//! the events bounds the rows.
//!
//! # Why these keys
//!
//! Every bucket is keyed on something the caller **cannot choose freely**: a
//! tenant that had to resolve before the request got this far, or an application
//! that had to resolve to a registered `app_id`. A caller cannot escape its
//! bucket by varying a header, an IP or a parameter, and the key space is
//! therefore bounded by the number of real tenants and applications rather than
//! by the number of distinct requests.
//!
//! **The remote address is deliberately not a key.** rust-oidc is normally
//! deployed behind a TLS-terminating reverse proxy, where the socket peer is the
//! proxy: an IP-keyed bucket would put every caller in the world into one bucket
//! and throttle the whole service. Using a forwarded header instead would mean
//! trusting a caller-supplied value unless the operator configures which proxies
//! to trust — configuration this project does not have yet. Keying on tenant and
//! application is correct in both deployments.
//!
//! # Why the collateral damage is bounded
//!
//! A bucket that refuses requests can be tripped deliberately by an attacker, so
//! each one is chosen so that tripping it costs a legitimate caller little or
//! nothing:
//!
//! - [`Limit::UnknownClient`] and [`Limit::UnknownUser`] count requests that name an
//!   identifier the tenant does not have. Such a request can never be a
//!   legitimate one, so refusing it has no collateral damage at all.
//! - [`Limit::ClientAuthFailure`] and [`Limit::DeviceCodeRequest`] are keyed per
//!   application, so one application's flood cannot affect another. This is the
//!   same trade Entra's smart lockout already makes for user accounts, which
//!   this project implements in [`crate::users`].
//!
//! # Following Entra
//!
//! Entra signals throttling with `429 Too Many Requests` and a `Retry-After`
//! header, flat at 60 seconds for the `client_credentials` grant
//! (learn.microsoft.com, "Understanding client and server throttling in
//! MSAL.NET", fetched 30 Sep 2026). That is the observable behaviour reproduced
//! here, and it is what MSAL already knows how to handle. Entra's escalating,
//! doubling back-off is documented for *account lockout*, which this project
//! implements separately in [`crate::users`]; there is no evidence that Entra
//! escalates a throttle, so these buckets use a flat window.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::now;

/// Length of every bucket's window, in seconds.
///
/// 60 matches the `Retry-After: 60` that Entra documents for `client_credentials`.
const WINDOW_SECS: i64 = 60;

/// Prune expired entries once the table reaches this many keys. The key space is
/// bounded by tenants x applications, so this is hygiene rather than a defence.
const PRUNE_AT: usize = 1024;

/// One rate-limited class of event.
///
/// **Every limit below is a number I invented.** They are set well above any
/// plausible legitimate rate and are not derived from Entra, which does not
/// publish its thresholds. They cannot be changed without a rebuild; that is the
/// first thing to revisit if any of them turns out to be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    /// Failed client authentication at the token endpoint, keyed per application.
    /// A working client does not fail client authentication, so this only counts
    /// a misconfigured client or an attack on a client secret.
    ClientAuthFailure,
    /// Client authentication naming a `client_id` the tenant does not have,
    /// keyed per tenant. Never a legitimate request.
    UnknownClient,
    /// A failed password check naming an account that does not exist, keyed per
    /// tenant. Never a legitimate sign-in. Note that this one does **not** change
    /// the response — see [`crate::routes::audit::sign_in_failure`].
    UnknownUser,
    /// Device authorization requests, keyed per application. Counts successes
    /// too: each one inserts a `device_codes` row, so the row growth is the point.
    DeviceCodeRequest,
    /// Auth API credential checks, keyed per calling application. Counts every
    /// check. The caller has authenticated, so a refusal (429) tells it nothing
    /// about any user.
    CredentialCheck,
    /// Auth API credential checks of one account, keyed by the account's id (so
    /// only real accounts have a bucket). Bounds password and code guessing
    /// against one person. Tripping it does **not** change the answer from the
    /// generic failure: a 429 for real accounts only would say which exist.
    CredentialCheckAccount,
}

impl Limit {
    pub const ALL: &'static [Limit] = &[
        Self::ClientAuthFailure,
        Self::UnknownClient,
        Self::UnknownUser,
        Self::DeviceCodeRequest,
        Self::CredentialCheck,
        Self::CredentialCheckAccount,
    ];

    /// Recorded in the audit row when a bucket trips.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientAuthFailure => "client_auth_failure",
            Self::UnknownClient => "unknown_client",
            Self::UnknownUser => "unknown_user",
            Self::DeviceCodeRequest => "device_code_request",
            Self::CredentialCheck => "credential_check",
            Self::CredentialCheckAccount => "credential_check_account",
        }
    }

    /// Events allowed within one window before the bucket starts refusing.
    pub fn allowance(self) -> u32 {
        match self {
            Self::ClientAuthFailure => 20,
            Self::UnknownClient => 20,
            Self::UnknownUser => 20,
            Self::DeviceCodeRequest => 60,
            // A login host checks each login once; 600 a minute is far above
            // any one host's real rate.
            Self::CredentialCheck => 600,
            // Ten tries a minute at one person's password and code.
            Self::CredentialCheckAccount => 10,
        }
    }

    pub fn window_secs(self) -> i64 {
        WINDOW_SECS
    }
}

/// Bucket key for a per-application limit. An application acts inside one tenant
/// here, and the pair keeps two tenants' registrations apart. The one definition:
/// a check and the matching count must never disagree about the key.
pub fn app_key(tenant_id: &str, app_id: &str) -> String {
    format!("{tenant_id}/{app_id}")
}

/// What counting one event did to its bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// Still below the allowance. Carry on.
    Under,
    /// This event reached the allowance: it is served, the bucket now refuses,
    /// and this is the single event that writes the "throttled" audit row.
    Reached,
    /// The bucket was already refusing. Nothing further should be recorded,
    /// which is what bounds the audit table. Carries the `Retry-After` seconds,
    /// computed under the same lock as the count so that a caller never has to
    /// ask a second time and guess if the window moved underneath it.
    AlreadyOver(RetryAfter),
}

/// Seconds a refused caller is told to wait, for the `Retry-After` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub u64);

#[derive(Debug, Clone, Copy)]
struct Window {
    start: i64,
    count: u32,
}

/// Fixed-window counters, held in this process only.
///
/// **Multiple server instances do not share these counters.** Each process keeps
/// its own, so N instances behind a load balancer allow up to N times the
/// configured rate, and a caller can be refused by one instance and served by
/// another. That is a real operational limitation, recorded in
/// `docs/decisions-log.md`; making it exact would mean putting the counters in
/// the database, which would turn every limited request into a write and hand an
/// attacker a cheaper denial of service than the one being prevented.
#[derive(Debug, Default)]
pub struct Limiter {
    state: Mutex<HashMap<(Limit, String), Window>>,
}

impl Limiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is this bucket currently refusing? Does not count the event.
    ///
    /// Call this before doing expensive work (a password hash, a signature
    /// check) that a refused request should not be able to buy.
    pub fn check(&self, limit: Limit, key: &str) -> Option<RetryAfter> {
        self.check_at(limit, key, now())
    }

    /// Count one event against a bucket.
    ///
    /// A refused event still counts: the limit is events *per window*, so a
    /// flood that keeps arriving keeps the bucket shut rather than being handed
    /// a fresh allowance the moment it stops being recorded.
    pub fn hit(&self, limit: Limit, key: &str) -> Hit {
        self.hit_at(limit, key, now())
    }

    /// [`Limiter::check`] with an explicit clock, for tests.
    pub fn check_at(&self, limit: Limit, key: &str, ts: i64) -> Option<RetryAfter> {
        let state = self.state.lock().expect("rate limiter mutex");
        let window = state.get(&(limit, key.to_string()))?;
        if expired(window, limit, ts) || window.count < limit.allowance() {
            return None;
        }
        Some(retry_after(window, limit, ts))
    }

    /// [`Limiter::hit`] with an explicit clock, for tests.
    pub fn hit_at(&self, limit: Limit, key: &str, ts: i64) -> Hit {
        let mut state = self.state.lock().expect("rate limiter mutex");
        if state.len() >= PRUNE_AT {
            state.retain(|(limit, _), window| !expired(window, *limit, ts));
        }
        let window = state
            .entry((limit, key.to_string()))
            .or_insert(Window { start: ts, count: 0 });
        if expired(window, limit, ts) {
            *window = Window { start: ts, count: 0 };
        }
        // Saturating so that a bucket left refusing for a long time cannot wrap
        // back under its allowance.
        window.count = window.count.saturating_add(1);
        match window.count.cmp(&limit.allowance()) {
            std::cmp::Ordering::Less => Hit::Under,
            std::cmp::Ordering::Equal => Hit::Reached,
            std::cmp::Ordering::Greater => Hit::AlreadyOver(retry_after(window, limit, ts)),
        }
    }

    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.state.lock().expect("rate limiter mutex").len()
    }
}

/// Whether `window` belongs to an earlier window than `ts`.
///
/// A backwards clock jump opens a new window rather than stranding the bucket in
/// the refusing state for the length of the jump. The cost is that a clock
/// oscillating across a window boundary resets the counter each time; the system
/// clock is not attacker-controlled, and the alternative strands legitimate
/// callers, so this is the better failure.
fn expired(window: &Window, limit: Limit, ts: i64) -> bool {
    ts < window.start || ts - window.start >= limit.window_secs()
}

fn retry_after(window: &Window, limit: Limit, ts: i64) -> RetryAfter {
    let remaining = window.start + limit.window_secs() - ts;
    // Never advertise 0: a caller that retries immediately is refused again.
    RetryAfter(remaining.clamp(1, limit.window_secs()) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_000_000;

    /// The allowance is the number of events *served*: the Nth trips the bucket
    /// and is still served, the (N+1)th is refused.
    #[test]
    fn allowance_events_are_served_and_the_next_is_refused() {
        let limiter = Limiter::new();
        let limit = Limit::ClientAuthFailure;
        for _ in 1..limit.allowance() {
            assert_eq!(limiter.hit_at(limit, "tenant/app", T0), Hit::Under);
            assert_eq!(limiter.check_at(limit, "tenant/app", T0), None);
        }
        assert_eq!(limiter.hit_at(limit, "tenant/app", T0), Hit::Reached);
        assert_eq!(limiter.check_at(limit, "tenant/app", T0), Some(RetryAfter(60)));
        assert_eq!(
            limiter.hit_at(limit, "tenant/app", T0),
            Hit::AlreadyOver(RetryAfter(60)),
            "a refused hit reports the same wait as a check"
        );
    }

    /// `Reached` fires exactly once per window, so the audit row that records a
    /// trip is written once however long the flood lasts.
    #[test]
    fn reached_is_reported_once_per_window() {
        let limiter = Limiter::new();
        let limit = Limit::UnknownClient;
        let mut reached = 0;
        for i in 0..limit.allowance() * 10 {
            if limiter.hit_at(limit, "tenant", T0 + i as i64 % WINDOW_SECS) == Hit::Reached {
                reached += 1;
            }
        }
        assert_eq!(reached, 1, "the trip must be reported once, not on every refusal");
    }

    /// The whole point: a sustained flood cannot produce more than `allowance`
    /// recordable events per window, so it cannot append audit rows without bound.
    #[test]
    fn a_sustained_flood_is_capped_per_window() {
        let limiter = Limiter::new();
        let limit = Limit::UnknownUser;
        let mut recorded = 0;
        // Ten thousand requests spread evenly over two windows. The clock must
        // advance monotonically: an earlier version of this test cycled `ts` with
        // a modulo, which walked the clock backwards every 120 seconds and so
        // legitimately opened a new window each time -- it was measuring a
        // clock-jump scenario, not a flood.
        const REQUESTS: i64 = 10_000;
        for i in 0..REQUESTS {
            let ts = T0 + (i * WINDOW_SECS * 2) / REQUESTS;
            if matches!(limiter.hit_at(limit, "tenant", ts), Hit::Under | Hit::Reached) {
                recorded += 1;
            }
        }
        assert!(
            recorded <= limit.allowance() * 2,
            "a flood of {REQUESTS} requests recorded {recorded} events, more than two windows' allowance"
        );
    }

    #[test]
    fn buckets_are_independent_across_keys_and_limits() {
        let limiter = Limiter::new();
        for _ in 0..Limit::ClientAuthFailure.allowance() + 5 {
            limiter.hit_at(Limit::ClientAuthFailure, "tenant/app-a", T0);
        }
        assert!(limiter.check_at(Limit::ClientAuthFailure, "tenant/app-a", T0).is_some());
        // A different application is untouched...
        assert_eq!(limiter.check_at(Limit::ClientAuthFailure, "tenant/app-b", T0), None);
        // ...and so is a different limit on the same key.
        assert_eq!(limiter.check_at(Limit::DeviceCodeRequest, "tenant/app-a", T0), None);
    }

    #[test]
    fn the_window_resets_and_retry_after_counts_down() {
        let limiter = Limiter::new();
        let limit = Limit::ClientAuthFailure;
        for _ in 0..limit.allowance() {
            limiter.hit_at(limit, "k", T0);
        }
        assert_eq!(limiter.check_at(limit, "k", T0), Some(RetryAfter(60)));
        assert_eq!(limiter.check_at(limit, "k", T0 + 59), Some(RetryAfter(1)));
        // Exactly one window later the bucket is open again.
        assert_eq!(limiter.check_at(limit, "k", T0 + WINDOW_SECS), None);
        assert_eq!(limiter.hit_at(limit, "k", T0 + WINDOW_SECS), Hit::Under);
    }

    /// Retry-After is never 0, or a well-behaved client retries into a refusal.
    #[test]
    fn retry_after_is_never_zero() {
        let limiter = Limiter::new();
        let limit = Limit::UnknownClient;
        for _ in 0..limit.allowance() {
            limiter.hit_at(limit, "k", T0);
        }
        for offset in 0..WINDOW_SECS {
            let RetryAfter(secs) = limiter.check_at(limit, "k", T0 + offset).expect("still refusing");
            assert!((1..=WINDOW_SECS as u64).contains(&secs), "Retry-After was {secs}");
        }
    }

    /// A clock that jumps backwards must not strand a bucket in the refusing
    /// state for as long as the jump.
    #[test]
    fn a_backwards_clock_jump_opens_a_new_window() {
        let limiter = Limiter::new();
        let limit = Limit::ClientAuthFailure;
        for _ in 0..limit.allowance() {
            limiter.hit_at(limit, "k", T0);
        }
        assert!(limiter.check_at(limit, "k", T0).is_some());
        assert_eq!(limiter.check_at(limit, "k", T0 - 3600), None);
    }

    #[test]
    fn expired_entries_are_pruned_rather_than_accumulating() {
        let limiter = Limiter::new();
        for i in 0..PRUNE_AT {
            limiter.hit_at(Limit::ClientAuthFailure, &format!("tenant/app-{i}"), T0);
        }
        // One window later a new key triggers the prune and clears the rest.
        limiter.hit_at(Limit::ClientAuthFailure, "tenant/app-new", T0 + WINDOW_SECS);
        assert!(
            limiter.tracked_keys() <= 2,
            "expired keys were kept: {} still tracked",
            limiter.tracked_keys()
        );
    }

    /// `check` and `hit` must address the same bucket, or the early refusal and
    /// the counting would drift apart and the limit would never take effect.
    #[test]
    fn app_key_addresses_the_same_bucket_from_both_sides() {
        let limiter = Limiter::new();
        let limit = Limit::ClientAuthFailure;
        let key = app_key("tenant-1", "app-1");
        for _ in 0..limit.allowance() {
            limiter.hit_at(limit, &key, T0);
        }
        assert!(limiter.check_at(limit, &app_key("tenant-1", "app-1"), T0).is_some());
        // The tenant is part of the key: the same app id under another tenant
        // is a different bucket.
        assert_eq!(limiter.check_at(limit, &app_key("tenant-2", "app-1"), T0), None);
    }

    #[test]
    fn every_limit_has_a_distinct_name_and_a_usable_allowance() {
        let mut names = std::collections::HashSet::new();
        for limit in Limit::ALL {
            assert!(names.insert(limit.as_str()), "duplicate name {}", limit.as_str());
            assert!(limit.allowance() > 0, "{} allows nothing", limit.as_str());
            assert!(limit.window_secs() > 0);
        }
    }
}
