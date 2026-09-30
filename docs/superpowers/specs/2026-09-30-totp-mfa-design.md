# TOTP multi-factor authentication

Date: 2026-09-30
Status: draft, awaiting review
Blocks: the admin console's MFA section (phase 4) — the console cannot manage a
factor that does not exist.

## Intent

MFA is 0% implemented: `grep -riE 'mfa|totp|otp' src/` returns only comments
explaining that the ROPC grant cannot do it. The `amr` claim is hardcoded
`["pwd"]` at `src/routes/authorize.rs:580` and `src/routes/device.rs:451`.

What already exists and should be reused rather than rebuilt:

- **Sessions carry `amr`** — `src/session.rs:22,85` stores it as a JSON array and
  `src/claims.rs:94,125` emits it into both the access token and the id_token. The
  plumbing for "how the user authenticated" is done; only the producer is missing.
- **Smart lockout** — `src/users.rs:106-195` implements Entra's doubling lockout
  (10 failures, 60s, doubling) with a `failed_logins`/`locked_until` pair.
- **Audit** — `audit::record` with an `Event` enum, and `sign_in_failure` already
  distinguishes outcomes.

Scope: software OATH TOTP (RFC 6238) only. Push notifications, FIDO2/WebAuthn,
certificate-based auth and SMS/voice are out of scope; the data model must not
make them harder to add.

## Entra parity

Entra's `amr` values include `pwd`, `otp`, `mfa`, `fed`, `wia`, `rsa`, `ngcmfa`.
For a password followed by a software OATH code, the intended emission is:

```
amr = ["pwd", "otp", "mfa"]
```

`pwd` for the first factor, `otp` for the software token, `mfa` to state that
more than one factor was used. (*The exact multiset Entra emits for this
combination is asserted from documentation, not from a live capture. Confirm
against a real tenant before claiming parity; the `Amr` enum makes the change a
one-line edit.*)

Enforcement in Entra is driven by Conditional Access, which we are not building.
We approximate it with two switches (below). Step-up via `acr_values` is **not**
in scope: `acr` is a v1.0 claim and v2.0 tokens do not carry it (see
`docs/conformance.md`).

## No magic values

Per the standing rule, this feature introduces enums and no bare literals:

- `Amr { Pwd, Otp, Mfa }` with `as_str`/`parse` — and the two existing hardcoded
  `["pwd"]` sites are converted to `&[Amr::Pwd]`, which also closes part of the
  `no-magic-values` queue item.
- `MfaMethod { TotpSoftware }` — the stored factor kind, so a second method does
  not need a schema change.
- `CredentialStatus { Pending, Active }` — enrollment is two-phase.
- `MfaOutcome { Ok, WrongCode, Replayed, Locked, NotEnrolled }` — mirrors
  `AuthResult`.
- New `Event` variants: `MfaEnrollStart`, `MfaEnrollComplete`, `MfaChallenge`,
  `MfaFailure`, `MfaDisabled`, `RecoveryCodeUsed`.

## Data model

One migration (`0011_mfa`) in all three of `migrations/{sqlite,postgres,mysql}/`
(`0009` is the audit-log indexes, `0010` the implicit-flow toggles).

```
user_mfa_credentials
  id            text primary key
  tenant_id     text not null
  user_id       text not null
  method        text not null          -- MfaMethod
  status        text not null          -- CredentialStatus
  secret_enc    blob not null          -- AEAD ciphertext, never plaintext
  digits        smallint not null      -- 6
  period_secs   smallint not null      -- 30
  algorithm     text not null          -- SHA1, for authenticator compatibility
  last_step     bigint                 -- highest accepted time step; replay guard
  failed_count  bigint not null
  locked_until  bigint
  created_at    bigint not null
  activated_at  bigint

user_recovery_codes
  id, tenant_id, user_id, code_hash, used_at, created_at
```

Engine notes, from the rules established in `docs/databases.md`:

- `smallint`, not `tinyint` — sqlx's `Any` driver cannot map MySQL `TINYINT`.
- `status`/`method` are exact-match columns, so MySQL needs `COLLATE utf8mb4_bin`.
- Booleans, if any are added later, bind as real `bool`, never `0`/`1`.
- Unique index on `(tenant_id, user_id, method)` for an active credential. MySQL
  has no partial index, so follow the existing generated-column pattern rather
  than inventing a new one.

**SHA1 is deliberate.** RFC 6238's default and what every authenticator app
implements; it is used as an HMAC key here, not as a collision-resistant hash.

## Secret storage

A TOTP seed is password-equivalent: anyone holding it can mint valid codes
forever. It cannot be hashed, because verification needs the original, so it must
be **encrypted at rest** — a stolen database dump must not yield working seeds.

Decision: encrypt with AES-256-GCM (or XChaCha20-Poly1305) under a server-held
key supplied out of band, not stored in the database. The signing keys in
`src/keys.rs` are the wrong key: they live in the same database, and rotation
there must not invalidate enrollments.

This adds a new operational requirement — a configured secret. The key must be
addressed explicitly in the plan:

- Where it comes from (env var / file path, consistent with existing config in
  `src/main.rs`).
- What happens when it is absent. **Fail closed at startup if any MFA credential
  exists**, rather than silently disabling MFA — a server that forgets its key
  and drops the second factor is worse than one that refuses to boot.
- A `key_id` column alongside `secret_enc` so the key can be rotated by
  re-wrapping rather than re-enrolling every user.

## Flows

### Enrollment (authenticated user)

1. Generate 20 random bytes; insert `status = Pending`.
2. Present the `otpauth://totp/{issuer}:{upn}?secret=...&issuer=...&digits=6&period=30`
   URI, as a QR code and as text.
3. The user submits one code. Only on success does the row become `Active`, and
   only then are recovery codes generated and shown once.

Two-phase enrollment matters: a user who scans a QR, then loses the device before
confirming, must not be locked out by a factor they never proved they had.

### Sign-in

The existing password step is unchanged. After `AuthResult::Ok(user)`, if the
user has an `Active` credential, the session is **not** created yet. Instead an
interstitial page collects the code, carrying the original request the same way
the account picker already does (the hidden `request` field, `src/routes/authorize.rs:452-489`).

On success, `session::create` is called with `&[Amr::Pwd, Amr::Otp, Amr::Mfa]`.

The pending state between the two steps must be bound to the browser and be
short-lived and single-use. It must not be a client-supplied "user id + mfa
pending" cookie that could be forged to skip the first factor — reuse the
signed/hashed cookie approach already used for the session and CSRF cookies.

### Verification

- Accept the current step and ±1 (RFC 6238 §6 clock drift) — a 90s window.
- **Reject any step ≤ `last_step`**, then record the accepted step. This is the
  replay guard: without it, a code shouted over the shoulder is reusable for 90s.
- Constant-time comparison (`ct_eq`, already in the tree).
- Failures feed a lockout on the credential row, mirroring `users::lockout_secs`.

The `last_step` update must be a single statement that both tests and sets, so it
is atomic and MySQL-safe (error 1093 forbids reading the table being updated in a
subquery):

```sql
UPDATE user_mfa_credentials SET last_step = ?, failed_count = 0
WHERE id = ? AND (last_step IS NULL OR last_step < ?)
```

Then check `rows_affected() == 1`. A concurrent duplicate submission loses the
race and is treated as a replay — which is the correct answer.

### Recovery codes

Hashed with the password hasher, single-use (`used_at`), and consuming one emits
`amr = ["pwd", "mfa"]` (no `otp`, since no token was used). Using a recovery code
is audited.

## Enforcement

Two switches, resolved as "either requires it":

- `TenantSettings.mfa_required: bool` (`src/tenant.rs:10`) — every user in the tenant.
- A per-user flag — individuals, typically admins.

Consequences that must be handled, not left implicit:

- **ROPC** (`src/routes/user_grants.rs:601`) cannot present a challenge. If MFA is
  required for the user, the grant must fail with Entra's
  `AADSTS50076`/`AADSTS50079` rather than quietly issuing a single-factor token.
  This is the security-relevant edge: a bypass here defeats the whole feature.
- **Device code flow** — the browser leg handles the challenge; no special case,
  but it needs a test.
- **Refresh tokens** carry the original `amr` forward. A token minted before MFA
  was required stays single-factor until it expires; whether enabling the setting
  should revoke existing families is a policy question for review. Recommendation:
  revoke, since that is the point of turning it on.
- **Admin console** — a platform admin enabling MFA for themselves must not be
  able to lock every admin out. The `check_delete` precedent in
  `src/admin/authz.rs` (refusing removal of the last platform binding) is the
  model.

## Testing

- Unit: RFC 6238 test vectors, so correctness is pinned to the spec rather than
  to our own implementation.
- Drift: a code from the previous, current and next step accepts; two steps away rejects.
- Replay: the same code twice — second attempt rejected, on all three engines.
- Enrollment: `Pending` never satisfies a challenge.
- Bypass attempts: posting the second step without passing the first; forging the
  pending cookie; ROPC for an MFA-required user.
- Claims: `amr` contains `pwd`,`otp`,`mfa` in the access token and the id_token.
- Lockout: repeated wrong codes lock the credential, and the lock is per credential.

## Open questions for review

1. Is `["pwd","otp","mfa"]` the multiset a real Entra tenant emits here?
2. Where does the encryption key come from, and is fail-closed-at-startup the
   right behaviour when it is missing?
3. Does enabling `mfa_required` revoke existing refresh-token families?
4. Recovery codes now, or a follow-up? They are the main support burden of MFA,
   but also the main bypass surface.
