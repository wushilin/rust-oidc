# Decisions made without asking

Judgment calls taken while working through the feature gaps, so they can be reviewed
or reversed deliberately rather than discovered later. Newest section first within
each group. Every one is reversible; the "to reverse" line says how.

Two standing rules drove most of these: **follow Entra ID v2.0 as closely as
possible**, and **no magic values**.

---

## Open — yours to decide, not mine

| # | Question | Why it is yours |
|---|---|---|
| A | **Branch integration**: merge `feat/admin-console` to `main`, open a PR, or keep it? | Asked twice, still unanswered. The branch carries everything below plus the half-built console. |
| B | **TOTP MFA, four questions** in `docs/superpowers/specs/2026-09-30-totp-mfa-design.md`: where the seed-encryption key comes from; whether a missing key should fail startup closed; whether enabling `mfa_required` revokes existing refresh families; recovery codes now or later. | The key-management one is operational and affects deployment. Guessing it would bake in an ops burden you did not choose. |
| C | **Rate limiting — now built; only the numbers are still yours.** Implemented in `src/ratelimit.rs` (decisions 29-38). What remains for you: the four allowances are **invented** (decision 37), there is no way to tune them without a rebuild, and the counters are in-process so multiple instances multiply the effective limits (decision 38). | The limits are a product decision and the per-instance behaviour is an operational one. |
| D | **`acr`**: emit it when `acr_values` is requested, or accept the omission? | Evidence is genuinely ambiguous — see decision 5. |

---

## Entra fidelity and conformance

**1. The extra ID token claims stay.** `oid`, `tid`, `uti`, `ver` are in every Entra
ID token; the conformance suite calls them non-requested claims. Kept.
*To reverse:* strip them in `src/routes/token.rs:547-554` — but every client reading
`tid`/`oid` breaks.

**2. `email` stays in the ID token for the `email` scope.** Entra does this without a
`claims` request. *To reverse:* gate it on a `claims` parameter we currently ignore.

**3. userinfo is NOT enriched — this reverses an earlier plan of mine.** I had queued
"add `preferred_username`, `updated_at`" as a gap. It is not one: those claims are
absent because Entra's userinfo is minimal, so adding them would trade the primary
goal for a suite warning. *To reverse:* add claims in `src/routes/userinfo.rs:86-104`.

**4. Access tokens remain valid after an authorization code is replayed.** The code
family is revoked, but access tokens are self-contained JWTs with no introspection, so
they cannot be retracted. Entra is identical. *To reverse:* only by adding
introspection or shortening lifetimes (already a tenant setting).

**5. `acr` reclassified from "accepted deviation" to open question.** I had justified
omitting it as "a v1.0 claim". Entra's live v2.0 metadata lists `acr` in
`claims_supported`, which contradicts that. But that list is unreliable in both
directions — it omits `oid` and `uti`, which Entra certainly emits — so metadata
cannot settle what a real token carries. Needs a capture from a live tenant. No code
changed. **This is question D above.**

**6. Request objects will NOT be implemented — this reverses my own claim.** I had
recorded them as the one real remaining gap, reasoning Entra supports them. Entra's
discovery says `request_uri_parameter_supported: false` and omits
`request_parameter_supported`, which Discovery defines as defaulting to false. Entra
does not accept them, so our `request_not_supported` is already faithful and building
it would diverge. Two conformance modules stay failed as a result.
*To reverse:* parse the `request` JWT and merge its claims over the query parameters.

**7. `response_types_supported` mirrors Entra exactly, mismatch included.** Entra
advertises four types but its docs demonstrate a fifth (bare `token`, the silent
refresh iframe). We reproduce both the behaviour and the metadata, so we are wrong in
the same way Entra is. *To reverse:* add `token` to the advertised list.

---

## Implicit and hybrid response types (commit `bc217fa`)

**8. All five types supported**, including bare `token`, because clients depend on
observed behaviour rather than metadata.

**9. Both per-app toggles default OFF.** Entra parity, and front-channel tokens land
in browser history and `Referer`. *To reverse:* change the migration defaults — not
recommended.

**10. The refusal now uses Entra's `unsupported_response`, not the RFC's
`unsupported_response_type`.** This changes an error value we already shipped; one
existing test asserted the old one. *To reverse:* one string, but then we diverge from
Entra.

**11. DEVIATION from Entra's prose — `response_mode=query` is refused when a token
would travel in it.** Entra's docs are silent; OAuth 2.0 Multiple Response Type
Encoding Practices forbids it. A token in a query string is logged by proxies and
leaks via `Referer`.

**12. DEVIATION from Entra's prose — bare `token` defaults to `fragment`.** Entra's
documentation says the default is `query` for an access token alone. RFC 6749 §4.2.2
mandates the fragment, and every Entra example passes `fragment` explicitly. I chose
the normative spec over one sentence. **This is the one place where I knowingly did
not follow Entra.** *To reverse:* two lines in `src/routes/authorize.rs`.

**13. `openid` is required when an ID token is requested**, rather than silently
returning no ID token. Entra's parameter table says the scope "must include openid".

**14. `nonce` is required for any response carrying an ID token.** Entra documents it
as required; there is no code exchange to bind the token otherwise.

**15. The SPA PKCE requirement now applies only when a code is issued.** An
`id_token`-only request has no code to protect.

**16. AADSTS700054 is paired with Entra's message.** The message is verified from
Microsoft's docs; the number is our closest match and is **not** verified as the
pairing Entra actually uses.

---

## Audit trail

**17. An unresolved client id is never logged.** It was being written verbatim, so a
client transposing `client_id`/`client_secret` stored its **secret** in the audit
table. Now a resolved app contributes its registered id; an unresolved one contributes
only `ClaimedShape::{Guid,Other}` — one bit, no content. I chose that bit over logging
nothing, so a transposition is still diagnosable.

**18. An unknown user's domain is logged only when it matches one of the tenant's own
domains.** Replaced a DNS-shape heuristic: a mistyped password can never equal one of
our own domains, so this is zero-leak by construction rather than by guesswork.

**19. A successful ROPC sign-in now writes `auth.sign_in`.** Without it, "when did
this user last authenticate" was unanswerable for password-grant clients.

**20. Three indexes on `audit_log`, and MySQL's `actor`/`action`/`target` narrowed to
`VARCHAR` with `utf8mb4_bin`.** MySQL cannot index `TEXT` without a prefix length. The
binary collation matters: the table default would fold case, making `cli` and `CLI` the
same actor.

**21. Retention is a CLI command, default 90 days.** `audit prune --older-than-days`,
following the `key prune` precedent — there is no scheduler in the server process, so
this needs cron. **The 90 days is my number, pulled from nothing.**

---

## Rate limiting (question C: the gap was settled, the numbers were not)

The gap was real: `grep -rniE "rate_?limit|throttl|governor" src/ Cargo.toml` returned
nothing, and every limited failure also writes an `audit_log` row, so an
unauthenticated caller could append rows indefinitely -- growing the table and pushing
the evidence of a real attack out of the operator's retention window. Implemented in
`src/ratelimit.rs`, tested in `tests/rate_limit.rs`.

**29. The observable behaviour follows Entra: `429` plus `Retry-After`.** Verified from
Microsoft Learn ("Understanding client and server throttling in MSAL.NET", fetched
30 Sep 2026): *"Microsoft Entra ID will reply with `429 Too Many Requests`, with a
`Retry-After: 60` header"* for `client_credentials`, and `HTTP 429` with `Retry-After`
generally. MSAL already knows how to handle it. **The window is 60 seconds because that
is the only interval Entra documents.**

**30. Entra's doubling back-off is NOT applied to throttling.** The doubling escalation
is documented for *account lockout*, which this project already implements separately
(`src/users.rs`, smart lockout). Entra's documented throttle is a flat `Retry-After: 60`.
Applying the doubling here would be inventing behaviour. *To reverse:* give `Limit` an
escalation like `users::lockout_secs`.

**31. The `error` value IS verified; the AADSTS number is not.** Entra's own
token-endpoint error table (v2-oauth2-auth-code-flow, fetched 30 Sep 2026) lists
`temporarily_unavailable` -- *"The server is temporarily too busy to handle the request.
Retry the request after a small delay."* -- and the authorize-endpoint table lists it
too. So that value is Entra's documented code for exactly this condition, not a guess.
**The number is still a guess:** `90055` is Entra's `TenantThrottlingError` ("There are
too many incoming requests"), whose first sentence is quoted, but its documented cause
(a blocked tenant) is narrower than ours, and Entra does not document which AADSTS
number accompanies its 429. Same caveat as decision 16.

**32. The remote address is deliberately NOT a rate-limit key.** rust-oidc is normally
behind a TLS-terminating proxy (the deployed service is), where the socket peer is the
proxy: an IP-keyed bucket would put the whole world into one bucket and throttle the
entire service. Trusting a forwarded header instead needs a trusted-proxy configuration
this project does not have. Every bucket is therefore keyed on a **tenant** or an
**application**, both of which had to resolve before the request got this far, so a
caller cannot escape its bucket by varying a parameter, a header or an address -- and
the key space is bounded by real entities rather than by requests. *To reverse:* add a
trusted-proxy setting and an IP-keyed bucket alongside these.

**33. Buckets are chosen so that tripping one costs a legitimate caller little or
nothing.** Two of the four count requests that can never be legitimate (a `client_id`
or an account the tenant does not have), so refusing those has no collateral damage at
all. The other two are keyed per application, so one application's flood cannot affect
another -- the same trade Entra's smart lockout already makes per user account. The
residual cost is asserted by a test rather than left to be discovered: an attacker who
knows a client id **can** throttle that client's token requests
(`a_throttled_application_is_refused_even_with_the_right_secret`).

**34. The unknown-account cap changes the audit row, not the response.** An unknown
account and a wrong password are deliberately indistinguishable at the token endpoint.
Returning 429 only for the unknown one would turn the rate limiter into an
account-enumeration oracle, so that bucket suppresses the *audit row* beyond its
allowance and leaves the response exactly as it was.
`unknown_user_sign_ins_are_capped_without_becoming_an_enumeration_oracle` asserts both
halves, and I teeth-checked it by adding the 429 -- the assertion fires.

**35. Evidence is bounded rather than discarded: one row per bucket per window records
the trip.** `security.throttled` is written by the single event that reaches the
allowance, never by the refusals that follow, so the fact of a flood survives while its
volume does not. Without this, capping the rows would hide the attack instead of the
noise.

**36. Password spraying against *known* accounts gets no new bucket.** Smart lockout
already caps each account at 10 failures, so the rows are bounded by
10 x accounts per lockout window -- bounded, not indefinite. A tenant-wide sign-in
bucket would have been the one piece of collateral damage worth avoiding: an attacker
could have used it to refuse every user's sign-in. *To reverse:* add
`Limit::SignInFailure` keyed per tenant, and accept that.

**37. The limits are mine, invented, and not tunable without a rebuild.**

| Bucket | Key | Allowance per 60s |
|---|---|---|
| `ClientAuthFailure` | tenant + application | 20 |
| `UnknownClient` | tenant | 20 |
| `UnknownUser` | tenant | 20 |
| `DeviceCodeRequest` | tenant + application | 60 |

**Every one of these four numbers is invented.** Entra does not publish its thresholds.
They are set well above any plausible legitimate rate -- a working client does not fail
client authentication at all -- but they are guesses, and there is no configuration knob,
so changing them needs a rebuild. That is the first thing to revisit if any of them
proves wrong, and adding env-var overrides is the obvious reversal.

**38. Counters are in-process, so multiple instances multiply the effective limits.**
N instances behind a load balancer allow up to N times the rate, and a caller can be
refused by one instance and served by the next. **This matters operationally and is the
main reason not to treat these numbers as exact.** The alternative -- counters in the
database -- would turn every limited request into a write, which hands an attacker a
cheaper denial of service than the one being prevented. The deployed service runs a
single instance, so today the limits are exact there. *To reverse:* move the counters
into a shared store.

---

## No magic values: the list is now finished

Every item on the user's remaining list is done: the scope type, the principal and
member types, the redirect platforms, the OAuth `error` strings, the AADSTS codes, the
`prompt` values, and the 19 `db::audit` call sites that passed raw action strings.

### The decisions

**39. The audit vocabulary moved into `src/db.rs`, beside the function that writes
it.** `audit_log.action` had two sources of truth: `routes::audit::Event` for the HTTP
layer and nineteen bare strings in `src/main.rs` for the CLI. One column, two lists,
neither of which said what the column could contain. `db::Event` is now the only list
(35 variants), `db::audit` takes it, and `routes::audit` re-exports it so the HTTP
layer's call sites are unchanged. `db::Actor` does the same for the `actor` column,
which had `"cli"` inline nineteen times and a separate `ANONYMOUS` constant.

**Every wire value is unchanged, verified rather than asserted:** the old and new
spellings were extracted from git and compared, and all 19 CLI actions match in the
same order, all 16 HTTP actions match, and the actor is still `cli`. That mattered
because renaming an action would split a deployment's history across two spellings in
a column that is already indexed and already has rows on the deployed service.
`tests/audit_vocabulary.rs` pins all 35 values by hand -- deriving the expected list
from `as_str` would have made the test agree with any rename.

**40. `bootstrap` keeps its missing `area.` prefix.** It is the one action that does
not follow `area.event`. Renaming it to `server.bootstrap` would be tidier and would
also mean "when was this server bootstrapped" no longer has a single answer on the
deployed database. The shape test skips it by name, with the reason in the code.
*To reverse:* rename the variant's string and accept the split, or migrate the rows.

**41. `Event::parse` exists although nothing reads the column back yet.** It tolerates
unknown values (returns `None`), so a row written by a newer build cannot stop an older
one reading the table -- the same rule as `Amr` (decision 22). The console's audit view
will need it.

**42. A stored redirect platform is now an enum, and that closed a fail-open.**
`app_redirect_uris.platform`, and the platform copied onto `auth_codes` and
`refresh_tokens`, were `&str` compared against three consts.
`authenticate_for_platform` tested `== "spa"` then `== "web"` and **fell through to
the public-client branch for anything else** -- and the public-client branch requires
no client authentication at all. So a confidential `web` client's authorization code
whose platform string this build could not read would be redeemed for a full access
token and ID token **with no secret**. It is now an exhaustive `match` on
`RedirectPlatform`, and `stored_platform` refuses a value it cannot parse.

*How reachable was it?* Not through the HTTP API today: `app_redirect_uris.platform`
carries `CHECK (platform IN ('web','spa','publicClient'))` on all three engines, and
the grant tables only ever get a value copied from there. **But `auth_codes.platform`
and `refresh_tokens.platform` have no such CHECK on any engine** -- only a comment --
so the guard was load-bearing for a hand-edited row, a restored database, and the
realistic case: a newer build adding a fourth platform while an older binary still
serves traffic during a rolling upgrade. Teeth-checked by restoring the fall-through;
the token came back, signed, with no secret presented.
*To reverse:* nothing to reverse. The optional extra step is a `CHECK` on those two
columns, not done because SQLite cannot add one without rebuilding the table.

**43. `PrincipalType` is one enum for two tables, with the narrower use guarded.**
`app_role_assignments.principal_type` takes `User`/`Group`/`ServicePrincipal`;
`role_bindings.principal_type` takes only the first two. Rather than two nearly
identical enums, there is one in `src/directory.rs` and `bindings::create` refuses
`ServicePrincipal` explicitly. `effective_for_user` already matched `User`/`Group` by
name so such a row granted nothing, but that was an implicit property of a query two
functions away; both halves now have a test.

**44. `allowed_member_types` is parsed, not substring-matched.** The old code asked
`types.contains("Application")` against the raw JSON text, so a hypothetical
`ApplicationImpersonation` member type would have counted as `Application`. It now
parses the array and compares enum values, dropping types this build does not know --
dropping is the safe direction, since an unknown type grants nothing.

**45. The CLI's `--platform`, `--type` and `--member-types` are `clap::ValueEnum`
with explicit `value(name = ...)`.** The accepted spellings are unchanged
(`publicClient`, not clap's default kebab-case `public-client`), so no documented
command changes; clap now rejects a bad value with a list of the good ones instead of
the server doing it in a `bail!`.


**46. The OAuth `error` value and the AADSTS number are enums.** `AadError.error` was
a `&'static str` and `.code` a bare `u32`, written out at 64 call sites.
`error::OAuthError` (19 values) and `error::Aadsts` (47 numbers) are now the only lists.
**All 64 (error, number) pairs are unchanged, verified by extracting them from git
before and after and comparing** -- these are a client-facing contract, not internal
naming.

The win beyond the rule: the set is now enumerable, so a test can assert things that
were previously unassertable. `no_two_conditions_quietly_claim_the_same_number` found
that 70016 is shared by `authorization_pending` and `slow_down` -- which is correct,
because Entra's 70016 *is* the device-flow error family, so it is one variant used at
two call sites rather than two variants with the same number. And the two numbers that
are **our guess** rather than an observed Entra pairing (700054 for
`unsupported_response`, decision 16; 90055 for the 429, decision 31) are now named as
such in the enum and pinned by a test, so "which of these did we invent?" has an
answer in code rather than only here.

**47. `prompt` is an enum, and discovery advertises `Prompt::SUPPORTED` rather than a
second copy of the list.** The four values were written once in the parser and again in
the discovery document. `tests/discovery.rs` pins the advertised four by hand.

**48. `prompt=create` stays accepted-and-ignored, and stays unadvertised.** It is real
in Entra -- but on **External ID** tenants (`*.ciamlogin.com`) with a self-service
sign-up user flow, not the workforce v2 endpoint this server clones. Entra's v2
authorize reference lists only `login`, `none`, `consent`, `select_account`. What a
workforce tenant does with `create` is undocumented and we have not captured it, so:
behaviour unchanged (this server has no sign-up, so it falls back to the sign-in page,
the least surprising option), not advertised, and the uncertainty is written into the
enum's doc comment rather than smoothed over. *To reverse:* reject it with AADSTS90023
like any other unknown prompt, which is what Entra's documented list implies.

---

## Housekeeping

**22. `Amr` is stored as strings, not parsed into the enum.** A token minted by an
older build must not be dropped for naming a method this build does not know. The enum
produces values; it never parses them back.

**23. `KeyStatus` binds its value into SQL instead of inlining the literal**, which
also routed two queries through `db::q` that had bypassed it — they only worked on all
three engines because they happened to carry no placeholders.

**24. Migration numbering:** `0009` audit indexes, `0010` implicit flow, MFA reserved
`0011`. Renumbered twice as work landed ahead of it.

**25. The conformance harness reuses client1's credentials for the
`client_secret_post` block.** rust-oidc accepts either auth method on any confidential
client, as Entra does, so one client covers both. **Now verified** (30 Sep 2026):
`oidcc-server-client-secret-post` went from one FAILURE to a clean pass in both the
basic and the form_post plan, and a per-module diff of all three plans shows it as the
only change. See `docs/conformance.md`.

**26. The three Entra extension fields in our discovery document are declared to the
suite rather than removed.** `cloud_instance_name`, `http_logout_supported` and
`tenant_region_scope` are flagged by `CheckForUnexpectedParametersInServerMetadata`
against the RFC 8414 schema. All three are verified present in Entra's own live
document, so they stay; `make_config.py` names them in
`server.allow_unexpected_metadata_fields`, which is the suite's documented mechanism.
They are listed one by one on purpose, not suppressed wholesale, so a fourth
unregistered field added by accident still warns. Re-ran the config plan to confirm:
it is now 0 warnings, 0 failures.
*To reverse:* drop the array from `make_config.py` and accept the warning, or stop
emitting the fields and diverge from Entra.

**27. `http_logout_supported` and `frontchannel_logout_supported` stay `false`, against
Entra, which publishes `true` for both.** They advertise front-channel logout
*notification* to registered RPs; we implement RP-initiated logout only. Advertising a
capability we do not have is worse than the divergence. *To reverse:* implement
front-channel logout notification, then flip both in `src/routes/discovery.rs`.

**28. The conformance suite tests the deployed service, not the working tree.**
`compat/conformance/run.sh` points at `https://gate.wushilin.net:9443/rust-oidc`. At the
30 Sep run that deployment still advertised `response_types_supported: ["code"]`, so it
predates commit `bc217fa`. I did **not** redeploy (out of scope), so the results are
evidence about the deployed build only. Recorded at the top of `docs/conformance.md`
so a future reader does not over-read them.
