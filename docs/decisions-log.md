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
| E | **Should `PlatformAdministrator` be able to grant roles?** Today it cannot (decision 68), so the deployed super admin can assume the second tenant but not administer it, and cannot fix that from the console. Widening the role, or granting that account `GlobalAdministrator` at `all` scope, both work; they mean different things. | It changes what the platform role *is*, which is the security model you agreed in the spec. |
| D | **`acr`**: emit it when `acr_values` is requested, or accept the omission? | Evidence is genuinely ambiguous — see decision 5. Untouched; still needs a capture from a live Entra tenant, which I cannot do. |

**None of this is deployed.** Everything above lives on `feat/admin-console` only.
The running service at `gate.wushilin.net:9443` still serves a build that predates even
commit `bc217fa`: its discovery advertises `"response_types_supported": ["code"]`, and a
token request with a bad `client_id` still answers `400` with no `Retry-After`, so it has
no rate limiting. Deploying is out of scope for the work that produced these notes, and
it is downstream of question A.

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

## Admin console: the authorization rules (plan tasks 3 and 5)

**49. Task 3 is tests only.** Its module arrived early with the `wids` work (ruling
R6 in the console ledger), so `tests/rbac_bindings.rs` is the coverage that task never
got. It pins the properties the design leans on rather than the happy path: an orphaned
`role_binding_tenants` row grants nothing, a tenant *alias* does not match a scope (so a
check that compared the raw URL segment could not be bypassed), and a role or scope kind
this build does not know is skipped instead of failing the request.

**50. `authz::delete` is the single entry point for removing a binding**, applying both
the no-widening rule and the lock-out rule, rather than leaving a handler to remember to
call two functions. *To reverse:* call `may_write_binding`, `check_delete` and
`bindings::delete` separately, and accept that a new handler can forget one.

**51. The lock-out rule counts bindings, not reachable people.** A binding to a group
with no members, or to a disabled or soft-deleted user, counts as one platform
administrator. So the rule prevents the obvious lock-out (deleting the only one) and not
every lock-out. Making it exact means joining `users` and `group_members` and deciding
what "reachable" means -- whether a disabled user counts, whether an empty group does --
which is a product question, not an implementation detail. Written into the function's
doc comment so nobody reads more into it than it does. *To reverse:* add the joins and
pick an answer.

**52. A teeth check found a coverage gap, not a bug, and the gap is now closed.**
Removing `scope_kind = 'all'` from the lock-out count left every test in
`tests/rbac_no_widening.rs` passing -- because none of them held a *tenant-scoped*
platform binding alongside the last all-scope one. With the bug, that scoped binding
would have been counted as a substitute, the all-scope one would have been deletable,
and the platform would have been locked out anyway, since a scoped platform binding
cannot create or assume a tenant.
`a_tenant_scoped_platform_binding_does_not_keep_the_platform_alive` now covers it and
was confirmed to fail against the seeded bug before the fix was restored.

**53. `authz::delete` treats "already gone" as success.** If a binding disappears between
the check and the delete, the end state is the one the caller asked for. *To reverse:*
return `NotPermitted` and make every caller handle a race it cannot do anything about.

---

## Admin console: the UI (plan tasks 7-14)

**54. The console signs in with its own password form, not an OIDC round-trip to
itself.** Plan task 6 (a reserved console app registration) and task 8's authorization
code exchange are **not built**. The console is the same process as the token endpoint,
so an OIDC loop would have to call itself over loopback -- and `reqwest` is a
dev-dependency only, so that meant adding an HTTP client to the production dependency
tree to talk to ourselves. The form resolves the account's tenant from its UPN suffix
and calls `users::authenticate_traced`, so Entra's smart lockout, the audit trail and
the password rules all apply unchanged. *Costs:* no SSO between the console and an
application sign-in, and no PKCE/`state` plumbing to get wrong. *To reverse:* implement
plan task 6, add an HTTP client, and swap `POST /admin/signin` for `/admin/callback`.

**55. The console session is eight hours and its cookie is `SameSite=Lax`.** The
lifetime is **invented**: a working day, so an unattended console is not one by the next
morning. `Lax` (not the `None` the OIDC cookies need for silent sign-in in an iframe)
means a cross-site form post does not carry the cookie at all; the console is never
embedded. Separate table and separate cookie from `sessions`, so an OIDC sign-in to any
application does not grant console access.

**56. The CSRF token is derived from the session cookie**, `sha256("rust-oidc admin
csrf v1" || cookie)`, rather than a second cookie (which the OIDC login form would
clobber, since it reuses one name) or a stored column. It is unguessable without the
cookie, which is `HttpOnly`, and it is bound to that one session -- another session's
token is refused. *To reverse:* add an `admin_sessions.csrf` column and a random value.

**57. The console's HTML is `format!` plus `html::escape`, not askama, and there is no
JavaScript at all.** The plan chose askama with vendored htmx; the user asked for the
UI "simple as a start", and `src/html.rs` already renders the sign-in pages this way, so
a second rendering mechanism in the same binary would have cost more than it saved. The
content security policy is therefore `default-src 'none'`, which is only honest because
nothing loads. The risk this takes on is a forgotten `e(...)` at an interpolation;
`a_display_name_cannot_inject_markup` holds that line and was teeth-checked by making
`e` the identity function. *To reverse:* add askama and port the page bodies; the
`view` module is the only file that knows how a page is built.

**58. A form post answers `303 See Other`, not the plan's `302`.** A refresh of the
result then cannot repeat the write.

**59. A console audit row's actor is the administrator's user id**, not their UPN. The
plan's test sketch asserted the UPN; every other actor in the table is an id
(`db::Actor::Id`), and an id does not change when a person is renamed.

**60. Disabling and deleting a user revoke everything the account holds** -- browser
sessions, console sessions and refresh tokens -- through one private helper, so the two
paths cannot diverge. `soft_delete` also clears `enabled`, which means the soft-delete
*filters* are belt to that braces: `a_deleted_row_cannot_sign_in_even_while_it_still_says_enabled`
exists because without it the filters could be deleted with every other test still green
(found by a teeth check, exactly as with decision 52).

**61. A tenant the administrator cannot read is not listed at all**, rather than listed
and greyed out. The console must not be a directory of every tenant on the deployment
for a delegated admin; `a_tenant_admin_does_not_see_other_tenants_listed` holds it.

**62. Roles are granted and revoked per tenant, not platform-wide.** The form lives at
`/admin/tenants/{tenant}/roles` because that is where a principal can be *named*: a UPN
and a group name are unique within a tenant, not across the deployment. The scope choice
is that tenant, or every tenant -- and the second option is only rendered, and only
accepted, for someone `may_write_binding` already allows it to, so the no-widening rule
decides what the form offers. `/admin/bindings` stays a read-only platform-wide list.
There is no confirmation step on a revoke: the refusals that matter are rules, not
prompts.

**63. The user list shows at most 200 accounts and does not page.** 200 is **invented**.
Beyond it the page says to narrow the search. *To reverse:* the `offset` argument is
already there; add the links.

**64. Searching by display name is case-sensitive on SQLite and Postgres and
case-insensitive on MySQL.** The UPN half of the search is matched against
`upn_folded`, so identity matching is the same everywhere; display names are not
identities. Using `lower()` instead would make the behaviour depend on the database's
locale, which `docs/databases.md` rules out.

**65. A console sign-in naming an unverified domain writes no audit row at all.** There
is no tenant to attribute it to and the space of invented domains is unbounded. A failed
sign-in for a *known* domain reuses `Limit::UnknownUser`, keyed per tenant, exactly as
the `/authorize` form does, and never changes the response -- a 429 for only the unknown
account would be an enumeration oracle (decision 33).

**66. Assuming a tenant changes nothing about what is permitted.** No handler consults
`acting_tenant` when deciding access: the `All`-scope binding that allowed the assume
already covers the tenant, so the assumed tenant is display and defaults only.
`assuming_does_not_widen_what_is_permitted` holds it.

**69. A delegated administrator's roles page shows neither the platform's
administrators nor another tenant's id.** `bindings::list_for_tenant` returns
`all`-scope bindings too, and a principal id resolves to a UPN whatever tenant the
account lives in, so the first version of the page would have told a tenant
administrator who the super administrator is -- an account in a tenant they cannot see.
An `all`-scope row is now shown only to somebody who can read platform-wide (who has
`/admin/bindings` for that), and a binding covering several tenants is summarised as
"this tenant and N others" rather than listing ids that are not theirs to know.

**70. A tenant-scoped `PlatformAdministrator` grant is refused, not stored.** The form
does not offer the role to anyone who cannot grant at every-tenant scope, and the post
refuses it as well. Its actions are platform-wide, so the binding would grant nothing
while reading, to whoever found it later, as a platform administrator who is not one --
which is the same confusion that made the lock-out rule wrong in decision 52. Found by a
test written for something else: the roles page listed "Platform Administrator" in its
`<select>`, which is how the trap came to light.

**68. `PlatformAdministrator` still holds no role over roles, and I did not widen it.**
On the deployed service `admin@wushilin.net` holds `PlatformAdministrator` at `all` plus
`GlobalAdministrator` scoped to the root tenant only. In the console that account can
create and assume any tenant, but it cannot administer the second tenant's users after
assuming (assuming grants nothing -- decision 66), cannot grant itself a wider binding
(the no-widening rule), and cannot even open `/admin/bindings`, because
`PlatformAdministrator`'s actions are tenant create/write/assume, keys and audit: no
`RoleBinding:Read`. That is the agreed role model doing exactly what it says, and the
console is honest about it -- but it means **that account cannot yet be used to
administer the OIDF Conformance tenant**, and no page can repair it. Giving
`PlatformAdministrator` `RoleBinding` actions would make the platform role able to
appoint tenant administrators anywhere, which is a real widening of what "platform
administrator" means and is yours to decide, not mine. See open question E.
*To work around it today:* grant that account `GlobalAdministrator` at `all` scope the
way `bootstrap` does.

**67. What the console did not have yet** when the first pass landed: no MFA section
(deliberately skipped -- TOTP does not exist and is blocked on question B), no groups,
applications, assignments, domains, tenant-settings or signing-key pages, no role-binding
writes, no paging, and no tenant create or disable. **Superseded by decision 88**: all of
those except MFA, assignment-required and paging are now built. Kept for the record
because it is what the branch claimed at that commit.

---

## Admin console: the remaining sections (applications, tenants, settings, keys, groups, audit)

**71. Every console write gets its own `admin.*` audit action, 26 of them**, rather than
reusing the CLI's `app.secret.add`, `tenant.create` and so on. The precedent was already
set by `admin.sign_in` against `auth.sign_in` (decision 59's neighbourhood): the actor of
a console action is a named person acting through a browser, and the actor of a CLI action
is an operator who already has database access. Keeping them apart means "what did people
do in the console" is one query. *The cost:* `Event` now has 74 variants and
`tests/audit_vocabulary.rs` pins every one by hand, so adding a page means adding a line
there too -- which is the point.
*To reverse:* collapse the `Admin*` variants onto the CLI ones; the actor column still
distinguishes them, less legibly.

**72. The tenants section is authorized at platform scope, which is stricter than the
spec.** The design spec's action table has `Tenant:Write` cover "settings and domains"
wherever the binding reaches, so a tenant's own Global Administrator would qualify. The
console instead requires an `all`-scope binding for create, rename, enable, disable and
both domain operations. Three reasons, in order of weight: disabling a tenant is
**unrecoverable from the console** by the person who did it (their own session dies with
their home tenant, and there is no CLI); the tenant list is a platform page by shape, not
a page inside one tenant; and a route with no `{tenant}` segment has no scope comparison
for a URL alias to reach at all. Being stricter than the agreed model is the safe
direction, but it *is* a divergence and it is yours to confirm.
*To reverse:* change `On::Platform` to `On::Tenant` in `src/admin/tenants.rs` -- but the
route then needs a `{tenant}` segment, and a disabled tenant cannot be addressed by one
(`tenant::resolve` refuses it), so re-enabling would become impossible from the web.

**73. Tenant *settings* are the exception: they are authorized per tenant.**
`Tenant:Write` against the tenant in the URL, which is the spec's own wording for that
action. So a tenant's Global Administrator can tune their own lifetimes and a platform
administrator can tune anyone's, because an `all`-scope binding covers every tenant. The
line between this and decision 72 is that lifetimes are configuration *inside* a tenant,
while existence, name and domains are facts *about* one.

**74. The lifetime bounds are invented.** Entra retired configurable token lifetimes for
v2.0, so there is no published range to copy. Access token 300..86 400 s, browser session
300..2 592 000 s, refresh token 3 600..31 536 000 s, plus a cross-field rule: a refresh
token must not be shorter than the access token it mints. They are chosen to exclude what
is obviously wrong rather than to match a documented limit, and they live on
`TenantSettings` next to the values. This is the **first write path those settings have
ever had** -- until now every tenant carried whatever `TenantSettings::default` produced
at `create`, and there was no CLI command either.
*To reverse:* widen the constants in `src/tenant.rs`; `save_settings` validates in one
place, so nothing else changes.

**75. The root tenant cannot be disabled.** Same shape of rule as
`authz::check_delete`'s no-lock-out: the root tenant holds the administrators who would
have to re-enable it, an administrator's console session is dropped the moment their home
tenant stops resolving, and the admin surface is deliberately web-only. Disabling it would
lock every administrator out of the deployment with no path back short of editing the
database by hand. The button is not offered for it either, not only refused.

**76. A verified domain cannot be withdrawn if it is the tenant's last, or if a live
account's user name still uses it.** The second refusal is the less obvious one: such an
account could still be authenticated through its own tenant, but the console's sign-in
resolves the tenant *from the UPN's domain*, so withdrawing it would quietly lock that
person out of the console. **What is not enforced:** nothing stops withdrawing the
`is_default` domain while another remains, which leaves the tenant with no default. No
code reads `is_default` except the ordering of the domain list, and there is no way to
*change* the default, so refusing it would make the first domain permanently
unremovable -- a worse trade.

**77. A new client secret is returned in a `200` page, the one deliberate exception to
decision 58's "a form post answers 303".** Only a SHA-256 hash is stored, so the response
that creates the secret is the only place its value can ever exist; a redirect would throw
it away. The consequence is accepted rather than hidden: a browser reload will offer to
repost and would mint a *second* secret, which is untidy but harmless (both are valid, and
either can be deleted). The value is not written into any form field on that page, is
never re-rendered afterwards, and never reaches `audit_log` -- the row carries the key id
and the expiry. `tests/admin_apps.rs` holds all four halves of that, and a teeth check
confirmed the audit assertion catches a leak.
*The alternative I rejected:* holding the value in the session row so a redirect could
show it. That stores a live credential at rest to save one reload warning.

**78. Pruning signing keys is authorized by `Key:Rotate`, because there is no
`Key:Prune`.** Rotation and pruning are two halves of one lifecycle and only
`PlatformAdministrator` holds either. Adding a verb would mean widening a role to hold it,
which is not a change to make quietly. **Surfaced rather than done.**

**79. A console key rotation is recorded against the administrator's home tenant, not
against no tenant.** The CLI's `key rotate` writes `tenant_id = NULL`, which is honest --
the keys belong to no tenant -- but the audit page filters by `tenant_id`, so a
tenant-less row is invisible to everybody. Attributing it to the tenant of the person who
did it keeps the one console action with platform-wide effect visible *somewhere*. The
actor is the person either way.
*To reverse:* pass `None` and add a platform audit page that can show tenant-less rows.

**80. The audit page shows the newest 100 matching rows and does not page.** **100 is
invented**, and smaller than the user list's 200 (decision 63) because audit rows are
much wider. The table is append-only, unbounded, and *unauthenticated requests append to
it* -- a failed client authentication is an event -- so an uncapped page is a denial of
service against the administrator's own browser. The filters are the three indexes `0009`
added for exactly this page, and the four query shapes are spelled out as separate
literals rather than assembled, because `db::sql_stmt` takes a `&'static str` (that is
what makes its SQL-safety assertion sound) and because an `OR`-based "no filter" trick
would stop the planner using those indexes.

**81. The audit page shows actors and targets as the identifiers they are**, not resolved
to names. Resolving would mean a query per row, up to 100 of them, and a row whose subject
has since been deleted would then read as though it had been about nobody. The user detail
page links to `audit?target={object id}` instead, which is what the `(target)` index is
for.

**82. The audit page does not show rows belonging to no tenant.** Today that is only the
CLI's `key rotate`. Showing them would mean deciding whose page they belong on; the page
says plainly that they are not there.

**83. App roles and exposed scopes can be added from the console but not removed or
disabled.** Deleting an `app_roles` row cascades to every `app_role_assignments` row that
references it, so one click would silently revoke access for everybody holding that role,
and `app_scopes` has the same shape. Entra makes you disable a role before deleting it; we
have an `enabled` column and no write path for it. **Not built**, and the page does not
pretend otherwise.
*To do it properly:* add `set_enabled` for both, then a delete that refuses while
assignments exist.

**84. An application must keep at least one Application ID URI.** `api://{appId}` is how a
scope names the application as a resource, so a registration with none could no longer be
asked for a token by name. Entra enforces nothing here; we do, because the alternative is
a registration that silently stops working.

**85. An unrecognised stored `app_scopes.type` is displayed as "unknown", not as `User`.**
The same fail-closed direction decision 42 took for `app_redirect_uris.platform`: who may
consent is a security property, and `User` is the weaker of the two values.

**86. `keys::list` fails on a key whose status it cannot parse**, rather than skipping the
row the way `apps::redirect_uris` does. Opposite direction to decision 42 and deliberately
so: a skipped redirect URI fails closed (it matches nothing), but a skipped signing key
would hide a key that *is* published in JWKS from the page that decides whether to rotate.
It cannot happen in practice -- the schema has a CHECK constraint and `load_keys` would
already have stopped the server signing.

**87. The isolation tests are written against the rendered table, not the whole page, and
that was a real trap rather than a tidiness point.** The audit page's filter `<select>`
necessarily names every action this build knows, and its search box echoes back whatever
was typed into it. A first version of those tests asserted over `page.body`: the
"newest first" assertion then compared positions inside the `<option>` list and failed,
and `!body.contains("fabrikam-secret")` failed on the administrator's *own* search term
coming back. Both would have been easy to "fix" by weakening the assertion into something
that proved nothing. The helper now extracts `<table>...</table>` and the absence
assertions are made there.

**88. What the console still does not have**, replacing decision 67: no MFA section (still
blocked on question B), no `appRoleAssignmentRequired` toggle (the CLI's
`app assignment-required` has no page), no removal or disabling of app roles and scopes
(decision 83), no paging anywhere (decisions 63 and 80), no platform-wide audit page
(decision 82), no way to change a tenant's default domain (decision 76), and no break-glass
path if the signing keys or the root tenant are broken. Everything else the CLI can do to
tenants, users, groups, applications, assignments and keys now has a page.

**89. A teeth check that did *not* bite, reported rather than buried.** Breaking the
tenant scoping inside `groups::find_by_id` -- the defence-in-depth layer -- left the groups
isolation test passing, because `AdminContext::require` refuses the request before the
lookup runs. That is the layering working as intended, but it meant the second layer was
untested, so `a_group_lookup_is_scoped_to_its_tenant_whatever_the_id` now tests it
directly, and that test does fail when the scoping is broken. The same is true of the
tenant id in every other domain function's `WHERE`: the gate is what the HTTP tests prove.


---

## Admin console: the flow tester (`/admin/tenants/{tenant}/flow`)

**90. The landing page is a readiness check, not a form with a Go button.** The
instruction was to "make the landing page of the flow explicit, what I need to configure as
what to test it", and the diagnostic value is the whole feature: the compat suites already
cover machine-driven fidelity. So the page states, item by item, what the chosen
application and flow need (`flowtest::Requirement`), what is configured now, and what to
change, and it offers to run the flow only when nothing is missing. Twelve requirements:
the service principal, the callback, the platform it is registered under, the client
secret, both front-channel toggles, `openid`, whether the scope resolves, user assignment,
the password grant, how the response gets back, and who redeems the code. Each one is
re-derived from the function the server itself uses -- `scopes::resolve` for the scope,
`apps::redirect_uris` for the callback -- so the page cannot drift from the endpoint it
describes.

**91. Running a flow is `App:Read`; registering anything is `App:Write`.** A flow test
changes no configuration, and the tokens it produces are the ones the person signing in
could already get from any browser: the authorize endpoint makes them authenticate there,
and the console session is no help at all. So a Global Reader can diagnose, which is the
role most likely to be handed to somebody debugging an integration. The two operations that
*do* change a registration -- adding the callback, registering the test client -- are
`App:Write`, like every other registration change. `tests/admin_flow.rs::a_reader_can_diagnose_but_not_register_anything`
holds both halves of that. **If you would rather a reader could not mint tokens at all,
`FlowOp::Start.action()` is the one line to change.**

**92. No silent configuration change, and the callback addition reuses the ordinary audit
event.** Registering `{base}/admin/flow/callback` on a real application is a button with its
own confirmation text, and it writes `admin.app.redirect_uri.add` with
`details.purpose = "flow_test"` -- not a flow-tester-specific event -- because an auditor
asking "what redirect URIs were added to this app" must see it. It then appears in the
applications section like any other redirect URI, where it can be removed. Registering the
test client likewise writes `admin.app.create` and `admin.app.redirect_uri.add`.

**93. The per-tenant flow tester client is registered as a `publicClient`.** That is what
makes it the zero-side-effect path *and* the complete one: a public client authenticates
with nothing, so PKCE alone binds the code, and the console can redeem it for real. A `web`
test client would have needed a secret the console cannot read (decision 97), and an `spa`
one would only be redeemable as a cross-origin request. One per tenant, recorded in
`flow_test_clients`; it is an ordinary application object, visible and deletable in the
applications section, and if it is deleted the console offers to create another.

**94. `form_post` for any response type that carries a token, and fragment mode is shown
rather than driven.** The console's CSP is `default-src 'none'` with no `script-src`
(`src/html.rs`, `src/admin/view.rs`), so there is nothing that could copy `location.hash`
into a form, and a fragment never reaches the server anyway. Rather than add a script or
relax the CSP for a debug page, `form_post` is the default as soon as a token is involved,
`query` with a token is refused on the page before the server has to refuse it, and
`fragment` prints the authorize URL to open by hand and says plainly that nothing will be
captured or checked. A fragment-mode start writes **no** pending row: a row that can never
be answered would only expire.

**95. `reqwest` is now a real dependency, and the token exchange is a genuine HTTP
request.** Features `default-features = false, features = ["rustls"]` (aws-lc-rs, the
provider the rest of the binary already uses); the body is built with
`url::form_urlencoded` and the response parsed with `serde_json`, so `form` and `json` are
not needed in the binary. The dev-dependency keeps `cookies`, `form` and `json` for the
test harness. The client is built with `.no_proxy()` -- an ambient `HTTP_PROXY` must not
put a middlebox between the console and the endpoint it is testing -- and a ten-second
timeout, invented. A debugger that called the handler directly instead would eventually
lie about the layer being debugged; the cost is that a deployment whose own TLS certificate
the process does not trust will show a transport error on the page, which is itself worth
seeing.

**96. `state`, `nonce` and the PKCE verifier are generated server-side, and the pending row
is what stands in for a CSRF token on the callback.** An identity provider's `form_post`
cannot carry the console's token, so the callback cannot be protected the way every other
console form is. Instead: `state` is 32 random bytes, the row is keyed by its SHA-256 (as
`auth_codes` and `device_codes` are keyed by the hash of their code), and the row is bound
to the console session that created it (`admin_session`, with `ON DELETE CASCADE`, so
signing out discards the pending rows). A callback that cannot name a live row belonging to
this session is reported as an error -- never ignored -- and that covers both a replay and
another administrator holding the URL. The callback also re-asks the guard
(`ctx.can_in(APP_READ, tenant)`) rather than trusting the row, because a grant can be
revoked between the request and its answer.

**97. The console cannot complete the token exchange for a `web` client, and says so as a
readiness item.** A web client must authenticate at the token endpoint, and only a SHA-256
hash of its client secret is stored -- deliberately, and it is not going to change. The
alternatives were all worse: asking the administrator to paste a secret into the console,
minting a short-lived secret on a production app as a side effect of a debug action, or
storing a test client's secret in clear. So the front channel is tested end to end (every
check on an ID token delivered there still runs), the exact token request is printed with
`client_secret=<the secret you hold>` for the administrator to run, and the readiness list
names the two ways to exercise the redemption too: the tenant's flow tester client, or a
callback registered under `spa`/`publicClient`. **This is the one readiness item that the
stored data does not permit implementing, and the only part of the feature where the
console stops short.**

**98. The password grant is a readiness item only.** It needs both the client secret the
console cannot read and a user's password, and an administration page is not where somebody
should be typing a user's password. So the page reports `allow_password_grant` and where to
change it, prints the request to run by hand, and has no password field anywhere -- which
`the_password_grant_is_reported_but_never_driven` asserts by looking for
`type="password"` in the rendered page.

**99. The resource's own `app_role_assignment_required` is reported but not enforced, and
the page says which.** This server checks assignment on the *client's* service principal at
`/authorize` (`routes::authorize`), not on the resource's. Both are shown: the client's as
a pass/fail checked against the administrator's own account (the likely signing-in user,
and the only one the console can check), the resource's as a note saying it will not refuse
the token here. Hiding the difference would make the page lie about the server; "assignment
required" with no indication of *where* would make it useless.

**100. A hybrid flow's two ID tokens are both kept.** The one delivered in the front
channel carries `c_hash` over the code beside it -- the only check that binds the two -- and
the one from the token endpoint does not. Collapsing them into one "ID token" section threw
that away, so the result page renders a list of tokens, each headed with what it is and
where it came from.

**101. Nothing from a flow test reaches the audit log but the outcome.** `admin.flow_test.start`
records the response type, the response mode, the clipped scope and whether the response
will be captured; `admin.flow_test.result` records the response type, the mode, an
`Outcome` and how many checks failed. No state, no nonce, no verifier, no code, no token,
no claim value -- and `a_code_flow_runs_end_to_end_and_every_check_passes` asserts that by
scanning *every* `details` value in the table for `eyJ`, `state`, `nonce` and
`code_verifier`. This follows decisions 17-18 and the rule in `src/routes/audit.rs`.

**102. The pending row lives ten minutes, is single use, and is deleted before the exchange
is made.** Ten minutes because that is the authorization code's own lifetime, so keeping it
longer buys nothing. Single use is enforced by taking the row with a `DELETE` whose
`rows_affected` must be 1, so two simultaneous callbacks cannot both proceed. Tokens are
never stored at all: the exchange happens inside the callback request and the values exist
only in that response, which is `no-store` like every console page -- the same shape as the
one-time secret reveal in the applications section.

**103. `ResponseType` and `ResponseMode` are now public, and `response_mode` parsing goes
through the enum.** The flow tester offers the same closed sets on a form and has to spell
them back into a request, and there must be one list. Making `ResponseMode` an enum with
`parse`/`as_str` also removed four bare `"query"`/`"fragment"`/`"form_post"` literals from
`routes::authorize`, which is the standing no-magic-values rule; the behaviour, including
the two error messages, is unchanged.

**104. Signature verification uses `verify_ignoring_expiry`, so `exp` is its own check.** An
expired token's signature is still either right or wrong, and reporting "signature failed"
for a token that merely expired would be the kind of misleading diagnosis this page exists
to prevent.

**105. What the flow tester does not do.** No device-code flow (it has its own pages and no
redirect URI to test), no refresh-token redemption, no client-credentials grant (there is no
browser in it, so there is nothing to drive), no `login_hint`, no `max_age`, no multiple
resources, and no history: a result page exists once and is not stored anywhere it could be
read again.

**106. A remedy is a link where there is a page to link to.** `Finding::fix` names the
place (`Fix::ApplicationPage`, `Fix::CallbackSection`, `Fix::ThisForm`) and the page builds
the link, so the readiness list answers "where do I change it" with an anchor rather than
only prose -- without `flowtest` learning any console URLs. The application's own page now
links the other way too, into the flow tester for that application.

**107. The client-secret requirement counts a certificate credential as well.** A web
client may authenticate with `private_key_jwt`, and the first version of the check said
"secret or certificate" in its failure text while only looking at `app_secrets`. It now
reads `app_key_credentials` too and says which of the two it found.

**108. Three teeth checks, all of which bit.** (a) Deleting the callback's own
`ctx.can_in(APP_READ, &tenant)` made
`the_callback_refuses_a_tenant_the_administrator_may_no_longer_read` fail -- it served the
full result page, with another tenant's user's claims in it, as `200`. (b) Dropping
`AND admin_session = ?` from `flowtest::take` made
`another_administrators_session_cannot_complete_a_flow_test` fail: the second
administrator read the first one's tokens. (c) Removing the `require` from `flow::post`
made `a_tenant_admin_cannot_flow_test_another_tenants_app` fail on the first POST it tried.
Each was restored and the suite re-run.

That third test only bites because it was **rewritten** after the first version did not.
Revoking the administrator's only role binding makes `AdminContext` answer `no_access`
before any handler runs, so the callback's own check was never reached and the test would
have passed with the guard deleted -- decision 89's trap exactly. The administrator now
keeps a binding on a second tenant, which is what makes the `403` the callback's own answer,
and the test asserts afterwards that the console session still works.

---

## Assignment required: enforced on every user grant

**109. "Assignment required" is now checked where every user grant ends, not only on the
authorize page.** It was enforced in exactly one place, `src/routes/authorize.rs`, so the
rule an administrator sets to block unassigned users did not hold for the password grant
or the device code grant, and a refresh token kept working after its holder was
unassigned. Confirmed by a probe before fixing: the password grant returned HTTP 200 with
an access token for an unassigned user on an app that required assignment. The check now
lives in `user_grants::issue`, the one function every user grant passes through, so it
cannot be routed around by choosing a different grant. Found by reading the flow tester's
readiness output, which surfaced that the rule was enforced in only one place.
*To reverse:* delete the block in `issue` — which reopens the bypass.

**110. The token endpoint answers `invalid_grant` with AADSTS50105.** The message text is
the same one the authorize page already used, now produced by a single function
(`apps::not_assigned_message`) so the two sites cannot drift. `invalid_grant` is what this
codebase uses for every other "this grant cannot be honoured" case at the token endpoint;
**the pairing of that OAuth error with 50105 is not verified against a live tenant**, the
same caveat as decisions 16 and the 429 number.

**111. Unassigning a user now cuts off their refresh token.** A consequence of 109 rather
than a separate choice, but it changes behaviour: previously a refresh token survived
unassignment until it expired. That is the point of unassigning someone, so it is the
intended outcome.

**112. NOT changed: assignment is still enforced on the *client's* service principal only,
never the *resource's*.** Entra is reported to enforce "assignment required" on the
resource API's service principal too, so that an API owner can restrict who may obtain a
token for it. That may be a real access-control gap here. I did not change it, because it
would alter which users can get tokens for which APIs on the strength of an Entra behaviour
I have not verified — and asserting Entra behaviour from memory has been wrong twice in
this project already. It needs checking against Microsoft's documentation first. The flow
tester's readiness page already reports this limitation rather than hiding it.

## Flow tester: a runnable command and a fresh sign-in

**113. The request the console cannot make is printed as a curl command, not as raw HTTP.**
It runs as pasted once one `export` line is filled in. The secret is read from an
environment variable named after the application (`Hello World` gives
`HELLO_WORLD_SECRET`, falling back to `CLIENT_SECRET` when the name has nothing usable and
prefixed `APP_` when it starts with a digit), so the secret never appears in the command
or in shell history as part of it. Every other value is single-quoted with `'` escaped,
because a command meant to be pasted must not let a value leave its quotes; that is
checked against a real shell, and the whole printed command is run with a real `curl`
against the test server in the integration test. The password-grant block gets the same
treatment, with `ROPC_USERNAME` and `ROPC_PASSWORD` (names invented).

**114. "Forget this sign-in" ends the browser's session with the tenant.** The authorize
endpoint remembers a sign-in, correctly, so a second flow test went straight through
without the sign-in page. The landing and result pages now say whether this browser is
signed in to the tenant and as whom, and offer a button that ends that session. It needs
`App:Read`, the same as running a test: it ends only the browser's own session, which the
logout endpoint would do anyway. It leaves the console session alone and writes
`session.end` with the administrator as actor. `prompt=login` on the form remains the
protocol's own way to force a sign-in; the button is for testing from a genuinely clean
state. *To reverse:* remove `FlowOp::ForgetSignIn`.

**115. The flow tester has one settings form, and Start belongs to it.** Start used to be
a separate form carrying the last-checked settings in hidden fields, so choosing a prompt
and pressing Start ran the flow without it: `select_account` showed no account picker and
looked broken. The Start button now belongs to the settings form by the `form` attribute
and submits what is on screen. Check became a post that redirects to the same readable
GET page. The page also says that `prompt=consent` shows nothing, because this server
has no consent screen. Verified on SQLite only, at the user's request (see 116).

**116. From here, commits are verified on SQLite only.** The user asked to skip the
Postgres and MySQL runs for now because they take 12-20 minutes each time. Both
deployments run SQLite. The last three-engine pass is commit `ccc02c1`; anything touching
SQL or migrations after it is unverified on the other two engines until that run is made
again.

## Consent page

**117. `prompt=consent` shows a consent page; nothing else does.** The page names the
application, the person, and every scope with what it means, and offers Allow and Deny.
Applications are still treated as consented by an administrator, so an ordinary sign-in
has no extra step and no existing client changes behaviour. **No grant is stored**: Allow
is not remembered, because the page appears only when asked for. This is a smaller thing
than Entra's consent framework, which also prompts on first use, records grants per user
and has an administrator-consent path; those remain a gap. *To extend:* store grants and
show the page when a requested scope has none.

**118. Deny answers `access_denied` with AADSTS65004**, delivered to the redirect URI in
the request's own response mode with its `state`. The wording is Entra's; **the number is
our guess**, marked so in the `Aadsts` enum like 700054 and 90055.

**119. `prompt=none consent` is refused**, like `none login`: a page cannot be both
required and forbidden.

**120. With `prompt=login consent`, the consent answer does not ask for the sign-in
again -- but only within ten minutes of that sign-in.** Otherwise posting a consent answer
would be a way around `prompt=login` on an old session. The ten minutes is invented.

**121. A sign-in now sets the session cookie on whatever follows it, a page as much as a
redirect.** It was attached only to a redirect, which never mattered while the only page
that could follow a sign-in was an error. The consent page follows one and has to find the
browser still signed in when it is answered. Found by the consent tests.

**122. Scope wording lives beside the list of OpenID scopes** (`scopes::oidc_description`),
with a test that every scope has its own, so one added later cannot reach the consent page
with the fallback text. A resource's own scopes use the display name its owner gave them.

## Token claims: ids beside names

**123. `group_ids` and `role_ids` are emitted beside `groups` and `roles`, same members,
same order.** `groups` here has always been names (decided at the start, against Entra,
which emits object ids) and `roles` is app role values. An application that wants a key
that survives a rename reads `group_ids[i]` for `groups[i]`. Both lists are built from one
ordered query (by name or value, then id), so they cannot fall out of step; neither appears
when its names are absent. These two claims are this server's own and do not exist in
Entra. They are in user tokens (ID and access) and application tokens.

## Console: tabs, the tenant in view, and platform roles

**124. The tabs follow the page, not the session.** There were ten links in one row,
always, built for whichever tenant the session defaulted to. Now a page is either at the
platform level (tabs: Tenants, Signing keys, Platform roles) or inside one tenant (that
tenant's tabs, built for that tenant, with a way back to the list). No tenant tab is
offered while no tenant is in view. The tenant in view is named in the top right.

**125. A platform administrator starts with no tenant in view.** After sign-in someone
with an every-tenant reach lands on the list of tenants; the root tenant is no longer the
default context. Someone whose roles are all inside a tenant lands in their own tenant.
Opening a tenant is following its name in the list. Assume is still there, and still
audited, but is no longer needed to work in a tenant.

**126. A tenant's name, domains and availability moved to its Settings tab.** They were
forms inside the cells of the tenants table. They still post to the tenants page, which
owns those operations and their platform-scope check, and return to Settings. Enable stays
on the list, because a disabled tenant has no pages of its own to enable it from.

**127. Add-forms are folded behind their label** (`<details>`, no script), so a page reads
as its tables. One is shown open when it comes back with an error. A table with no rows is
replaced by a sentence; that is done once, where a page is assembled, rather than at each
table.

**128. Platform roles can be granted and revoked from the console.** The page was
read-only. A grant names an account by its sign-in name (the tenant is found from the part
after the @), a role, and where it applies: every tenant, or the tenants ticked. Both rules
are the existing ones in `authz`: nobody grants reach they do not hold, and the last
binding that can administer the platform cannot be revoked. These events are written to
the root tenant's audit log. Groups are granted roles from their tenant's Roles tab.

**129. Visual direction.** One accent (petrol) for actions; amber is used for exactly one
thing, the tenant in view. System fonts only, because the content security policy allows
no web fonts; a monospace stack for identifiers, which are machine strings. Table headings
are sentence case. Left-aligned under the tabs rather than a centred column. Checked with
screenshots in light, dark and at phone width.

**130. A new user is named by the part before the @ and a picked domain.** The tenant's
verified domains are offered beside the box. Typing a whole name works too, and then the
picker hides itself: the box carries a pattern a name with an @ does not match, and the
stylesheet hides the picker beside a non-matching box. No script. The form is `novalidate`
so that pattern never blocks a submit; everything is checked again on the server, where a
domain this tenant has not verified is refused whichever way it arrived.

**131. A new user's email starts out as their user name.** Email is a contact address and
is not required; left empty at creation it is set to the user name, and the form says it is
not the sign-in name. Clearing it later on the edit page leaves it empty.

**132. Find by id, limited to what the reader could open anyway.** A box in the header
says what an id is: user, group, application (object id or client id), service principal,
app role, scope or tenant. An object is reported only if its tenant is one the
administrator's roles read with the action that kind needs; anything else gets the same
answer as an id that does not exist, so the search is not a way round the tenant boundary.

**133. The audit log shows names, under the same limit.** Actor and target are shown by
name, linking to the find page, with the id as the tooltip. An actor from a tenant the
reader cannot read, such as a platform administrator acting in theirs, stays an id.

**134. The tenant ticks on the platform role form show only when they apply**, and
**assuming a tenant goes into it** rather than back to the list.

**135. Only the root tenant's accounts and groups reach beyond their own tenant**
(user's rule, 2 Oct). A principal of any other tenant can hold roles in its own tenant
and nowhere else. It is enforced in two places, neither of them a page:
`bindings::create` refuses the grant inside the transaction that writes the row
(`ReachRefused`), and `bindings::effective_for_user` clips every scope to the user's own
tenant on read (`Scope::held_by`), so a row that arrived some other way (older build,
restore, hand edit) grants nothing extra. The rule itself is two functions on `Scope`
in `src/rbac.rs`. Both halves are teeth-checked in `tests/rbac_reach.rs`. A grant to a
principal that does not exist is now refused too. *Not done:* a database trigger or
CHECK; the rule needs a join to `tenants` and would have to be written three times, once
per engine. *To reverse:* make `may_be_held_by` return `true` and `held_by` return `self`.

**136. The Platform roles page names each principal's tenant** in its own column, and
marks any stored binding the rule above leaves without effect.

**137. An assumed tenant is left with Leave only.** The "All tenants" link is shown for
a tenant that was opened, not for one that is assumed.

**138. The console roles are redefined** (user's design, 2 Oct), replacing the
Entra-shaped set, which overlapped and did not say what each could do. Nine roles:
Global Administrator (everything, outside tenants and in every one); Tenant
Administrator and Tenant Viewer (everything in a tenant, or seeing all of it); and an
administrator and a viewer each for users, groups and applications. A viewer holds
only read actions; the three narrow kinds share no action. Gone: Global Reader, Cloud
Application Administrator, Privileged Role Administrator, Platform Administrator.
Mine within that: only the tenant roles read the audit log and manage roles; the
stored id `GroupsAdministrator` is kept (shown as "Group Administrator").

**139. Where a role applies is never chosen** (user's rule, superseding 135's
"named tenants"). Global Administrator is everything and can be held only from the root
tenant; every other role applies to the tenant its holder belongs to. It is one
function, `RoleId::scope_held_by`, enforced in `bindings::create` (`ScopeRefused`) and
on read in `effective_for_user`. No form asks for a scope or a tenant. Consequence: a
root-tenant account can no longer be, say, User Administrator of another tenant; it is
Global Administrator or nothing there. *To reverse:* widen `scope_held_by`.

**140. `wids` keeps Entra's ids.** In a tenant's tokens a Tenant Administrator (and a
Global Administrator) is Entra's Global Administrator, a Tenant Viewer is Global
Reader, and the user, group and application administrators keep their own template
ids. The three narrow viewers have no Entra counterpart and are not in `wids`.

**141. The flow tester needs `App:Write`**, every operation of it, so it belongs to
Application Administrator (and above) and no viewer has it. Before, any reader of
applications could run it.

**142. Existing bindings are migrated in place by `0012_console_roles`**: platform role
folded into Global Administrator; tenant-scoped Global Administrator and Privileged
Role Administrator become Tenant Administrator; Cloud Application Administrator becomes
Application Administrator; Global Reader becomes Tenant Viewer; every non-global
binding is cut to its holder's own tenant, and what then applies nowhere is deleted.
Dry-run on copies of both live databases: nobody lost anything. **Not run on Postgres
or MySQL** (SQLite-only testing for now); the SQL is identical on all three and written
to avoid MySQL's same-table subquery limit, but that is untested.

**143. A tenant has one domain, and it is changed, not added to** (user's decision,
2 Oct). `tenant::change_domain` swaps the domain and renames every account in one
transaction (`alice@old` to `alice@new`); ids, passwords, groups, roles and assignments
do not move. Mine: a contact email that was just the user name follows it, any other is
left alone; soft-deleted accounts are renamed too (they still hold their name); it is a
Global Administrator's operation, like the other tenant-level changes. No schema
constraint enforces "one": the gateway's root tenant already has two, and a unique index
would have stopped that database from starting. Such a tenant is shown its domains, can
withdraw unused ones, and is brought to one by a change (refused if two accounts would
collide). The old domain stops working as a tenant alias in URLs.

**144. The last person who can act as Global Administrator cannot be removed, by any
route** (after the user deleted the last one on the gateway). The old rule counted
bindings; this one counts live, enabled root-tenant accounts holding the role directly
or through a group, inside the transaction of every change that could take one away:
deleting or disabling a user, revoking a binding, removing a group member
(`admin::lockout`). Separately, the console refuses deleting or disabling the account
one is signed in with. `rust-oidc user restore` un-deletes an account from the host,
the way back in if it happens anyway.

**145. An empty group can be deleted**, taking the console and app roles granted to it.
One with members is refused: there is no confirmation step in a script-free console, so
emptying it first is the confirmation.

**146. Users and groups are assigned to an application, and roles are ticked on the
assignment** (user's design, 2 Oct). Before, a person was "assigned" only by holding at
least one app role, so an application with no roles could have nobody assigned. Now
`app_assignments` holds who is assigned; `app_role_assignments` holds the roles they
were given, which may be none. `apps::assign` sets the whole role set in one
transaction, and assigning again is how roles are changed. "Assignment required" checks
the assignment; the `roles` claim is unchanged. Entra's own model is the same idea with
a "Default Access" role id standing for no role; a separate table says it without a
magic id. Mine: roles for *client applications* (application permissions) stay one row
per role, in their own section of the page; granting one role the old way (CLI) also
assigns. `0013_app_assignments` assigns everyone who already held a role; not run on
Postgres or MySQL.

**147. User and group operations work on many rows at once** (user's request). The
users list, the groups list and a group's members each have a tick box per row and one
in the heading meaning "every row listed", with buttons underneath: enable, disable,
delete, add to a group; delete groups; remove members. A group takes several user names
at once, and a user's groups are tick boxes saved together. No script: the boxes join a
form by the `form` attribute, and the heading box is a field the server reads. Mine:
each row goes through the same storage function, rules and audit entry as a single
change, so some may be refused while others succeed and the page says which and why;
bulk deletes need a "confirm" tick; "all" on the users list means the rows the current
search listed.

**148. Each role view shows only its own grants** (user's request). The global page
("Global roles") lists and revokes only Global Administrators and grants only that; a
tenant's Roles tab lists and revokes only what is bound to that tenant. A tenant role is
therefore granted inside the tenant and no longer from the global page by account name.

**149. A Configuration tab in the global view** (user's request): the addresses an
outside application is configured with (with `{tenant}` as placeholder, and each
tenant's own issuer and discovery link) and what the server supports. Mine: read-only,
for a Global Administrator, and built from `routes::discovery::Endpoint` and the lists
beside it, which the discovery document now uses too, so the two cannot disagree. I
read "external integrations" as what a client needs; server settings (database, TLS,
rate limits) are not on it.

**150. UI round (user's list, 3 Oct).** Assume tenant is removed: opening a tenant is
how one works in it (the session column stays, unused). Destructive actions ask first
in a dialog built on the HTML popover attributes, so the console stays script-free;
bulk dialogs show how many rows are ticked by CSS counters. The application page is
split into Entra's sections with an overview of tiles. Global Administrator can be
granted to a group of the root tenant, and a user by the part before the @. Find by id
shows deleted users, applications and groups read-only, and restores users. Mine:
groups are still deleted outright, and a `deleted_groups` row records what they were,
because the original `UNIQUE (tenant_id, name)` on every engine would make a
soft-deleted group's name unusable; a deleted group is not restorable.

**151. MFA with an authenticator app (TOTP, RFC 6238)** as agreed on 3 Oct: secrets
stored as is in `user_totp` (the user's decision), recovery codes hashed, ten at a
time, each once; a user setting (Default / Required / Not required) over a tenant
switch, plus per-application "Require MFA" and a per-tenant console switch. Anyone
enrolled is asked at every sign-in; anyone required but not enrolled sets one up at
that sign-in and is then signed out. Mine: codes are accepted one 30-second step either
side and never twice (the last step is stored); five wrong codes end the sign-in; the
second step is a ticket in `mfa_pending` (ten minutes) rather than a half-made session,
so nothing is signed in before the second factor; an existing session without `mfa`
is stepped up for an app or user that needs it, without the password again;
`prompt=none` answers `interaction_required` with AADSTS50076/50079; the password grant
and refresh tokens are refused with `invalid_grant` and the same numbers when the
sign-in they carry had no second factor; `amr` becomes `["pwd","mfa"]`. "Require MFA"
on an application is checked for the client being signed in to, not for the API in
the scope. An admin reset removes the authenticator and codes and ends the sessions.

**152. "Must choose a new password at next sign-in"**: an admin reset sets it by
default (a ticked box), as does creating an account in the console; the CLI has
`--require-change`. The change page comes after the password and any second factor and
before any session or token; the password grant gets AADSTS50055. **Password history**:
per tenant, default 3, 0-24, kept as Argon2 hashes (24 per user); an admin's temporary
password is exempt, every other new password is checked. Mine: any new password ends
the user's sessions and refresh tokens, as resets already did.

**153. My Account** at `/{tenant}/myaccount`, as agreed: profile read-only; change
password knowing the current one; set up an authenticator voluntarily; replace it after
confirming with a current code or a recovery code; new recovery codes after an
authenticator code (a recovery code is refused for that); sign out everywhere. Mine: it
signs in with the tenant's own browser session, so a user signed in to an application
is signed in here, under the same steps (second factor, forced change); a voluntary
set-up keeps the user signed in (only a set-up at sign-in signs them out); a password
changed here ends every other session and keeps this browser's; the address is on the
Configuration page. Forgot-password is out (no mail).

**154. Signing in to an application of another tenant** (user's design, 3 Oct): the
application accepts other tenants (a switch that cannot be turned off while any of
theirs are assigned), the account is assigned directly or through a group of its own
tenant (named `name@domain`, flagged "membership managed by"), and the account's own
tenant lets it: a tenant default (off) and a per-user Default / Allow / Disallow. One
function, `access::decide`, answers it for browser, device code, password grant and
every token (so a refresh stops when a lever changes) and for the console's Check
sign-in tool. Mine: the password is checked in the account's own tenant; MFA, lockout,
forced change and password history are its own tenant's; the token is issued by the
application's tenant with `idp` = the home issuer and `acct` = 1, no `groups`, no
`wids`; `oid` stays the account's own (Entra gives guests a new one); refusals are
AADSTS50020, 50105 and 500213 (the last our guess). An unassigned or refused user is
now refused right after the password, before any second step or session.
Check sign-in says only "not assigned" about another tenant's account that is not
assigned here.

## Housekeeping

**22. `Amr` is stored as strings, not parsed into the enum.** A token minted by an
older build must not be dropped for naming a method this build does not know. The enum
produces values; it never parses them back.

**23. `KeyStatus` binds its value into SQL instead of inlining the literal**, which
also routed two queries through `db::q` that had bypassed it — they only worked on all
three engines because they happened to carry no placeholders.

**24. Migration numbering:** `0009` audit indexes, `0010` implicit flow, `0011` the flow
tester's two tables, MFA reserved `0012`. Renumbered three times as work landed ahead of it.

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

## Transactions: every change through one engine (`src/txn`)

The design was agreed with the owner (see `TODO.md` and `AGENT.md`). These are the
choices made while building it that the owner did not make explicitly.

**29. A transaction declares its locks; the engine takes them, sorted, before it
runs.** The agreed design had each transaction take its own locks as it went, in a
fixed order. The first batch test showed why that is not enough: in a batch, a later
transaction may need a lock that sorts before one an earlier transaction already
holds (enable account B, then disable account A, needs the Administrators lock after
B's row). So each transaction still names its own locks (`Transaction::locks`), and
the engine takes every lock of the run or the whole batch up front, sorted by
`LockTarget`'s derived order (kind, then id) and each once. Two transactions can then
never wait on each other in a cycle; a lock not granted within 5 s is `Busy`. A
transaction that names an account by user name (resolved only inside it) locks the
account's tenant instead. *To reverse:* give `Cx` a `lock` method again and accept
that batches must be ordered by hand.

**30. Global rules are checked at the end and by the storage layer.** The engine
checks the last-Global-Administrator rule once, against the final state. The storage
functions that can remove one still check it themselves, inside their own savepoint,
so a batch "grant B, then revoke A" works and "revoke A, then grant B" is refused at
its first step. *To reverse:* drop the per-function checks; the engine's check alone
then decides.

**31. Passwords are checked and hashed before the transaction**, by
`users::prepare_password` (length, history, hash) or `NewPassword::for_new_account`.
Checking against the remembered passwords is outside the transaction too, so two
changes at the same instant could both pass the history rule; that race is accepted.
A transaction is only ever given a `NewPassword`, never a plain password.

**32. Setting a user's groups on their page writes one audit row**,
`admin.user.groups`, on the account, listing the groups joined and left: one change,
one row. It used to write one `admin.group.member.add`/`remove` row per group. Adding
several user names to a group from the group's page is still one transaction (and one
row) per name, as with every bulk button.

**33. The command line's audit rows use the console's event names.** A CLI change is
the same transaction as the console's, so it records the same event (`admin.user.create`
rather than `user.create`), with actor `cli`. The old CLI names stay in `Event` so old
rows still read back.

**34. Tenant transactions: the tenants page's changes are authorized at platform scope
in the engine too, and name the tenant by id.** Create, rename, enable, disable, change
domain and remove domain run as `Scope::Platform` transactions (an every-tenant grant),
the same rule the page has always applied (`On::Platform`), rather than
`Scope::Tenant`, which would let a tenant's own administrator rename or re-domain their
tenant through any other caller of the engine. Saving settings stays
`Scope::Tenant`. These transactions take the tenant's id only (the lock is on that
row); a domain in its place is refused as not found. Disabling declares the
administrators lock, since it can take administrators away. *To reverse:* change
`scope()` in `src/txn/ops/tenants.rs`.

**35. A user's own changes (My Account, and the forced password change and MFA
set-up at sign-in) are transactions run as the user** (`Actor::User`,
`Scope::Own`). What changed with it: their audit rows belong to the user's *home*
tenant, also when they signed in to another tenant's application; `mfa.enrolled`
always records `voluntary`; "sign out everywhere" records its own event,
`session.end_everywhere` (it was `session.end` with `everywhere: true`); replacing
recovery codes is refused without an authenticator; and a database error while
changing a password shows the error page rather than the raw error in the form.
Recovery codes are generated (and hashed, SHA-256) before the transaction, like
passwords.
