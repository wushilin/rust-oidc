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
| C | **Rate limiting**: none exists anywhere in the project, and unauthenticated callers can append audit rows. Needs limits, scope and storage chosen. | Real gap, its own piece of work, and the limits are a product decision. |
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
