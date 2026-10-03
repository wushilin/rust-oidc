# OpenID conformance: results and accepted deviations

This records what the official OpenID Foundation conformance suite reports against
rust-oidc, and which of its complaints we accept rather than fix. It is derived from
the three plan exports in `~/.cache/rust-oidc-conformance/results` (latest run
**30 Sep 2026**, superseding 29 Sep): the basic, config and form_post certification
plans. `compat/conformance/README.md` covers how to run them.

Every module not listed below passed cleanly.

**What the suite actually tests.** `compat/conformance/run.sh` points the suite at the
*deployed* service (`https://gate.wushilin.net:9443/rust-oidc`), not at a binary built
from the working tree. At the 30 Sep run that deployment still advertised
`"response_types_supported": ["code"]`, so it predates commit `bc217fa` (implicit and
hybrid response types). Every result below is therefore evidence about the deployed
build, not about `HEAD`. The implicit/hybrid work is covered by `tests/implicit_flow.rs`
instead, and the certification plans used here exercise only `code` in any case.

## Why there are accepted deviations

rust-oidc's overriding goal is to behave like Microsoft Entra ID v2.0 at the protocol
level. Entra itself is not a certified-clean OIDC OP: it emits extra claims and
omits others. Where the suite's expectation and Entra's behaviour disagree, we follow
Entra and record the divergence here. A deviation is only acceptable if it is Entra's
behaviour — not merely convenient for us.

Entra's behaviour is asserted below from documented behaviour and from what our compat
suites observed, not from a live capture of Entra for each individual claim. Items
marked (*unverified against a live tenant*) would benefit from a real Entra capture
before certification is claimed publicly.

## Accepted: extra and missing id_token claims

| Suite check | What it says | Why we accept it |
|---|---|---|
| `EnsureIdTokenDoesNotContainNonRequestedClaims` | id_token contains non-requested claims `oid`, `tid`, `uti`, `ver` | These are core Entra v2.0 claims, present in every Entra id_token. Removing them would break every client that reads `tid`/`oid`. Emitted at `src/routes/token.rs:547-554`. |
| `EnsureIdTokenDoesNotContainEmailForScopeEmail` | `email` appears in the id_token although the suite did not request it via `claims` | Entra puts `email` in the id_token when the `email` scope is granted, without needing a `claims` request. |
| `ValidateIdTokenACRClaimAgainstAcrValuesRequest` | `acr_values` was requested so the server SHOULD return `acr`, but did not | **Resolved 2026-10-04 (not yet re-run):** `acr` is now emitted and `acr_values` honoured — see below. |

Note the spec language: `acr` is a SHOULD, and the suite raises these three as WARNING,
not FAILURE. They do not block certification on their own.

**`acr` was decided by the owner on 2026-10-04: emit it, and honour `acr_values`.**
Two levels: `"1"` = password, `"2"` = password + a second factor, advertised in
`acr_values_supported` and derived from `amr` (`src/claims.rs`, `Acr`). Asking for
`acr_values=2` makes an account without an authenticator set one up at that sign-in,
and a password-only session is stepped up. The suite asks for values of its own
(e.g. `1 2`), so the first known one is taken and unknown ones are ignored; the next
conformance run should turn this warning into a pass. Entra itself does step-up with
Conditional Access authentication contexts (`acrs`), not `acr`; this is a deliberate
divergence (decision 38).

## Accepted: minimal userinfo response

Two checks complain about the userinfo response shape:

- `VerifyScopesReturnedInUserInfoClaims` — "'claims' in userinfo doesn't contain all
  scope items of scope in authorization request"
- `EnsureUserInfoContainsName` — "name not found in userinfo" (in `oidcc-claims-essential`)

`src/routes/userinfo.rs:86-104` returns `sub`, plus `name`/`family_name`/`given_name`
for the `profile` scope and `email` for the `email` scope. The suite wants the full set
of standard claims implied by each scope — `preferred_username`, `updated_at`,
`email_verified`, `locale`, and the rest.

**We accept this and do not enrich userinfo.** Entra's v2.0 userinfo endpoint is
likewise minimal; adding OIDC standard claims that Entra does not return would move us
away from the primary goal to satisfy a suite warning. This reverses an earlier note in
this project's queue that treated the missing claims as a gap to close — the claims are
absent because Entra omits them, not by oversight. (*unverified against a live tenant*)

`EnsureUserInfoContainsName` has a second cause: that module asks for `name` as an
essential claim through the OIDC `claims` request parameter, which rust-oidc ignores
(as Entra does — Entra drives optional claims from the app registration, and uses
`claims` for claims challenges/CAE instead).

## Accepted: access tokens survive authorization-code replay

`oidcc-codereuse-30seconds` / `EnsureHttpStatusCodeIs4xx`: after an authorization code
is replayed, the suite expects the access token issued from the first use to be
rejected at the resource endpoint.

rust-oidc revokes the **code family** on replay — the refresh token and session are
killed (`revoke_code_family` in `src/routes/user_grants.rs`), which is the security
property that matters. It cannot retract an already-issued access token: those are
self-contained JWTs validated offline against the JWKS, with no introspection round
trip, so they remain valid until they expire. Entra is architecturally identical here.
Shortening access-token lifetime is the only lever, and it is a tenant setting.

## Manual review items (not defects)

Four modules end in REVIEW because the suite requires a human to upload a screenshot:

- `oidcc-ensure-registered-redirect-uri` → `ExpectRedirectUriErrorPage`
- `oidcc-max-age-1` → `ExpectSecondLoginPage`
- `oidcc-prompt-login` → `ExpectSecondLoginPage`
- `oidcc-response-type-missing` → `ExpectResponseTypeMissingErrorPage`

The server behaved correctly in all four; the screenshots are a certification-submission
step, not something the automated run can clear.

## Real gaps

### Request objects are not supported (2 failing modules) — accepted, not a gap

`oidcc-ensure-request-object-with-redirect-uri` and
`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` fail.

rust-oidc rejects both parameters explicitly — `request_not_supported` and
`request_uri_not_supported` at `src/routes/authorize.rs:271-287` — and advertises
`request_parameter_supported: false` / `request_uri_parameter_supported: false` in
discovery (`src/routes/discovery.rs:51-53`). The basic certification profile requires
support, so the suite reports `request_parameter_supported must be: true`.

**This was previously recorded here as the one real remaining gap, on the grounds that
Entra supports request objects. That was wrong.** Entra's own v2.0 discovery document
says `"request_uri_parameter_supported": false` and omits `request_parameter_supported`
entirely, which OpenID Connect Discovery §3 defines as defaulting to `false`. Entra does
not accept JWT request objects on the v2.0 authorize endpoint, so our behaviour is
already the faithful one and implementing request objects would move us *away* from
Entra. Accepted, and closed.

The follow-on failures in the unsigned-request-object module
(`CheckCallbackHttpMethodIsPost`, `CheckCallbackContentTypeIsFormUrlEncoded`,
`RejectErrorInUrlQuery`) are consequences of the same choice, not a separate form_post
bug: that module carries `response_mode=form_post` *inside* the request JWT. Since we
never parse the JWT we never see the parameter, so the error is delivered as a query
redirect. Error delivery does honour `response_mode` for every parameter we can actually
see — `Validated::error` routes through `Validated::respond`
(`src/routes/authorize.rs:99-126`), which handles `form_post`.

### Latent trap: the login POST handler discards response_mode and state

`src/routes/authorize.rs:505-514` builds a `Validated` with
`response_mode: ResponseMode::Query` and `state: None`. This is currently harmless:
that value is used only for tenant/client context, login-page rendering, auditing and
`html::error`. The real response is built by `run()`, which re-derives `response_mode`
and `state` from the original request carried in the hidden `request` field.

But any future `v.error(...)` or `v.respond(...)` added to that handler would silently
force a query redirect and drop `state`, breaking form_post clients in a way no current
test would catch.

## Our discovery document vs. Entra's

Compared field by field against the live document at
`https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
(fetched 2026-09-30). This is ground truth for metadata, though **not** for token
contents: Entra's `claims_supported` omits `oid` and `uti`, which it certainly emits,
so the list understates reality.

Exact matches: `scopes_supported` (`openid profile email offline_access`, so the
conformance SKIPs for the `address` and `phone` scopes are faithful, not an omission),
`response_modes_supported`, `subject_types_supported` (`pairwise`),
`id_token_signing_alg_values_supported` (`RS256`), `request_uri_parameter_supported`
(`false`), and the shape of `userinfo_endpoint`.

Equivalent: Entra omits `request_parameter_supported`, `claims_parameter_supported`,
`code_challenge_methods_supported` and `prompt_values_supported`; we state the first two
as `false` (the spec default, so identical in meaning) and advertise the latter two,
which Entra supports without announcing. Advertising a capability we really have is the
better behaviour.

Two real divergences, both found by this comparison rather than by the suite:

| Field | Entra | rust-oidc |
|---|---|---|
| `response_types_supported` | `code`, `id_token`, `code id_token`, `id_token token` | `code` only |
| `token_endpoint_auth_methods_supported` | adds `self_signed_tls_client_auth` | omits it |

**The implicit and hybrid response types are a genuine gap.** Entra supports them, and
the project's goal is that an app written for Entra works here with configuration changes
only — which includes clients configured for `code id_token`. Note how Entra gates them:
they are **opt-in per app registration** (the "ID tokens" / "Access tokens" checkboxes),
off by default. That is the faithful design and it is also the safe one, matching the
precedent already set for ROPC by `applications.allow_password_grant`.

`self_signed_tls_client_auth` (mTLS client authentication) is niche and needs TLS client
certificates plumbed through the listener; recorded, not planned.

## Fixed: harness config gap for client_secret_post

`oidcc-server-client-secret-post` failed with
`GetStaticClientConfiguration: As static client was selected, the test configuration
must contain a client configuration` — before the module ever contacted the server.

This was our harness config, not the server. `OIDCCServerTestClientSecretPost.configureClient()`
does `config.add("client", config.get("client_secret_post"))`, overwriting `client` with
the per-method client block, because most servers restrict a client to a single auth
method. Our generated config had no `client_secret_post` key, so `client` became JSON
null and the static-client check threw.

`compat/conformance/make_config.py` now emits a `client_secret_post` block reusing
client1's credentials. rust-oidc accepts either method on any confidential client
(`client_credentials_from_request`, `src/routes/token.rs:180-210`, which also rejects
presenting both at once with AADSTS50148), as Entra does, so one client covers both.

**Re-run and confirmed on 30 Sep 2026.** In both plans that contain the module it went
from one FAILURE to a clean pass:

| Plan | 29 Sep | 30 Sep |
|---|---|---|
| `oidcc-basic-certification-test-plan` | FAILURE `GetStaticClientConfiguration` | no failure, no warning |
| `oidcc-formpost-basic-certification-test-plan` | FAILURE `GetStaticClientConfiguration` | no failure, no warning |

The module's log shows it now reaches the server: the browser automation fills the
sign-in form, the token request is made with `client_secret_post`, and
`CallProtectedResource` / `EnsureHttpStatusCodeIs200` both succeed. Nothing else
changed between the two runs — a per-module diff of all three plans shows this module
as the only difference.

## Accepted: three Entra extension fields in the discovery document

The config plan raises one WARNING that was present on 29 Sep too but was not recorded
here: `oidcc-discovery-endpoint-verification` /
`CheckForUnexpectedParametersInServerMetadata`, against the RFC 8414 schema. Its
`unknown_properties` list is exactly three fields:

`cloud_instance_name`, `http_logout_supported`, `tenant_region_scope`.

All three are verified present in Entra's own live document (fetched 30 Sep 2026):
`"cloud_instance_name": "microsoftonline.com"`, `"http_logout_supported": true`,
`"tenant_region_scope": null`. They are Microsoft extensions, not spec fields, so the
suite is right that they are unregistered and we are right to emit them. The suite's
own remedy is to name them in `server.allow_unexpected_metadata_fields`, which
`make_config.py` now does — listing the three explicitly, so a *fourth* unregistered
field added by accident in future would still warn.

Re-run to confirm rather than assume: the config plan now reports **0 warnings, 0
failures** (`oidcc-config-certification-test-plan--qjcSXaU5rJG7f-30-Sep-2026.zip`).
That plan is now completely clean.

### Two related divergences found in the same comparison

- **`http_logout_supported` and `frontchannel_logout_supported`: Entra says `true`, we
  say `false`.** Deliberate. Both fields advertise front-channel logout *notification*
  to registered RPs (the logout iframe); rust-oidc implements RP-initiated logout at
  `end_session_endpoint` but does not notify other RPs. Advertising `true` would be a
  false capability claim, which is worse than the divergence. Revisit if front-channel
  logout notification is ever implemented.
- **Entra's other extension fields are omitted on purpose:** `cloud_graph_host_name`,
  `msgraph_host`, `rbac_url`, `kerberos_endpoint`, `mtls_endpoint_aliases`,
  `tls_client_certificate_bound_access_tokens`. The first four name Microsoft's own
  services and would be fabrications here; the last two belong with the unimplemented
  mTLS client authentication recorded above.
