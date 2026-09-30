# OpenID conformance: results and accepted deviations

This records what the official OpenID Foundation conformance suite reports against
rust-oidc, and which of its complaints we accept rather than fix. It is derived from
the three plan exports in `~/.cache/rust-oidc-conformance/results` (run 29 Sep 2026):
the basic, config and form_post certification plans. `compat/conformance/README.md`
covers how to run them.

Every module not listed below passed cleanly.

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
| `ValidateIdTokenACRClaimAgainstAcrValuesRequest` | `acr_values` was requested so the server SHOULD return `acr`, but did not | `acr` is an Entra **v1.0** claim; v2.0 tokens do not carry it. rust-oidc emits no `acr` anywhere, deliberately. (*unverified against a live tenant*) |

Note the spec language: `acr` is a SHOULD, and the suite raises these three as WARNING,
not FAILURE. They do not block certification on their own.

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

### Request objects are not supported (2 failing modules)

`oidcc-ensure-request-object-with-redirect-uri` and
`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` fail.

rust-oidc rejects both parameters explicitly — `request_not_supported` and
`request_uri_not_supported` at `src/routes/authorize.rs:271-287` — and advertises
`request_parameter_supported: false` / `request_uri_parameter_supported: false` in
discovery (`src/routes/discovery.rs:51-53`). That is honest, but the basic certification
profile requires support, so the suite reports `request_parameter_supported must be: true`.

The follow-on failures in the unsigned-request-object module
(`CheckCallbackHttpMethodIsPost`, `CheckCallbackContentTypeIsFormUrlEncoded`,
`RejectErrorInUrlQuery`) are **consequences of the same gap, not a separate form_post
bug**: that module carries `response_mode=form_post` *inside* the request JWT. Since we
never parse the JWT we never see the parameter, so the error is delivered as a query
redirect. Error delivery does honour `response_mode` for every parameter we can
actually see — `Validated::error` routes through `Validated::respond`
(`src/routes/authorize.rs:99-126`), which handles `form_post`.

Closing this means parsing the `request` JWT and merging its claims over the query
parameters. Entra supports request objects, so this is a genuine fidelity gap.

### Latent trap: the login POST handler discards response_mode and state

`src/routes/authorize.rs:505-514` builds a `Validated` with
`response_mode: ResponseMode::Query` and `state: None`. This is currently harmless:
that value is used only for tenant/client context, login-page rendering, auditing and
`html::error`. The real response is built by `run()`, which re-derives `response_mode`
and `state` from the original request carried in the hidden `request` field.

But any future `v.error(...)` or `v.respond(...)` added to that handler would silently
force a query redirect and drop `state`, breaking form_post clients in a way no current
test would catch.

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
This module has not yet been re-run with the corrected config.
