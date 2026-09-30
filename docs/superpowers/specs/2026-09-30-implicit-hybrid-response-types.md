# Implicit and hybrid response types

Date: 2026-09-30
Status: building
Driver: user — "let's follow entra behavior closely. it is by far the most common OIDC."

## Intent

rust-oidc accepts `response_type=code` only (`src/routes/authorize.rs:290-301`).
Entra accepts more, so a client configured for Entra's hybrid flow fails here —
against the project's goal that an Entra app works with configuration changes only.

Found by comparing our discovery document field by field against Entra's live one,
not by the conformance suite. See `docs/conformance.md`.

## Verified Entra behaviour

From `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
and `https://learn.microsoft.com/entra/identity-platform/v2-oauth2-implicit-grant-flow`
(both fetched 2026-09-30):

- `response_types_supported`: `["code", "id_token", "code id_token", "id_token token"]`.
- The docs also demonstrate bare **`response_type=token`** (the silent-refresh
  hidden-iframe pattern with `prompt=none`), which the metadata does **not** advertise.
  We reproduce the behaviour *and* the metadata, mismatch included: clients depend on
  behaviour, and the goal is parity.
- `nonce` is **"required … Only required when an id_token is requested."**
- `response_mode` "Defaults to `query` for just an access token, but `fragment` if the
  request includes an id_token."
- Both are **opt-in per app registration**, via **ID tokens** and **access tokens** under
  *Implicit grant and hybrid flows* (manifest: `oauth2AllowIdTokenImplicitFlow`,
  `oauth2AllowImplicitFlow`). Off by default.
- When not enabled, the error is `unsupported_response`, with the message
  *"The provided value for the input parameter 'response_type' is not allowed for this
  client. Expected value is 'code'"*.
- "The implicit grant doesn't provide refresh tokens."
- Response carries, per requested type: `code`, `access_token`, `token_type` (always
  `Bearer`), `expires_in`, `scope`, `id_token`, `state`.
- `claims_supported` lists `at_hash` and `c_hash`, so Entra emits them.

Note our existing error is `unsupported_response_type` / AADSTS700054 with a different
message. Entra's actual value is `unsupported_response`, so this changes.

## Two inferences, flagged

Entra's documentation does not state these; both come from the specs.

1. **`response_mode=query` is rejected when the response carries `id_token` or `token`.**
   OAuth 2.0 Multiple Response Type Encoding Practices says the query mode MUST NOT be
   used for these, because a token in a query string lands in proxy and server logs and
   in `Referer`.
2. **Bare `token` defaults to `fragment`, not `query`.** The doc sentence says `query`,
   but RFC 6749 §4.2.2 mandates the fragment for an implicit access-token response, and
   every Entra example passes `response_mode=fragment` explicitly. Defaulting to `query`
   would put an access token in a URL that gets logged. Deliberate deviation from one
   sentence of prose, in favour of the normative spec.

## Design

**`ResponseType` enum**, not a set of booleans: the five supported combinations, so
`nonce`, `c_hash`, `at_hash` and response-mode decisions are exhaustive matches the
compiler checks. Parsing is order-insensitive (`code id_token` and `id_token code` are
the same request, and Entra's docs write it both ways), and any unlisted combination —
`code token`, `code id_token token` — is rejected.

```rust
pub enum ResponseType { Code, IdToken, Token, CodeIdToken, IdTokenToken }
```

**Per-app opt-in.** Migration `0010` adds two booleans to `applications`, following
`allow_password_grant` exactly (`INTEGER`/`BOOLEAN`/`SMALLINT` per engine, bound as real
`bool`). Gating:

| response_type | needs ID tokens | needs access tokens |
|---|---|---|
| `code` | — | — |
| `id_token` | yes | — |
| `code id_token` | yes | — |
| `id_token token` | yes | yes |
| `token` | — | yes |

**`c_hash` / `at_hash`** (OIDC Core 3.3.2.11) bind the id_token to what travels beside
it: left-most 128 bits of SHA-256, base64url. `c_hash` when a code accompanies the
id_token, `at_hash` when an access token does. Without these, a hybrid response's
id_token can be paired with a code from a different response. `at_hash` must be computed
inside `claims::issue`, which mints the access token; `c_hash` comes from the caller.

**No refresh token** in an implicit response, per Entra. A hybrid `code id_token`
response's code redeems normally, refresh token included.

**PKCE** stays required for SPA-platform clients. `id_token`-only requests have no code
to protect, so the check applies only when a code is issued.

## Testing

- Each of the five types end to end, plus rejection of `code token` and
  `code id_token token`.
- Not-enabled → `unsupported_response` with Entra's exact message, for each toggle
  independently (ID tokens off but access tokens on, and the reverse).
- `nonce` missing: rejected for every type containing `id_token`, accepted for `code`
  and `token`.
- `response_mode`: default `fragment` when `id_token` or `token` present, `query` for
  bare `code`; explicit `query` rejected for token-bearing responses; `form_post` works.
- `c_hash` verifies against the delivered code; `at_hash` against the delivered access
  token; neither appears when the corresponding artifact is absent.
- A hybrid code still redeems at the token endpoint and yields a refresh token; an
  implicit response contains none.
- Order-insensitivity: `id_token code` behaves as `code id_token`.
