# rust-oidc

An OAuth 2.0 / OpenID Connect provider that follows the **Microsoft Entra ID v2.0** protocol:
the same endpoint layout, token claims, error format and client-secret semantics. Apps
written for Entra should work with configuration changes only. Storage is SQLite, and
tenants (realms) are built in.

**Status: phase 1.** Tenants, app registrations, service principals, app roles, signing
keys, discovery, JWKS and the `client_credentials` grant are done. User sign-in
(authorize, auth code + PKCE, refresh tokens), TOTP MFA and the admin console come next.

## Quick start

```sh
cargo build --release
B=target/release/rust-oidc

# Root tenant, first Global Administrator, signing keys
$B bootstrap --domain example.com --admin-upn admin@example.com   # prompts for a password

# A tenant with an API and a service account that calls it
$B tenant create --name Contoso --domain contoso.com
$B app create --tenant contoso.com --name orders-api                 # -> appId A
$B app create --tenant contoso.com --name billing-worker             # -> appId B
$B app role add    --tenant contoso.com --app A --value Orders.Read --member-types Application
$B app role assign --tenant contoso.com --resource A --role Orders.Read --app B
$B app secret add  --tenant contoso.com --app B                      # -> secretText (shown once)

$B serve --public-url http://localhost:8080/rust-oidc

curl -s http://localhost:8080/rust-oidc/contoso.com/oauth2/v2.0/token \
  -d grant_type=client_credentials -d client_id=B --data-urlencode client_secret=... \
  -d scope=api://A/.default
```

## Endpoints

`{tenant}` is a tenant GUID or one of the tenant's verified domains. Tokens and
metadata always use the GUID.

| Endpoint | Path |
|---|---|
| Discovery | `/rust-oidc/{tenant}/v2.0/.well-known/openid-configuration` |
| Keys (JWKS) | `/rust-oidc/{tenant}/discovery/v2.0/keys` (also `/rust-oidc/common/...`) |
| Token | `/rust-oidc/{tenant}/oauth2/v2.0/token` |
| Issuer | `https://host/rust-oidc/{tid}/v2.0` |

## Configuration

Every option can be passed as a flag or an environment variable.

| Variable | Default | |
|---|---|---|
| `RUST_OIDC_DATABASE` | `sqlite://data/rust-oidc.db` | |
| `RUST_OIDC_PUBLIC_URL` | `http://localhost:8080/rust-oidc` | External base URL. Its path is the route prefix. |
| `RUST_OIDC_BIND` | `0.0.0.0:8080` | |
| `RUST_OIDC_TLS_MODE` | `none` | `none`, `files` or `acme` |
| `RUST_OIDC_TLS_CERT` / `RUST_OIDC_TLS_KEY` | | PEM files for `files` mode |
| `RUST_OIDC_ACME_DOMAINS` | | Comma-separated, for `acme` mode (TLS-ALPN-01, needs port 443 reachable) |
| `RUST_OIDC_ACME_EMAIL` | | |
| `RUST_OIDC_ACME_CACHE_DIR` | `data/acme` | Keep this directory to avoid Let's Encrypt rate limits |
| `RUST_OIDC_ACME_PRODUCTION` | `false` | Uses Let's Encrypt staging until set |

## Using Microsoft client libraries

MSAL checks that an authority is a Microsoft cloud. Turn that off:

- **MSAL Python:** `ConfidentialClientApplication(client_id, client_credential=..., authority="https://host/rust-oidc/<tenant>", instance_discovery=False)`,
  or `oidc_authority="https://host/rust-oidc/<tid>/v2.0"`.
- **MSAL Node:** `auth: { authority: "https://host/rust-oidc/<tenant>", knownAuthorities: ["host"] }`,
  or `protocolMode: "OIDC"` with the issuer as the authority.

With a path prefix, MSAL uses the first path segment (`rust-oidc`) as its cache "realm".
This is harmless while every app belongs to a single tenant.

## Signing keys

RS256 keys are shared by all tenants, as in Entra. Each key is wrapped in a self-signed
certificate, and `kid` = `x5t` = the certificate thumbprint. A `next` key is always
published before it is used.

```sh
rust-oidc key list
rust-oidc key rotate                     # next -> active, active -> retired, new next
rust-oidc key prune --older-than-days 2
```

Running servers pick up rotations within 30 seconds.

## Tests

```sh
cargo test          # protocol, error codes, key rotation, tenant isolation
compat/run.sh       # MSAL Python + MSAL Node against a TLS server (needs python3, node)
```

## Deliberate differences from Entra

- `groups` holds group names, not object IDs.
- There is no interactive consent. Apps are treated as admin-consented.
- The implicit grant is not supported.
- Client secrets are stored as SHA-256 hashes. They are ~200-bit random values, so a slow hash adds nothing.
