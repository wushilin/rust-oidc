# rust-oidc

An OAuth 2.0 / OpenID Connect provider that follows the **Microsoft Entra ID v2.0** protocol:
the same endpoint layout, token claims, error format and client-secret semantics. Apps
written for Entra should work with configuration changes only. Storage is SQLite, and
tenants (realms) are built in.

**Status: phase 2.** Done:
- Tenants, app registrations, service principals, app roles and signing keys.
- Service-account tokens (`client_credentials`).
- Interactive sign-in: authorize and login page, auth code + PKCE, ID tokens, refresh
  tokens, UserInfo and logout.

TOTP MFA and the admin console come next.

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
| Authorize | `/rust-oidc/{tenant}/oauth2/v2.0/authorize` (GET or POST) |
| Token | `/rust-oidc/{tenant}/oauth2/v2.0/token` |
| Logout | `/rust-oidc/{tenant}/oauth2/v2.0/logout` |
| UserInfo | `/rust-oidc/oidc/userinfo` (accepts the "Graph" token, as in Entra) |
| Issuer | `https://host/rust-oidc/{tid}/v2.0` |

## Sign-in behaviour (as in Entra)

- **Response modes:** `query`, `fragment` and `form_post`.
- **Prompts:** `prompt=none|login|select_account|consent`, plus `max_age` and `login_hint`.
- **Client rules depend on the redirect URI's platform:**
  - `web` is a confidential client and must authenticate.
  - `spa` must use PKCE and redeem codes cross-origin. Its refresh tokens have a fixed 24h lifetime.
  - `publicClient` needs no secret.
- **Redirect URIs match exactly**, except that the port is ignored for `http://localhost`.
- **Scopes:** `api://{app}/{scope}` or `/.default`, with one resource per request. Without
  a resource you get a token for Graph's app ID, which the UserInfo endpoint accepts.
- **Refresh tokens:** a refresh token can be used for a different resource. Refresh
  tokens rotate on each use, and replaying an old one revokes the whole chain.
- **`sub` is pairwise** (different for each app). `oid` is the stable user ID.
- **`client_info`** is returned for MSAL.
- **Accounts lock** for 60 seconds after 10 failed sign-ins, doubling after each further failure.
- **A password reset** revokes the user's refresh tokens and sessions.

```sh
$B user create --tenant contoso.com --upn alice@contoso.com --display-name "Alice Smith" --email alice@contoso.com
$B group create --tenant contoso.com --name engineering
$B group add-member --tenant contoso.com --group engineering --user alice@contoso.com
$B app add-redirect-uri --tenant contoso.com --app W --platform web --uri https://portal.contoso.com/signin-oidc
$B app add-scope --tenant contoso.com --app A --value Orders.Read
$B app assignment-required --tenant contoso.com --app W --required true
```

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
cargo test          # protocol, error codes, sign-in flows, key rotation, tenant isolation
compat/run.sh       # MSAL Python (app + user), MSAL Node, openid-client (certified RP) over TLS
```

## Deliberate differences from Entra

- `groups` holds group names, not object IDs.
- There is no interactive consent. Apps are treated as admin-consented.
- The implicit grant is not supported.
- Refresh tokens rotate, and replaying an old one revokes the chain. Entra keeps old refresh tokens valid.
- ID tokens include `email_verified` when an email is present.
- Client secrets are stored as SHA-256 hashes. They are ~200-bit random values, so a slow hash adds nothing.
