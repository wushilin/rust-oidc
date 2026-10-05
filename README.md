# rust-oidc

An OAuth 2.0 / OpenID Connect provider that follows the **Microsoft Entra ID v2.0** protocol:
the same endpoint layout, token claims, error format and client-secret semantics. Apps
written for Entra should work with configuration changes only. Storage is SQLite by default (PostgreSQL and MySQL are also supported, see [docs/databases.md](docs/databases.md)), and
tenants (realms) are built in.

**Status: phase 5.** Done:
- Tenants, app registrations, service principals, app roles and signing keys.
- Service-account tokens (`client_credentials`).
- Interactive sign-in: authorize and login page, auth code + PKCE, ID tokens, refresh
  tokens, UserInfo and logout.
- Implicit and hybrid response types, the device authorization grant, on-behalf-of,
  certificate client authentication (`private_key_jwt`), rate limiting and an audit trail.
- The **admin console** (web UI at `/rust-oidc/admin`), covering tenants, users, groups,
  applications, assignments, console roles, tenant settings, signing keys and the audit
  log.

TOTP MFA does not exist, and is the one administrative area with no page.

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
| Device code | `/rust-oidc/{tenant}/oauth2/v2.0/devicecode` |
| Auth API | `/rust-oidc/{tenant}/api/v1/authenticate` (see [Legacy application integration](#legacy-application-integration-the-auth-api)) |
| Issuer | `https://host/rust-oidc/{tid}/v2.0` |
| Admin console | `/rust-oidc/admin` (sign in with an administrator account) |

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
- **Throttling:** too many failed client authentications for one app, too many requests
  naming a client id or an account the tenant does not have, or too many device
  authorization requests for one app, get `429` with a `Retry-After` header, as Entra
  does. The counters are in-process, so several server instances multiply the effective
  limits. See `src/ratelimit.rs` and `docs/decisions-log.md` for the numbers, all of
  which are guesses.

```sh
$B user create --tenant contoso.com --upn alice@contoso.com --display-name "Alice Smith" --email alice@contoso.com
$B group create --tenant contoso.com --name engineering
$B group add-member --tenant contoso.com --group engineering --user alice@contoso.com
$B app add-redirect-uri --tenant contoso.com --app W --platform web --uri https://portal.contoso.com/signin-oidc
$B app add-scope --tenant contoso.com --app A --value Orders.Read
$B app assignment-required --tenant contoso.com --app W --required true
```

## Configuration

The recommended way is a configuration file:

```sh
rust-oidc --generate-config-file config.toml   # a commented file with the settings in effect
rust-oidc -c config.toml serve                 # -c / --config works for every command
```

`--generate-config-file` fills the file from the `RUST_OIDC_*` environment where
set, else the defaults, so an existing env-file deployment converts with
`set -a; . ./rust-oidc.env; set +a; rust-oidc --generate-config-file config.toml`.
It never overwrites a file, and creates it readable by its owner only (a database
URL can hold a password). Unknown keys are an error.

With `-c`, a flag given on the command line still overrides the file, and the file
overrides environment variables and defaults. Without `-c`, every option can be
passed as a flag or an environment variable:

| File key | Variable | Default | |
|---|---|---|---|
| `database.url` | `RUST_OIDC_DATABASE` | `sqlite://data/rust-oidc.db` | SQLite, PostgreSQL or MySQL URL; see [docs/databases.md](docs/databases.md) |
| `server.public_url` | `RUST_OIDC_PUBLIC_URL` | `http://localhost:8080/rust-oidc` | External base URL. Its path is the route prefix. |
| `server.bind` | `RUST_OIDC_BIND` | `0.0.0.0:8080` | |
| `tls.mode` | `RUST_OIDC_TLS_MODE` | `none` | `none`, `files` or `acme` |
| `tls.cert` / `tls.key` | `RUST_OIDC_TLS_CERT` / `RUST_OIDC_TLS_KEY` | | PEM files for `files` mode |
| `tls.acme.domains` | `RUST_OIDC_ACME_DOMAINS` | | For `acme` mode (TLS-ALPN-01, needs port 443 reachable); comma-separated in the variable |
| `tls.acme.email` | `RUST_OIDC_ACME_EMAIL` | | |
| `tls.acme.cache_dir` | `RUST_OIDC_ACME_CACHE_DIR` | `data/acme` | Keep this directory to avoid Let's Encrypt rate limits |
| `tls.acme.production` | `RUST_OIDC_ACME_PRODUCTION` | `false` | Uses Let's Encrypt staging until set |
| `log.filter` | `RUST_LOG` | `info,tower_http=info,sqlx=warn` | A `tracing` filter |

## Legacy application integration: the Auth API

Some things that need sign-in cannot run an OAuth browser flow: a Linux login prompt
(PAM), SSH with keyboard-interactive, a VPN or network appliance, an old application
with its own user-name-and-password screen. For these, rust-oidc has a built-in
**Auth API**. An application that an administrator has trusted with it can send a
user's **user name, password and authenticator code** and get back whether they are
right, and on success who the user is: profile, groups and roles.

This is an extension; Entra has no such API (its answer is RADIUS through the NPS
extension). See decision 40 in `docs/decisions-log.md`.

**Linux login:** [pam-rust-oidc](https://github.com/wushilin/pam-rust-oidc) is a PAM
module built on this API. SSH (or any PAM service) asks for the password and
authenticator code, and the module checks them with `Credentials.Verify`; it maps
the short Unix user name to the user's UPN, can create accounts at first login,
and leaves local and system accounts to `pam_unix`. Its README covers sshd, sudo,
SELinux and AppArmor, and keeping a break-glass local account.

**Prefer a real OAuth flow where you can.** With the Auth API the integrating host
sees the user's password, so a compromised host can capture it. Where the prompt can
show a URL and a code, the device code flow (`/oauth2/v2.0/devicecode`) signs the user
in on their own phone or browser and the host never sees the password; that is how
Entra signs users in to Linux VMs over SSH.

### What protects it

- **An administrator must grant it.** The Auth API is a built-in resource, like
  Microsoft Graph, with one application permission, `Credentials.Verify`. It is
  granted per application, on that application's **API permissions** page; that grant
  is the consent, and nobody else can give it. It is checked on every call, so
  revoking it stops the application at once.
- **Only users assigned to the calling application** (directly or through a group) can
  be checked. An application cannot even move the lockout counter of anyone else.
- **MFA is mandatory.** The user must have an authenticator, and the check needs a
  fresh code from it; recovery codes are refused. A password alone confirms nothing.
  A code is spent when a check succeeds, so it cannot be replayed.
- **Failures say nothing.** Every failure about the user (wrong password, wrong code,
  unknown, disabled, locked, not assigned, no authenticator, must change password,
  throttled) gets the same answer, byte for byte. The reason is in the audit log, as
  a failed sign-in with `via: auth_api`.
- **Limits.** Wrong passwords count toward the account's lockout, as at sign-in.
  Checks are limited per calling application (600 a minute) and per account (10 a
  minute).

### Set it up

In the admin console, for the integrating host (one application per host or per
kind of host):

1. **Applications → New application**, e.g. "Linux Login". Note its application
   (client) id.
2. **Certificates & secrets**: upload a certificate (recommended) or create a client
   secret. A self-signed certificate is enough:

   ```sh
   umask 077
   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
     -days 365 -subj "/CN=linux-login"
   ```

   Upload `cert.pem` only. `key.pem` stays on the host.
3. **API permissions**: **Auth API → `Credentials.Verify` → Grant**.
4. **Users and groups**: assign who may log in through it. Each person needs an
   authenticator (**My Account → set up authenticator**, or at their next sign-in if
   MFA is required of them).
5. Optionally, define **app roles** on the application (for example `Host.Admin`,
   `Host.User`) and give them in the assignments; the host receives them on every
   successful check and can map them to local privileges.

### Call it

Two requests. First the application signs in as itself (client credentials, with
the certificate as a `private_key_jwt` assertion or with the secret) and gets a token
for the Auth API; reuse it until it expires (about an hour):

```
POST {base}/{tenant}/oauth2/v2.0/token
grant_type=client_credentials
client_id=<application id>
scope=api://auth-api/.default
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<JWT signed with key.pem: aud = the token endpoint, iss = sub = the application id, a unique jti, exp within 10 minutes, x5t = base64url SHA-1 of the certificate>
```

Then one check per login:

```
POST {base}/{tenant}/api/v1/authenticate
Authorization: Bearer <token>
Content-Type: application/json

{"upn": "alice@contoso.com", "password": "...", "otp": "123456"}
```

`{tenant}` is the application's tenant, by domain or id.

The Auth API has two fixed names, the same in every deployment and never changing:
**`api://auth-api`** and its app id **`3bc73980-9fde-4fa7-9f74-9d421f0a127d`**, as
Microsoft Graph is both `https://graph.microsoft.com` and
`00000003-0000-0000-c000-000000000000`. Either works in `scope`; the token's `aud` is
always the app id. No application can register `api://auth-api` as its own
identifier URI. A token for any other API is refused (`401`), and the client
credentials grant accepts only a `/.default` scope. For Linux logins, use
[pam-rust-oidc](https://github.com/wushilin/pam-rust-oidc) rather than writing your
own. A complete, working shell client is in
[`examples/auth-api/check-login.sh`](examples/auth-api/check-login.sh):
it builds the certificate assertion with `openssl`, gets the token, asks for a login
and exits 0 on success, 1 otherwise, which is the decision a PAM module acts on.

### The answer

On success:

```json
{
  "result": true,
  "oid": "…", "tid": "…",
  "preferred_username": "alice@contoso.com",
  "name": "Alice Smith", "given_name": "Alice", "family_name": "Smith",
  "email": "alice.smith@contoso.com",
  "groups":    [{ "id": "…", "name": "linux-admins" }],
  "app_roles": [{ "id": "…", "value": "Host.Admin" }],
  "amr": ["pwd", "mfa"],
  "acr": "2"
}
```

`groups` are the user's groups; `app_roles` the roles they hold on the calling
application. Use either to decide what they may do on the host.

Every failure about the user, `200`:

```json
{ "result": false, "code": "invalid_credentials", "msg": "The user name, password or code is not valid." }
```

Problems with the calling application are HTTP errors instead:

| Status | Meaning |
|---|---|
| `401 invalid_token` | No token, an expired one, or one not issued for the Auth API in this tenant. |
| `403 insufficient_scope` | The application does not hold `Credentials.Verify` (or it was revoked). A token fetched before the grant does not carry it: get a new one. |
| `429` | The application's own limit; wait `Retry-After` seconds. |
| `400 invalid_request` | The body is not JSON with `upn`, `password` and `otp`. |

### If a check fails with credentials you know are right

Look in the tenant's **Audit log** for the failed sign-in with `via: auth_api`; its
`reason` is one of `not_assigned`, `no_authenticator`, `bad_code` (wrong, or already
used: wait for the next code), `bad_password`, `locked`, `disabled`,
`must_change_password` (the user must sign in once in a browser and choose a new
password) or `throttled`.

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

## Admin console

`/rust-oidc/admin`, server-rendered, no JavaScript. Sign in with an account that holds a
console role; a user with none is told so rather than shown an error. Everything below is
web-only: there is no CLI equivalent for the pages marked *new*, and several have none at
all (tenant settings, group membership, audit).

- **Who can do what** is a role (which carries actions) granted at a scope (`all`, or a
  list of tenants). A tenant administrator sees only the tenants they are bound to, and
  no page or nav entry offers an action the guard would refuse.
- **A platform administrator can assume a tenant** and act as its administrator. Every
  action stays attributable to them personally in `audit_log`; the assume itself is
  recorded.

| Page | What it does | Action required |
|---|---|---|
| `/admin/tenants` | List; create, rename, enable/disable, add and withdraw verified domains | `Tenant:Read`; writes need `Tenant:Create`/`Tenant:Write` **at `all` scope** |
| `/admin/tenants/{tenant}/users` | List, search, create, edit, enable/disable, reset password, delete | `User:Read`, `User:Write`, `User:Reset` |
| `/admin/tenants/{tenant}/groups` | List, create, add and remove members | `Group:Read`, `Group:Write` |
| `/admin/tenants/{tenant}/apps` | Register; secrets, certificates, redirect URIs per platform, Application ID URIs, exposed scopes, app roles, role assignments, and the password-grant and implicit toggles | `App:Read`, `App:Write`; credentials need `App:Rotate`; assignments need `Assignment:Write` |
| `/admin/tenants/{tenant}/roles` | Grant and revoke console roles | `RoleBinding:Read`, `RoleBinding:Write` |
| `/admin/tenants/{tenant}/flow` | Flow tester: what a flow needs configured, then drive it and read the result | `App:Read`; registering the callback or a test client needs `App:Write` |
| `/admin/tenants/{tenant}/settings` | Token, session and refresh-token lifetimes | `Tenant:Write` |
| `/admin/tenants/{tenant}/audit` | The tenant's audit log, filtered by action and target | `Audit:Read` |
| `/admin/keys` | Signing keys, rotate and prune | `Key:Read`, `Key:Rotate`, **at `all` scope** |
| `/admin/bindings` | Every role binding on the deployment, read-only | `RoleBinding:Read` at `all` scope |

Things worth knowing before using it:

- **A client secret is shown exactly once**, on the page that creates it, because only a
  SHA-256 hash is stored. It is never put in the audit log. Certificates are uploaded as
  PEM; a file containing a private key is refused.
- **Rotating a signing key affects every tenant** — the keys are shared, as in Entra — and
  the page says so before offering the button.
- **Granting a role revoke is refused if it would leave the platform with no
  administrator**, and the root tenant cannot be disabled, for the same reason: there is no
  CLI to repair either.
- **Adding somebody to a group can grant them administrative rights**, because a console
  role binding may name a group.
- No MFA page (TOTP does not exist), no paging on any list, and app roles and exposed
  scopes can be added but not removed. See `docs/decisions-log.md`.

### Flow tester

`/admin/tenants/{tenant}/flow` drives a real OAuth/OIDC flow against this server and shows
what came back, for the times when a client says "it does not work" and you want to see the
protocol rather than the client. The compatibility suites in `compat/` cover machine-driven
fidelity; this is for reading one flow with your own eyes.

**The landing page is a readiness check, not a form.** Pick an application and a flow, and
the page states item by item what that combination needs, what is configured now, and what
to change: the service principal, the callback URI (with the exact string, and which
platform it is registered under), the client secret, `allow_id_token_implicit` and
`allow_access_token_implicit` by name, `openid`, whether the scope resolves to a resource
that exposes it, app role assignment, `allow_password_grant`, how the response gets back,
and who redeems the code. It offers to run the flow only when nothing is missing.

Then it sends the authorize request with a `state`, a `nonce` and a PKCE verifier it
generated and held, and the result page shows the request, the response, the real HTTP token
request and reply, and both tokens decoded -- with `nonce`, `c_hash`, `at_hash`, `iss`,
`aud`, `exp` and the signature checked and any failure marked.

Worth knowing:

- **It changes nothing on its own.** Registering the callback on a real application is a
  button of its own, audited as the redirect URI addition it is, and removable in the
  applications section. There is also a per-tenant **flow tester client** the console will
  register on request: one public client whose only redirect URI is the callback, which is
  the zero-side-effect way to exercise the server.
- **`form_post` is used for any response type that carries a token.** The console has no
  JavaScript and a `default-src 'none'` CSP, so a URL fragment can never reach it; fragment
  mode prints the authorize URL for you to open and says that nothing will be captured.
- **A `web` client's code cannot be redeemed by the console**, because only a SHA-256 hash
  of its secret is stored. The front channel is still tested end to end and the exact token
  request is printed for you to run. Use the flow tester client to exercise the redemption
  too.
- **No tokens are logged or stored.** The audit log records that a flow test ran, by whom,
  against which application, with what response type, and how it ended -- never the code,
  the tokens, the state or the nonce. The pending row is deleted as soon as it is used.

## Deliberate differences from Entra

- `groups` holds group names, not object IDs.
- There is no interactive consent. Apps are treated as admin-consented.
- The implicit and hybrid response types are **off by default** on every app, as in
  Entra, and enabled per app (`app implicit --id-tokens/--access-tokens`).
- Refresh tokens rotate, and replaying an old one revokes the chain. Entra keeps old refresh tokens valid.
- ID tokens include `email_verified` when an email is present.
- Client secrets are stored as SHA-256 hashes. They are ~200-bit random values, so a slow hash adds nothing.
- Tokens carry `acr` (`"1"` password, `"2"` with MFA), and `acr_values=2` steps a sign-in up to MFA. Entra's v2.0 tokens omit `acr` and step up through Conditional Access instead.
- The built-in Auth API (above) has no Entra counterpart.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
