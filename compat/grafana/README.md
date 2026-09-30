# Grafana (generic OAuth)

Proves that stock Grafana signs a user in through rust-oidc using its generic
OAuth provider, with no plugin and no Grafana-side workaround.

```
compat/run.sh grafana      # or just: compat/run.sh
```

Skipped with a message when `podman` is not installed.

## What it exercises

Grafana 11 runs in podman, configured only through `GF_AUTH_GENERIC_OAUTH_*`
(client id/secret, `AUTH_URL`, `TOKEN_URL`, `API_URL` = rust-oidc's `/oidc/userinfo`,
scopes, PKCE, and `GF_SERVER_ROOT_URL` so the redirect URI is
`http://localhost:13000/login/generic_oauth`).

1. **Login** — a scripted browser (`../common/browser.py`) requests
   `/login/generic_oauth`, follows the redirect to rust-oidc, submits the login
   form and comes back to Grafana. The test then asks Grafana `/api/user` with the
   session cookie and asserts the signed-in login (`preferred_username`) and email.
2. **Wrong client secret** — a second Grafana (port 13001) with a bad secret must
   end up with no session (`/api/user` is 401) *and* log the token-exchange
   failure (`invalid_client`, `AADSTS7000215`). Asserting on both stops a login that
   never started from passing as a rejection.

## Things that are easy to get wrong here

- **Two URLs for one server.** The browser-facing `AUTH_URL` uses rust-oidc's
  public URL (`https://localhost:18444`); Grafana's server-side `TOKEN_URL` and
  `API_URL` use `host.containers.internal` (rootless podman cannot reach the
  host's LAN IP, so the container gets `--add-host ...:host-gateway`). Grafana does
  not validate `iss`, so the difference is harmless here.
- **Trusting the dev CA.** Go honours `SSL_CERT_FILE`; the CA is mounted and pointed
  at. TLS verification stays on.
- **`/api/health` is green before OAuth works.** An early run got a 3xx without a
  `Location` header in that window. Readiness therefore also requires
  `/login/generic_oauth` to redirect.
- **Cold start is slow** (SQLite migrations; ~30-60 s), hence the 120 s poll.
- **The redirect URI is http.** Entra permits `http://localhost`; rust-oidc accepts
  it as a web redirect URI, and both Grafana ports are registered in `run.sh`.
