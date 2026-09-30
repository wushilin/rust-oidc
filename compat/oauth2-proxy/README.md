# oauth2-proxy (`--provider=oidc`)

Proves that oauth2-proxy accepts rust-oidc as a strict OIDC provider: full
discovery, then authorization-code login with ID-token validation.

```
compat/run.sh oauth2-proxy      # or just: compat/run.sh
```

Skipped with a message when `podman` is not installed.

## What it exercises

oauth2-proxy runs in podman with `--oidc-issuer-url=$RUST_OIDC_BASE/$TENANT_ID/v2.0`.
Nothing is relaxed: no `--skip-oidc-discovery`, no
`--insecure-oidc-skip-issuer-verification`. go-oidc requires the discovery
document's `issuer` to equal the URL it was fetched from, verifies the ID token's
signature against the JWKS, `iss`, `aud` and expiry, and oauth2-proxy checks the
nonce. A stub upstream on the host echoes the headers oauth2-proxy injects.

1. **Startup** — oauth2-proxy exits if discovery or issuer validation fails, so
   "still running and `/ping` answers" proves them.
2. **Unauthenticated request** — `/protected` is redirected to rust-oidc's authorize
   endpoint.
3. **Login** — browser follows authorize, submits the login form, returns to
   `/oauth2/callback`; `/protected` then reaches the upstream with
   `X-Forwarded-Email` set, and `/oauth2/userinfo` returns 200.
4. **Unverified email** — a user whose `email_verified` is false is refused.

## Things that are easy to get wrong here

- **Host networking.** The Kafka suite's `--add-host host.containers.internal`
  trick cannot be used: rust-oidc's issuer is its public URL (`https://localhost:...`),
  and fetching discovery from any other name makes go-oidc reject the issuer
  mismatch, correctly. The container therefore uses `--network host` so that
  `localhost` is the host's. The issuer check stays fully on.
- **`email_verified` is emitted from the user record**, and a freshly created user
  has it false. oauth2-proxy honours that (`email in id_token ... isn't verified`,
  HTTP 500 at the callback), so the first run of this suite failed. That is
  correct behaviour by both sides, not a rust-oidc bug. The CLI cannot verify an
  email (only the admin console can), so `run.sh` creates a second user (bob) and
  flips the flag in the throwaway SQLite database. alice stays unverified and is the
  negative case.
- **`--skip-provider-button=true`** so an unauthenticated request is a 302 to the
  provider rather than oauth2-proxy's own 403 sign-in page.
- **`podman logs` can lag** the container's stdout, so log assertions poll.
- Cookies are `--cookie-secure=false` because the proxy itself is plain HTTP on
  localhost.
