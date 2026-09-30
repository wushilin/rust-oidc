# Kafka SASL/OAUTHBEARER (OIDC)

Proves that a stock Apache Kafka broker accepts rust-oidc access tokens using
Kafka's own OpenID support (KIP-768) — no custom callback handlers.

Run it with the rest of the compatibility suites:

```
compat/run.sh kafka      # or just: compat/run.sh
```

It is skipped with a message when `podman` is not installed.

## What it exercises

A single-node KRaft broker runs in podman. Its client listener is
`SASL_PLAINTEXT`/`OAUTHBEARER`, validated by Kafka's stock
`OAuthBearerValidatorCallbackHandler`, which fetches rust-oidc's JWKS over HTTPS
and checks the token's **signature**, **issuer** and **audience**. The console
producer and consumer authenticate through `OAuthBearerLoginCallbackHandler`,
which performs a `client_credentials` grant against rust-oidc.

1. **Happy path** — produce and consume a message with a token obtained for
   `api://$API_APP_ID/.default`.
2. **Wrong audience** — request a token for a different resource app and assert
   the broker refuses it.

## Things that are easy to get wrong here

- **The issuer and the fetch URL differ on purpose.** The token's `iss` comes
  from rust-oidc's `--public-url` (`localhost`), while the broker reaches the
  host at `host.containers.internal`. `expected.issuer` must match the token,
  not the URL being fetched.
- **Rootless podman cannot reach the host's LAN IP**, so the container gets
  `--add-host host.containers.internal:host-gateway`, and `compat/run.sh` binds
  `0.0.0.0` and adds that name to the dev certificate's SANs.
- **Java needs the dev CA in a truststore.** It is built with the image's own
  `keytool`, as root, because the image's normal user cannot write to the mount.
- **The console tools exit 0 even when the broker rejects them**, and
  `podman exec` needs `-i` or the producer reads EOF and silently sends nothing.
  The rejection test therefore asserts on the client's error text *and* on a
  fresh rejection appearing in the broker log — never on an exit code.

## Note on claims

App-only tokens carry no `scp`/`scope` claim (this matches Entra, which conveys
app permissions in `roles`). Kafka treats scope as optional, so validation
passes. If a future Kafka version required a scope set, the fix belongs here
(`sasl.oauthbearer.scope.claim.name=roles`), not in the token contents.
