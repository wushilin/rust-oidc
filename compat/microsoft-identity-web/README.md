# Microsoft.Identity.Web compatibility suite

`OrdersApi` is a minimal ASP.NET Core web API protected with
`Microsoft.Identity.Web` 3.8.4 (.NET 8), configured the way an Entra app is:

```
AzureAd:Instance   = <rust-oidc base>/          (e.g. https://localhost:18444/rust-oidc/)
AzureAd:TenantId   = <tenant GUID>
AzureAd:ClientId   = <API appId>
AzureAd:Audience   = <API appId>
```

`test_msidweb.sh` (run via `compat/run.sh msidweb`, part of the default list)
obtains tokens from rust-oidc and calls `/whoami` with them.

| Check | Expected |
|---|---|
| client_credentials token for the API | 200; `aud`, `azp`, `tid`, `idtyp=app`, `roles` = the assigned app roles, no `scp` |
| delegated (ROPC) user token | 200; `preferred_username`, `name`, `scp=Orders.Read`, `tid`, no `roles` |
| genuine token for a different API (wrong audience) | 401 |
| tampered signature (app and user token), tampered payload | 401 |
| genuine token from a second tenant, audience matching the API | 401 with `IDX40001` (issuer) after the signature was accepted |
| no token | 401 |

## Validation knob required: none

Microsoft.Identity.Web accepts rust-oidc with no override. No `ValidateIssuer`,
`ValidIssuers`, custom `IssuerValidator`, or instance-discovery switch is set.
Signature (JWKS from discovery), issuer, audience, lifetime and `tid` are all
validated by the library's defaults. The last check above proves the issuer
validation is active rather than absent.

Why it works: `AadIssuerValidator` handles an authority host it does not know as
its own alias, and rust-oidc's issuer has Entra's shape,
`{base}/{tenantId}/v2.0`, with `tid` in the token.

Two non-validation settings are used:

- **TLS trust**: the dev certificate is trusted with `SSL_CERT_FILE=$CA_FILE`
  (OpenSSL on Linux). Certificate validation is not skipped.
- `MapInboundClaims = false` so claims keep their wire names (`scp`, `tid`,
  `roles`) instead of WS-* URIs. This changes naming only.

## Running

Needs the .NET 8 SDK. It self-skips when `dotnet` is not on PATH; if the SDK is
installed but not on PATH, set `DOTNET_DIR`:

```
DOTNET_DIR=~/.dotnet compat/run.sh msidweb
```
