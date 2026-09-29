"""Application (service-to-service) authentication with MSAL Python.

Exercises rust-oidc exactly as an Entra ID confidential client would:
client_credentials with a client secret and `.default` scope, then validates
the access token the way a resource API does (JWKS from discovery, RS256,
issuer, audience, roles).

Configuration comes from environment variables set by compat/run.sh.
"""

import os
import ssl
import sys

import jwt
import msal
import requests

BASE = os.environ["RUST_OIDC_BASE"]            # https://localhost:18443/rust-oidc
TENANT_ID = os.environ["TENANT_ID"]
TENANT_DOMAIN = os.environ["TENANT_DOMAIN"]
API_APP_ID = os.environ["API_APP_ID"]
CLIENT_ID = os.environ["CLIENT_APP_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
CA_FILE = os.environ["CA_FILE"]
EXPECTED_ROLES = sorted(os.environ["EXPECTED_ROLES"].split(","))
SCOPE = [f"api://{API_APP_ID}/.default"]

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f": {detail}"))
    if not cond:
        failures.append(name)


def validate(token, tenant_id):
    """Validate like a resource API: keys from the discovery document's jwks_uri."""
    config = requests.get(
        f"{BASE}/{tenant_id}/v2.0/.well-known/openid-configuration", verify=CA_FILE
    ).json()
    jwks = jwt.PyJWKClient(config["jwks_uri"], ssl_context=ssl.create_default_context(cafile=CA_FILE))
    key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key.key, algorithms=["RS256"], audience=API_APP_ID, issuer=config["issuer"]
    )


def entra_style_app(authority, secret=CLIENT_SECRET):
    # instance_discovery=False: skip the call to login.microsoftonline.com that
    # MSAL makes to check the authority is a Microsoft cloud.
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        client_credential=secret,
        authority=authority,
        instance_discovery=False,
        verify=CA_FILE,
    )


# 1. Entra-style authority, tenant by GUID.
app = entra_style_app(f"{BASE}/{TENANT_ID}")
result = app.acquire_token_for_client(scopes=SCOPE)
check("entra authority (GUID): token issued", "access_token" in result, result)
if "access_token" in result:
    claims = validate(result["access_token"], TENANT_ID)
    check("token: aud is the API appId", claims["aud"] == API_APP_ID, claims)
    check("token: azp is the client appId", claims["azp"] == CLIENT_ID, claims)
    check("token: tid", claims["tid"] == TENANT_ID, claims)
    check("token: ver 2.0", claims["ver"] == "2.0", claims)
    check("token: idtyp app", claims.get("idtyp") == "app", claims)
    check("token: oid == sub", claims["oid"] == claims["sub"], claims)
    check("token: roles", sorted(claims.get("roles", [])) == EXPECTED_ROLES, claims)
    check("msal: token_type Bearer", result.get("token_type") == "Bearer", result)

    # MSAL serves the second request from its cache.
    again = app.acquire_token_for_client(scopes=SCOPE)
    check("msal: second call served from cache",
          again.get("token_source") == "cache" and again["access_token"] == result["access_token"], again)

# 2. Entra-style authority, tenant by verified domain.
result = entra_style_app(f"{BASE}/{TENANT_DOMAIN}").acquire_token_for_client(scopes=SCOPE)
check("entra authority (domain): token issued", "access_token" in result, result)
if "access_token" in result:
    check("entra authority (domain): tid is the GUID", validate(result["access_token"], TENANT_ID)["tid"] == TENANT_ID)

# 3. Generic OIDC authority mode (MSAL validates issuer == authority).
oidc_app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    oidc_authority=f"{BASE}/{TENANT_ID}/v2.0",
    verify=CA_FILE,
)
result = oidc_app.acquire_token_for_client(scopes=SCOPE)
check("oidc_authority: token issued", "access_token" in result, result)

# 4. Error surface: MSAL exposes Entra's error fields unchanged.
result = entra_style_app(f"{BASE}/{TENANT_ID}", secret="wrong").acquire_token_for_client(scopes=SCOPE)
check("bad secret: error invalid_client", result.get("error") == "invalid_client", result)
check("bad secret: AADSTS7000215", result.get("error_codes") == [7000215], result)
check("bad secret: description has AADSTS prefix",
      result.get("error_description", "").startswith("AADSTS7000215:"), result)

result = entra_style_app(f"{BASE}/{TENANT_ID}").acquire_token_for_client(scopes=["api://nope/.default"])
check("unknown resource: AADSTS500011", result.get("error_codes") == [500011], result)

if failures:
    print(f"\n{len(failures)} check(s) failed")
    sys.exit(1)
print("\nall MSAL Python checks passed")
