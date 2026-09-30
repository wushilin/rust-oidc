"""The phase-5 grants, driven by MSAL Python rather than by hand.

Covers ROPC, the device code flow, on-behalf-of and certificate (private_key_jwt)
client authentication. Using the real Microsoft library matters here: it builds
the requests and validates the responses the way an Entra app would, including
deriving `x5t` from a certificate thumbprint itself.
"""

import html
import os
import re
import sys

import jwt
import msal
import requests

BASE = os.environ["RUST_OIDC_BASE"]
TENANT_ID = os.environ["TENANT_ID"]
WEB_APP_ID = os.environ["WEB_APP_ID"]
WEB_SECRET = os.environ["WEB_SECRET"]
API_APP_ID = os.environ["API_APP_ID"]
API_SECRET = os.environ["API_SECRET"]
CLIENT_APP_ID = os.environ["CLIENT_APP_ID"]
DOWNSTREAM_APP_ID = os.environ["DOWNSTREAM_APP_ID"]
CLIENT_CERT_KEY = os.environ["CLIENT_CERT_KEY"]
CLIENT_CERT_THUMBPRINT = os.environ["CLIENT_CERT_THUMBPRINT"]
USER_UPN = os.environ["USER_UPN"]
USER_PASSWORD = os.environ["USER_PASSWORD"]
CA_FILE = os.environ["CA_FILE"]

AUTHORITY = f"{BASE}/{TENANT_ID}"

# MSAL's ROPC path first does Entra user-realm discovery at
# https://{host}/common/userrealm/{upn}. It derives that host from the authority
# WITHOUT the path prefix and WITHOUT the port, so it probes the bare host root,
# which is not ours to serve here. MSAL treats a 404 as "this domain has no realm
# endpoint" and caches that, then falls back to plain ROPC -- which is what
# happens against a host that simply does not serve the path. We seed that same
# cache so the probe is skipped instead of failing on a refused connection.
# Operationally this means an MSAL ROPC client needs the host root to answer 404
# there (a reverse proxy in front of rust-oidc does), or the same seeding.
msal.authority.Authority._domains_without_user_realm_discovery.add(
    requests.utils.urlparse(BASE).hostname
)

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f": {detail}"))
    if not cond:
        failures.append(name)


def claims(token, audience):
    """Validate against the published JWKS, as the resource API would."""
    import ssl

    jwks = jwt.PyJWKClient(
        f"{BASE}/{TENANT_ID}/discovery/v2.0/keys",
        ssl_context=ssl.create_default_context(cafile=CA_FILE),
    )
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=audience,
        issuer=f"{BASE}/{TENANT_ID}/v2.0",
    )


def field(page, name):
    m = re.search(rf'name="{name}" value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


def app(client_id, secret, **kw):
    return msal.ConfidentialClientApplication(
        client_id,
        authority=AUTHORITY,
        client_credential=secret,
        instance_discovery=False,
        verify=CA_FILE,
        **kw,
    )


# ---- ROPC -------------------------------------------------------------------

web = app(WEB_APP_ID, WEB_SECRET)
scope = [f"api://{API_APP_ID}/Orders.Read"]
result = web.acquire_token_by_username_password(USER_UPN, USER_PASSWORD, scopes=scope)
check("ropc: token issued", "access_token" in result, str(result))
if "access_token" in result:
    c = claims(result["access_token"], API_APP_ID)
    check("ropc: the signed-in user", c.get("preferred_username") == USER_UPN, str(c))
    check("ropc: amr is pwd", c.get("amr") == ["pwd"], str(c.get("amr")))
    check("ropc: azp is the client", c.get("azp") == WEB_APP_ID, str(c.get("azp")))
    user_assertion = result["access_token"]
else:
    user_assertion = None

bad = web.acquire_token_by_username_password(USER_UPN, "wrong-password", scopes=scope)
check("ropc: wrong password rejected", "access_token" not in bad, str(bad))
check("ropc: AADSTS50126", 50126 in bad.get("error_codes", []), str(bad.get("error_codes")))

# ---- device code flow -------------------------------------------------------

device_app = msal.PublicClientApplication(
    WEB_APP_ID, authority=AUTHORITY, instance_discovery=False, verify=CA_FILE
)
# MSAL adds openid/profile/offline_access itself and rejects them as input, so
# ask only for the API scope.
flow = device_app.initiate_device_flow(scopes=[f"api://{API_APP_ID}/Orders.Read"])
check("device: flow started", "user_code" in flow, str(flow))
if "user_code" in flow:
    check("device: verification_uri", "verification_uri" in flow, str(flow))
    check("device: message names the code", flow["user_code"] in flow.get("message", ""), str(flow))

    # Approve it the way the user would: open the page, sign in, confirm.
    session = requests.Session()
    page = session.get(
        f"{BASE}/{TENANT_ID}/oauth2/deviceauth",
        params={"user_code": flow["user_code"]},
        verify=CA_FILE,
    )
    action = html.unescape(re.search(r'action="([^"]+)"', page.text).group(1))
    page = session.post(
        action,
        data={
            "csrf": field(page.text, "csrf"),
            "request": field(page.text, "request"),
            "op": "login",
            "upn": USER_UPN,
            "password": USER_PASSWORD,
        },
        verify=CA_FILE,
    )
    check("device: approval page shown", field(page.text, "request") is not None, page.text[:200])
    action = html.unescape(re.search(r'action="([^"]+)"', page.text).group(1))
    approved = session.post(
        action,
        data={
            "csrf": field(page.text, "csrf"),
            "request": field(page.text, "request"),
            "op": "approve",
        },
        verify=CA_FILE,
    )
    check("device: approved", approved.status_code == 200, str(approved.status_code))

    # MSAL polls until the code is redeemed.
    result = device_app.acquire_token_by_device_flow(flow)
    check("device: token issued", "access_token" in result, str(result))
    check("device: id_token for openid", "id_token" in result, str(result.keys()))
    if "id_token_claims" in result:
        check(
            "device: the signed-in user",
            result["id_token_claims"].get("preferred_username") == USER_UPN,
            str(result["id_token_claims"]),
        )

# ---- on-behalf-of -----------------------------------------------------------

if user_assertion:
    middle_tier = app(API_APP_ID, API_SECRET)
    result = middle_tier.acquire_token_on_behalf_of(
        user_assertion, scopes=[f"api://{DOWNSTREAM_APP_ID}/Reports.Read"]
    )
    check("obo: token issued", "access_token" in result, str(result))
    if "access_token" in result:
        c = claims(result["access_token"], DOWNSTREAM_APP_ID)
        check("obo: same user", c.get("preferred_username") == USER_UPN, str(c))
        check("obo: middle tier is the caller", c.get("azp") == API_APP_ID, str(c.get("azp")))
        check("obo: downstream scope", c.get("scp") == "Reports.Read", str(c.get("scp")))

    # A token addressed to someone else must not be exchangeable.
    stolen = middle_tier.acquire_token_on_behalf_of(
        result.get("access_token", "x.y.z"), scopes=[f"api://{DOWNSTREAM_APP_ID}/Reports.Read"]
    )
    check("obo: wrong-audience assertion refused", "access_token" not in stolen, str(stolen)[:200])

# ---- certificate client authentication (private_key_jwt) --------------------

with open(CLIENT_CERT_KEY) as fh:
    private_key = fh.read()

cert_app = app(
    CLIENT_APP_ID,
    {"private_key": private_key, "thumbprint": CLIENT_CERT_THUMBPRINT},
)
result = cert_app.acquire_token_for_client(scopes=[f"api://{API_APP_ID}/.default"])
check("cert: token issued", "access_token" in result, str(result))
if "access_token" in result:
    c = claims(result["access_token"], API_APP_ID)
    # azpacr 2 means the client proved itself with a certificate, not a secret.
    check("cert: azpacr is 2", c.get("azpacr") == "2", str(c.get("azpacr")))
    check("cert: app roles", sorted(c.get("roles", [])) == ["Orders.Read", "Orders.Write"], str(c.get("roles")))
    check("cert: idtyp app", c.get("idtyp") == "app", str(c.get("idtyp")))

print()
if failures:
    print(f"{len(failures)} failed: {', '.join(failures)}")
    sys.exit(1)
print("all new-grant checks passed")
