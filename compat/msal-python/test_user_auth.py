"""Interactive user sign-in with MSAL Python (confidential web app).

MSAL builds the authorize URL (PKCE, nonce, state, client_info); a scripted
"browser" fills in rust-oidc's login form; MSAL then redeems the code, validates
the ID token and manages its cache and refresh tokens. Checks the result the
way an Entra-integrated app would see it.
"""

import hashlib
import html
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

import msal
import requests

BASE = os.environ["RUST_OIDC_BASE"]
TENANT_ID = os.environ["TENANT_ID"]
WEB_APP_ID = os.environ["WEB_APP_ID"]
WEB_SECRET = os.environ["WEB_SECRET"]
REDIRECT_URI = os.environ["WEB_REDIRECT_URI"]
API_APP_ID = os.environ["API_APP_ID"]
USER_UPN = os.environ["USER_UPN"]
USER_PASSWORD = os.environ["USER_PASSWORD"]
CA_FILE = os.environ["CA_FILE"]

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f": {detail}"))
    if not cond:
        failures.append(name)


def field(page, name):
    m = re.search(rf'name="{name}" value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


def browser_sign_in(session, auth_uri):
    """Follow the authorize URL, submit the login form, return the redirect query."""
    resp = session.get(auth_uri, allow_redirects=False, verify=CA_FILE)
    if resp.status_code == 200:
        action = html.unescape(re.search(r'action="([^"]+)"', resp.text).group(1))
        resp = session.post(
            action,
            data={
                "csrf": field(resp.text, "csrf"),
                "request": field(resp.text, "request"),
                "op": "login",
                "upn": USER_UPN,
                "password": USER_PASSWORD,
            },
            allow_redirects=False,
            verify=CA_FILE,
        )
    assert resp.status_code == 302, f"expected redirect, got {resp.status_code}: {resp.text[:300]}"
    location = resp.headers["Location"]
    assert location.startswith(REDIRECT_URI), location
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


app = msal.ConfidentialClientApplication(
    WEB_APP_ID,
    client_credential=WEB_SECRET,
    authority=f"{BASE}/{TENANT_ID}",
    instance_discovery=False,
    verify=CA_FILE,
)
browser = requests.Session()
api_scope = f"api://{API_APP_ID}/Orders.Read"

# 1. Auth code flow for the API scope.
flow = app.initiate_auth_code_flow([api_scope], redirect_uri=REDIRECT_URI)
check("authorize URL uses PKCE S256", "code_challenge_method=S256" in flow["auth_uri"], flow["auth_uri"])
auth_response = browser_sign_in(browser, flow["auth_uri"])
result = app.acquire_token_by_auth_code_flow(flow, auth_response)
check("code redeemed", "access_token" in result, result)
claims = result.get("id_token_claims", {})
check("id token: aud is the client", claims.get("aud") == WEB_APP_ID, claims)
# MSAL sends sha256(nonce) and validates the echo itself (it raises on mismatch).
check("id token: nonce is MSAL's hashed nonce",
      claims.get("nonce") == hashlib.sha256(flow["nonce"].encode()).hexdigest(), claims)
check("id token: tid", claims.get("tid") == TENANT_ID, claims)
check("id token: preferred_username", claims.get("preferred_username") == USER_UPN, claims)
check("refresh token issued", "refresh_token" in result, list(result))

# 2. MSAL account model (built from client_info).
accounts = app.get_accounts()
check("one account in cache", len(accounts) == 1, accounts)
account = accounts[0]
check("home_account_id = oid.tid", account["home_account_id"] == f"{claims.get('oid')}.{TENANT_ID}", account)
check("account username", account["username"] == USER_UPN, account)

# 3. Silent: cached token, then forced refresh.
silent = app.acquire_token_silent([api_scope], account=account)
check("silent: served from cache", silent and silent.get("token_source") == "cache", silent)
refreshed = app.acquire_token_silent([api_scope], account=account, force_refresh=True)
check("silent: refresh token grant", refreshed and refreshed.get("token_source") == "identity_provider", refreshed)
check("silent: new access token", refreshed and refreshed.get("access_token") != result["access_token"])

# 4. Same refresh token, different resource (Graph / UserInfo).
graph = app.acquire_token_silent(["User.Read"], account=account)
check("silent: token for another resource", graph and "access_token" in graph, graph)
if graph and "access_token" in graph:
    info = requests.get(
        f"{BASE}/oidc/userinfo", headers={"Authorization": f"Bearer {graph['access_token']}"}, verify=CA_FILE
    )
    check("userinfo: 200", info.status_code == 200, info.text)
    check("userinfo: sub matches id token", info.json().get("sub") == claims.get("sub"), info.text)

# 5. SSO: a second flow with the same browser needs no password.
flow2 = app.initiate_auth_code_flow(["User.Read"], redirect_uri=REDIRECT_URI)
resp = browser.get(flow2["auth_uri"], allow_redirects=False, verify=CA_FILE)
check("SSO: immediate redirect", resp.status_code == 302, resp.status_code)

# 6. prompt=none without a session -> MSAL surfaces login_required.
flow3 = app.initiate_auth_code_flow(["User.Read"], redirect_uri=REDIRECT_URI, prompt="none")
resp = requests.get(flow3["auth_uri"], allow_redirects=False, verify=CA_FILE)
params = {k: v[0] for k, v in parse_qs(urlparse(resp.headers["Location"]).query).items()}
result = app.acquire_token_by_auth_code_flow(flow3, params)
check("prompt=none: login_required", result.get("error") == "login_required", result)

if failures:
    print(f"\n{len(failures)} check(s) failed")
    sys.exit(1)
print("\nall MSAL Python user sign-in checks passed")
