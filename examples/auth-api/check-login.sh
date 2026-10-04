#!/usr/bin/env bash
# Check a Linux login against rust-oidc's Auth API, signing in as the
# "Linux Login" application with a certificate (private_key_jwt).
#
# One-time setup in the admin console, on the Linux Login application:
#   1. Certificates & secrets -> upload cert.pem (this directory). Never key.pem.
#   2. API permissions -> Auth API -> Credentials.Verify -> Grant.
#   3. Users and groups -> assign the people (or groups) who may log in.
#      Each needs an authenticator set up (My Account -> set up authenticator).
#
# Needs: curl, jq, openssl.
set -euo pipefail
cd "$(dirname "$0")"

# ---- fill these in ----
BASE="https://login.example.com/rust-oidc"   # the deployment's public URL
TENANT="example.com"                          # the app's tenant: domain or id
CLIENT_ID="<Linux Login application (client) id>"
KEY="key.pem"                                  # private key for cert.pem
CERT="cert.pem"
# -----------------------

AUTH_API="3bc73980-9fde-4fa7-9f74-9d421f0a127d"   # the built-in Auth API's app id

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# The assertion's audience is the exact token endpoint, with the tenant's id:
# take it from the discovery document rather than building it by hand.
TOKEN_ENDPOINT=$(curl -fsS "$BASE/$TENANT/v2.0/.well-known/openid-configuration" | jq -r .token_endpoint)

# 1. A client assertion: a short-lived JWT signed with the private key. The x5t
#    header (base64url SHA-1 of the certificate) says which certificate to check.
x5t=$(openssl x509 -in "$CERT" -outform DER | openssl dgst -sha1 -binary | b64url)
now=$(date +%s)
header=$(jq -cn --arg x5t "$x5t" '{alg: "RS256", typ: "JWT", x5t: $x5t}' | b64url)
payload=$(jq -cn --arg aud "$TOKEN_ENDPOINT" --arg id "$CLIENT_ID" \
  --arg jti "$(openssl rand -hex 16)" --argjson nbf "$now" --argjson exp "$((now + 300))" \
  '{aud: $aud, iss: $id, sub: $id, jti: $jti, nbf: $nbf, exp: $exp}' | b64url)
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$KEY" -binary | b64url)
ASSERTION="$header.$payload.$signature"

# 2. The application's own token for the Auth API. A real PAM module would keep
#    it until it expires (expires_in, about an hour) instead of asking each time.
RESPONSE=$(curl -sS "$TOKEN_ENDPOINT" \
  -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$ASSERTION" \
  -d scope="$AUTH_API/.default")
TOKEN=$(jq -r '.access_token // empty' <<<"$RESPONSE")
if [[ -z "$TOKEN" ]]; then
  echo "Could not get a token:" >&2
  jq . <<<"$RESPONSE" >&2
  exit 1
fi
if ! jq -e '.roles | index("Credentials.Verify")' >/dev/null 2>&1 \
     < <(cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null); then
  echo "Warning: the token does not carry Credentials.Verify; grant it on the API permissions page." >&2
fi

# 3. The login itself.
read -r  -p "User name: " LOGIN_UPN
read -rs -p "Password: "  LOGIN_PW; echo
read -r  -p "Authenticator code: " LOGIN_OTP

ANSWER=$(jq -n --arg upn "$LOGIN_UPN" --arg pw "$LOGIN_PW" --arg otp "$LOGIN_OTP" \
    '{upn: $upn, password: $pw, otp: $otp}' |
  curl -sS -X POST "$BASE/$TENANT/api/v1/authenticate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @-)
jq . <<<"$ANSWER"

# A PAM module decides on this alone.
if [[ "$(jq -r .result <<<"$ANSWER")" == "true" ]]; then
  echo "LOGIN OK"
else
  echo "LOGIN REFUSED"
  exit 1
fi
