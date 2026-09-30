#!/usr/bin/env bash
# Microsoft.Identity.Web compatibility test against rust-oidc.
#
# A minimal ASP.NET Core web API (OrdersApi) protects an endpoint with
# Microsoft.Identity.Web, configured like an Entra app: AzureAd:Instance / TenantId /
# ClientId / Audience. The library fetches rust-oidc's discovery document and JWKS
# and validates signature, issuer, audience, lifetime and tid. None of that is
# relaxed. Tokens come from rust-oidc over the wire; the script calls the API with
# them and asserts the outcome.
#
# TLS: the dev certificate is trusted through SSL_CERT_FILE (OpenSSL on Linux), not
# by skipping validation.
#
# Invoked by compat/run.sh with the fixtures it provisions.
set -euo pipefail

: "${TENANT_ID:?}" "${API_APP_ID:?}" "${CLIENT_APP_ID:?}" "${CLIENT_SECRET:?}" "${CA_FILE:?}"
: "${RUST_OIDC_BASE:?}" "${WEB_APP_ID:?}" "${WEB_SECRET:?}" "${USER_UPN:?}" "${USER_PASSWORD:?}"
: "${DOWNSTREAM_APP_ID:?}" "${OTHER_TENANT_DOMAIN:?}" "${OTHER_API_APP_ID:?}" "${OTHER_CLIENT_APP_ID:?}" "${OTHER_CLIENT_SECRET:?}" "${EXPECTED_ROLES:?}"

# A .NET SDK that is not on PATH can be named with DOTNET_DIR (e.g. ~/.dotnet).
[[ -n "${DOTNET_DIR:-}" ]] && export PATH="$DOTNET_DIR:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
if ! command -v dotnet >/dev/null 2>&1; then
  echo "SKIP: dotnet not installed; the Microsoft.Identity.Web suite needs the .NET 8 SDK"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
API_PORT="${MSIDWEB_PORT:-15080}"
API_URL="http://127.0.0.1:$API_PORT"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "--- building OrdersApi ---"
dotnet build "$HERE/OrdersApi.csproj" -c Release -o "$WORK/out" -v q --nologo >"$WORK/build.log" 2>&1 \
  || { cat "$WORK/build.log"; exit 1; }

start_api() { # port, instance, [audience] -> sets API_PID; the server under test lives on $API_URL
  local port="$1" instance="$2" audience="${3:-$API_APP_ID}"
  SSL_CERT_FILE="$CA_FILE" \
  AzureAd__Instance="$instance" AzureAd__TenantId="$TENANT_ID" \
  AzureAd__ClientId="$audience" AzureAd__Audience="$audience" \
  ASPNETCORE_URLS="http://127.0.0.1:$port" \
    dotnet "$WORK/out/OrdersApi.dll" >"$WORK/api-$port.log" 2>&1 &
  API_PID=$!; PIDS+=("$API_PID")
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$port/healthz" >/dev/null && return 0
    sleep 0.2
  done
  echo "OrdersApi did not start"; cat "$WORK/api-$port.log"; exit 1
}

echo "--- starting OrdersApi ---"
# Instance is the rust-oidc base; Microsoft.Identity.Web derives the authority
# {Instance}/{TenantId}/v2.0 and the discovery document from it. No validation
# override of any kind is configured.
start_api "$API_PORT" "$RUST_OIDC_BASE/"

failures=0
check() { # name, condition-exit-status, detail
  if [[ "$2" == 0 ]]; then echo "PASS $1"; else echo "FAIL $1: ${3:-}"; failures=$((failures + 1)); fi
}
token_endpoint="$RUST_OIDC_BASE/$TENANT_ID/oauth2/v2.0/token"
access_token() { python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
call() { # token -> writes body to $WORK/body, prints status
  curl -s -o "$WORK/body" -w '%{http_code}' -H "Authorization: Bearer $1" "$API_URL/whoami"
}
claims_check() { # name, python expression over dict `c` (claim name -> list of values)
  if python3 -c "import json,sys; c=json.load(open('$WORK/body')); sys.exit(0 if ($2) else 1)"; then
    echo "PASS $1"
  else
    echo "FAIL $1: $(cat "$WORK/body")"; failures=$((failures + 1))
  fi
}

APP_TOKEN=$(curl -sf --cacert "$CA_FILE" "$token_endpoint" -d grant_type=client_credentials \
  -d client_id="$CLIENT_APP_ID" --data-urlencode client_secret="$CLIENT_SECRET" \
  --data-urlencode scope="api://$API_APP_ID/.default" | access_token)
USER_TOKEN=$(curl -sf --cacert "$CA_FILE" "$token_endpoint" -d grant_type=password \
  -d client_id="$WEB_APP_ID" --data-urlencode client_secret="$WEB_SECRET" \
  --data-urlencode username="$USER_UPN" --data-urlencode password="$USER_PASSWORD" \
  --data-urlencode scope="api://$API_APP_ID/Orders.Read" | access_token)
WRONG_AUD_TOKEN=$(curl -sf --cacert "$CA_FILE" "$token_endpoint" -d grant_type=password \
  -d client_id="$WEB_APP_ID" --data-urlencode client_secret="$WEB_SECRET" \
  --data-urlencode username="$USER_UPN" --data-urlencode password="$USER_PASSWORD" \
  --data-urlencode scope="api://$DOWNSTREAM_APP_ID/Reports.Read" | access_token)

# No credentials at all is the baseline for the 401 checks.
status=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/whoami")
check "no token: 401" $([[ "$status" == 401 ]] && echo 0 || echo 1) "got $status"

# 1. Application token.
status=$(call "$APP_TOKEN")
check "app token: accepted (200)" $([[ "$status" == 200 ]] && echo 0 || echo 1) "got $status"
if [[ "$status" == 200 ]]; then
  claims_check "app token: aud is the API appId" "c['aud']==['$API_APP_ID']"
  claims_check "app token: azp is the client appId" "c['azp']==['$CLIENT_APP_ID']"
  claims_check "app token: tid" "c['tid']==['$TENANT_ID']"
  claims_check "app token: idtyp app" "c['idtyp']==['app']"
  claims_check "app token: roles" "sorted(c['roles'])==sorted('$EXPECTED_ROLES'.split(','))"
  claims_check "app token: no scp" "'scp' not in c"
fi

# 2. Delegated (user) token.
status=$(call "$USER_TOKEN")
check "user token: accepted (200)" $([[ "$status" == 200 ]] && echo 0 || echo 1) "got $status"
if [[ "$status" == 200 ]]; then
  claims_check "user token: preferred_username" "c['preferred_username']==['$USER_UPN']"
  claims_check "user token: name" "c['name']==['Alice Smith']"
  claims_check "user token: scp" "c['scp']==['Orders.Read']"
  claims_check "user token: tid" "c['tid']==['$TENANT_ID']"
  claims_check "user token: idtyp is not app" "c.get('idtyp')!=['app']"
  claims_check "user token: no app roles" "'roles' not in c"
fi

# 3. Wrong audience: a genuine, correctly signed token for a different API.
status=$(call "$WRONG_AUD_TOKEN")
check "wrong audience: 401" $([[ "$status" == 401 ]] && echo 0 || echo 1) "got $status"

# 4. Tampered signature: flip a character in the middle of the signature segment.
tamper() {
  python3 - "$1" <<'PY'
import sys
h, p, s = sys.argv[1].split(".")
i = len(s) // 2
s = s[:i] + ("A" if s[i] != "A" else "B") + s[i + 1:]
print(f"{h}.{p}.{s}")
PY
}
for name in APP USER; do
  var="${name}_TOKEN"
  status=$(call "$(tamper "${!var}")")
  check "tampered signature ($name token): 401" $([[ "$status" == 401 ]] && echo 0 || echo 1) "got $status"
done
# Tampered payload with the original signature (escalating roles) must also fail.
forged=$(python3 - "$APP_TOKEN" <<'PY'
import base64, json, sys
h, p, s = sys.argv[1].split(".")
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
c["roles"] = c.get("roles", []) + ["Orders.Admin"]
p = base64.urlsafe_b64encode(json.dumps(c).encode()).decode().rstrip("=")
print(f"{h}.{p}.{s}")
PY
)
status=$(call "$forged")
check "tampered payload: 401" $([[ "$status" == 401 ]] && echo 0 || echo 1) "got $status"

# 5. Issuer validation is live. A second tenant (Fabrikam) on the same server issues
# a genuine token for its own API. An instance configured for Contoso but with
# Fabrikam's API as audience passes the audience check, so only issuer/tenant
# validation stands between that token and a 200.
OTHER_TOKEN=$(curl -sf --cacert "$CA_FILE" "$token_endpoint" -d grant_type=client_credentials \
  -d client_id="$OTHER_CLIENT_APP_ID" --data-urlencode client_secret="$OTHER_CLIENT_SECRET" \
  --data-urlencode scope="api://$OTHER_API_APP_ID/.default" \
  | access_token 2>/dev/null) || OTHER_TOKEN=""
if [[ -z "$OTHER_TOKEN" ]]; then
  # The token endpoint is per tenant; a token for Fabrikam comes from Fabrikam's.
  OTHER_TOKEN=$(curl -sf --cacert "$CA_FILE" "$RUST_OIDC_BASE/$OTHER_TENANT_DOMAIN/oauth2/v2.0/token" \
    -d grant_type=client_credentials -d client_id="$OTHER_CLIENT_APP_ID" \
    --data-urlencode client_secret="$OTHER_CLIENT_SECRET" \
    --data-urlencode scope="api://$OTHER_API_APP_ID/.default" | access_token)
fi
CROSS_PORT=$((API_PORT + 1))
start_api "$CROSS_PORT" "$RUST_OIDC_BASE/" "$OTHER_API_APP_ID"
status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $OTHER_TOKEN" "http://127.0.0.1:$CROSS_PORT/whoami")
check "other tenant's token (aud matches, issuer does not): 401" $([[ "$status" == 401 ]] && echo 0 || echo 1) "got $status"
echo "     (OrdersApi says: $(grep -o "Bearer was not authenticated.*" "$WORK/api-$CROSS_PORT.log" | head -1 | cut -c1-300))"
check "other tenant's token: rejected by issuer validation (IDX40001, after signature passed)" \
  $(grep -q 'IDX40001' "$WORK/api-$CROSS_PORT.log" && echo 0 || echo 1) "$(grep -m3 IDX "$WORK/api-$CROSS_PORT.log")"

# Sanity: the checks above must be failing for the right reason, not because the
# API is broken. The untampered tokens were accepted, and the log names the reason.
if [[ $failures -ne 0 ]]; then
  echo "--- OrdersApi log ---"; tail -40 "$WORK/api-$API_PORT.log"
  echo "$failures check(s) failed"
  exit 1
fi
echo "all Microsoft.Identity.Web checks passed"
