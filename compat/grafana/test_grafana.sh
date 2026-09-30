#!/usr/bin/env bash
# Grafana generic-OAuth compatibility test against rust-oidc.
#
# Grafana runs in podman and is configured through GF_AUTH_GENERIC_OAUTH_* to use
# rust-oidc as its identity provider. A scripted browser follows the authorize
# redirect, submits rust-oidc's login form, and lands back on Grafana; the test
# then asks Grafana who it thinks is signed in. A second Grafana with the wrong
# client secret must NOT end up signed in.
#
# Invoked by compat/run.sh with the fixtures it provisions.
set -euo pipefail

: "${TENANT_ID:?}" "${GRAFANA_APP_ID:?}" "${GRAFANA_SECRET:?}" "${CA_FILE:?}"
: "${RUST_OIDC_BASE:?}" "${PORT:?}" "${GRAFANA_PORT:?}" "${GRAFANA_BAD_PORT:?}"
: "${USER_UPN:?}" "${USER_PASSWORD:?}"

if ! command -v podman >/dev/null 2>&1; then
  echo "SKIP: podman not installed; the Grafana suite needs a container runtime"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${GRAFANA_IMAGE:-docker.io/grafana/grafana:11.2.0}"
GOOD="rust-oidc-grafana-compat"
BAD="rust-oidc-grafana-compat-badsecret"

HOST_ALIAS="host.containers.internal"
OIDC_IN_CONTAINER="https://$HOST_ALIAS:$PORT/rust-oidc"
# The browser (this script, on the host) uses the public URL; Grafana's server-side
# calls use the host-gateway alias. Both name the same server.
AUTH_URL="$RUST_OIDC_BASE/$TENANT_ID/oauth2/v2.0/authorize"
TOKEN_URL="$OIDC_IN_CONTAINER/$TENANT_ID/oauth2/v2.0/token"
USERINFO_URL="$OIDC_IN_CONTAINER/oidc/userinfo"

WORK="$(mktemp -d)"
cleanup() {
  podman rm -f "$GOOD" "$BAD" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
podman rm -f "$GOOD" "$BAD" >/dev/null 2>&1 || true
cp "$CA_FILE" "$WORK/ca.pem"
chmod -R a+rX "$WORK"

start_grafana() { # $1 name, $2 host port, $3 client secret
  podman run -d --name "$1" \
    --add-host "$HOST_ALIAS:host-gateway" \
    -p "127.0.0.1:$2:3000" \
    -v "$WORK/ca.pem:/etc/ssl/rust-oidc-ca.pem:ro,z" \
    -e SSL_CERT_FILE=/etc/ssl/rust-oidc-ca.pem \
    -e GF_SERVER_ROOT_URL="http://localhost:$2/" \
    -e GF_LOG_LEVEL=info \
    -e GF_USERS_ALLOW_SIGN_UP=false \
    -e GF_AUTH_GENERIC_OAUTH_ENABLED=true \
    -e GF_AUTH_GENERIC_OAUTH_NAME=rust-oidc \
    -e GF_AUTH_GENERIC_OAUTH_CLIENT_ID="$GRAFANA_APP_ID" \
    -e GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$3" \
    -e GF_AUTH_GENERIC_OAUTH_SCOPES="openid profile email" \
    -e GF_AUTH_GENERIC_OAUTH_AUTH_URL="$AUTH_URL" \
    -e GF_AUTH_GENERIC_OAUTH_TOKEN_URL="$TOKEN_URL" \
    -e GF_AUTH_GENERIC_OAUTH_API_URL="$USERINFO_URL" \
    -e GF_AUTH_GENERIC_OAUTH_USE_PKCE=true \
    -e GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true \
    -e GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH=preferred_username \
    -e GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH=name \
    -e GF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH=email \
    "$IMAGE" >/dev/null
}

wait_ready() { # $1 host port
  for _ in $(seq 1 120); do
    # /api/health goes green before OAuth is usable (the first attempt at this suite
    # hit a 3xx with no Location in that window), so require the OAuth login
    # endpoint to actually redirect.
    curl -sf "http://127.0.0.1:$1/api/health" >/dev/null 2>&1 \
      && [[ -n "$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$1/login/generic_oauth")" ]] && return 0
    sleep 1
  done
  return 1
}

echo "--- starting Grafana ($IMAGE) ---"
start_grafana "$GOOD" "$GRAFANA_PORT" "$GRAFANA_SECRET"
start_grafana "$BAD" "$GRAFANA_BAD_PORT" "not-the-secret"
wait_ready "$GRAFANA_PORT" || { echo "FAIL: Grafana did not become ready"; podman logs --tail 15 "$GOOD" 2>&1 | cut -c1-250; exit 1; }
wait_ready "$GRAFANA_BAD_PORT" || { echo "FAIL: second Grafana did not become ready"; podman logs --tail 15 "$BAD" 2>&1 | cut -c1-250; exit 1; }

jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
status=0

echo "--- OAuth login (expects signed-in user) ---"
out="$(python3 "$HERE/drive_login.py" "http://localhost:$GRAFANA_PORT")" || { echo "FAIL: driver crashed"; status=1; out='{}'; }
api="$(jget "d.get('api_status')" <<<"$out")"
login="$(jget "(d.get('user') or {}).get('login')" <<<"$out")"
email="$(jget "(d.get('user') or {}).get('email')" <<<"$out")"
if [[ "$api" == "200" && "$login" == "$USER_UPN" && "$email" == "alice@example.org" ]]; then
  echo "PASS: Grafana reports signed-in user login=$login email=$email"
else
  echo "FAIL: expected login=$USER_UPN email=alice@example.org via /api/user, got status=$api login=$login email=$email"
  echo "  $out"; status=1
fi
# Confirm the round trip really went through rust-oidc, not a local shortcut.
if grep -q "/oauth2/v2.0/authorize" <<<"$out" && grep -q "/login/generic_oauth" <<<"$out"; then
  echo "PASS: flow visited rust-oidc authorize and returned to /login/generic_oauth"
else
  echo "FAIL: redirect chain did not include rust-oidc authorize and the Grafana callback"; echo "  $out"; status=1
fi

echo "--- wrong client secret (expects rejection) ---"
out="$(python3 "$HERE/drive_login.py" "http://localhost:$GRAFANA_BAD_PORT")" || out='{}'
api="$(jget "d.get('api_status')" <<<"$out")"
# Assert on Grafana's own session state AND on the failure it logged, so a login
# that simply never started cannot pass as a rejection.
refused=0
for _ in $(seq 1 10); do  # `podman logs` can lag the container's stdout
  podman logs "$BAD" 2>&1 | grep -qiE "invalid_client|Failed to get token|oauth2: .*cannot fetch token|AADSTS" && { refused=1; break; }
  sleep 1
done
if [[ "$api" != "200" && $refused -eq 1 ]]; then
  echo "PASS: Grafana refused to sign in with a wrong client secret (api/user=$api)"
  podman logs "$BAD" 2>&1 | grep -iE "invalid_client|cannot fetch token|Failed to get token" | tail -1 | cut -c1-300 | sed 's/^/       /'
else
  echo "FAIL: wrong-secret login was not rejected as expected (api/user=$api)"
  echo "  $out"; status=1
fi

if [[ $status -ne 0 ]]; then
  echo "--- grafana log (good instance) ---"
  podman logs --tail 60 "$GOOD" 2>&1 | grep -iE "oauth|error|warn" | tail -30
fi
exit $status
