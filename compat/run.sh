#!/usr/bin/env bash
# Compatibility tests against real Microsoft client libraries.
#
# Starts rust-oidc over TLS (self-signed dev certificate) with a fresh database,
# provisions a tenant, an API app with app roles and a client app with a secret,
# then runs the MSAL Python and MSAL Node suites.
#
# Usage: compat/run.sh [python|node|rp]...   (default: all)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPAT="$ROOT/compat"
PORT="${PORT:-18443}"
SUITES=("${@:-python node rp}")
SUITES=(${SUITES[@]})

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/debug/rust-oidc"
export RUST_OIDC_DATABASE="sqlite://$WORK/db.sqlite"
export RUST_LOG="${RUST_LOG:-warn}"
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

# ---- fixtures ----
"$BIN" dev-cert --out "$WORK/tls" --names localhost,127.0.0.1 >/dev/null
RUST_OIDC_PASSWORD='Compat-Admin-1!' "$BIN" bootstrap --domain root.test --admin-upn admin@root.test >/dev/null
TENANT_DOMAIN="contoso.test"
TENANT_ID=$("$BIN" tenant create --name Contoso --domain "$TENANT_DOMAIN" | json '["tenantId"]')
API_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name orders-api | json '["appId"]')
CLIENT_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name billing-worker | json '["appId"]')
for role in Orders.Read Orders.Write; do
  "$BIN" app role add --tenant "$TENANT_DOMAIN" --app "$API_APP_ID" --value "$role" --member-types Application >/dev/null
  "$BIN" app role assign --tenant "$TENANT_DOMAIN" --resource "$API_APP_ID" --role "$role" --app "$CLIENT_APP_ID"
done
# A user-only role must not appear in app-only tokens.
"$BIN" app role add --tenant "$TENANT_DOMAIN" --app "$API_APP_ID" --value Orders.Admin --member-types User >/dev/null
CLIENT_SECRET=$("$BIN" app secret add --tenant "$TENANT_DOMAIN" --app "$CLIENT_APP_ID" --days 1 | json '["secretText"]')

# Interactive sign-in: a user, a web app and a delegated scope on the API.
USER_UPN="alice@$TENANT_DOMAIN"
USER_PASSWORD='Compat-User-1!'
RUST_OIDC_PASSWORD="$USER_PASSWORD" "$BIN" user create --tenant "$TENANT_DOMAIN" --upn "$USER_UPN" \
  --display-name "Alice Smith" --given-name Alice --family-name Smith --email alice@example.org >/dev/null
"$BIN" app add-scope --tenant "$TENANT_DOMAIN" --app "$API_APP_ID" --value Orders.Read >/dev/null
WEB_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name web-portal | json '["appId"]')
WEB_REDIRECT_URI="https://app.contoso.test/callback"
"$BIN" app add-redirect-uri --tenant "$TENANT_DOMAIN" --app "$WEB_APP_ID" --platform web --uri "$WEB_REDIRECT_URI"
WEB_SECRET=$("$BIN" app secret add --tenant "$TENANT_DOMAIN" --app "$WEB_APP_ID" --days 1 | json '["secretText"]')

# ---- server ----
export RUST_OIDC_BASE="https://localhost:$PORT/rust-oidc"
"$BIN" serve --bind "127.0.0.1:$PORT" --public-url "$RUST_OIDC_BASE" \
  --tls-mode files --tls-cert "$WORK/tls/cert.pem" --tls-key "$WORK/tls/key.pem" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf --cacert "$WORK/tls/cert.pem" "$RUST_OIDC_BASE/healthz" >/dev/null && break
  sleep 0.1
done
curl -sf --cacert "$WORK/tls/cert.pem" "$RUST_OIDC_BASE/healthz" >/dev/null || { cat "$WORK/server.log"; exit 1; }

export TENANT_ID TENANT_DOMAIN API_APP_ID CLIENT_APP_ID CLIENT_SECRET
export USER_UPN USER_PASSWORD WEB_APP_ID WEB_SECRET WEB_REDIRECT_URI
export CA_FILE="$WORK/tls/cert.pem"
export EXPECTED_ROLES="Orders.Read,Orders.Write"

status=0
for suite in "${SUITES[@]}"; do
  echo "=== $suite ==="
  case "$suite" in
    python)
      [[ -x "$COMPAT/.venv/bin/python" ]] || {
        python3 -m venv "$COMPAT/.venv"
        "$COMPAT/.venv/bin/pip" install -q -r "$COMPAT/msal-python/requirements.txt"
      }
      "$COMPAT/.venv/bin/python" "$COMPAT/msal-python/test_app_auth.py" || status=1
      "$COMPAT/.venv/bin/python" "$COMPAT/msal-python/test_user_auth.py" || status=1
      ;;
    node)
      [[ -d "$COMPAT/msal-node/node_modules" ]] || (cd "$COMPAT/msal-node" && npm ci --silent)
      NODE_EXTRA_CA_CERTS="$CA_FILE" node "$COMPAT/msal-node/test_app_auth.mjs" || status=1
      ;;
    rp)
      [[ -d "$COMPAT/openid-client/node_modules" ]] || (cd "$COMPAT/openid-client" && npm ci --silent)
      NODE_EXTRA_CA_CERTS="$CA_FILE" node "$COMPAT/openid-client/test_rp.mjs" || status=1
      ;;
    *) echo "unknown suite: $suite"; status=1 ;;
  esac
done

if [[ $status -ne 0 ]]; then
  echo "--- server log ---"
  tail -50 "$WORK/server.log"
fi
exit $status
