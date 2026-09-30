#!/usr/bin/env bash
# Compatibility tests against real Microsoft client libraries.
#
# Starts rust-oidc over TLS (self-signed dev certificate) with a fresh database,
# provisions a tenant, an API app with app roles and a client app with a secret,
# then runs the MSAL Python and MSAL Node suites.
#
# Usage: compat/run.sh [python|node|rp|kafka|grafana|oauth2-proxy|msidweb]...   (default: all)
#
# The kafka, grafana and oauth2-proxy suites need podman and are skipped when it
# is not installed; msidweb likewise needs the .NET 8 SDK (dotnet).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPAT="$ROOT/compat"
# 18443 is taken by the conformance suite's nginx (compat/conformance), and the
# server now binds 0.0.0.0 for the Kafka container, so the two would collide.
PORT="${PORT:-18444}"
SUITES=("${@:-python node rp kafka grafana oauth2-proxy msidweb}")
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
# host.containers.internal is how the Kafka container reaches this server.
"$BIN" dev-cert --out "$WORK/tls" --names localhost,127.0.0.1,host.containers.internal >/dev/null
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

# ---- fixtures for the phase-5 grants ----
# ROPC is opt-in per app, so turn it on deliberately for the web app.
"$BIN" app password-grant --tenant "$TENANT_DOMAIN" --app "$WEB_APP_ID" --allowed true >/dev/null
# The middle tier needs its own credential to perform on-behalf-of, and a
# downstream API to exchange the user's token for.
API_SECRET=$("$BIN" app secret add --tenant "$TENANT_DOMAIN" --app "$API_APP_ID" --days 1 | json '["secretText"]')
DOWNSTREAM_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name reports-api | json '["appId"]')
"$BIN" app add-scope --tenant "$TENANT_DOMAIN" --app "$DOWNSTREAM_APP_ID" --value Reports.Read >/dev/null
# A certificate credential, so MSAL can authenticate with private_key_jwt. MSAL
# derives x5t from the hex thumbprint, which independently checks our convention.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/client-key.pem" \
  -out "$WORK/client-cert.pem" -days 2 -subj "/CN=billing-worker" 2>/dev/null
"$BIN" app key add --tenant "$TENANT_DOMAIN" --app "$CLIENT_APP_ID" \
  --cert "$WORK/client-cert.pem" --name "compat cert" >/dev/null
CLIENT_CERT_KEY="$WORK/client-key.pem"
CLIENT_CERT_THUMBPRINT=$(openssl x509 -in "$WORK/client-cert.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')

# ---- fixtures for the container relying-party suites (grafana, oauth2-proxy) ----
# Each RP is a confidential web app with its own registered redirect URI. Grafana
# gets two ports: the second instance is deliberately misconfigured (wrong secret).
GRAFANA_PORT="${GRAFANA_PORT:-13000}"
GRAFANA_BAD_PORT="${GRAFANA_BAD_PORT:-13001}"
OAUTH2_PROXY_PORT="${OAUTH2_PROXY_PORT:-14180}"
OAUTH2_PROXY_UPSTREAM_PORT="${OAUTH2_PROXY_UPSTREAM_PORT:-14181}"
GRAFANA_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name grafana | json '["appId"]')
for p in "$GRAFANA_PORT" "$GRAFANA_BAD_PORT"; do
  "$BIN" app add-redirect-uri --tenant "$TENANT_DOMAIN" --app "$GRAFANA_APP_ID" --platform web \
    --uri "http://localhost:$p/login/generic_oauth" >/dev/null
done
GRAFANA_SECRET=$("$BIN" app secret add --tenant "$TENANT_DOMAIN" --app "$GRAFANA_APP_ID" --days 1 | json '["secretText"]')
OAUTH2_PROXY_APP_ID=$("$BIN" app create --tenant "$TENANT_DOMAIN" --name oauth2-proxy | json '["appId"]')
"$BIN" app add-redirect-uri --tenant "$TENANT_DOMAIN" --app "$OAUTH2_PROXY_APP_ID" --platform web \
  --uri "http://localhost:$OAUTH2_PROXY_PORT/oauth2/callback" >/dev/null
OAUTH2_PROXY_SECRET=$("$BIN" app secret add --tenant "$TENANT_DOMAIN" --app "$OAUTH2_PROXY_APP_ID" --days 1 | json '["secretText"]')
# oauth2-proxy refuses an ID token whose email_verified is false, which is what a
# freshly created user has (alice, above). The CLI has no way to verify an email
# (only the admin console does), so a second user is created and flipped directly
# in the throwaway database. alice stays unverified as the negative case.
VERIFIED_UPN="bob@$TENANT_DOMAIN"
RUST_OIDC_PASSWORD="$USER_PASSWORD" "$BIN" user create --tenant "$TENANT_DOMAIN" --upn "$VERIFIED_UPN" \
  --display-name "Bob Jones" --given-name Bob --family-name Jones --email bob@example.org >/dev/null
python3 - "$WORK/db.sqlite" "$VERIFIED_UPN" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
n = con.execute("UPDATE users SET email_verified = 1 WHERE upn = ?", (sys.argv[2],)).rowcount
con.commit()
assert n == 1, f"expected to verify exactly one user, updated {n}"
PY

# ---- fixtures for the msidweb suite ----
# A second tenant with its own API and client. Its tokens are genuinely signed by
# this server but carry another tenant's issuer, which Microsoft.Identity.Web must
# refuse when configured for Contoso (the issuer-validation negative case).
OTHER_TENANT_DOMAIN="fabrikam.test"
"$BIN" tenant create --name Fabrikam --domain "$OTHER_TENANT_DOMAIN" >/dev/null
OTHER_API_APP_ID=$("$BIN" app create --tenant "$OTHER_TENANT_DOMAIN" --name fabrikam-api | json '["appId"]')
OTHER_CLIENT_APP_ID=$("$BIN" app create --tenant "$OTHER_TENANT_DOMAIN" --name fabrikam-worker | json '["appId"]')
"$BIN" app role add --tenant "$OTHER_TENANT_DOMAIN" --app "$OTHER_API_APP_ID" --value Orders.Read --member-types Application >/dev/null
"$BIN" app role assign --tenant "$OTHER_TENANT_DOMAIN" --resource "$OTHER_API_APP_ID" --role Orders.Read --app "$OTHER_CLIENT_APP_ID" >/dev/null
OTHER_CLIENT_SECRET=$("$BIN" app secret add --tenant "$OTHER_TENANT_DOMAIN" --app "$OTHER_CLIENT_APP_ID" --days 1 | json '["secretText"]')

# ---- server ----
export RUST_OIDC_BASE="https://localhost:$PORT/rust-oidc"
# Bound to [::] so the Kafka container can reach it via the host gateway and the
# Node suites still connect over ::1: Node 18 resolves localhost to IPv6 first
# and does not fall back, so an IPv4-only bind fails with ECONNREFUSED ::1.
"$BIN" serve --bind "[::]:$PORT" --public-url "$RUST_OIDC_BASE" \
  --tls-mode files --tls-cert "$WORK/tls/cert.pem" --tls-key "$WORK/tls/key.pem" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf --cacert "$WORK/tls/cert.pem" "$RUST_OIDC_BASE/healthz" >/dev/null && break
  sleep 0.1
done
curl -sf --cacert "$WORK/tls/cert.pem" "$RUST_OIDC_BASE/healthz" >/dev/null || { cat "$WORK/server.log"; exit 1; }

export PORT
export TENANT_ID TENANT_DOMAIN API_APP_ID CLIENT_APP_ID CLIENT_SECRET
export API_SECRET DOWNSTREAM_APP_ID CLIENT_CERT_KEY CLIENT_CERT_THUMBPRINT
export USER_UPN USER_PASSWORD WEB_APP_ID WEB_SECRET WEB_REDIRECT_URI
export CA_FILE="$WORK/tls/cert.pem"
export GRAFANA_APP_ID GRAFANA_SECRET GRAFANA_PORT GRAFANA_BAD_PORT
export VERIFIED_UPN
export OAUTH2_PROXY_APP_ID OAUTH2_PROXY_SECRET OAUTH2_PROXY_PORT OAUTH2_PROXY_UPSTREAM_PORT
export OTHER_TENANT_DOMAIN OTHER_API_APP_ID OTHER_CLIENT_APP_ID OTHER_CLIENT_SECRET
export EXPECTED_ROLES="Orders.Read,Orders.Write"

# jose and oauth4webapi use the WebCrypto global, which Node 18 exposes in ESM
# only behind a flag (it is unflagged from Node 19). Without this both Node
# suites die with "ReferenceError: crypto is not defined".
NODE_FLAGS=()
if [[ "$(node -p 'process.versions.node.split(".")[0]')" -lt 19 ]]; then
  NODE_FLAGS=(--experimental-global-webcrypto)
fi

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
      "$COMPAT/.venv/bin/python" "$COMPAT/msal-python/test_new_grants.py" || status=1
      ;;
    node)
      [[ -d "$COMPAT/msal-node/node_modules" ]] || (cd "$COMPAT/msal-node" && npm ci --silent)
      NODE_EXTRA_CA_CERTS="$CA_FILE" node "${NODE_FLAGS[@]}" "$COMPAT/msal-node/test_app_auth.mjs" || status=1
      ;;
    rp)
      [[ -d "$COMPAT/openid-client/node_modules" ]] || (cd "$COMPAT/openid-client" && npm ci --silent)
      NODE_EXTRA_CA_CERTS="$CA_FILE" node "${NODE_FLAGS[@]}" "$COMPAT/openid-client/test_rp.mjs" || status=1
      ;;
    kafka)
      "$COMPAT/kafka/test_oauthbearer.sh" || status=1
      ;;
    grafana)
      "$COMPAT/grafana/test_grafana.sh" || status=1
      ;;
    oauth2-proxy)
      "$COMPAT/oauth2-proxy/test_oauth2_proxy.sh" || status=1
      ;;
    msidweb)
      "$COMPAT/microsoft-identity-web/test_msidweb.sh" || status=1
      ;;
    *) echo "unknown suite: $suite"; status=1 ;;
  esac
done

if [[ $status -ne 0 ]]; then
  echo "--- server log ---"
  tail -50 "$WORK/server.log"
fi
exit $status
