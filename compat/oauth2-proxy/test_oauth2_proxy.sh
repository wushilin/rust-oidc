#!/usr/bin/env bash
# oauth2-proxy (--provider=oidc) compatibility test against rust-oidc.
#
# oauth2-proxy runs in podman with full OIDC discovery against rust-oidc's issuer.
# It (via go-oidc) checks the discovered issuer, the ID token signature against
# the JWKS, iss, aud and expiry, and (via oauth2-proxy) the nonce. None of that is
# relaxed. A scripted browser drives the login; a stub upstream on the host echoes
# the identity headers oauth2-proxy injects.
#
# Invoked by compat/run.sh with the fixtures it provisions.
set -euo pipefail

: "${TENANT_ID:?}" "${OAUTH2_PROXY_APP_ID:?}" "${OAUTH2_PROXY_SECRET:?}" "${CA_FILE:?}"
: "${RUST_OIDC_BASE:?}" "${OAUTH2_PROXY_PORT:?}" "${OAUTH2_PROXY_UPSTREAM_PORT:?}"
: "${USER_UPN:?}" "${VERIFIED_UPN:?}" "${USER_PASSWORD:?}"

if ! command -v podman >/dev/null 2>&1; then
  echo "SKIP: podman not installed; the oauth2-proxy suite needs a container runtime"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${OAUTH2_PROXY_IMAGE:-quay.io/oauth2-proxy/oauth2-proxy:v7.7.1}"
NAME="rust-oidc-oauth2-proxy-compat"
ISSUER="$RUST_OIDC_BASE/$TENANT_ID/v2.0"

WORK="$(mktemp -d)"
UPSTREAM_PID=""
cleanup() {
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
  podman rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
podman rm -f "$NAME" >/dev/null 2>&1 || true
cp "$CA_FILE" "$WORK/ca.pem"
chmod -R a+rX "$WORK"

python3 "$HERE/upstream.py" "$OAUTH2_PROXY_UPSTREAM_PORT" &
UPSTREAM_PID=$!

# Host networking, deliberately. oauth2-proxy fetches discovery from the issuer URL
# and go-oidc rejects the document unless its `issuer` equals that URL. rust-oidc's
# issuer is its public URL (https://localhost:PORT/...), so the container must be
# able to reach *localhost* as the host does; the --add-host alias used by the Kafka
# suite would change the URL and (correctly) fail issuer validation.
COOKIE_SECRET="$(python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
echo "--- starting oauth2-proxy ($IMAGE) ---"
podman run -d --name "$NAME" --network host \
  -v "$WORK/ca.pem:/etc/ssl/rust-oidc-ca.pem:ro,z" \
  "$IMAGE" \
  --provider=oidc \
  --oidc-issuer-url="$ISSUER" \
  --provider-ca-file=/etc/ssl/rust-oidc-ca.pem \
  --client-id="$OAUTH2_PROXY_APP_ID" \
  --client-secret="$OAUTH2_PROXY_SECRET" \
  --cookie-secret="$COOKIE_SECRET" \
  --cookie-secure=false \
  --redirect-url="http://localhost:$OAUTH2_PROXY_PORT/oauth2/callback" \
  --http-address="127.0.0.1:$OAUTH2_PROXY_PORT" \
  --upstream="http://127.0.0.1:$OAUTH2_PROXY_UPSTREAM_PORT" \
  --email-domain='*' \
  --scope="openid profile email" \
  --code-challenge-method=S256 \
  --skip-provider-button=true \
  --pass-user-headers=true >/dev/null

ready=0
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$OAUTH2_PROXY_PORT/ping" >/dev/null 2>&1 && { ready=1; break; }
  # oauth2-proxy exits at startup if OIDC discovery fails; stop waiting then.
  [[ "$(podman inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" == "true" ]] || break
  sleep 1
done
if [[ $ready -ne 1 ]]; then
  echo "FAIL: oauth2-proxy did not start (OIDC discovery or provider setup failed)"
  podman logs --tail 30 "$NAME" 2>&1 | cut -c1-300
  exit 1
fi
echo "PASS: oauth2-proxy started: OIDC discovery and issuer validation against $ISSUER succeeded"

jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1" 2>/dev/null || true; }
status=0
out="$(python3 "$HERE/drive_login.py" "http://localhost:$OAUTH2_PROXY_PORT" "$VERIFIED_UPN")" || { echo "FAIL: driver crashed"; out='{}'; status=1; }

echo "--- unauthenticated request ---"
code="$(jget "d['unauth']['status']" <<<"$out")"
loc="$(jget "d['unauth']['location']" <<<"$out")"
start_loc="$(jget "d['unauth']['start_location']" <<<"$out")"
AUTHORIZE="$RUST_OIDC_BASE/$TENANT_ID/oauth2/v2.0/authorize?"
if [[ "$code" == "302" && "$loc" == "$AUTHORIZE"* && "$start_loc" == "$AUTHORIZE"* ]]; then
  echo "PASS: unauthenticated /protected is redirected to rust-oidc authorize (also via /oauth2/start)"
else
  echo "FAIL: unauthenticated request was not sent to rust-oidc: status=$code location=$loc start=$start_loc"; status=1
fi

echo "--- login ---"
hops="$(jget "'\n'.join(d['login']['hops'])" <<<"$out")"
if grep -q "/oauth2/v2.0/authorize" <<<"$hops" && grep -q "/oauth2/callback" <<<"$hops"; then
  echo "PASS: browser was sent to rust-oidc authorize and came back to /oauth2/callback"
else
  echo "FAIL: redirect chain lacks rust-oidc authorize / proxy callback:"; sed 's/^/    /' <<<"$hops"; status=1
fi
pstatus="$(jget "d['protected']['status']" <<<"$out")"
fuser="$(jget "d['protected']['echo']['headers'].get('X-Forwarded-User')" <<<"$out")"
femail="$(jget "d['protected']['echo']['headers'].get('X-Forwarded-Email')" <<<"$out")"
if [[ "$pstatus" == "200" && "$femail" == "bob@example.org" ]]; then
  echo "PASS: authenticated /protected reached the upstream as user=$fuser email=$femail"
else
  echo "FAIL: expected 200 with X-Forwarded-Email=bob@example.org, got status=$pstatus user=$fuser email=$femail"
  cut -c1-800 <<<"$out"; status=1
fi

echo "--- ID token validation ---"
# A successful callback means oauth2-proxy verified signature, iss, aud, exp and
# nonce. Assert positively on its session, and negatively on validation errors.
ustatus="$(jget "d['userinfo']['status']" <<<"$out")"
if [[ "$ustatus" == "200" ]] && ! podman logs "$NAME" 2>&1 | grep -qiE "failed to verify|nonce|invalid.*(signature|audience|issuer)|unable to verify|Error redeeming"; then
  echo "PASS: ID token accepted (signature, iss, aud, nonce), session userinfo 200, no validation errors logged"
else
  echo "FAIL: ID token validation problem (userinfo=$ustatus)"
  podman logs "$NAME" 2>&1 | grep -iE "error|fail|nonce|verify" | tail -5 | cut -c1-300 | sed 's/^/    /'
  status=1
fi

echo "--- unverified email (expects rejection) ---"
# alice's email_verified is false. oauth2-proxy honours that claim, so her login must
# fail at the callback and leave her without access.
out2="$(python3 "$HERE/drive_login.py" "http://localhost:$OAUTH2_PROXY_PORT" "$USER_UPN")" || out2='{}'
p2="$(jget "d['protected']['status']" <<<"$out2")"
# `podman logs` can lag the container's stdout by a moment, so poll for the line.
refused=0
for _ in $(seq 1 10); do
  podman logs "$NAME" 2>&1 | grep -q "isn't verified" && { refused=1; break; }
  sleep 1
done
if [[ "$p2" != "200" && $refused -eq 1 ]]; then
  echo "PASS: oauth2-proxy refused the unverified-email user (upstream status $p2)"
else
  echo "FAIL: unverified-email user was not refused (upstream status $p2)"
  jget "d['login']['final_url']" <<<"$out2"; jget "d['login']['body_head']" <<<"$out2"
  podman logs --tail 8 "$NAME" 2>&1 | cut -c1-300; status=1
fi

if [[ $status -ne 0 ]]; then
  echo "--- oauth2-proxy log ---"
  podman logs --tail 30 "$NAME" 2>&1 | cut -c1-300
fi
exit $status
