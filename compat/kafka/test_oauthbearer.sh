#!/usr/bin/env bash
# Kafka SASL/OAUTHBEARER (OIDC) compatibility test against rust-oidc.
#
# A single-node Kafka broker in podman validates rust-oidc access tokens with
# Kafka's own OAuthBearerValidatorCallbackHandler (KIP-768): it fetches the JWKS
# from rust-oidc and checks signature, issuer and audience. The console producer
# and consumer authenticate with OAuthBearerLoginCallbackHandler, which performs
# a client_credentials grant against rust-oidc's token endpoint.
#
# Invoked by compat/run.sh with the fixtures it provisions.
set -euo pipefail

: "${TENANT_ID:?}" "${API_APP_ID:?}" "${CLIENT_APP_ID:?}" "${CLIENT_SECRET:?}"
: "${WEB_APP_ID:?}" "${CA_FILE:?}" "${RUST_OIDC_BASE:?}" "${PORT:?}"

if ! command -v podman >/dev/null 2>&1; then
  echo "SKIP: podman not installed; the Kafka suite needs a container runtime"
  exit 0
fi

IMAGE="${KAFKA_IMAGE:-docker.io/apache/kafka:3.9.1}"
NAME="rust-oidc-kafka-compat"
TOPIC="orders"
MESSAGE="hello-from-rust-oidc-$$"
STORE_PASS="changeit"

# The broker reaches rust-oidc on the host. Under rootless podman the host's own
# LAN IP is unreachable from a container, so use the host-gateway alias.
HOST_ALIAS="host.containers.internal"
OIDC_IN_CONTAINER="https://$HOST_ALIAS:$PORT/rust-oidc"
TOKEN_URL="$OIDC_IN_CONTAINER/$TENANT_ID/oauth2/v2.0/token"
JWKS_URL="$OIDC_IN_CONTAINER/$TENANT_ID/discovery/v2.0/keys"
# The token's `iss` comes from rust-oidc's public URL, NOT from the address the
# broker happens to fetch from, so these two deliberately differ.
ISSUER="$RUST_OIDC_BASE/$TENANT_ID/v2.0"

WORK="$(mktemp -d)"
cleanup() {
  podman rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
podman rm -f "$NAME" >/dev/null 2>&1 || true

cp "$CA_FILE" "$WORK/ca.pem"
chmod -R a+rX "$WORK"

jaas() { # $1 = resource appId to request a token for
  printf '%s' "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId=\"$CLIENT_APP_ID\" clientSecret=\"$CLIENT_SECRET\" scope=\"api://$1/.default\";"
}

props() { # $1 = output file, $2 = resource appId
  cat > "$1" <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=OAUTHBEARER
sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler
sasl.oauthbearer.token.endpoint.url=$TOKEN_URL
sasl.jaas.config=$(jaas "$2")
EOF
}
props "$WORK/client.properties" "$API_APP_ID"
props "$WORK/client-wrong-audience.properties" "$WEB_APP_ID"

# Java needs the dev CA in a truststore; use the image's own keytool. The image
# runs as a non-root user that cannot write into the bind mount, so build the
# store as root and leave it readable for the broker process.
podman run --rm --user 0 -v "$WORK:/work:z" --entrypoint /bin/sh "$IMAGE" -c \
  "keytool -importcert -noprompt -alias rust-oidc -file /work/ca.pem \
     -keystore /work/truststore.jks -storepass $STORE_PASS >/dev/null \
   && chmod 644 /work/truststore.jks" \
  || { echo "FAIL: could not build truststore"; exit 1; }

TLS_OPTS="-Djavax.net.ssl.trustStore=/work/truststore.jks -Djavax.net.ssl.trustStorePassword=$STORE_PASS"

echo "--- starting Kafka broker ($IMAGE) ---"
podman run -d --name "$NAME" \
  --add-host "$HOST_ALIAS:host-gateway" \
  -v "$WORK:/work:z" \
  -e KAFKA_NODE_ID=1 \
  -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENERS=CLIENT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093,INTERNAL://0.0.0.0:9094 \
  -e KAFKA_ADVERTISED_LISTENERS=CLIENT://localhost:9092,INTERNAL://localhost:9094 \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CLIENT:SASL_PLAINTEXT,CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_SASL_ENABLED_MECHANISMS=OAUTHBEARER \
  -e KAFKA_LISTENER_NAME_CLIENT_SASL_ENABLED_MECHANISMS=OAUTHBEARER \
  -e KAFKA_LISTENER_NAME_CLIENT_OAUTHBEARER_SASL_SERVER_CALLBACK_HANDLER_CLASS=org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler \
  -e KAFKA_LISTENER_NAME_CLIENT_OAUTHBEARER_SASL_JAAS_CONFIG="org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;" \
  -e KAFKA_SASL_OAUTHBEARER_JWKS_ENDPOINT_URL="$JWKS_URL" \
  -e KAFKA_SASL_OAUTHBEARER_EXPECTED_AUDIENCE="$API_APP_ID" \
  -e KAFKA_SASL_OAUTHBEARER_EXPECTED_ISSUER="$ISSUER" \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
  -e KAFKA_OPTS="$TLS_OPTS" \
  "$IMAGE" >/dev/null

K() { podman exec -e KAFKA_OPTS="$TLS_OPTS" "$NAME" "$@"; }
# The console producer reads its records from stdin, so it needs `exec -i`;
# without it the producer sees EOF at once, sends nothing and still exits 0.
KI() { podman exec -i -e KAFKA_OPTS="$TLS_OPTS" "$NAME" "$@"; }

ready=0
for _ in $(seq 1 60); do
  if K /opt/kafka/bin/kafka-broker-api-versions.sh \
       --bootstrap-server localhost:9094 >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if [[ $ready -ne 1 ]]; then
  echo "FAIL: broker did not become ready"
  podman logs --tail 40 "$NAME"
  exit 1
fi

# The topic is created over the PLAINTEXT internal listener so that a failure
# here is never confused with an authentication failure.
K /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9094 \
  --create --topic "$TOPIC" --partitions 1 --replication-factor 1 >/dev/null

status=0

echo "--- OAUTHBEARER produce/consume (expects success) ---"
if printf '%s\n' "$MESSAGE" | KI /opt/kafka/bin/kafka-console-producer.sh \
     --bootstrap-server localhost:9092 --topic "$TOPIC" \
     --producer.config /work/client.properties >/dev/null 2>"$WORK/produce.err"; then
  got="$(K /opt/kafka/bin/kafka-console-consumer.sh \
           --bootstrap-server localhost:9092 --topic "$TOPIC" \
           --consumer.config /work/client.properties \
           --from-beginning --max-messages 1 --timeout-ms 30000 \
           2>"$WORK/consume.err" | tr -d '\r\n')"
  if [[ "$got" == "$MESSAGE" ]]; then
    echo "PASS: produced and consumed '$got' using an OIDC access token"
  else
    echo "FAIL: expected '$MESSAGE', consumed '$got'"
    tail -20 "$WORK/consume.err"; status=1
  fi
else
  echo "FAIL: producer could not authenticate with a valid token"
  tail -20 "$WORK/produce.err"; status=1
fi

echo "--- wrong audience (expects rejection) ---"
# The console tools exit 0 even when the broker refuses them, so assert on the
# error the client reports AND on a fresh rejection in the broker's own log,
# rather than on an exit code. A metadata call is enough to force SASL.
marker="doesn't contain an acceptable identifier"
before=$(podman logs "$NAME" 2>&1 | grep -c "$marker" || true)
out="$(K /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
         --command-config /work/client-wrong-audience.properties --list 2>&1 || true)"
after=$(podman logs "$NAME" 2>&1 | grep -c "$marker" || true)
if grep -qiE "authenticat|invalid_token|SaslAuthentication" <<<"$out" && [[ "$after" -gt "$before" ]]; then
  echo "PASS: broker rejected the wrong-audience token (aud=$WEB_APP_ID, expected $API_APP_ID)"
  podman logs "$NAME" 2>&1 | grep "$marker" | tail -1 | sed 's/^/       /'
else
  echo "FAIL: the wrong-audience token was not rejected as expected"
  echo "  client output:"; printf '%s\n' "$out" | tail -10 | sed 's/^/    /'
  echo "  broker rejections before=$before after=$after"
  status=1
fi

if [[ $status -ne 0 ]]; then
  echo "--- broker log ---"
  podman logs --tail 40 "$NAME"
fi
exit $status
