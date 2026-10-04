#!/usr/bin/env bash
# Run OpenID Foundation conformance plans against a deployed rust-oidc.
#
# Prereqs (see README in this dir): podman + podman-compose, a clone of
# https://gitlab.com/openid/conformance-suite at $SUITE (for scripts/), and a
# fixture JSON (tenant, user, two clients) at $FIXTURE.
#
# Usage: compat/conformance/run.sh [plan-spec ...]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUITE="${SUITE:-$HOME/conformance-suite}"
FIXTURE="${FIXTURE:-$SUITE/rust-oidc-fixture.json}"
WORK="${WORK:-$HOME/.cache/rust-oidc-conformance}"
# The deployment under test: titanl serves on 10443 since 2026-10-01.
BASE="${RUST_OIDC_BASE:-https://gate.wushilin.net:10443/rust-oidc}"
mkdir -p "$WORK"

PLANS=("$@")
if [[ ${#PLANS[@]} -eq 0 ]]; then
  PLANS=(
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
    "oidcc-config-certification-test-plan"
    "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  )
fi

cp "$HERE/compose.yml" "$WORK/compose.yml"
mkdir -p "$WORK/mongo-data"
(cd "$WORK" && podman-compose -p oidf up -d >/dev/null)

python3 "$HERE/make_config.py" "$FIXTURE" "$BASE" > "$WORK/config.json"
chmod 600 "$WORK/config.json"

# The plan runner writes its zip/HTML exports here but does not create the dir;
# without this every plan dies with "No such file or directory: /work/results/...zip"
# after its modules have already run.
mkdir -p "$WORK/results"

# Wait for the suite API.
for _ in $(seq 1 90); do
  curl -sk -o /dev/null -w '%{http_code}' https://localhost:18443/api/runner/available 2>/dev/null | grep -q 200 && break
  sleep 2
done

NET=$(podman network ls --format '{{.Name}}' | grep -E '^oidf' | head -1)
ARGS=()
for p in "${PLANS[@]}"; do ARGS+=("$p" /work/config.json); done

# Run the suite's own runner inside the compose network so its URLs resolve.
podman run --rm --network "$NET" \
  -v "$SUITE/scripts:/scripts:ro,z" -v "$WORK:/work:z" -w /work \
  -e CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/ \
  -e CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/ \
  -e CONFORMANCE_DEV_MODE=1 \
  docker.io/library/python:3.12-slim \
  sh -c "pip install -q -r /scripts/requirements.txt && python3 /scripts/run-test-plan.py --export-dir /work/results ${ARGS[*]@Q}"
