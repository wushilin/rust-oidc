#!/usr/bin/env bash
# Run the test suite against SQLite, PostgreSQL and MySQL.
#
# Starts one throwaway container per server engine in podman, waits until each
# accepts a real query, exports the env vars tests/common/mod.rs looks for, runs
# `cargo test` (once per engine for the HTTP-level tests, which pick their engine
# from RUST_OIDC_TEST_ENGINE), and removes the containers on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required" >&2
  exit 1
fi

PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:16}"
MY_IMAGE="${MY_IMAGE:-docker.io/library/mysql:8}"
PG_NAME="rust-oidc-test-pg"
MY_NAME="rust-oidc-test-my"
PG_PORT="${PG_PORT:-15432}"
MY_PORT="${MY_PORT:-13306}"
READY_TIMEOUT="${READY_TIMEOUT:-180}"

cleanup() {
  podman rm -f "$PG_NAME" "$MY_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# Throwaway data: keep it on tmpfs and skip durability. On a disk-backed MySQL
# each test's fresh database costs ~10s of DDL; on tmpfs it costs well under 1s.
# The connection cap is raised because many test databases are live at once.
podman run -d --name "$PG_NAME" --tmpfs /var/lib/postgresql/data:rw \
  -e POSTGRES_PASSWORD=test -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" \
  -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=500 >/dev/null
podman run -d --name "$MY_NAME" --tmpfs /var/lib/mysql:rw \
  -e MYSQL_ROOT_PASSWORD=test -p "127.0.0.1:$MY_PORT:3306" "$MY_IMAGE" \
  --skip-log-bin --innodb-flush-log-at-trx-commit=0 --innodb-doublewrite=0 --max-connections=500 >/dev/null

wait_ready() { # $1 = label, remaining args = probe command run inside the container
  local label="$1" name="$2"; shift 2
  local deadline=$((SECONDS + READY_TIMEOUT))
  until podman exec "$name" "$@" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "$label did not become ready within ${READY_TIMEOUT}s" >&2
      podman logs --tail 30 "$name" >&2 || true
      exit 1
    fi
    sleep 1
  done
  echo "$label ready"
}
# A real query over TCP, not just a socket: both images run a temporary
# bootstrap server (unix socket only) before the real one comes up.
wait_ready postgres "$PG_NAME" psql -h 127.0.0.1 -U postgres -c 'select 1'
wait_ready mysql "$MY_NAME" mysql -h 127.0.0.1 -uroot -ptest -e 'select 1'

export RUST_OIDC_TEST_POSTGRES="postgres://postgres:test@127.0.0.1:$PG_PORT/postgres"
export RUST_OIDC_TEST_MYSQL="mysql://root:test@127.0.0.1:$MY_PORT/mysql"

status=0
for engine in sqlite postgres mysql; do
  echo "=== cargo test (HTTP-level tests on $engine; db tests on every engine) ==="
  RUST_OIDC_TEST_ENGINE="$engine" cargo test "$@" || status=$?
done
exit "$status"
