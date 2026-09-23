#!/usr/bin/env bash
# Bootstraps a disposable GLPI 11.0.9 + MariaDB + TLS-proxy environment for
# the real GLPI integration suite (ADR 0009 "Two-layer test policy").
#
# This is test infrastructure only: the adapter under test still exercises
# the production GLPI V1 apirest.php contract exclusively over HTTPS.
# Everything provisioned here is ephemeral, generated per run, and torn
# down unconditionally on exit (including failure).
#
# Requires: docker compose (v2 plugin), curl, openssl.
#
# Usage:
#   source <(crates/permissionsync-adapter-glpi/tests/real-glpi/bootstrap.sh)
#   cargo test -p permissionsync-adapter-glpi --test real_glpi -- --ignored
#
# NOTE: the PHP bootstrap this script drives (bootstrap.php) has NOT been
# executed against a real GLPI 11.0.9 container in this environment
# (Docker is unavailable here). Verify it against an actual container
# before relying on it in CI.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

# --- Isolation: non-colliding project name, generated credentials, and
# --- TLS material kept entirely outside the repository working tree. ---
run_suffix="$$-${RANDOM}"
project_name="permissionsync-glpi-real-${run_suffix}"
tls_dir="$(mktemp -d "${TMPDIR:-/tmp}/permissionsync-glpi-tls.XXXXXX")"

GLPI_TEST_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
GLPI_TEST_DB_PASSWORD="$(openssl rand -hex 24)"
export GLPI_TEST_DB_ROOT_PASSWORD GLPI_TEST_DB_PASSWORD

# --- Dynamically allocated host ports (collision-safe): ask the kernel
# --- for two free ephemeral ports and release them immediately before
# --- compose binds them; this is inherently best-effort (TOCTOU) but
# --- avoids fixed ports colliding with concurrent runs or other services.
find_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

GLPI_TEST_HTTP_PORT="$(find_free_port)"
GLPI_TEST_HTTPS_PORT="$(find_free_port)"
export GLPI_TEST_HTTP_PORT GLPI_TEST_HTTPS_PORT GLPI_TEST_TLS_DIR="$tls_dir"

compose() {
  docker compose -p "$project_name" "$@"
}

cleanup() {
  local status=$?
  echo "Tearing down the disposable GLPI environment (project ${project_name})..." >&2
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tls_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "Generating an ephemeral TLS CA and server certificate under ${tls_dir}..." >&2
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout "${tls_dir}/ca.key" -out "${tls_dir}/ca.crt" \
  -subj "/CN=permissionsync-glpi-real-integration-ca"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${tls_dir}/server.key" -out "${tls_dir}/server.csr" \
  -subj "/CN=127.0.0.1"
openssl x509 -req -in "${tls_dir}/server.csr" -CA "${tls_dir}/ca.crt" -CAkey "${tls_dir}/ca.key" \
  -CAcreateserial -days 2 -out "${tls_dir}/server.crt" \
  -extfile <(printf "subjectAltName=IP:127.0.0.1")

# --- Step A: base DB + GLPI install readiness (no V1 API dependency). ---
echo "Starting the disposable database and GLPI containers..." >&2
compose up -d --wait --wait-timeout 180 db glpi

echo "Waiting for GLPI base HTTP readiness (status.php, no API required)..." >&2
deadline=$((SECONDS + 120))
until curl -fsS "http://127.0.0.1:${GLPI_TEST_HTTP_PORT}/status.php" >/dev/null 2>&1; do
  if (( SECONDS > deadline )); then
    echo "GLPI base HTTP readiness did not succeed within the bounded timeout." >&2
    exit 1
  fi
  sleep 2
done

# --- Step B: bootstrap/configuration through GLPI's own PHP object API. ---
echo "Provisioning the V1 API, a dedicated service account, and ephemeral tokens..." >&2
bootstrap_output="$(compose exec -T glpi php bootstrap.php)" || {
  echo "GLPI PHP bootstrap failed:" >&2
  echo "$bootstrap_output" >&2
  exit 1
}

APP_TOKEN="$(printf '%s\n' "$bootstrap_output" | grep -m1 '^APP_TOKEN=' | cut -d= -f2-)"
USER_TOKEN="$(printf '%s\n' "$bootstrap_output" | grep -m1 '^USER_TOKEN=' | cut -d= -f2-)"
SERVICE_USERNAME="$(printf '%s\n' "$bootstrap_output" | grep -m1 '^SERVICE_USERNAME=' | cut -d= -f2-)"

if [[ -z "${APP_TOKEN}" || -z "${USER_TOKEN}" || -z "${SERVICE_USERNAME}" ]]; then
  echo "GLPI PHP bootstrap did not print the expected credentials:" >&2
  echo "$bootstrap_output" >&2
  exit 1
fi

# --- Step C: bring up the TLS-facing endpoint now that the backend is
# --- fully configured. ---
echo "Starting the TLS proxy..." >&2
compose up -d --wait --wait-timeout 60 tls-proxy

# --- Step D: actively prove initSession works with the generated
# --- credentials before handing control to adapter tests. ---
echo "Verifying initSession against the disposable environment..." >&2
init_session_deadline=$((SECONDS + 60))
init_session_ok=0
while (( SECONDS <= init_session_deadline )); do
  http_status="$(curl -k -s -o /tmp/permissionsync-glpi-init-session.$$ -w '%{http_code}' \
    -H "Authorization: user_token ${USER_TOKEN}" \
    -H "App-Token: ${APP_TOKEN}" \
    "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php/initSession" || echo 000)"
  if [[ "$http_status" == "200" ]]; then
    init_session_ok=1
    session_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_token"])' \
      /tmp/permissionsync-glpi-init-session.$$)"
    curl -k -s -o /dev/null \
      -H "Session-Token: ${session_token}" \
      -H "App-Token: ${APP_TOKEN}" \
      "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php/killSession" || true
    rm -f /tmp/permissionsync-glpi-init-session.$$
    break
  fi
  rm -f /tmp/permissionsync-glpi-init-session.$$
  sleep 2
done

if [[ "$init_session_ok" != "1" ]]; then
  echo "initSession did not succeed with the generated App-Token/User-Token within the bounded timeout." >&2
  exit 1
fi

trap - EXIT INT TERM
# Intentionally do NOT run cleanup here: the environment must stay up for
# the calling test process. The caller is responsible for invoking
# `docker compose -p ${project_name} down --volumes --remove-orphans` and
# removing ${tls_dir} once done; teardown.sh below does exactly that.
cat > "${script_dir}/.real-glpi-run-env" <<ENV
PERMISSIONSYNC_GLPI_PROJECT_NAME=${project_name}
PERMISSIONSYNC_GLPI_TLS_DIR=${tls_dir}
ENV

echo "export GLPI_TEST_ENDPOINT=https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php"
echo "export GLPI_TEST_APP_TOKEN=${APP_TOKEN}"
echo "export GLPI_TEST_USER_TOKEN=${USER_TOKEN}"
echo "export GLPI_TEST_CA_PEM_PATH=${tls_dir}/ca.crt"
echo "export GLPI_TEST_COMPOSE_PROJECT=${project_name}"
echo "export GLPI_TEST_DB_ROOT_PASSWORD=${GLPI_TEST_DB_ROOT_PASSWORD}"
echo "# Run '${script_dir}/teardown.sh' when done to tear the environment down."
