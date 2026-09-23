#!/usr/bin/env bash
# Bootstrap a disposable GLPI 11.0.9 environment for the ignored real suite.
# NOTE: Docker is unavailable in the current development environment, so this
# bootstrap and the real suite remain unexecuted locally.
set -euo pipefail

runtime_base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
runtime_dir="$(mktemp -d "${runtime_base%/}/permissionsync-glpi.XXXXXX")"
runtime_env="${runtime_dir}/runtime.env"
bootstrap_stdout="${runtime_dir}/bootstrap.stdout"
bootstrap_stderr="${runtime_dir}/bootstrap.stderr"
compose_base_stdout="${runtime_dir}/compose-base.stdout"
compose_base_stderr="${runtime_dir}/compose-base.stderr"
project_name="permissionsync-glpi-real-$$-${RANDOM}"
tls_dir="${runtime_dir}/tls"

umask 077
mkdir -p "$tls_dir"
touch "$runtime_env" "$bootstrap_stdout" "$bootstrap_stderr" "$compose_base_stdout" "$compose_base_stderr"
chmod 600 "$runtime_env" "$bootstrap_stdout" "$bootstrap_stderr" "$compose_base_stdout" "$compose_base_stderr"

env_put() {
  local name="$1" value="$2" escaped
  escaped="${value//\'/\'\\\'}"
  printf "%s='%s'\n" "$name" "$escaped" >> "$runtime_env"
}

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_:
    socket_.bind(("127.0.0.1", 0))
    print(socket_.getsockname()[1])
PY
}

env_put GLPI_TEST_DB_ROOT_PASSWORD "$(openssl rand -hex 24)"
env_put GLPI_TEST_DB_PASSWORD "$(openssl rand -hex 24)"
env_put GLPI_TEST_HTTP_PORT "$(find_free_port)"
env_put GLPI_TEST_HTTPS_PORT "$(find_free_port)"
env_put GLPI_TEST_TLS_DIR "$tls_dir"
env_put PERMISSIONSYNC_GLPI_PROJECT_NAME "$project_name"
env_put GLPI_TEST_RUNTIME_DIR "$runtime_dir"
env_put GLPI_TEST_RUNTIME_ENV "$runtime_env"

# shellcheck disable=SC1090
source "$runtime_env"
env_put GLPI_TEST_ENDPOINT "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php"
env_put GLPI_TEST_CA_PEM_PATH "${tls_dir}/ca.crt"
env_put GLPI_TEST_COMPOSE_PROJECT "$project_name"

compose() {
  docker compose --env-file "$runtime_env" -p "$project_name" "$@"
}

cleanup_failed_bootstrap() {
  local status=$?
  if ! compose down --volumes --remove-orphans >/dev/null 2>&1; then
    printf '%s\n' 'GLPI bootstrap cleanup failed; docker compose down diagnostics were redacted.' >&2
  fi
  rm -rf "$runtime_dir"
  exit "$status"
}
trap cleanup_failed_bootstrap EXIT INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout "${tls_dir}/ca.key" -out "${tls_dir}/ca.crt" \
  -subj "/CN=permissionsync-glpi-real-integration-ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${tls_dir}/server.key" -out "${tls_dir}/server.csr" \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
openssl x509 -req -in "${tls_dir}/server.csr" -CA "${tls_dir}/ca.crt" -CAkey "${tls_dir}/ca.key" \
  -CAcreateserial -days 2 -out "${tls_dir}/server.crt" \
  -extfile <(printf 'subjectAltName=IP:127.0.0.1') >/dev/null 2>&1

if ! compose up -d --wait --wait-timeout 180 db glpi >"$compose_base_stdout" 2>"$compose_base_stderr"; then
  printf '%s\n' 'GLPI base containers did not start; captured output was redacted.' >&2
  exit 1
fi

deadline=$((SECONDS + 120))
until curl --fail --silent --show-error "http://127.0.0.1:${GLPI_TEST_HTTP_PORT}/status.php" >/dev/null; do
  if ((SECONDS > deadline)); then
    printf '%s\n' 'GLPI base HTTP readiness timed out.' >&2
    exit 1
  fi
  sleep 2
done

if ! compose exec -T glpi php bootstrap.php >"$bootstrap_stdout" 2>"$bootstrap_stderr"; then
  printf '%s\n' 'GLPI PHP bootstrap failed; captured output was redacted.' >&2
  exit 1
fi

python3 - "$bootstrap_stdout" "$runtime_env" <<'PY'
import re
import sys

output_path, env_path = sys.argv[1:]
expected = {
    "APP_TOKEN": "GLPI_TEST_APP_TOKEN",
    "USER_TOKEN": "GLPI_TEST_USER_TOKEN",
    "SERVICE_USERNAME": "GLPI_TEST_SERVICE_USERNAME",
    "TARGET_PROFILE_A": "GLPI_TEST_TARGET_PROFILE_A",
    "TARGET_PROFILE_B": "GLPI_TEST_TARGET_PROFILE_B",
    "TARGET_PROFILE_C": "GLPI_TEST_TARGET_PROFILE_C",
}
values = {}
with open(output_path, encoding="utf-8") as output:
    for line in output.read().splitlines():
        match = re.fullmatch(r"([A-Z_]+)=([^\r\n=]+)", line)
        if not match or match.group(1) not in expected or match.group(1) in values:
            raise SystemExit("GLPI PHP bootstrap emitted an unexpected credential record")
        values[match.group(1)] = match.group(2)
if set(values) != set(expected):
    raise SystemExit("GLPI PHP bootstrap did not emit every required credential record")
with open(env_path, "a", encoding="utf-8") as environment:
    for source, destination in expected.items():
        value = values[source].replace("'", "'\\''")
        environment.write(f"{destination}='{value}'\n")
PY

# shellcheck disable=SC1090
source "$runtime_env"
printf '::add-mask::%s\n' "$GLPI_TEST_APP_TOKEN"
printf '::add-mask::%s\n' "$GLPI_TEST_USER_TOKEN"

compose up -d --wait --wait-timeout 60 tls-proxy

init_response="${runtime_dir}/init-session.json"
init_session_deadline=$((SECONDS + 60))
init_session_ok=0
while ((SECONDS <= init_session_deadline)); do
  if http_status="$(curl --cacert "${tls_dir}/ca.crt" --silent --show-error --output "$init_response" --write-out '%{http_code}' \
    -H "Authorization: user_token ${GLPI_TEST_USER_TOKEN}" \
    -H "App-Token: ${GLPI_TEST_APP_TOKEN}" \
    "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php/initSession" 2>/dev/null)" && [[ "$http_status" == '200' ]]; then
    session_token="$(python3 - "$init_response" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get("session_token")
if not isinstance(value, str) or not value:
    raise SystemExit(1)
print(value)
PY
)" || session_token=''
    if [[ -n "$session_token" ]]; then
      printf '::add-mask::%s\n' "$session_token"
      curl --cacert "${tls_dir}/ca.crt" --silent --show-error --output /dev/null \
        -H "Session-Token: ${session_token}" \
        -H "App-Token: ${GLPI_TEST_APP_TOKEN}" \
        "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php/killSession" >/dev/null
      init_session_ok=1
      break
    fi
  fi
  sleep 2
done
rm -f "$init_response"

if [[ "$init_session_ok" != '1' ]]; then
  printf '%s\n' 'initSession did not succeed with the generated credentials.' >&2
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'GLPI_TEST_RUNTIME_ENV=%s\n' "$runtime_env" >> "$GITHUB_ENV"
fi
trap - EXIT INT TERM
printf 'export GLPI_TEST_RUNTIME_ENV=%q\n' "$runtime_env"
