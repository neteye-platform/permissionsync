#!/usr/bin/env bash
# Bootstrap a disposable GLPI 11.0.9 environment for the ignored real suite.
# diagnostics.sh and teardown.sh own failure diagnostics and destructive
# cleanup, respectively. On a local failure after the runtime directory is
# created, this script reports the safe runtime-env locator (never its
# contents) on stderr so diagnostics/teardown can still be run manually.
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
proxy_log_dir="${runtime_dir}/proxy-logs"

umask 077
mkdir -p "$tls_dir"
mkdir -p "$proxy_log_dir"
# This ephemeral test-only directory holds no secrets, only the killSession
# proxy log's timestamp/method/upstream-status lines; the official nginx image's
# worker process runs as an unprivileged user, so it must be writable by it.
chmod 777 "$proxy_log_dir"
touch "$runtime_env" "$bootstrap_stdout" "$bootstrap_stderr" "$compose_base_stdout" "$compose_base_stderr"
chmod 600 "$runtime_env" "$bootstrap_stdout" "$bootstrap_stderr" "$compose_base_stdout" "$compose_base_stderr"

env_put() {
  local name="$1" value="$2" escaped
  escaped="${value//\'/\'\\\'}"
  printf "%s='%s'\n" "$name" "$escaped" >> "$runtime_env"
}

# GitHub `::add-mask::` workflow commands only make sense (and are only safe)
# inside GitHub Actions: outside of it they are ordinary stdout, and the
# documented local usage is `source <(bootstrap.sh)`, where a local shell
# would otherwise try to execute `::add-mask::<secret>` as a command and could
# echo the secret in the resulting error. Gate masking on GITHUB_ACTIONS so
# local stdout never contains it.
mask_secret() {
  if [[ "${GITHUB_ACTIONS:-}" == 'true' ]]; then
    printf '::add-mask::%s\n' "$1"
  fi
}

# If bootstrap fails after the runtime directory (and possibly containers)
# already exist, print only the safe runtime-env locator plus the follow-up
# commands, never runtime.env contents or credentials, and never delete
# anything here: diagnostics.sh/teardown.sh own that. The original bootstrap
# exit status is preserved.
report_recovery_on_failure() {
  local status=$?
  if ((status != 0)); then
    {
      printf '%s\n' 'Bootstrap failed after creating a disposable runtime directory.'
      printf 'Runtime env locator: %s\n' "$runtime_env"
      printf 'Diagnostics: GLPI_TEST_RUNTIME_ENV=%q ./diagnostics.sh\n' "$runtime_env"
      printf 'Teardown:   GLPI_TEST_RUNTIME_ENV=%q ./teardown.sh\n' "$runtime_env"
    } >&2
  fi
  exit "$status"
}
trap report_recovery_on_failure EXIT

env_put GLPI_TEST_DB_ROOT_PASSWORD "$(openssl rand -hex 24)"
env_put GLPI_TEST_DB_PASSWORD "$(openssl rand -hex 24)"
env_put GLPI_TEST_TLS_DIR "$tls_dir"
env_put GLPI_TEST_PROXY_LOG_DIR "$proxy_log_dir"
env_put PERMISSIONSYNC_GLPI_PROJECT_NAME "$project_name"
env_put GLPI_TEST_RUNTIME_DIR "$runtime_dir"
env_put GLPI_TEST_RUNTIME_ENV "$runtime_env"

# Export the runtime-env locator to $GITHUB_ENV as soon as the runtime
# directory and its diagnostic files exist, so a later CI step can find
# bootstrap.stderr/compose-base.stderr even if bootstrap fails below. This is
# a filesystem path locator only; it is never a secret value.
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'GLPI_TEST_RUNTIME_ENV=%s\n' "$runtime_env" >> "$GITHUB_ENV"
fi

compose() {
  docker compose --env-file "$runtime_env" -p "$project_name" "$@"
}

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

# Docker assigned the host port when the compose file published it with an
# empty host-port component (`127.0.0.1::80`); discover the real bound port
# now instead of preselecting one and racing another process for it.
http_port_mapping="$(compose port glpi 80)"
http_port="${http_port_mapping##*:}"
if [[ -z "$http_port" || ! "$http_port" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'Could not determine the Docker-assigned GLPI HTTP host port.' >&2
  exit 1
fi
env_put GLPI_TEST_HTTP_PORT "$http_port"
# shellcheck disable=SC1090
source "$runtime_env"

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
    "TOPOLOGY_USER_TOKEN": "GLPI_TEST_TOPOLOGY_USER_TOKEN",
    "TOPOLOGY_BRANCH_TWO": "GLPI_TEST_TOPOLOGY_BRANCH_TWO",
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
mask_secret "$GLPI_TEST_APP_TOKEN"
mask_secret "$GLPI_TEST_USER_TOKEN"
mask_secret "$GLPI_TEST_TOPOLOGY_USER_TOKEN"

killsession_log="${proxy_log_dir}/killsession.log"
# The private runtime directory contains only this safe timestamp/method/
# upstream-status log. Initialize it before nginx starts so the exclusive
# cleanup test can require exactly one record without truncating a live log.
: > "$killsession_log"
chmod 666 "$killsession_log"

if ! compose up -d --wait --wait-timeout 60 tls-proxy cleanup-proxy >/dev/null; then
  printf '%s\n' 'GLPI TLS proxies did not start.' >&2
  exit 1
fi

https_port_mapping="$(compose port tls-proxy 8443)"
https_port="${https_port_mapping##*:}"
if [[ -z "$https_port" || ! "$https_port" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'Could not determine the Docker-assigned tls-proxy HTTPS host port.' >&2
  exit 1
fi
env_put GLPI_TEST_HTTPS_PORT "$https_port"
cleanup_https_port_mapping="$(compose port cleanup-proxy 8444)"
cleanup_https_port="${cleanup_https_port_mapping##*:}"
if [[ -z "$cleanup_https_port" || ! "$cleanup_https_port" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'Could not determine the Docker-assigned cleanup-proxy HTTPS host port.' >&2
  exit 1
fi
env_put GLPI_TEST_CLEANUP_HTTPS_PORT "$cleanup_https_port"
# shellcheck disable=SC1090
source "$runtime_env"

# `cleanup-proxy` has no Docker healthcheck, so `compose up --wait` only
# proves the container is running, not that its dedicated 8444 HTTPS listener
# already accepts connections. Probe a non-mutating, unauthenticated path
# proxied to real GLPI to prove TLS (via the generated CA), the 8444 listener,
# and reachability to the real GLPI container all work. This deliberately
# never requests `/apirest.php/killSession`, so it cannot write to the
# dedicated `killsession.log` before the cleanup test runs.
cleanup_proxy_deadline=$((SECONDS + 60))
until curl --cacert "${tls_dir}/ca.crt" --fail --silent --show-error --output /dev/null \
  "https://127.0.0.1:${GLPI_TEST_CLEANUP_HTTPS_PORT}/status.php"; do
  if ((SECONDS > cleanup_proxy_deadline)); then
    printf '%s\n' 'cleanup-proxy HTTPS readiness timed out.' >&2
    exit 1
  fi
  sleep 2
done

# GLPI_TEST_ENDPOINT depends on the real (not preselected) HTTPS port, so it
# is computed only now that port is known.
env_put GLPI_TEST_ENDPOINT "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php"
env_put GLPI_TEST_CLEANUP_ENDPOINT "https://127.0.0.1:${GLPI_TEST_CLEANUP_HTTPS_PORT}/apirest.php"
env_put GLPI_TEST_CA_PEM_PATH "${tls_dir}/ca.crt"
env_put GLPI_TEST_COMPOSE_PROJECT "$project_name"
# shellcheck disable=SC1090
source "$runtime_env"

init_response="${runtime_dir}/init-session.json"
killsession_response="${runtime_dir}/kill-session.txt"
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
      mask_secret "$session_token"
      kill_status="$(curl --cacert "${tls_dir}/ca.crt" --silent --show-error --output "$killsession_response" --write-out '%{http_code}' \
        -H "Session-Token: ${session_token}" \
        -H "App-Token: ${GLPI_TEST_APP_TOKEN}" \
        "https://127.0.0.1:${GLPI_TEST_HTTPS_PORT}/apirest.php/killSession" 2>/dev/null)" || kill_status=''
      if [[ "$kill_status" == '200' ]] && python3 - "$killsession_response" >/dev/null 2>&1 <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response:
    if json.load(response) is not True:
        raise SystemExit(1)
PY
      then
        init_session_ok=1
        break
      fi
    fi
  fi
  sleep 2
done
rm -f "$init_response" "$killsession_response"

if [[ "$init_session_ok" != '1' ]]; then
  printf '%s\n' 'initSession and killSession did not both succeed with the generated credentials.' >&2
  exit 1
fi

printf 'export GLPI_TEST_RUNTIME_ENV=%q\n' "$runtime_env"
