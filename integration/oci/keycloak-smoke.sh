#!/usr/bin/env bash
# End-to-end deployment contract for the production PermissionSync OCI image
# against the disposable supported-Keycloak environment.
#
# Usage: keycloak-smoke.sh <image-reference>
#
# The image must already be built, and the disposable Keycloak environment
# created by crates/permissionsync-auth/integration/keycloak/bootstrap.sh must
# already be exported into the environment:
#
#   source <(crates/permissionsync-auth/integration/keycloak/bootstrap.sh)
#   set -a; source "$KEYCLOAK_TEST_RUNTIME_ENV"; set +a
#   integration/oci/keycloak-smoke.sh permissionsync:local
#
# This proves the built image, not `cargo test`, can run with exactly the
# supported external configuration contract and reach a real HTTPS Keycloak
# through PermissionSync's existing private trust-anchor configuration. It
# requires neither GLPI nor a Permission Provider: the synchronization request
# below carries no `permissionsync:<target>` scope, so it completes as the
# targetless successful no-op the inbound contract defines.
set -euo pipefail

image="${1:-}"
if [[ -z "$image" ]]; then
  printf '%s\n' 'usage: keycloak-smoke.sh <image-reference>' >&2
  exit 2
fi

: "${KEYCLOAK_TEST_ISSUER:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_AUDIENCE:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_INTERNAL_JWKS_URI:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_COMPOSE_NETWORK:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_CA_PEM_PATH:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_TOKEN_ENDPOINT:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_CALLER_CLIENT_ID:?the disposable Keycloak runtime environment must be sourced first}"
: "${KEYCLOAK_TEST_CALLER_CLIENT_SECRET:?the disposable Keycloak runtime environment must be sourced first}"

work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/permissionsync-oci-keycloak.XXXXXX")"
container_id=''

cleanup() {
  local status=$?
  if [[ -n "$container_id" ]]; then
    docker rm --force "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
  exit "$status"
}
trap cleanup EXIT

fail() {
  printf 'deployment contract violation: %s\n' "$1" >&2
  exit 1
}

# One external YAML document, generated for this run only. It is the single
# configuration input the container receives, and it is the only place the
# disposable CA and the Keycloak endpoints appear.
#
# The trusted source is the in-network JWKS URI, because the container reaches
# Keycloak over the compose network rather than through the host's published
# port. The configured issuer stays the realm's own issuer, which is exactly
# what ADR-0002 allows: a trusted JWKS source may be reached at a different
# host name than the issuer it belongs to, as long as it was reached only
# through configured trust.
{
  cat <<CONFIGURATION
listener:
  address: "0.0.0.0"
  port: 8443
request:
  overall_deadline_milliseconds: 10000
  inbound_admission_limit: 8
  synchronization_capacity: 4
shutdown:
  grace_milliseconds: 10000
authentication:
  issuer: "${KEYCLOAK_TEST_ISSUER}"
  audience: "${KEYCLOAK_TEST_AUDIENCE}"
  algorithms: ["RS256"]
  source:
    jwks_uri: "${KEYCLOAK_TEST_INTERNAL_JWKS_URI}"
  cache:
    freshness_milliseconds: 300000
    stale_if_error_milliseconds: 600000
  metadata_operation_timeout_milliseconds: 5000
  clock_skew_milliseconds: 30000
  additional_trust_anchors_pem:
    - |
CONFIGURATION
  sed 's/^/      /' "$KEYCLOAK_TEST_CA_PEM_PATH"
  cat <<'CONFIGURATION'
observability:
  log_level: info
targets: []
CONFIGURATION
} > "${work_dir}/permissionsync.yaml"
chmod 644 "${work_dir}/permissionsync.yaml"

printf '=== starting the production image with one externally mounted document ===\n'
# `PERMISSIONSYNC_CONFIG_FILE` is the only environment value supplied.
container_id="$(docker run --detach \
  --network "$KEYCLOAK_TEST_COMPOSE_NETWORK" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --publish '127.0.0.1::8443' \
  --env PERMISSIONSYNC_CONFIG_FILE=/etc/permissionsync/permissionsync.yaml \
  --volume "${work_dir}/permissionsync.yaml:/etc/permissionsync/permissionsync.yaml:ro,Z" \
  "$image")"

port="$(docker inspect "$container_id" \
  --format '{{(index .NetworkSettings.Ports "8443/tcp" 0).HostPort}}')"
if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
  docker logs "$container_id" 2>&1 | tail -40 >&2
  fail 'could not determine the published listener port'
fi
printf 'published listener port: %s\n' "$port"

status_of() {
  curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${port}$1" || true
}

printf '=== liveness ===\n'
deadline=$((SECONDS + 60))
until [[ "$(status_of /healthz)" == '200' ]]; do
  if ((SECONDS > deadline)); then
    docker logs "$container_id" 2>&1 | tail -40 >&2
    fail '/healthz did not return 200 within the bounded startup window'
  fi
  sleep 1
done
printf '/healthz: 200\n'

printf '=== readiness once trusted verifier state exists ===\n'
# Readiness turns true only after the bounded verifier warm-up has retrieved
# real JWKS from Keycloak over HTTPS through the configured trust anchor.
deadline=$((SECONDS + 90))
until [[ "$(status_of /readyz)" == '200' ]]; do
  if ((SECONDS > deadline)); then
    docker logs "$container_id" 2>&1 | tail -40 >&2
    fail '/readyz did not become 200 within the bounded warm-up window'
  fi
  sleep 1
done
printf '/readyz: 200\n'

printf '=== a real Keycloak token is accepted ===\n'
# Requested with no PermissionSync target scope, so this exercises
# authentication and body validation without needing GLPI or a Provider. The
# client secret travels in the request body from a heredoc, never on a command
# line, and the token is written to a private file rather than any log.
token_response="${work_dir}/token.json"
if ! curl --cacert "$KEYCLOAK_TEST_CA_PEM_PATH" --fail --silent --output "$token_response" \
  --data '@-' "$KEYCLOAK_TEST_TOKEN_ENDPOINT" <<REQUEST
grant_type=client_credentials&client_id=${KEYCLOAK_TEST_CALLER_CLIENT_ID}&client_secret=${KEYCLOAK_TEST_CALLER_CLIENT_SECRET}
REQUEST
then
  fail 'the provisioned technical caller could not obtain a Client Credentials token'
fi
access_token="$(python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response:
    token = json.load(response).get("access_token")
if not isinstance(token, str) or not token:
    raise SystemExit(1)
print(token)
' "$token_response")" || fail 'the token response carried no access token'
rm -f "$token_response"

body='{"event_type":"LOGIN","username":"permissionsync-oci-smoke","groups":[]}'

unauthenticated="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data "$body" \
  "http://127.0.0.1:${port}/api/sync-user" || true)"
printf 'POST /api/sync-user without a credential: %s\n' "$unauthenticated"
[[ "$unauthenticated" == '401' ]] ||
  fail "expected 401 without a credential, found ${unauthenticated}"

# `--header @-` is not available, so the bearer header is supplied through a
# private config file rather than argv.
printf 'header = "Authorization: Bearer %s"\n' "$access_token" > "${work_dir}/curl.config"
chmod 600 "${work_dir}/curl.config"
targetless="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --config "${work_dir}/curl.config" \
  --request POST --header 'Content-Type: application/json' --data "$body" \
  "http://127.0.0.1:${port}/api/sync-user" || true)"
rm -f "${work_dir}/curl.config"
printf 'POST /api/sync-user with a real targetless token: %s\n' "$targetless"
[[ "$targetless" == '204' ]] ||
  fail "expected a targetless successful 204, found ${targetless}"

printf '=== SIGTERM terminates the container cleanly ===\n'
docker kill --signal=TERM "$container_id" >/dev/null
deadline=$((SECONDS + 30))
until [[ "$(docker inspect "$container_id" --format '{{.State.Status}}')" == 'exited' ]]; do
  if ((SECONDS > deadline)); then
    fail 'the container did not exit within the bounded shutdown window'
  fi
  sleep 1
done
exit_code="$(docker inspect "$container_id" --format '{{.State.ExitCode}}')"
printf 'exit code after SIGTERM: %s\n' "$exit_code"
[[ "$exit_code" == '0' ]] || fail "expected a clean exit after SIGTERM, found ${exit_code}"

docker rm --force "$container_id" >/dev/null
container_id=''

printf 'production image deployment contract satisfied\n'
