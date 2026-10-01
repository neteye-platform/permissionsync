#!/usr/bin/env bash
# Deterministic contract checks for the production PermissionSync OCI image.
#
# Usage: image-contract.sh <image-reference>
#
# The image must already be built. Nothing here needs Keycloak, GLPI, a
# Provider, or any network service: every property proved below is a property
# of the image itself or of a container started from it with one externally
# mounted configuration document.
#
# `integration/oci/keycloak-smoke.sh` owns the end-to-end deployment contract
# against a real disposable Keycloak; this script owns image hygiene, the
# missing-configuration failure, the ADR-0006 "valid configuration, metadata
# source unreachable" readiness case, and direct signal delivery.
set -euo pipefail

image="${1:-}"
if [[ -z "$image" ]]; then
  printf '%s\n' 'usage: image-contract.sh <image-reference>' >&2
  exit 2
fi

work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/permissionsync-oci-contract.XXXXXX")"
container_id=''
export_container_id=''

cleanup() {
  local status=$?
  if [[ -n "$container_id" ]]; then
    docker rm --force "$container_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$export_container_id" ]]; then
    docker rm --force "$export_container_id" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
  exit "$status"
}
trap cleanup EXIT

fail() {
  printf 'image contract violation: %s\n' "$1" >&2
  exit 1
}

inspect() {
  docker image inspect "$image" --format "$1"
}

printf '=== static image metadata ===\n'

user="$(inspect '{{.Config.User}}')"
printf 'user: %s\n' "$user"
# A numeric UID:GID is required, not a name: Kubernetes cannot enforce
# runAsNonRoot against a user name it would have to resolve inside the image.
[[ "$user" == '65532:65532' ]] || fail "expected the image to run as 65532:65532, found '${user}'"

entrypoint="$(inspect '{{json .Config.Entrypoint}}')"
printf 'entrypoint: %s\n' "$entrypoint"
[[ "$entrypoint" == '["/usr/local/bin/permissionsync"]' ]] ||
  fail "expected an explicit executable entrypoint with no shell wrapper, found ${entrypoint}"

command_value="$(inspect '{{json .Config.Cmd}}')"
printf 'cmd: %s\n' "$command_value"
case "$command_value" in
'null' | '[]') ;;
*) fail "expected no default command, found ${command_value}" ;;
esac

# The configuration contract is exactly one external file whose path comes only
# from the environment. Baking the variable, or any configuration document,
# into the image would make the artifact deployment-specific.
if docker image inspect "$image" --format '{{range .Config.Env}}{{println .}}{{end}}' |
  grep -q '^PERMISSIONSYNC_CONFIG_FILE='; then
  fail 'the image presets PERMISSIONSYNC_CONFIG_FILE; configuration must be supplied externally'
fi

printf '=== OCI labels ===\n'
for label in \
  'org.opencontainers.image.title' \
  'org.opencontainers.image.source' \
  'org.opencontainers.image.licenses' \
  'org.opencontainers.image.vendor'; do
  value="$(docker image inspect "$image" --format "{{index .Config.Labels \"${label}\"}}")"
  printf '%s: %s\n' "$label" "$value"
  [[ -n "$value" && "$value" != '<no value>' ]] || fail "missing OCI label ${label}"
done

printf '=== image filesystem ===\n'
export_container_id="$(docker create "$image")"
docker export "$export_container_id" > "${work_dir}/image.tar"
docker rm --force "$export_container_id" >/dev/null
export_container_id=''
tar --list --file "${work_dir}/image.tar" > "${work_dir}/entries.txt"
printf 'entries: %s\n' "$(wc -l < "${work_dir}/entries.txt")"

grep -qx 'usr/local/bin/permissionsync' "${work_dir}/entries.txt" ||
  fail 'the expected executable /usr/local/bin/permissionsync is absent'

# No shell: a shell in the final image would also be the simplest way to turn
# the entrypoint into a wrapper that swallows signals.
while read -r forbidden; do
  if grep -qx "$forbidden" "${work_dir}/entries.txt"; then
    fail "the runtime image contains ${forbidden}"
  fi
done <<'FORBIDDEN'
bin/sh
bin/bash
bin/dash
usr/bin/sh
usr/bin/bash
usr/bin/dash
usr/bin/busybox
usr/bin/apt
usr/bin/dpkg
usr/bin/cargo
usr/bin/rustc
usr/local/bin/cargo
usr/local/bin/rustc
FORBIDDEN

# No build tree, Cargo state, build cache, or compiled intermediate: the
# multi-stage build is necessary but not by itself sufficient evidence.
if grep -Eq '(^|/)(Cargo\.toml|Cargo\.lock|rust-toolchain\.toml)$' "${work_dir}/entries.txt"; then
  fail 'the runtime image contains workspace manifests'
fi
if grep -Eq '\.(rs|rlib|rmeta|d)$' "${work_dir}/entries.txt"; then
  fail 'the runtime image contains Rust sources or build intermediates'
fi
if grep -Eq '^(src|crates|target)/' "${work_dir}/entries.txt"; then
  fail 'the runtime image contains a source or build tree'
fi
if grep -Eq '^(usr/local/)?(cargo|rustup)/' "${work_dir}/entries.txt"; then
  fail 'the runtime image contains Cargo or rustup state'
fi

# No configuration, private trust material, or credential of any kind. The
# system trust store the TLS stack needs is the single allowed exception, and
# it is allowed only at its own path.
if grep -Eq '\.(ya?ml|pem|key|p12|env|pfx|jks)$' "${work_dir}/entries.txt"; then
  fail 'the runtime image contains configuration, trust, or credential material'
fi
if grep -E '\.crt$' "${work_dir}/entries.txt" |
  grep -qvx 'etc/ssl/certs/ca-certificates.crt'; then
  fail 'the runtime image contains certificate material outside the system trust store'
fi

printf '=== missing configuration fails fast ===\n'
missing_status=0
docker run --rm "$image" > "${work_dir}/missing.stdout" 2> "${work_dir}/missing.stderr" ||
  missing_status=$?
printf 'exit status: %s\n' "$missing_status"
((missing_status != 0)) || fail 'the service started without PERMISSIONSYNC_CONFIG_FILE'
grep -q 'PERMISSIONSYNC_CONFIG_FILE' "${work_dir}/missing.stderr" ||
  fail 'the missing-configuration diagnostic did not name the required variable'

printf '=== serving with one externally mounted document ===\n'
# Valid local configuration whose authentication metadata source is
# deliberately unresolvable. ADR-0006 case B: the process must bind and serve
# with readiness false rather than fail startup or crash-loop. The document
# carries placeholder values only and is created, used, and removed here.
cat > "${work_dir}/permissionsync.yaml" <<'CONFIGURATION'
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
  issuer: "https://keycloak.invalid/realms/permissionsync-image-contract"
  audience: "permissionsync"
  algorithms: ["RS256"]
  source:
    oidc_discovery_uri: "https://keycloak.invalid/realms/permissionsync-image-contract/.well-known/openid-configuration"
  cache:
    freshness_milliseconds: 300000
    stale_if_error_milliseconds: 600000
  metadata_operation_timeout_milliseconds: 2000
  clock_skew_milliseconds: 30000
observability:
  log_level: info
targets: []
CONFIGURATION
chmod 644 "${work_dir}/permissionsync.yaml"

# Exactly the hardening the Kubernetes deployment contract example applies:
# read-only root filesystem, every capability dropped, no privilege
# escalation, and the image's own non-root user.
container_id="$(docker run --detach \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --publish '127.0.0.1::8443' \
  --env PERMISSIONSYNC_CONFIG_FILE=/etc/permissionsync/permissionsync.yaml \
  --volume "${work_dir}/permissionsync.yaml:/etc/permissionsync/permissionsync.yaml:ro,Z" \
  "$image")"

# The host port was assigned by the container engine when the listener was
# published with an empty host-port component, so it is discovered now rather
# than preselected and raced against another process.
port="$(docker inspect "$container_id" \
  --format '{{(index .NetworkSettings.Ports "8443/tcp" 0).HostPort}}')"
if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
  docker logs "$container_id" 2>&1 | tail -40 >&2
  fail 'could not determine the published listener port'
fi
printf 'published listener port: %s\n' "$port"

# Bounded readiness polling against the liveness endpoint; no fixed sleep is
# used to decide that the process came up.
deadline=$((SECONDS + 60))
until [[ "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${port}/healthz" || true)" == '200' ]]; do
  if ((SECONDS > deadline)); then
    docker logs "$container_id" 2>&1 | tail -40 >&2
    fail '/healthz did not return 200 within the bounded startup window'
  fi
  sleep 1
done
printf '/healthz: 200\n'

readiness="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${port}/readyz" || true)"
printf '/readyz: %s\n' "$readiness"
[[ "$readiness" == '503' ]] ||
  fail "expected /readyz to be 503 while no trusted verifier state exists, found ${readiness}"

metrics="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${port}/metrics" || true)"
printf '/metrics: %s\n' "$metrics"
[[ "$metrics" == '200' ]] || fail "expected /metrics to be 200, found ${metrics}"

entry_path="$(docker inspect "$container_id" --format '{{.Path}}')"
printf 'pid 1 path: %s\n' "$entry_path"
[[ "$entry_path" == '/usr/local/bin/permissionsync' ]] ||
  fail "expected the executable itself to be the container process, found ${entry_path}"

printf '=== SIGTERM reaches the executable directly ===\n'
docker kill --signal=TERM "$container_id" >/dev/null
# Bounded wait on the container state, not a fixed sleep. A shell wrapper
# would report 143 here; the executable's own handler returns success.
deadline=$((SECONDS + 30))
until [[ "$(docker inspect "$container_id" --format '{{.State.Status}}')" == 'exited' ]]; do
  if ((SECONDS > deadline)); then
    fail 'the container did not exit within the bounded shutdown window'
  fi
  sleep 1
done
exit_code="$(docker inspect "$container_id" --format '{{.State.ExitCode}}')"
printf 'exit code after SIGTERM: %s\n' "$exit_code"
[[ "$exit_code" == '0' ]] ||
  fail "expected a clean exit after SIGTERM, found ${exit_code}"

docker rm --force "$container_id" >/dev/null
container_id=''

printf 'image contract satisfied\n'
