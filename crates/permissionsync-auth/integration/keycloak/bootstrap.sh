#!/usr/bin/env bash
# Bootstrap the disposable supported-Keycloak environment for the ignored real
# contract suite. docker-compose.yml pins the release it uses.
#
# diagnostics.sh and teardown.sh own failure diagnostics and destructive
# cleanup, respectively. On a local failure after the runtime directory is
# created, this script reports the safe runtime-env locator (never its
# contents) on stderr so diagnostics/teardown can still be run manually.
#
# The environment is disposable in every respect: an ephemeral CA and server
# certificate, an in-memory Keycloak store, container-engine-assigned host
# ports, and client secrets generated per run and exposed only through a
# private runtime-env file.
set -euo pipefail

runtime_base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
runtime_dir="$(mktemp -d "${runtime_base%/}/permissionsync-keycloak.XXXXXX")"
runtime_env="${runtime_dir}/runtime.env"
provision_stdout="${runtime_dir}/provision.stdout"
provision_stderr="${runtime_dir}/provision.stderr"
compose_stdout="${runtime_dir}/compose.stdout"
compose_stderr="${runtime_dir}/compose.stderr"
project_name="permissionsync-keycloak-real-$$-${RANDOM}"
tls_dir="${runtime_dir}/tls"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
proxy_conf="${runtime_dir}/nginx-stream.conf"

umask 077
mkdir -p "$tls_dir"
touch "$runtime_env" "$provision_stdout" "$provision_stderr" "$compose_stdout" "$compose_stderr"
chmod 600 "$runtime_env" "$provision_stdout" "$provision_stderr" "$compose_stdout" "$compose_stderr"
# Keycloak reads its certificate and key as its own unprivileged container
# user, which is not the user running this script, so the path down to the TLS
# material has to be traversable. The runtime directory stays unlistable
# (`711`), and every file that is not deliberately published to the container
# keeps mode 600, so the generated credentials in runtime.env, the provisioning
# output, and the CA private key remain unreadable.
chmod 711 "$runtime_dir"
chmod 755 "$tls_dir"

# The reviewed forwarder configuration is mounted from a copy inside this
# run's disposable state rather than from the working tree.
cp -- "${script_dir}/nginx-stream.conf" "$proxy_conf"
chmod 644 "$proxy_conf"

# runtime.env is consumed by two different parsers: this script's own
# `source`, and `docker compose --env-file`'s dotenv grammar. Both treat a
# double-quoted value's `\\`, `\"`, and `\$` identically, so double-quoting
# with only those three escapes round-trips identically under both. CR, LF,
# and a literal backtick are rejected outright rather than encoded, because a
# backtick means two different things under the two grammars. This matches the
# escaping model of the real-GLPI bootstrap in
# crates/permissionsync-adapter-glpi/integration/glpi/bootstrap.sh.
env_put() {
  local name="$1" value="$2" escaped
  case "$value" in
  *$'\r'* | *$'\n'* | *'`'*)
    printf '%s\n' 'runtime.env write refused: a generated value contained a disallowed character (CR, LF, or backtick).' >&2
    exit 1
    ;;
  esac
  escaped="${value//\\/\\\\}"
  escaped="${escaped//\"/\\\"}"
  escaped="${escaped//\$/\\\$}"
  printf '%s="%s"\n' "$name" "$escaped" >> "$runtime_env"
}

# GitHub `::add-mask::` workflow commands only make sense, and are only safe,
# inside GitHub Actions: outside of it they are ordinary stdout, and the
# documented local usage is `source <(bootstrap.sh)`, where a local shell
# would otherwise try to execute `::add-mask::<secret>` as a command and could
# echo the secret in the resulting error.
mask_secret() {
  if [[ "${GITHUB_ACTIONS:-}" == 'true' ]]; then
    printf '::add-mask::%s\n' "$1"
  fi
}

# If bootstrap fails after the runtime directory (and possibly containers)
# already exist, print only the safe runtime-env locator plus the follow-up
# commands, never runtime.env contents or credentials, and never delete
# anything here: diagnostics.sh/teardown.sh own that.
report_recovery_on_failure() {
  local status=$?
  if ((status != 0)); then
    {
      printf '%s\n' 'Bootstrap failed after creating a disposable runtime directory.'
      printf 'Runtime env locator: %s\n' "$runtime_env"
      printf 'Diagnostics: KEYCLOAK_TEST_RUNTIME_ENV=%q ./diagnostics.sh\n' "$runtime_env"
      printf 'Teardown:   KEYCLOAK_TEST_RUNTIME_ENV=%q ./teardown.sh\n' "$runtime_env"
    } >&2
  fi
  exit "$status"
}
trap report_recovery_on_failure EXIT

admin_username='permissionsync-contract-admin'
admin_password="$(openssl rand -hex 24)"
mask_secret "$admin_password"
env_put KEYCLOAK_TEST_ADMIN_USERNAME "$admin_username"
env_put KEYCLOAK_TEST_ADMIN_PASSWORD "$admin_password"
env_put KEYCLOAK_TEST_TLS_DIR "$tls_dir"
env_put KEYCLOAK_TEST_PROXY_CONF "$proxy_conf"
env_put KEYCLOAK_TEST_CA_PEM_PATH "${tls_dir}/ca.crt"
env_put KEYCLOAK_TEST_COMPOSE_PROJECT "$project_name"
env_put KEYCLOAK_TEST_RUNTIME_DIR "$runtime_dir"
env_put KEYCLOAK_TEST_RUNTIME_ENV "$runtime_env"

# The compose file's pinned image tag is the single declaration of the
# supported release, so Renovate updating it there needs no second edit here.
keycloak_release="$(sed -n \
  's|^[[:space:]]*image:[[:space:]]*quay\.io/keycloak/keycloak:\([^@[:space:]]*\)@.*|\1|p' \
  "${script_dir}/docker-compose.yml")"
if [[ -z "$keycloak_release" ]]; then
  printf '%s\n' 'Could not read the pinned Keycloak release from docker-compose.yml.' >&2
  exit 1
fi
env_put KEYCLOAK_TEST_RELEASE "$keycloak_release"

# Export the runtime-env locator to $GITHUB_ENV as soon as the runtime
# directory and its diagnostic files exist, so a later CI step can find
# provision.stderr/compose.stderr even if bootstrap fails below. This is a
# filesystem path locator only; it is never a secret value.
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'KEYCLOAK_TEST_RUNTIME_ENV=%s\n' "$runtime_env" >> "$GITHUB_ENV"
fi

compose() {
  docker compose --env-file "$runtime_env" -p "$project_name" "$@"
}

discover_published_port() {
  local service="$1" container_port="$2" mapping port
  mapping="$(compose port "$service" "$container_port")"
  port="${mapping##*:}"
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    printf 'Could not determine the assigned host port for %s:%s.\n' "$service" "$container_port" >&2
    exit 1
  fi
  printf '%s\n' "$port"
}

# Disposable local trust: one ephemeral CA signs one server certificate whose
# SANs cover both names this environment is reached by. `127.0.0.1` is the
# host-side published port used by the contract suite, and `keycloak` is the
# compose-network name the production-image smoke test uses. Hostname
# verification therefore stays enabled everywhere; nothing disables or
# bypasses certificate validation.
# Both certificates carry the basic constraints, key usage, and extended key
# usage a strict verifier requires, so every client in this environment keeps
# full certificate and hostname validation enabled.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "${tls_dir}/ca.key" -out "${tls_dir}/ca.crt" \
  -subj "/CN=permissionsync-keycloak-real-integration-ca" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "${tls_dir}/server.key" -out "${tls_dir}/server.csr" \
  -subj "/CN=keycloak" >/dev/null 2>&1
openssl x509 -req -in "${tls_dir}/server.csr" -CA "${tls_dir}/ca.crt" -CAkey "${tls_dir}/ca.key" \
  -CAcreateserial -days 2 -out "${tls_dir}/server.crt" \
  -extfile <(printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=IP:127.0.0.1,DNS:keycloak,DNS:localhost') >/dev/null 2>&1
# Keycloak reads these as its own unprivileged container user. The private key
# is an ephemeral test key that exists only inside this runtime directory and
# is destroyed by teardown.sh.
chmod 644 "${tls_dir}/ca.crt" "${tls_dir}/server.crt" "${tls_dir}/server.key"
chmod 600 "${tls_dir}/ca.key" "${tls_dir}/server.csr"

if ! compose up -d keycloak >"$compose_stdout" 2>"$compose_stderr"; then
  printf '%s\n' 'Keycloak did not start; captured output was redacted.' >&2
  exit 1
fi

https_port="$(discover_published_port keycloak 8443)"
env_put KEYCLOAK_TEST_HTTPS_PORT "$https_port"
base_url="https://127.0.0.1:${https_port}"
env_put KEYCLOAK_TEST_BASE_URL "$base_url"

# Bounded readiness polling against a real unauthenticated Keycloak metadata
# endpoint over the generated CA, so readiness means "serving HTTPS and able to
# answer realm metadata", not merely "container running".
deadline=$((SECONDS + 240))
until curl --cacert "${tls_dir}/ca.crt" --fail --silent --output /dev/null \
  "${base_url}/realms/master/.well-known/openid-configuration" 2>/dev/null; do
  if ((SECONDS > deadline)); then
    printf '%s\n' 'Keycloak HTTPS metadata readiness timed out.' >&2
    exit 1
  fi
  sleep 2
done

# Client secrets are generated here, next to the administrator password
# above, and handed to provision.py through its environment, so provisioning
# neither creates nor prints a credential.
caller_client_secret="$(openssl rand -hex 24)"
minimal_client_secret="$(openssl rand -hex 24)"
disallowed_algorithm_client_secret="$(openssl rand -hex 24)"
shortlived_client_secret="$(openssl rand -hex 24)"
wrong_audience_client_secret="$(openssl rand -hex 24)"
foreign_client_secret="$(openssl rand -hex 24)"
rotation_client_secret="$(openssl rand -hex 24)"
for secret in \
  "$caller_client_secret" \
  "$minimal_client_secret" \
  "$disallowed_algorithm_client_secret" \
  "$shortlived_client_secret" \
  "$wrong_audience_client_secret" \
  "$foreign_client_secret" \
  "$rotation_client_secret"; do
  mask_secret "$secret"
done
env_put KEYCLOAK_TEST_CALLER_CLIENT_SECRET "$caller_client_secret"
env_put KEYCLOAK_TEST_MINIMAL_CLIENT_SECRET "$minimal_client_secret"
env_put KEYCLOAK_TEST_DISALLOWED_ALGORITHM_CLIENT_SECRET \
  "$disallowed_algorithm_client_secret"
env_put KEYCLOAK_TEST_SHORTLIVED_CLIENT_SECRET "$shortlived_client_secret"
env_put KEYCLOAK_TEST_WRONG_AUDIENCE_CLIENT_SECRET "$wrong_audience_client_secret"
env_put KEYCLOAK_TEST_FOREIGN_CLIENT_SECRET "$foreign_client_secret"
env_put KEYCLOAK_TEST_ROTATION_CLIENT_SECRET "$rotation_client_secret"

if ! KEYCLOAK_BASE_URL="$base_url" \
  KEYCLOAK_CA_PEM="${tls_dir}/ca.crt" \
  KEYCLOAK_ADMIN_USERNAME="$admin_username" \
  KEYCLOAK_ADMIN_PASSWORD="$admin_password" \
  KEYCLOAK_CLIENT_SECRET_CALLER="$caller_client_secret" \
  KEYCLOAK_CLIENT_SECRET_MINIMAL="$minimal_client_secret" \
  KEYCLOAK_CLIENT_SECRET_DISALLOWED_ALGORITHM="$disallowed_algorithm_client_secret" \
  KEYCLOAK_CLIENT_SECRET_SHORTLIVED="$shortlived_client_secret" \
  KEYCLOAK_CLIENT_SECRET_WRONG_AUDIENCE="$wrong_audience_client_secret" \
  KEYCLOAK_CLIENT_SECRET_FOREIGN="$foreign_client_secret" \
  KEYCLOAK_CLIENT_SECRET_ROTATION="$rotation_client_secret" \
  python3 "${script_dir}/provision.py" >"$provision_stdout" 2>"$provision_stderr"; then
  printf '%s\n' 'Keycloak provisioning failed; captured output was redacted.' >&2
  exit 1
fi

python3 - "$provision_stdout" "$runtime_env" <<'PY'
import re
import sys

output_path, env_path = sys.argv[1:]
expected = {
    "REALM",
    "FOREIGN_REALM",
    "AUDIENCE",
    "WRONG_AUDIENCE",
    "BASELINE_ALGORITHM",
    "DISALLOWED_ALGORITHM",
    "SHORTLIVED_LIFESPAN_SECONDS",
    "TARGET_SCOPE",
    "SECOND_TARGET_SCOPE",
    "INVALID_TARGET_SCOPE",
    "NOISE_SCOPE",
    "CASE_DIFFERENT_SCOPE",
    "LOOKALIKE_PREFIX_SCOPE",
    "LOOKALIKE_SUFFIX_SCOPE",
    "CALLER_CLIENT_ID",
    "MINIMAL_CLIENT_ID",
    "DISALLOWED_ALGORITHM_CLIENT_ID",
    "SHORTLIVED_CLIENT_ID",
    "WRONG_AUDIENCE_CLIENT_ID",
    "FOREIGN_CLIENT_ID",
    "ROTATION_REALM",
    "ROTATION_CLIENT_ID",
}
values = {}
with open(output_path, encoding="utf-8") as output:
    for line in output.read().splitlines():
        match = re.fullmatch(r"([A-Z_0-9]+)=([^\r\n=`]+)", line)
        if not match or match.group(1) not in expected or match.group(1) in values:
            raise SystemExit("Keycloak provisioning emitted an unexpected record")
        values[match.group(1)] = match.group(2)
if set(values) != expected:
    raise SystemExit("Keycloak provisioning did not emit every required record")

# Same dual-consumer (bash `source` / `docker compose --env-file`) escaping
# model as env_put() in bootstrap.sh: double-quoted output escaping only
# backslash, double quote, and dollar. CR, LF, and backtick are already
# excluded by the regex above.
def escape_runtime_env_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


with open(env_path, "a", encoding="utf-8") as environment:
    for name in sorted(values):
        environment.write(f"KEYCLOAK_TEST_{name}={escape_runtime_env_value(values[name])}\n")
PY

# shellcheck disable=SC1090
source "$runtime_env"

realm_base="${base_url}/realms/${KEYCLOAK_TEST_REALM}"
env_put KEYCLOAK_TEST_ISSUER "$realm_base"
env_put KEYCLOAK_TEST_DISCOVERY_URI "${realm_base}/.well-known/openid-configuration"
env_put KEYCLOAK_TEST_JWKS_URI "${realm_base}/protocol/openid-connect/certs"
env_put KEYCLOAK_TEST_TOKEN_ENDPOINT "${realm_base}/protocol/openid-connect/token"
env_put KEYCLOAK_TEST_FOREIGN_TOKEN_ENDPOINT \
  "${base_url}/realms/${KEYCLOAK_TEST_FOREIGN_REALM}/protocol/openid-connect/token"

rotation_realm_base="${base_url}/realms/${KEYCLOAK_TEST_ROTATION_REALM}"
env_put KEYCLOAK_TEST_ROTATION_ISSUER "$rotation_realm_base"
env_put KEYCLOAK_TEST_ROTATION_DISCOVERY_URI \
  "${rotation_realm_base}/.well-known/openid-configuration"
env_put KEYCLOAK_TEST_ROTATION_TOKEN_ENDPOINT \
  "${rotation_realm_base}/protocol/openid-connect/token"

# The production image reaches Keycloak over the compose network rather than
# through the host's published port, so the smoke test needs the in-network
# JWKS URI and the network name. The issuer stays the realm's frontend URL
# above, which is exactly what ADR-0002 allows: a trusted JWKS source may be
# reached at a different host name than the issuer it belongs to.
env_put KEYCLOAK_TEST_INTERNAL_JWKS_URI \
  "https://keycloak:8443/realms/${KEYCLOAK_TEST_REALM}/protocol/openid-connect/certs"
env_put KEYCLOAK_TEST_COMPOSE_NETWORK "${project_name}_default"

if ! compose up -d outage-proxy >>"$compose_stdout" 2>>"$compose_stderr"; then
  printf '%s\n' 'The disposable outage proxy did not start; captured output was redacted.' >&2
  exit 1
fi

outage_port="$(discover_published_port outage-proxy 8444)"
env_put KEYCLOAK_TEST_OUTAGE_JWKS_URI \
  "https://127.0.0.1:${outage_port}/realms/${KEYCLOAK_TEST_REALM}/protocol/openid-connect/certs"

# The forwarder has no container healthcheck, so prove the published listener
# really reaches Keycloak's JWKS endpoint through the generated CA before the
# suite depends on it.
outage_deadline=$((SECONDS + 60))
until curl --cacert "${tls_dir}/ca.crt" --fail --silent --output /dev/null \
  "https://127.0.0.1:${outage_port}/realms/${KEYCLOAK_TEST_REALM}/protocol/openid-connect/certs" 2>/dev/null; do
  if ((SECONDS > outage_deadline)); then
    printf '%s\n' 'Disposable outage-proxy HTTPS readiness timed out.' >&2
    exit 1
  fi
  sleep 2
done

# Prove the provisioned realm really issues the token contract the suite
# depends on before declaring the environment ready. Only the presence of the
# token is checked here; no token, claim set, or secret is printed.
if ! curl --cacert "${tls_dir}/ca.crt" --fail --silent --show-error --output /dev/null \
  --data "@-" "${realm_base}/protocol/openid-connect/token" <<REQUEST
grant_type=client_credentials&client_id=${KEYCLOAK_TEST_CALLER_CLIENT_ID}&client_secret=${KEYCLOAK_TEST_CALLER_CLIENT_SECRET}
REQUEST
then
  printf '%s\n' 'The provisioned technical caller could not obtain a Client Credentials token.' >&2
  exit 1
fi

printf 'export KEYCLOAK_TEST_RUNTIME_ENV=%q\n' "$runtime_env"
