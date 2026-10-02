#!/usr/bin/env bash
# Best-effort diagnostics for a failed real-Keycloak contract run.
#
# This script never fails the calling CI job: diagnostics are secondary to the
# primary test failure already recorded by the earlier step. It must NEVER
# print provision.stdout or the runtime env file's raw contents, because both
# contain generated client secrets and the bootstrap administrator password.
# Other diagnostic streams are redacted defensively: Keycloak and compose
# output is not expected to contain credentials, but that is not sufficient
# reason to print it unredacted.
set -uo pipefail

runtime_env="${KEYCLOAK_TEST_RUNTIME_ENV:-}"
if [[ -z "$runtime_env" || ! -f "$runtime_env" ]]; then
    printf '%s\n' 'No Keycloak runtime environment was ever created; nothing to diagnose.'
    exit 0
fi

# shellcheck disable=SC1090
if ! source "$runtime_env" >/dev/null 2>&1; then
    printf '%s\n' 'Keycloak runtime environment could not be loaded; diagnostics unavailable.' >&2
    exit 0
fi

# The values to redact are handed to the redaction filter through a private
# file inside the already-private runtime directory, never through its process
# argument vector, which any local user can read from /proc. The file is
# removed when this script exits, and teardown removes the whole runtime
# directory regardless.
secrets_file="$(mktemp "${KEYCLOAK_TEST_RUNTIME_DIR:-${TMPDIR:-/tmp}}/redaction.XXXXXX")"
chmod 600 "$secrets_file"
trap 'rm -f -- "$secrets_file"' EXIT

for secret in \
    "${KEYCLOAK_TEST_ADMIN_PASSWORD:-}" \
    "${KEYCLOAK_TEST_CALLER_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_MINIMAL_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_DISALLOWED_ALGORITHM_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_SHORTLIVED_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_WRONG_AUDIENCE_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_FOREIGN_CLIENT_SECRET:-}" \
    "${KEYCLOAK_TEST_ROTATION_CLIENT_SECRET:-}"; do
    # Every generated value is hexadecimal, so one per line is unambiguous. A
    # value that somehow contained a newline is skipped rather than written as
    # two partial patterns that would redact nothing useful.
    if [[ -n "$secret" && "$secret" != *$'\n'* ]]; then
        printf '%s\n' "$secret" >>"$secrets_file"
    fi
done

redact() {
    python3 -c '
import sys

with open(sys.argv[1], encoding="utf-8") as patterns:
    secrets = [secret for secret in patterns.read().splitlines() if secret]
for line in sys.stdin:
    for secret in secrets:
        line = line.replace(secret, "[REDACTED]")
    sys.stdout.write(line)
' "$secrets_file"
}

if [[ -n "${KEYCLOAK_TEST_COMPOSE_PROJECT:-}" ]]; then
    printf '\n=== docker compose logs (keycloak outage-proxy) ===\n'
    if ! docker compose --env-file "$runtime_env" \
        -p "$KEYCLOAK_TEST_COMPOSE_PROJECT" \
        logs --no-color keycloak outage-proxy 2>&1 | redact; then
        printf '%s\n' 'docker compose logs unavailable; project may not have started.'
    fi
else
    printf '%s\n' 'No compose project name recorded; skipping docker compose logs.'
fi

if [[ -n "${KEYCLOAK_TEST_RUNTIME_DIR:-}" ]]; then
    for name in provision.stderr compose.stdout compose.stderr; do
        path="${KEYCLOAK_TEST_RUNTIME_DIR}/${name}"
        if [[ -s "$path" ]]; then
            printf '\n=== %s ===\n' "$name"
            redact <"$path" || printf '%s\n' "failed to read ${name}"
        else
            printf '\n=== %s ===\n(empty or missing)\n' "$name"
        fi
    done
fi

exit 0
