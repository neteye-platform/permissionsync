#!/usr/bin/env bash
# Best-effort diagnostics for a failed real-GLPI test run.
#
# This script never fails the calling CI job: diagnostics are secondary to
# the primary test failure already recorded by the earlier step. It must
# NEVER print bootstrap.stdout or the runtime env file's raw contents, since
# both can contain generated credentials (App-Token, User Token, Session
# Token, DB password). Other diagnostic streams are redacted defensively: PHP
# and docker-compose output is not expected to contain credentials, but that is
# not sufficient reason to print it unredacted.
set -uo pipefail

runtime_env="${GLPI_TEST_RUNTIME_ENV:-}"
if [[ -z "$runtime_env" || ! -f "$runtime_env" ]]; then
    printf '%s\n' 'No GLPI runtime environment was ever created; nothing to diagnose.'
    exit 0
fi

# shellcheck disable=SC1090
if ! source "$runtime_env" >/dev/null 2>&1; then
    printf '%s\n' 'GLPI runtime environment could not be loaded; diagnostics unavailable.' >&2
    exit 0
fi

# The values to redact are handed to the redaction filter through a private
# file inside the already-private runtime directory, never through its process
# argument vector, which any local user can read from /proc. The file is
# removed when this script exits, and teardown removes the whole runtime
# directory regardless.
secrets_file="$(mktemp "${GLPI_TEST_RUNTIME_DIR:-${TMPDIR:-/tmp}}/redaction.XXXXXX")"
chmod 600 "$secrets_file"
trap 'rm -f -- "$secrets_file"' EXIT

for secret in \
    "${GLPI_TEST_DB_ROOT_PASSWORD:-}" \
    "${GLPI_TEST_DB_PASSWORD:-}" \
    "${GLPI_TEST_APP_TOKEN:-}" \
    "${GLPI_TEST_USER_TOKEN:-}" \
    "${GLPI_TEST_TOPOLOGY_USER_TOKEN:-}"; do
    # Every generated value is a single-line hexadecimal or token string, so
    # one per line is unambiguous. A value that somehow contained a newline is
    # skipped rather than written as two partial patterns that would redact
    # nothing useful.
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

if [[ -n "${PERMISSIONSYNC_GLPI_PROJECT_NAME:-}" ]]; then
    printf '\n=== docker compose logs (glpi db tls-proxy cleanup-proxy) ===\n'
    if ! docker compose --env-file "$runtime_env" \
        -p "$PERMISSIONSYNC_GLPI_PROJECT_NAME" \
        logs --no-color glpi db tls-proxy cleanup-proxy 2>&1 | redact; then
        printf '%s\n' 'docker compose logs unavailable; project may not have started.'
    fi
else
    printf '%s\n' 'No compose project name recorded; skipping docker compose logs.'
fi

if [[ -n "${GLPI_TEST_RUNTIME_DIR:-}" ]]; then
    for name in bootstrap.stderr compose-base.stdout compose-base.stderr; do
        path="${GLPI_TEST_RUNTIME_DIR}/${name}"
        if [[ -s "$path" ]]; then
            printf '\n=== %s ===\n' "$name"
            redact <"$path" || printf '%s\n' "failed to read ${name}"
        else
            printf '\n=== %s ===\n(empty or missing)\n' "$name"
        fi
    done
fi

exit 0
