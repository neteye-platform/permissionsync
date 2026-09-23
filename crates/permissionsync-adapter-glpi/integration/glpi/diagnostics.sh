#!/usr/bin/env bash
# Best-effort diagnostics for a failed real-GLPI test run.
#
# This script never fails the calling CI job: diagnostics are secondary to
# the primary test failure already recorded by the earlier step. It must
# NEVER print bootstrap.stdout or the runtime env file's raw contents, since
# both can contain generated credentials (App-Token, User Token, Session
# Token, DB password). bootstrap.stderr and compose-base.stdout/stderr only
# ever capture PHP/docker-compose diagnostic output, not credential values,
# so they are safe to print in full.
set -uo pipefail

runtime_env="${GLPI_TEST_RUNTIME_ENV:-}"
if [[ -z "$runtime_env" || ! -f "$runtime_env" ]]; then
  printf '%s\n' 'No GLPI runtime environment was ever created; nothing to diagnose.'
  exit 0
fi

# shellcheck disable=SC1090
source "$runtime_env"

if [[ -n "${PERMISSIONSYNC_GLPI_PROJECT_NAME:-}" ]]; then
  printf '\n=== docker compose logs (glpi db tls-proxy) ===\n'
  docker compose --env-file "$runtime_env" \
    -p "$PERMISSIONSYNC_GLPI_PROJECT_NAME" \
    logs --no-color glpi db tls-proxy \
    || printf '%s\n' 'docker compose logs unavailable; project may not have started.'
else
  printf '%s\n' 'No compose project name recorded; skipping docker compose logs.'
fi

if [[ -n "${GLPI_TEST_RUNTIME_DIR:-}" ]]; then
  for name in bootstrap.stderr compose-base.stdout compose-base.stderr; do
    path="${GLPI_TEST_RUNTIME_DIR}/${name}"
    if [[ -s "$path" ]]; then
      printf '\n=== %s ===\n' "$name"
      cat "$path" || printf '%s\n' "failed to read ${name}"
    else
      printf '\n=== %s ===\n(empty or missing)\n' "$name"
    fi
  done
fi

exit 0
