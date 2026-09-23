#!/usr/bin/env bash
# Tear down the disposable environment created by bootstrap.sh.
set -euo pipefail

runtime_env="${GLPI_TEST_RUNTIME_ENV:-${1:-}}"
if [[ -z "$runtime_env" || ! -f "$runtime_env" ]]; then
  printf '%s\n' 'GLPI teardown requires GLPI_TEST_RUNTIME_ENV from bootstrap.sh.' >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$runtime_env"
: "${PERMISSIONSYNC_GLPI_PROJECT_NAME:?runtime environment lacks project name}"
: "${GLPI_TEST_RUNTIME_DIR:?runtime environment lacks runtime directory}"

if ! docker compose --env-file "$runtime_env" -p "$PERMISSIONSYNC_GLPI_PROJECT_NAME" down --volumes --remove-orphans; then
  printf '%s\n' 'GLPI teardown failed: docker compose down did not complete.' >&2
  exit 1
fi

rm -rf "$GLPI_TEST_RUNTIME_DIR"
