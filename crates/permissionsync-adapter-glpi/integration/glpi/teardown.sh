#!/usr/bin/env bash
# Tear down the disposable environment created by bootstrap.sh.
set -euo pipefail

runtime_env="${GLPI_TEST_RUNTIME_ENV:-}"
if [[ -z "$runtime_env" ]]; then
  printf '%s\n' 'No GLPI runtime environment was ever created; nothing to tear down.'
  exit 0
fi

if [[ ! -f "$runtime_env" ]]; then
  printf '%s\n' 'GLPI runtime environment is missing; nothing to tear down.'
  exit 0
fi

safe_runtime_dir=''
if [[ "$runtime_env" == */runtime.env ]]; then
  candidate_runtime_dir="${runtime_env%/runtime.env}"
  if [[ "$runtime_env" == "$candidate_runtime_dir/runtime.env" &&
    "$candidate_runtime_dir" =~ ^/.*/permissionsync-glpi\.[A-Za-z0-9]{6}$ &&
    "$candidate_runtime_dir" != *'//'* &&
    "$candidate_runtime_dir" != *'/./'* &&
    "$candidate_runtime_dir" != *'/../'* &&
    -d "$candidate_runtime_dir" && ! -L "$candidate_runtime_dir" &&
    ! -L "$runtime_env" ]]; then
    safe_runtime_dir="$candidate_runtime_dir"
  fi
fi

if [[ -z "$safe_runtime_dir" ]]; then
  printf '%s\n' 'GLPI runtime environment is not in a safe generated runtime directory.' >&2
  exit 1
fi

readonly safe_runtime_dir

cleanup_runtime_dir() {
  local status=$?

  if ! rm -rf -- "$safe_runtime_dir"; then
    printf '%s\n' 'GLPI teardown failed: could not remove the generated runtime directory.' >&2
    if ((status == 0)); then
      status=1
    fi
  fi

  trap - EXIT
  exit "$status"
}

trap cleanup_runtime_dir EXIT

unset PERMISSIONSYNC_GLPI_PROJECT_NAME GLPI_TEST_RUNTIME_DIR
# shellcheck disable=SC1090
source "$runtime_env"
: "${PERMISSIONSYNC_GLPI_PROJECT_NAME:?runtime environment lacks project name}"
: "${GLPI_TEST_RUNTIME_DIR:?runtime environment lacks runtime directory}"

if [[ "$GLPI_TEST_RUNTIME_DIR" != "$safe_runtime_dir" ]]; then
  printf '%s\n' 'GLPI runtime environment declares an unexpected runtime directory.' >&2
  exit 1
fi

if ! docker compose --env-file "$runtime_env" -p "$PERMISSIONSYNC_GLPI_PROJECT_NAME" down --volumes --remove-orphans; then
  printf '%s\n' 'GLPI teardown failed: docker compose down did not complete.' >&2
  exit 1
fi
