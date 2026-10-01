#!/usr/bin/env bash
# Tear down the disposable environment created by bootstrap.sh.
set -euo pipefail

runtime_env="${KEYCLOAK_TEST_RUNTIME_ENV:-}"
if [[ -z "$runtime_env" ]]; then
  printf '%s\n' 'No Keycloak runtime environment was ever created; nothing to tear down.'
  exit 0
fi

if [[ ! -f "$runtime_env" ]]; then
  printf '%s\n' 'KEYCLOAK_TEST_RUNTIME_ENV is set but its runtime env file no longer exists; cleanup state has been unexpectedly lost.' >&2
  exit 1
fi

safe_runtime_dir=''
if [[ "$runtime_env" == */runtime.env ]]; then
  candidate_runtime_dir="${runtime_env%/runtime.env}"
  if [[ "$runtime_env" == "$candidate_runtime_dir/runtime.env" &&
    "$candidate_runtime_dir" =~ ^/.*/permissionsync-keycloak\.[A-Za-z0-9]{6}$ &&
    "$candidate_runtime_dir" != *'//'* &&
    "$candidate_runtime_dir" != *'/./'* &&
    "$candidate_runtime_dir" != *'/../'* &&
    -d "$candidate_runtime_dir" && ! -L "$candidate_runtime_dir" &&
    ! -L "$runtime_env" ]]; then
    safe_runtime_dir="$candidate_runtime_dir"
  fi
fi

if [[ -z "$safe_runtime_dir" ]]; then
  printf '%s\n' 'Keycloak runtime environment is not in a safe generated runtime directory.' >&2
  exit 1
fi

readonly safe_runtime_dir

unset KEYCLOAK_TEST_COMPOSE_PROJECT KEYCLOAK_TEST_RUNTIME_DIR
# shellcheck disable=SC1090
source "$runtime_env"
: "${KEYCLOAK_TEST_COMPOSE_PROJECT:?runtime environment lacks project name}"
: "${KEYCLOAK_TEST_RUNTIME_DIR:?runtime environment lacks runtime directory}"

if [[ "$KEYCLOAK_TEST_RUNTIME_DIR" != "$safe_runtime_dir" ]]; then
  printf '%s\n' 'Keycloak runtime environment declares an unexpected runtime directory.' >&2
  exit 1
fi

# The runtime directory (and its runtime.env) must only be removed after a
# successful `docker compose down`. On failure it must be preserved so that
# teardown can be retried; a blanket EXIT trap cannot express that conditional
# cleanup safely, so this is handled inline instead.
if ! docker compose --env-file "$runtime_env" -p "$KEYCLOAK_TEST_COMPOSE_PROJECT" down --volumes --remove-orphans; then
  printf '%s\n' 'Keycloak teardown failed: docker compose down did not complete; preserving runtime directory for retry.' >&2
  exit 1
fi

if ! rm -rf -- "$safe_runtime_dir"; then
  printf '%s\n' 'Keycloak teardown failed: could not remove the generated runtime directory.' >&2
  exit 1
fi
