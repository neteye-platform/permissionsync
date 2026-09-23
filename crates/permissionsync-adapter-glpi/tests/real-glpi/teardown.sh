#!/usr/bin/env bash
# Tears down the disposable GLPI environment left running by bootstrap.sh
# after a successful run. Safe to call multiple times.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

env_file="${script_dir}/.real-glpi-run-env"
if [[ ! -f "$env_file" ]]; then
  echo "No recorded disposable GLPI environment to tear down (${env_file} not found)." >&2
  exit 0
fi

# shellcheck disable=SC1090
source "$env_file"

if [[ -n "${PERMISSIONSYNC_GLPI_PROJECT_NAME:-}" ]]; then
  docker compose -p "$PERMISSIONSYNC_GLPI_PROJECT_NAME" down --volumes --remove-orphans || true
fi

if [[ -n "${PERMISSIONSYNC_GLPI_TLS_DIR:-}" ]]; then
  rm -rf "$PERMISSIONSYNC_GLPI_TLS_DIR"
fi

rm -f "$env_file"
