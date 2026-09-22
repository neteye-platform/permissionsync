#!/usr/bin/env bash
# Bootstraps a disposable GLPI 11.0.9 + MariaDB environment for the real GLPI
# integration suite. This is test infrastructure only, per ADR 0009's
# "Two-layer test policy": disposable per-run credentials, no shared or
# long-lived state, and the actual adapter tests still exercise the
# production GLPI V1 apirest.php contract, not direct database access.
#
# Requires: docker compose (v2 plugin), curl.
#
# NOTE: the exact GLPI database bootstrap SQL below (glpi_configs,
# glpi_apiclients, glpi_users.api_token) was derived from the GLPI 11.0.x
# schema and conventions but has not been executed against a running
# container in this environment (no Docker available). Verify it against an
# actual GLPI 11.0.9 container before relying on it in CI.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

APP_TOKEN="$(openssl rand -hex 20)"
USER_TOKEN="$(openssl rand -hex 20)"
export APP_TOKEN USER_TOKEN

echo "Generating an ephemeral TLS CA and server certificate for the local test proxy..." >&2
rm -rf ./tls
mkdir -p ./tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout ./tls/ca.key -out ./tls/ca.crt \
  -subj "/CN=permissionsync-glpi-real-integration-ca"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ./tls/server.key -out ./tls/server.csr \
  -subj "/CN=127.0.0.1"
openssl x509 -req -in ./tls/server.csr -CA ./tls/ca.crt -CAkey ./tls/ca.key \
  -CAcreateserial -days 2 -out ./tls/server.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1")

echo "Starting disposable GLPI + database + TLS proxy containers..." >&2
docker compose up -d --wait --wait-timeout 180

echo "Waiting for GLPI apirest.php to respond..." >&2
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:8080/apirest.php/" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "Provisioning a disposable API client and service-account token..." >&2
docker compose exec -T db mariadb -uroot -pglpi-test-root-password glpi <<SQL
INSERT INTO glpi_configs (context, name, value)
  VALUES ('core', 'enable_api', '1')
  ON DUPLICATE KEY UPDATE value = '1';
INSERT INTO glpi_configs (context, name, value)
  VALUES ('core', 'enable_api_login_credentials', '1')
  ON DUPLICATE KEY UPDATE value = '1';

INSERT INTO glpi_apiclients
    (entities_id, is_recursive, name, is_active, app_token, date_creation, date_mod)
  VALUES
    (0, 1, 'permissionsync-real-integration', 1, '${APP_TOKEN}', NOW(), NOW())
  ON DUPLICATE KEY UPDATE app_token = '${APP_TOKEN}', is_active = 1;

-- The default seeded super-admin account (login "glpi") already has
-- Super-Admin rights across the recursive root entity from GLPI's own
-- install defaults, which satisfies the ADR 0009 complete-visibility
-- precondition for this disposable environment.
UPDATE glpi_users SET api_token = '${USER_TOKEN}' WHERE name = 'glpi';
SQL

echo "GLPI_TEST_ENDPOINT=https://127.0.0.1:8443/apirest.php"
echo "GLPI_TEST_APP_TOKEN=${APP_TOKEN}"
echo "GLPI_TEST_USER_TOKEN=${USER_TOKEN}"
echo "GLPI_TEST_CA_PEM_PATH=${script_dir}/tls/ca.crt"
