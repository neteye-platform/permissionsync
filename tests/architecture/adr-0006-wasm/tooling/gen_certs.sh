#!/usr/bin/env bash
# Generate ephemeral test-only CA + server certificate into the suite's
# gitignored `generated/certs/` dir. Never commit private keys/materials.
#
# The host verifies the fake servers' TLS certs against this CA (Gate 6 tests
# explicit-CA trust), so the server cert must chain to the generated CA and
# carry the IP:127.0.0.1 SAN the host connects to.

set -euo pipefail

POC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$POC/generated/certs"
DAYS=365
CA_CN="permissionsync-poc-ca"
SERVER_CN="127.0.0.1"

mkdir -p "$OUT"

# CA private key + self-signed CA cert.
openssl genrsa -out "$OUT/ca-pk" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/ca-pk" \
    -sha256 -days $DAYS \
    -subj "/CN=$CA_CN" \
    -out "$OUT/ca.crt"

# Server private key + CSR, signed by the CA, with the 127.0.0.1 SAN.
openssl genrsa -out "$OUT/server-pk" 2048 2>/dev/null
openssl req -new -key "$OUT/server-pk" \
    -subj "/CN=$SERVER_CN" \
    -out "$OUT/server.csr"
printf "subjectAltName=IP:127.0.0.1\n" > "$OUT/ext.cnf"
openssl x509 -req -in "$OUT/server.csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca-pk" -CAcreateserial \
    -days $DAYS -sha256 \
    -extfile "$OUT/ext.cnf" \
    -out "$OUT/server.crt"

rm -f "$OUT/server.csr" "$OUT/ext.cnf" "$OUT/ca.srl"
echo "generated ephemeral certs in $OUT"
