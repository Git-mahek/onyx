#!/usr/bin/env bash
# Generate a throwaway CA and a broker certificate for local TLS testing.
# Usage: ./gen_certs.sh [outdir] [broker-hostname]
set -euo pipefail

OUT="${1:-certs}"
HOST="${2:-localhost}"
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=Sensor Test CA"

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=$HOST"
printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n" "$HOST" > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile san.ext

rm -f server.csr san.ext ca.srl
chmod 600 ca.key
chmod 644 ca.crt server.crt server.key   # readable inside the broker container; test certs only
echo "wrote $OUT/ca.crt, $OUT/server.crt, $OUT/server.key (CA key: $OUT/ca.key)"
