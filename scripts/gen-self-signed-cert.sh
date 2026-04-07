#!/usr/bin/env bash
# Generate a self-signed TLS cert for ForSight (nginx). Re-run if the server IP changes.
# Usage:
#   ./scripts/gen-self-signed-cert.sh
#   ./scripts/gen-self-signed-cert.sh 192.168.1.50
#   OUTDIR=/path/to/certs ./scripts/gen-self-signed-cert.sh 10.0.0.5
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="${OUTDIR:-$ROOT/deploy/certs}"
IP="${1:-${IP:-}}"
mkdir -p "$OUTDIR"
KEY="$OUTDIR/forsight.key"
CRT="$OUTDIR/forsight.crt"

SAN="DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1"
if [[ -n "$IP" ]]; then
  SAN="$SAN,IP:${IP}"
fi

openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout "$KEY" \
  -out "$CRT" \
  -subj "/CN=forsight/O=ForSight" \
  -addext "subjectAltName=$SAN"

chmod 600 "$KEY"
echo "Wrote $CRT and $KEY (SAN: $SAN)"
echo "If clients use another IP or hostname, re-run with that address as the argument."
