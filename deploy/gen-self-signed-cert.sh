#!/usr/bin/env bash
# Wrapper — real script lives in scripts/ (single copy to maintain).
# Usage: ./deploy/gen-self-signed-cert.sh [IP_OR_HOSTNAME]
# Same as: ./scripts/gen-self-signed-cert.sh [IP_OR_HOSTNAME]
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$REPO_ROOT/scripts/gen-self-signed-cert.sh" "$@"
