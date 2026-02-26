#!/usr/bin/env bash
# Build or serve ForSight docs using the .venv-docs env (so Material theme is used).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv-docs"
if [[ ! -d "$VENV" ]]; then
  echo "Creating .venv-docs and installing mkdocs-material..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -r "$ROOT/docs/requirements.txt"
fi
if [[ "${1:-}" == "serve" ]]; then
  exec "$VENV/bin/mkdocs" serve "${@:2}"
else
  exec "$VENV/bin/mkdocs" build "$@"
fi
