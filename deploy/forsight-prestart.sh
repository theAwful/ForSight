#!/usr/bin/env bash
# Prepare data dirs and seed wordlists before uvicorn starts (systemd ExecStartPre).
# Requires: FORSIGHT_APP_ROOT (repo root, e.g. /opt/forsight), FORSIGHT_DATA_DIR (e.g. /var/lib/forsight).
set -euo pipefail
ROOT="${FORSIGHT_APP_ROOT:?Set FORSIGHT_APP_ROOT to the ForSight repo root}"
DATA="${FORSIGHT_DATA_DIR:?Set FORSIGHT_DATA_DIR}"
mkdir -p "$DATA/uploads" "$DATA/results" "$DATA/wordlists"
WORD_SRC="$ROOT/backend/data/wordlists"
if [[ -d "$WORD_SRC" ]]; then
  for f in "$WORD_SRC"/*; do
    [[ -e "$f" ]] || continue
    base=$(basename "$f")
    [[ -e "$DATA/wordlists/$base" ]] || cp "$f" "$DATA/wordlists/"
  done
fi
