#!/bin/sh
set -e
mkdir -p /app/data/uploads /app/data/results /app/data/wordlists
# Seed default wordlists if volume is empty (first run)
for f in /app/wordlists-default/*; do
  [ -e "$f" ] && [ ! -e "/app/data/wordlists/$(basename "$f")" ] && cp "$f" /app/data/wordlists/
done
exec "$@"
