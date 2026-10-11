#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DURATION="${DURATION:-20s}"
CONNECTIONS="${CONNECTIONS:-64}"
TARGET="${TARGET:-http://127.0.0.1:4000/v1/attest}"

if ! command -v oha >/dev/null 2>&1; then
    echo "error: oha is not installed (cargo install oha)"
    exit 1
fi

exec oha \
  --no-tui \
  -z "$DURATION" \
  -c "$CONNECTIONS" \
  -m POST \
  -D bench/commitment.bin \
  -T application/octet-stream \
  --http-version 1.1 \
  "$TARGET"
