#!/usr/bin/env sh
set -eu

DURATION="${DURATION:-20s}"
CONNECTIONS="${CONNECTIONS:-128}"
TARGET="${TARGET:-http://127.0.0.1:3000/attest}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

exec oha \
  --no-tui \
  -z "$DURATION" \
  -c "$CONNECTIONS" \
  -m POST \
  -D "$HERE/commitment.bin" \
  -T application/octet-stream \
  --http-version 1.1 \
  "$TARGET"
