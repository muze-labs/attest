#!/usr/bin/env sh
set -eu

LEAVES_PER_SECOND="${LEAVES_PER_SECOND:-150000}"
SECONDS="${SECONDS:-60}"

RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native}" \
  cargo run --release --bin merkle_hier -- "$LEAVES_PER_SECOND" "$SECONDS"
