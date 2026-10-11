#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TLS_DIR="bench/tls"
CERT="$TLS_DIR/bench.crt"
KEY="$TLS_DIR/bench.key"
PEM="$TLS_DIR/bench.pem"
CFG="bench/haproxy.cfg"

mkdir -p "$TLS_DIR"

cleanup() {
    echo
    echo "Stopping services..."

    if [ -n "${HAPROXY_PID:-}" ] && kill -0 "$HAPROXY_PID" 2>/dev/null; then
        kill "$HAPROXY_PID" 2>/dev/null || true
        wait "$HAPROXY_PID" 2>/dev/null || true
    fi

    if [ -n "${RUST_PID:-}" ] && kill -0 "$RUST_PID" 2>/dev/null; then
        kill "$RUST_PID" 2>/dev/null || true
        wait "$RUST_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

for cmd in cargo haproxy openssl curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: $cmd is not installed"
        exit 1
    fi
done

if [ ! -f "$PEM" ]; then
    echo "Generating temporary benchmark TLS certificate..."
    openssl req -x509 -newkey ec \
        -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes \
        -keyout "$KEY" \
        -out "$CERT" \
        -days 1 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    cat "$CERT" "$KEY" > "$PEM"
fi

echo "Checking HAProxy configuration..."
haproxy -c -f "$CFG"

echo
echo "Starting Muze attestation server on :4000..."
MUZE_ATTEST_BIND=127.0.0.1:4000 \
MUZE_ATTEST_PUBLIC_BASE_URL=https://localhost:4443 \
    cargo run --release -- serve &
RUST_PID=$!

echo "Waiting for attestation server..."
for _ in $(seq 1 200); do
    if curl -fsS http://127.0.0.1:4000/health >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$RUST_PID" 2>/dev/null; then
        echo "error: attestation server exited during startup"
        exit 1
    fi
    sleep 0.1
done

if ! curl -fsS http://127.0.0.1:4000/health >/dev/null 2>&1; then
    echo "error: attestation server did not become ready"
    exit 1
fi

echo "Starting HAProxy TLS frontend on :4443..."
haproxy -f "$CFG" -db &
HAPROXY_PID=$!

echo "Waiting for HTTPS frontend..."
for _ in $(seq 1 100); do
    if curl -kfsS https://127.0.0.1:4443/health >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
        echo "error: HAProxy exited during startup"
        exit 1
    fi
    sleep 0.1
done

if ! curl -kfsS https://127.0.0.1:4443/health >/dev/null 2>&1; then
    echo "error: HTTPS frontend did not become ready"
    exit 1
fi

echo
echo "Running:"
echo "  HTTP  http://127.0.0.1:4000"
echo "  HTTPS https://127.0.0.1:4443"
echo
echo "Benchmark with:"
echo "  CONNECTIONS=64 ./bench/run-oha-tls.sh"
echo
echo "Press Ctrl-C to stop both."
echo

# Wait while either service runs; cleanup trap stops the other one.
while kill -0 "$RUST_PID" 2>/dev/null && kill -0 "$HAPROXY_PID" 2>/dev/null; do
    sleep 1
done
