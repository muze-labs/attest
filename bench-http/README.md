# Muze Temporal Attestation — hot-path benchmark

This is the first implementation experiment for the Muze temporal-attestation service.
It intentionally benchmarks only the synchronous work that a v1 ingest request is
expected to require.

## What it measures

For each synthetic 32-byte client commitment:

1. generate a fresh 128-bit attestation nonce using a per-worker ChaCha12 CSPRNG;
2. construct a compact 72-byte receipt body;
3. sign it using Ed25519;
4. append the 64-byte signature (136-byte receipt total);
5. SHA-256 hash the signed receipt;
6. construct a 36-byte binary CIDv1 for the receipt as a raw IPLD block.

No heap allocation is required by our receipt assembly code on the hot path.

## What it deliberately does *not* measure yet

- HTTP parsing / response serialization;
- queues or channels;
- durable storage;
- Merkle batching;
- final proof generation;
- OpenTimestamps / other external anchoring;
- Kubo/IPFS publication;
- billing / accounts;
- textual CID/base32 encoding.

Those should be added as separate benchmark layers so we can see exactly where
throughput is lost.

## Why there is a nonce

The same commitment may legitimately be attested more than once. The receipt CID
is the attestation identifier, so each receipt needs unique entropy. In production,
each worker's ChaCha RNG must be securely seeded from the operating system or a
securely seeded master RNG. The benchmark uses deterministic seeds only to make
runs reproducible.

## Run the Criterion microbenchmarks

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench
```

This separately reports:

- Ed25519 signing of the receipt body;
- SHA-256 + binary CID construction;
- the complete nonce + receipt + sign + CID path.

## Run the simple throughput benchmark

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin throughput -- 1000000
```

The optional second argument controls worker count:

```bash
cargo run --release --bin throughput -- 5000000 8
```

The executable prints single-thread and multi-thread attestations/second.

## What result matters

The first useful number is:

> complete in-memory receipts signed and assigned a binary CID per second per core.

That is an upper bound for the real ingest service. The next benchmark should put
exactly this operation behind a minimal HTTP server and measure how much throughput
network/protocol handling costs.

## Important: this is benchmark/prototype code

The receipt binary layout is deliberately compact and stable enough to benchmark,
but it is not yet the final protocol specification. In particular:

- production key loading/rotation is absent;
- RNG seeding is deliberately deterministic here;
- service-policy and key-history references are not yet encoded;
- the receipt is represented as an IPLD `raw` block rather than DAG-CBOR;
- there is no external anchor or final proof yet.

Do not deploy this as a timestamp service.

## HTTP/1.1 end-to-end benchmark

Version 0.2 adds a deliberately minimal raw-Hyper server around the exact same
receipt hot path. It measures:

```
HTTP POST -> parse 32-byte commitment -> nonce -> Ed25519 signature
          -> receipt -> SHA-256/CID -> 172-byte HTTP response
```

It still has **no persistence, queue, Merkle batching, IPFS, TLS, authentication,
or external anchor**. The point is to measure how much HTTP/network plumbing
costs before those are added.

The benchmark server uses a fixed signing key and deterministic per-worker RNG
streams. **Do not use it as production code.**

### Start the server

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin http_server
```

It listens on `127.0.0.1:3000` by default. A different bind address can be
passed as the first argument:

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin http_server -- 0.0.0.0:3000
```

Smoke test:

```bash
curl http://127.0.0.1:3000/health
curl --data-binary @bench/commitment.bin \
     -H 'Content-Type: application/octet-stream' \
     -o /tmp/receipt.bin \
     http://127.0.0.1:3000/attest
wc -c /tmp/receipt.bin
```

The response should be 172 bytes: 136 receipt bytes followed by 36 binary CID
bytes.

### Load generation with oha

`oha` is convenient because it supports a binary request body and HTTP/1.1
keep-alive. Install it separately if needed, then run:

```bash
./bench/run-oha.sh
```

Defaults are 20 seconds and 128 concurrent connections. Tune them without
editing the script:

```bash
CONNECTIONS=32  DURATION=20s ./bench/run-oha.sh
CONNECTIONS=64  DURATION=20s ./bench/run-oha.sh
CONNECTIONS=128 DURATION=20s ./bench/run-oha.sh
CONNECTIONS=256 DURATION=20s ./bench/run-oha.sh
```

For the first pass, use the best throughput of those runs rather than assuming
more concurrency is always better.

### Important benchmark caveat

If `oha` and the server run on the same 4-core/8-thread machine, the reported
number measures **combined client + server capacity**, because the load generator
competes with the signer for CPU. That is still useful as a first end-to-end
number, but it is not the server ceiling.

For a clean server-capacity measurement, run `oha` from a second machine on a
fast LAN and bind the server to its LAN address / `0.0.0.0:3000`.

### What to compare

The previous in-memory result on `werkdoos` was about 326k attestations/s across
4 physical cores. The useful number here is the fraction retained once HTTP is
added:

```
HTTP efficiency = HTTP requests/s / 326,693
```

Do not optimize prematurely. If localhost HTTP remains comfortably above about
100k requests/s, the next benchmark should add the asynchronous enqueue/batch
boundary rather than micro-optimizing request parsing.

## Hierarchical one-second → one-minute Merkle benchmark

Version 0.4 adds the architecture intended for the infrastructure tier rather
than retaining a monolithic minute-sized tree.

At the default settings it processes:

- 150,000 commitment leaves per one-second tree;
- 60 independent one-second trees;
- one top tree over the 60 one-second roots.

Each local tree is discarded as soon as its root and proof paths have been
processed, so peak Merkle working memory is roughly one 150k-leaf tree rather
than one 9M-leaf tree.

Run:

```bash
./bench/run-merkle-hier.sh
```

Or tune it to the measured HTTP rate:

```bash
LEAVES_PER_SECOND=154000 SECONDS=60 ./bench/run-merkle-hier.sh
```

It reports:

- local-tree build throughput;
- proof-path extraction throughput;
- Linux resident/peak memory;
- local and minute-level proof depths;
- combined standalone Merkle path size;
- implied proof-output MiB/s and TiB/day at saturation;
- an upper bound for unique shared tree-node bytes;
- verification of complete two-level proofs for sample leaves.

The proof-output numbers are important: hierarchical Merkle aggregation removes
the large RAM requirement, but a standalone proof still needs its sibling hashes.
That information must eventually live with the client, in a proof store, or in a
shared structure. The benchmark makes that next scaling tradeoff explicit.
