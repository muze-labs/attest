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
