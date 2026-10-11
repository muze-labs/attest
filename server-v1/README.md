# Muze Temporal Attestation Service — v1 prototype

A deliberately small Rust service for one statement:

> **Muze attests that this cryptographic commitment was available to the service no later than time X.**

The service never needs the source data. Clients hash locally and send only a 32-byte SHA-256 digest.

## What is implemented

- Rust/Hyper web server.
- Human-readable pages explaining the trust model and binary format.
- `POST /v1/attest`: high-throughput binary attestation API.
- Public Ed25519 key disclosure at `/keys`, `/v1/keys/current`, `/v1/keys/current.raw`, and a `.well-known` URL.
- `/decode`: browser decoder/verifier explaining what an attestation means.
- `/health`: human-readable live clock health, source list, offsets, thresholds, and issuance decision.
- `/v1/health`: machine-readable clock/service health.
- Canonical 127-byte binary attestation format.
- Textual `mta1_<base64url>` representation for copy/paste.
- Separate `format_version` and `assurance_level` fields.
- CLI commands for key generation, hashing, decoding, and local verification.
- No database and no attestation persistence.

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release -- serve
```

Then open <http://127.0.0.1:3000/>.

On first start a new Ed25519 signing key is created at `data/signing.key`. The file is the issuer identity for this prototype. Back it up and keep it private if you intend other systems to rely on attestations from this instance.

Configuration:

```bash
MUZE_ATTEST_BIND=0.0.0.0:3000
MUZE_ATTEST_KEY=/secure/path/signing.key
MUZE_ATTEST_ISSUER='Muze Temporal Attestation Service'
MUZE_ATTEST_NTP_MIN_VALID=3
MUZE_ATTEST_NTP_SOURCE_THRESHOLD_MS=100
MUZE_ATTEST_NTP_LOCAL_THRESHOLD_MS=250
cargo run --release -- serve
```

For public deployment, put TLS/reverse-proxy infrastructure in front of the Rust service.

## API

The primary protocol is binary.

### `POST /v1/attest`

Request body: exactly 32 raw bytes containing a SHA-256 digest.

Response body: exactly 127 bytes containing a Muze Temporal Attestation.

```bash
sha256sum evidence.bin
# Convert the digest to 32 binary bytes, then:
curl --data-binary @digest.bin \
  -H 'Content-Type: application/octet-stream' \
  -o evidence.mta \
  http://127.0.0.1:3000/v1/attest
```

The home page includes a browser demo that hashes text locally and submits only the digest.

## Attestation format

See [`docs/protocol.md`](docs/protocol.md).

V1 layout:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `MTA\0` |
| 4 | 1 | format version = `1` |
| 5 | 1 | assurance level = `1` |
| 6 | 1 | hash algorithm = `1` (SHA-256) |
| 7 | 32 | digest |
| 39 | 8 | signed big-endian Unix milliseconds UTC |
| 47 | 16 | key ID |
| 63 | 64 | Ed25519 signature over bytes 0..62 |

Total: **127 bytes**.

Text form: `mta1_` + unpadded base64url of those 127 bytes.

## Assurance level 1

Level 1 is a **trusted-issuer upper-bound timestamp**.

A valid attestation means:

> The issuer represented by the signing key attests that the commitment was available to it no later than the signed time.

It does **not** prove:

- that the underlying data is true;
- who created the data;
- when the data was first created;
- that Muze could not deliberately backdate an attestation.

Independent anchoring and bounded-time challenges are intended as separate, stronger assurance levels later.

## Clock health

Clock health is part of the assurance-level-1 trust boundary. The service cross-checks its host UTC clock against five independently operated public NTP services:

- `time.cloudflare.com` — Cloudflare
- `time.nist.gov` — NIST
- `time.windows.com` — Microsoft
- `ntp.ubuntu.com` — Canonical / Ubuntu
- `time.meta.com` — Meta

Defaults:

- check all five in parallel every 30 seconds;
- require at least 3 valid sources;
- reject a source if it differs by more than 100 ms from the median of reachable sources;
- refuse issuance if the median of valid sources says the local clock differs by more than 250 ms;
- refuse issuance if clock-health information is more than 90 seconds old;
- retain the in-process guard that refuses issuance if the local clock moves backwards.

The human-readable `/health` page publishes the source list, current offsets, source status, thresholds, and issuance decision. `/v1/health` provides the same information as JSON.

These checks currently use ordinary NTP rather than cryptographically authenticated NTS. They protect well against accidental clock errors and isolated bad sources, but NTS is an appropriate later hardening step.

All clock-health settings can be changed with environment variables documented by `--help`.

## Tests

```bash
cargo test
```

## Useful CLI commands

```bash
cargo run --release -- hash evidence.bin
cargo run --release -- decode evidence.mta
```

For `verify`, download the raw key directly, for example: `curl -o muze-public.key http://127.0.0.1:3000/v1/keys/current.raw`.

## Security / deployment notes

- Never log request bodies/digests by default.
- Protect `data/signing.key`; it is an online signing key.
- Use TLS for public deployment.
- Treat clock health as part of the security boundary.
- A future key-history mechanism should timestamp and publish rotations rather than silently replacing keys.
