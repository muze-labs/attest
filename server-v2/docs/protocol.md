# Muze Temporal Attestation Protocol v1

## Statement

Assurance level 1 represents this statement:

> The issuer identified by `key_id` attests that the commitment in `digest` was available to the issuer no later than `timestamp_ms`.

The relying party chooses whether to trust that issuer's clock and operational honesty.

## API version vs format version vs assurance level

They are independent:

- API version: HTTP contract, currently `/v1/...`.
- Format version: binary serialization semantics, currently `1`.
- Assurance level: security/trust statement, currently `1`.

A future `/v2/attest` endpoint could still emit format `1`, assurance `1`; or format `1` could carry a separately specified assurance level `2`.

## Canonical binary representation

All integers are unsigned/signed as specified and serialized big-endian. There is no optional padding.

```text
offset  size  field
0       4     magic = 4d 54 41 00 ("MTA\\0")
4       1     format_version = 01
5       1     assurance_level = 01
6       1     hash_algorithm = 01 (SHA-256)
7       32    digest
39      8     timestamp_ms: signed i64 Unix milliseconds UTC, big-endian
47      16    key_id
63      64    Ed25519 signature over bytes [0,63)
```

Total length: 127 bytes.

## Key ID

```text
key_id = first 16 bytes of SHA-256(raw 32-byte Ed25519 public key)
```

This is an identifier, not an independent trust anchor. A verifier still needs a trusted binding from `key_id` to the issuer/public key.

## Text representation

For transport, copy/paste, logs under explicit user control, and UI:

```text
mta1_<base64url-without-padding(binary-attestation)>
```

The binary representation remains normative.

## Hash algorithm 1

`1` = SHA-256, digest exactly 32 bytes.

## Assurance level 1

Name: `trusted-issuer-upper-bound`

The verifier trusts:

- that the signing private key is controlled by the stated issuer;
- that the issuer's clock is sufficiently accurate;
- that the issuer does not intentionally backdate.

The signature protects integrity and issuer authenticity. It does not independently prove clock honesty.


## Issuer clock-health requirement

For the Muze reference service, assurance level 1 is issued only while the service clock is healthy. The current implementation cross-checks the local UTC clock against five public NTP operators, requires a 3-of-5 quorum after source-outlier rejection, requires the valid-source median to remain within the configured local-clock threshold, expires stale health state, and retains an in-process backwards-clock guard.

Clock-health policy is an issuer operational property rather than part of the 127-byte attestation format. A relying party still decides whether it trusts the issuer's clock operation. The reference service publishes its current clock sources, thresholds, offsets, and issuance decision at `/health` and `/v1/health`.

Ordinary NTP is not cryptographically authenticated; stronger future deployments may use NTS or higher assurance levels with independent anchoring.

## Verification

1. Parse exactly 127 bytes.
2. Check magic, format version, assurance level, and hash algorithm are understood.
3. Resolve `key_id` to a trusted Ed25519 public key.
4. Confirm that `key_id` matches the resolved public key.
5. Verify the Ed25519 signature over bytes 0..62.
6. If verifying content, SHA-256 the exact content bytes and compare with `digest`.
7. Interpret `timestamp_ms` according to the assurance-level semantics.

Unknown assurance levels must not silently inherit level-1 meaning.
