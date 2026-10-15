# Attest

**Status: Experimental — not yet suitable for production use.**

Attest is an open-source project by [Muze](https://muze.nl) exploring
infrastructure-scale, low-cost cryptographic timestamp attestation.

## Why?

Verifiable credentials, provenance records, and delegated authority
all benefit from independently verifiable evidence of when information
existed.

Existing timestamping services are generally designed around individual
documents. Attest explores whether we can provide timestamp attestation
at infrastructure scale, cheaply enough to make it practical for
millions of everyday transactions.

## How it works

Attest accepts cryptographic hashes rather than documents or other
private information.

The initial implementation issues compact, cryptographically signed
receipts. Future versions aim to support independent anchoring and
verification through batched proofs.

An attestation provides evidence that particular data existed no later
than a certain time. It does not establish that the data is true or
that an associated action actually occurred.

## Current status

This repository contains experimental implementations and benchmarks.

The current focus is on signed attestations, performance, and
reliability. Independent anchoring is a planned next step.

**Do not rely on this software yet for legal, security-critical,
or other production applications.**

## License

MIT — Copyright 2026 Muze.nl.
